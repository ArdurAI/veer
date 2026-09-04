package administration

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestEligibleActionsAreClosedAndIndependent(t *testing.T) {
	t.Parallel()
	want := []authorization.Action{
		authorization.ActionAuditExport,
		authorization.ActionOperationQuarantine,
		authorization.ActionWorkRedrive,
	}
	got := EligibleActions()
	if !slices.Equal(got, want) {
		t.Fatalf("EligibleActions() = %v, want %v", got, want)
	}
	got[0] = authorization.ActionResourceDelete
	if slices.Equal(EligibleActions(), got) {
		t.Fatal("EligibleActions returned mutable registry storage")
	}
	for _, action := range authorization.Actions() {
		wantEligible := slices.Contains(want, action)
		if validAction(action) != wantEligible {
			t.Fatalf("validAction(%q) = %t, want %t", action, validAction(action), wantEligible)
		}
	}
	if validAction(authorization.Action("audit.export\x00")) {
		t.Fatal("open action vocabulary accepted")
	}
}

func TestClosedDiagnosticVocabularies(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind TargetKind
		want string
	}{
		{TargetKindPlatformAudit, "PlatformAudit"},
		{TargetKindWorkspaceAudit, "WorkspaceAudit"},
		{TargetKindOperation, "Operation"},
		{TargetKind("secret-kind-canary"), "Invalid"},
	} {
		if got := test.kind.String(); got != test.want {
			t.Fatalf("TargetKind(%q).String() = %q, want %q", test.kind, got, test.want)
		}
	}
	for _, test := range []struct {
		state GrantState
		want  string
	}{
		{GrantStateActive, "Active"},
		{GrantStateConsumed, "Consumed"},
		{GrantStateRevoked, "Revoked"},
		{GrantStateExpired, "Expired"},
		{GrantState(255), "Invalid"},
	} {
		if got := test.state.String(); got != test.want {
			t.Fatalf("GrantState(%d).String() = %q, want %q", test.state, got, test.want)
		}
	}
}

func TestAdministratorUsesExactHumanIdentity(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	if ValidateAdministrator(administrator) != nil || administrator.ID() != testAdministratorID ||
		!administrator.MatchesPrincipal(principal) {
		t.Fatal("constructed exact administrator binding is invalid")
	}

	changedInputs := []identity.PrincipalInput{
		{Kind: identity.KindHuman, Issuer: testIssuer + "/other", Subject: testSubject, Audiences: []string{"veer-api"}},
		{Kind: identity.KindHuman, Issuer: testIssuer, Subject: strings.ToUpper(testSubject), Audiences: []string{"veer-api"}},
	}
	for _, input := range changedInputs {
		changed, err := identity.NewPrincipal(input)
		if err != nil {
			t.Fatal(err)
		}
		if administrator.MatchesPrincipal(changed) {
			t.Fatal("administrator matched a different exact issuer/subject")
		}
	}

	sameLogical, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"another-audience"},
		Groups:    []string{"changed-policy-input"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !administrator.MatchesPrincipal(sameLogical) {
		t.Fatal("mutable audience/group claims changed exact identity matching")
	}

	workloadClaim, err := identity.NewWorkloadIdentity("spiffe://workload-canary")
	if err != nil {
		t.Fatal(err)
	}
	workload, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindWorkload, Issuer: testIssuer, Subject: testSubject,
		Audiences: []string{"veer-api"}, WorkloadIdentity: &workloadClaim,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAdministrator(testAdministratorID, workload); !errors.Is(err, ErrAdministratorNotHuman) {
		t.Fatalf("NewAdministrator(workload) error = %v, want ErrAdministratorNotHuman", err)
	}
	if _, err := NewAdministrator("short", principal); !errors.Is(err, ErrInvalidAdministrator) {
		t.Fatalf("NewAdministrator(invalid ID) error = %v", err)
	}
}

func TestLedgerAdministratorDirectoryBoundsAndDuplicates(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	if _, err := NewLedger([]Administrator{administrator, administrator}); !errors.Is(err, ErrDuplicateAdministratorID) {
		t.Fatalf("NewLedger(duplicate ID) error = %v", err)
	}
	otherID := mustAdministrator(t, testOtherAdministratorID, principal)
	if _, err := NewLedger([]Administrator{administrator, otherID}); !errors.Is(err, ErrDuplicateAdministrator) {
		t.Fatalf("NewLedger(duplicate identity) error = %v", err)
	}
	tooMany := make([]Administrator, 0, MaxAdministrators+1)
	for index := range MaxAdministrators + 1 {
		p := mustPrincipal(t, testIssuer, generatedID("subject", index).String())
		tooMany = append(tooMany, mustAdministrator(t, generatedID("adm", index), p))
	}
	if _, err := NewLedger(tooMany); !errors.Is(err, ErrTooManyAdministrators) {
		t.Fatalf("NewLedger(over limit) error = %v", err)
	}
	if ledger, err := NewLedger(nil); err != nil || ledger.state == nil {
		t.Fatalf("NewLedger(empty) = %v, %v", ledger, err)
	}
}

func TestTargetResolutionSealsPlatformWorkspaceAndOperationScope(t *testing.T) {
	t.Parallel()
	fixture := newHierarchyFixture(t)

	platform := ResolvePlatformAuditExportTarget()
	if ValidateTarget(platform) != nil || platform.Kind() != TargetKindPlatformAudit {
		t.Fatal("platform target is invalid")
	}
	for name, accessor := range map[string]func() (resource.ID, bool){
		"object":      platform.ObjectID,
		"workspace":   platform.WorkspaceID,
		"resource":    platform.ResourceID,
		"environment": platform.EnvironmentID,
		"connection":  platform.ProviderConnectionID,
	} {
		if id, present := accessor(); present || id != "" {
			t.Fatalf("platform %s ID = %q, %t", name, id, present)
		}
	}

	workspace, err := ResolveWorkspaceAuditExportTarget(fixture.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Kind() != TargetKindWorkspaceAudit {
		t.Fatalf("workspace target kind = %q", workspace.Kind())
	}
	for name, accessor := range map[string]func() (resource.ID, bool){
		"object":    workspace.ObjectID,
		"workspace": workspace.WorkspaceID,
		"resource":  workspace.ResourceID,
	} {
		if id, present := accessor(); !present || id != fixture.workspace {
			t.Fatalf("workspace %s ID = %q, %t", name, id, present)
		}
	}

	operationTarget, err := ResolveOperationTarget(fixture.snapshot, fixture.operation)
	if err != nil {
		t.Fatal(err)
	}
	objectID, objectPresent := operationTarget.ObjectID()
	assertOptionalID(t, objectID, objectPresent, testOperationID)
	workspaceID, workspacePresent := operationTarget.WorkspaceID()
	assertOptionalID(t, workspaceID, workspacePresent, fixture.workspace)
	resourceID, resourcePresent := operationTarget.ResourceID()
	assertOptionalID(t, resourceID, resourcePresent, fixture.environment)
	environmentID, environmentPresent := operationTarget.EnvironmentID()
	assertOptionalID(t, environmentID, environmentPresent, fixture.environment)
	connectionID, connectionPresent := operationTarget.ProviderConnectionID()
	assertOptionalID(t, connectionID, connectionPresent, fixture.connection)

	// A retained Workspace target has no provider binding, so the Operation's
	// absent Environment/ProviderConnection pair is valid.
	workspaceOperation, err := ResolveOperationTarget(fixture.snapshot, fixture.workspaceOperation)
	if err != nil {
		t.Fatalf("ResolveOperationTarget(unbound retained workspace) error = %v", err)
	}
	if _, present := workspaceOperation.EnvironmentID(); present {
		t.Fatal("workspace operation gained an environment binding")
	}
	if _, present := workspaceOperation.ProviderConnectionID(); present {
		t.Fatal("workspace operation gained a provider binding")
	}
	impossibleTarget := operationTarget
	impossibleTarget.providerConnectionID = nil
	if err := ValidateTarget(impossibleTarget); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ValidateTarget(one-sided environment) error = %v", err)
	}
	impossibleTarget = workspaceOperation
	impossibleTarget.providerConnectionID = idPointer(fixture.connection)
	if err := ValidateTarget(impossibleTarget); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ValidateTarget(one-sided provider) error = %v", err)
	}

	tampered := fixture.operation
	otherEnvironment := resource.ID("env_01JADMIN00000000000000099")
	tampered.EnvironmentID = &otherEnvironment
	if _, err := ResolveOperationTarget(fixture.snapshot, tampered); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ResolveOperationTarget(tampered environment) error = %v", err)
	}
	tampered = fixture.operation
	otherConnection := resource.ID("con_01JADMIN00000000000000099")
	tampered.ProviderConnectionID = &otherConnection
	if _, err := ResolveOperationTarget(fixture.snapshot, tampered); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ResolveOperationTarget(unretained connection) error = %v", err)
	}
	if _, err := ResolveWorkspaceAuditExportTarget(hierarchy.Snapshot{}); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ResolveWorkspaceAuditExportTarget(zero) error = %v", err)
	}
}

func TestResolveOperationTargetAllowsUnboundEnvironmentScopedResources(t *testing.T) {
	t.Parallel()
	fixture := newHierarchyFixture(t)
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)

	resources := []struct {
		name string
		id   resource.ID
	}{
		{name: "environment", id: fixture.environment},
		{name: "application", id: fixture.application},
		{name: "component", id: fixture.component},
		{name: "provider connection", id: fixture.connection},
	}
	for index, test := range resources {
		t.Run(test.name, func(t *testing.T) {
			value, err := operation.New(operation.Input{
				ID:              generatedID("op", index+10),
				WorkspaceID:     fixture.workspace,
				ResourceID:      test.id,
				Generation:      1,
				ResourceVersion: fmt.Sprintf("rv_admin_unbound_%d", index),
				CreatedAt:       testNow,
			})
			if err != nil {
				t.Fatal(err)
			}

			target, err := ResolveOperationTarget(fixture.snapshot, value)
			if err != nil {
				t.Fatalf("ResolveOperationTarget(unbound %s) error = %v", test.name, err)
			}
			resourceID, present := target.ResourceID()
			assertOptionalID(t, resourceID, present, test.id)
			if _, present := target.EnvironmentID(); present {
				t.Fatal("unbound operation target gained an environment binding")
			}
			if _, present := target.ProviderConnectionID(); present {
				t.Fatal("unbound operation target gained a provider binding")
			}

			ledger := mustLedger(t, administrator)
			request := mustRequest(
				t,
				generatedID("elv", index+10),
				administrator,
				principal,
				authorization.ActionOperationQuarantine,
				target,
				time.Minute,
			)
			grant, err := ledger.Issue(
				testNow,
				mustReceipt(t, generatedID("prf", index+10), request, testNow, testNow),
			)
			if err != nil {
				t.Fatalf("Issue(unbound %s target) error = %v", test.name, err)
			}
			if !equalTarget(grant.Target(), target) {
				t.Fatal("issued grant lost its unbound operation target")
			}
		})
	}
}

func TestElevationRequestValidationAndNormalization(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	offset := time.FixedZone("request-offset", -6*60*60)
	requestedAt := testNow.In(offset).Add(456_789 * time.Nanosecond)
	request, err := NewElevationRequest(
		testGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		target,
		strings.Repeat("界", MaxReasonRunes),
		strings.Repeat("c", MaxCaseReferenceRunes),
		requestedAt,
		MaxElevationDuration,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.RequestedAt().Location() != time.UTC ||
		request.RequestedAt().Nanosecond()%int(time.Millisecond) != 0 ||
		request.Duration() != MaxElevationDuration {
		t.Fatalf("request time/duration not canonical: %v / %v", request.RequestedAt(), request.Duration())
	}
	if !identity.SameLogicalIdentity(request.Principal(), principal) ||
		request.AdministratorID() != testAdministratorID || request.ID() != testGrantID ||
		request.Action() != authorization.ActionAuditExport || !equalTarget(request.Target(), target) {
		t.Fatal("request accessors changed a bound value")
	}
	if reference, present := request.CaseReference(); !present || len([]rune(reference)) != MaxCaseReferenceRunes {
		t.Fatal("request lost the bounded case reference")
	}

	tests := []struct {
		name     string
		action   authorization.Action
		target   Target
		reason   string
		caseRef  string
		time     time.Time
		duration time.Duration
		want     error
	}{
		{"tenant action", authorization.ActionResourceDelete, target, "reason", "", testNow, time.Minute, ErrInvalidAction},
		{"action target mismatch", authorization.ActionOperationQuarantine, target, "reason", "", testNow, time.Minute, ErrActionTargetMismatch},
		{"empty reason", authorization.ActionAuditExport, target, "", "", testNow, time.Minute, ErrInvalidReason},
		{"space padded reason", authorization.ActionAuditExport, target, " reason", "", testNow, time.Minute, ErrInvalidReason},
		{"reason over rune bound", authorization.ActionAuditExport, target, strings.Repeat("界", MaxReasonRunes+1), "", testNow, time.Minute, ErrInvalidReason},
		{"case over rune bound", authorization.ActionAuditExport, target, "reason", strings.Repeat("界", MaxCaseReferenceRunes+1), testNow, time.Minute, ErrInvalidCaseReference},
		{"zero clock", authorization.ActionAuditExport, target, "reason", "", time.Time{}, time.Minute, ErrInvalidClock},
		{"zero duration", authorization.ActionAuditExport, target, "reason", "", testNow, 0, ErrInvalidElevationDuration},
		{"over duration", authorization.ActionAuditExport, target, "reason", "", testNow, MaxElevationDuration + time.Millisecond, ErrInvalidElevationDuration},
		{"sub-millisecond duration", authorization.ActionAuditExport, target, "reason", "", testNow, time.Nanosecond, ErrInvalidElevationDuration},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewElevationRequest(
				testGrantID, administrator, principal, test.action, test.target,
				test.reason, test.caseRef, test.time, test.duration,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("NewElevationRequest() error = %v, want %v", err, test.want)
			}
		})
	}

	other := mustPrincipal(t, testIssuer, testSubject+"-other")
	if _, err := NewElevationRequest(
		testGrantID, administrator, other, authorization.ActionAuditExport, target,
		"reason", "", testNow, time.Minute,
	); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("NewElevationRequest(identity mismatch) error = %v", err)
	}
}

func TestElevationTextBytePreflightRejectsLargeUTF8WithoutEcho(t *testing.T) {
	t.Parallel()

	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	largeReason := "large-reason-canary-" + strings.Repeat("界", 1<<16)
	_, err := NewElevationRequest(
		testGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		target,
		largeReason,
		"",
		testNow,
		time.Minute,
	)
	if !errors.Is(err, ErrInvalidReason) {
		t.Fatalf("large reason error class = %v", err)
	}
	if strings.Contains(err.Error(), "large-reason-canary") {
		t.Fatal("large reason was echoed in its validation error")
	}

	largeCaseReference := "large-case-canary-" + strings.Repeat("界", 1<<16)
	_, err = NewElevationRequest(
		testGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		target,
		"bounded reason",
		largeCaseReference,
		testNow,
		time.Minute,
	)
	if !errors.Is(err, ErrInvalidCaseReference) {
		t.Fatalf("large case reference error class = %v", err)
	}
	if strings.Contains(err.Error(), "large-case-canary") {
		t.Fatal("large case reference was echoed in its validation error")
	}
}

func TestStrongAuthReceiptFreshnessAndTimeOrdering(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), MaxElevationDuration,
	)
	receipt, err := NewStrongAuthReceipt(
		testProofID,
		request,
		testNow.Add(-MaxStrongAuthProofAge).Add(222*time.Microsecond),
		testNow.Add(888*time.Microsecond),
	)
	if err != nil {
		t.Fatalf("exact proof-age boundary rejected: %v", err)
	}
	if receipt.VerifiedAt().Nanosecond()%int(time.Millisecond) != 0 ||
		receipt.AuthenticatedAt().Nanosecond()%int(time.Millisecond) != 0 ||
		receipt.ProofID() != testProofID || receipt.Request().ID() != request.ID() ||
		!identity.SameLogicalIdentity(receipt.Request().Principal(), request.Principal()) {
		t.Fatal("receipt accessors are not canonical and bound")
	}

	if _, err := NewStrongAuthReceipt(
		"prf_01JADMIN00000000000000002", request,
		testNow.Add(-MaxStrongAuthProofAge-time.Millisecond), testNow,
	); !errors.Is(err, ErrStrongAuthProofStale) {
		t.Fatalf("stale proof error = %v", err)
	}
	if _, err := NewStrongAuthReceipt(
		"prf_01JADMIN00000000000000003", request, testNow, testNow.Add(-time.Millisecond),
	); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("verification before request/auth error = %v", err)
	}
	if _, err := NewStrongAuthReceipt("short", request, testNow, testNow); !errors.Is(err, ErrInvalidStrongAuthProofID) {
		t.Fatalf("invalid proof ID error = %v", err)
	}
}

func TestLedgerIssueIsAtomicAndReplaySafe(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	ledger := mustLedger(t, administrator)
	target := ResolvePlatformAuditExportTarget()
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, MaxElevationDuration,
	)
	receipt := mustReceipt(t, testProofID, request, testNow.Add(-time.Minute), testNow)
	grant, err := ledger.Issue(testNow, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if grant.ID() != testGrantID || grant.AdministratorID() != testAdministratorID ||
		grant.Action() != authorization.ActionAuditExport || !equalTarget(grant.Target(), target) ||
		grant.IssuedAt() != testNow || grant.ExpiresAt() != testNow.Add(MaxElevationDuration) {
		t.Fatal("issued grant did not preserve exact binding")
	}
	if reason := grant.Reason(); reason != testReason {
		t.Fatalf("grant reason = %q", reason)
	}
	if reference, present := grant.CaseReference(); !present || reference != testCaseReference {
		t.Fatalf("grant case reference = %q, %t", reference, present)
	}
	if _, err := ledger.Issue(testNow, receipt); !errors.Is(err, ErrStrongAuthProofReplayed) {
		t.Fatalf("replayed receipt error = %v", err)
	}

	// A duplicate grant failure must not partially retain its otherwise-new
	// proof ID. Reconstructing that proof for a unique grant can still issue.
	proof2 := resource.ID("prf_01JADMIN00000000000000002")
	duplicateGrantRequest := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, time.Minute,
	)
	duplicateGrantReceipt := mustReceipt(t, proof2, duplicateGrantRequest, testNow, testNow)
	if _, err := ledger.Issue(testNow, duplicateGrantReceipt); !errors.Is(err, ErrDuplicateGrantID) {
		t.Fatalf("duplicate grant ID error = %v", err)
	}
	uniqueRequest := mustRequest(
		t, "elv_01JADMIN00000000000000002", administrator, principal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	uniqueReceipt := mustReceipt(t, proof2, uniqueRequest, testNow, testNow)
	if _, err := ledger.Issue(testNow, uniqueReceipt); err != nil {
		t.Fatalf("proof ID was partially tombstoned after failed issue: %v", err)
	}

	otherPrincipal := mustPrincipal(t, testIssuer, testSubject+"-other")
	otherAdministrator := mustAdministrator(t, testOtherAdministratorID, otherPrincipal)
	unregisteredRequest := mustRequest(
		t, "elv_01JADMIN00000000000000003", otherAdministrator, otherPrincipal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	unregisteredReceipt := mustReceipt(
		t, "prf_01JADMIN00000000000000003", unregisteredRequest, testNow, testNow,
	)
	if _, err := ledger.Issue(testNow, unregisteredReceipt); !errors.Is(err, ErrAdministratorNotRegistered) {
		t.Fatalf("unregistered administrator error = %v", err)
	}

	// Possessing the configured opaque ID is insufficient when its exact
	// issuer-and-subject binding differs.
	misboundAdministrator := mustAdministrator(t, testAdministratorID, otherPrincipal)
	misboundRequest := mustRequest(
		t, "elv_01JADMIN00000000000000004", misboundAdministrator, otherPrincipal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	misboundReceipt := mustReceipt(
		t, "prf_01JADMIN00000000000000004", misboundRequest, testNow, testNow,
	)
	if _, err := ledger.Issue(testNow, misboundReceipt); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("misbound configured administrator error = %v", err)
	}
}

func TestLedgerIssueRechecksProofAgeAndDoesNotAdvanceOnRegression(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, time.Minute,
	)
	receipt := mustReceipt(t, testProofID, request, testNow, testNow)

	exactLedger := mustLedger(t, administrator)
	if _, err := exactLedger.Issue(testNow.Add(MaxStrongAuthProofAge), receipt); err != nil {
		t.Fatalf("Issue(exact proof-age boundary) error = %v", err)
	}
	staleLedger := mustLedger(t, administrator)
	if _, err := staleLedger.Issue(
		testNow.Add(MaxStrongAuthProofAge+time.Millisecond), receipt,
	); !errors.Is(err, ErrStrongAuthProofStale) {
		t.Fatalf("Issue(delayed stale receipt) error = %v", err)
	}

	futureVerified := testNow.Add(time.Second)
	futureReceipt := mustReceipt(
		t, "prf_01JADMIN00000000000000005", request, futureVerified, futureVerified,
	)
	regressionLedger := mustLedger(t, administrator)
	if _, err := regressionLedger.Issue(testNow, futureReceipt); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("Issue(before verification) error = %v", err)
	}
	if _, err := regressionLedger.Issue(futureVerified, futureReceipt); err != nil {
		t.Fatalf("failed regressed issue changed ledger state/high water: %v", err)
	}
}

func TestLedgerGrantLifecycleIsOneWayAndExpiryIsClosed(t *testing.T) {
	t.Parallel()
	fixture := newHierarchyFixture(t)
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target, err := ResolveOperationTarget(fixture.snapshot, fixture.operation)
	if err != nil {
		t.Fatal(err)
	}
	ledger := mustLedger(t, administrator)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionWorkRedrive,
		target, MaxElevationDuration,
	)
	grant, err := ledger.Issue(
		testNow,
		mustReceipt(t, testProofID, request, testNow.Add(-time.Minute), testNow),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := ledger.StateAt(testNow, grant); err != nil || state != GrantStateActive {
		t.Fatalf("StateAt(issue) = %v, %v", state, err)
	}
	if _, err := ledger.Consume(
		testNow.Add(time.Second), grant, authorization.ActionOperationQuarantine, target,
	); !errors.Is(err, ErrGrantScopeMismatch) {
		t.Fatalf("Consume(wrong action) error = %v", err)
	}
	if state, err := ledger.StateAt(testNow.Add(time.Second), grant); err != nil || state != GrantStateActive {
		t.Fatalf("scope mismatch changed state to %v, %v", state, err)
	}
	receipt, err := ledger.Consume(
		testNow.Add(2*time.Second), grant, authorization.ActionWorkRedrive, target,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.GrantID() != grant.ID() || receipt.AdministratorID() != grant.AdministratorID() ||
		receipt.Action() != grant.Action() || !equalTarget(receipt.Target(), grant.Target()) ||
		receipt.Reason() != grant.Reason() || receipt.IssuedAt() != grant.IssuedAt() ||
		receipt.ExpiresAt() != grant.ExpiresAt() || receipt.ConsumedAt() != testNow.Add(2*time.Second) {
		t.Fatal("consumption receipt lost grant evidence")
	}
	if reference, present := receipt.CaseReference(); !present || reference != testCaseReference {
		t.Fatal("consumption receipt lost case reference")
	}
	if _, err := ledger.Consume(
		testNow.Add(3*time.Second), grant, authorization.ActionWorkRedrive, target,
	); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("Consume(replay) error = %v", err)
	}
	if _, err := ledger.Revoke(testNow.Add(3*time.Second), grant); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("Revoke(consumed) error = %v", err)
	}

	// Reissuing from the same verified proof is forbidden; there is no renewal
	// transition on Grant or Ledger.
	if _, err := ledger.Issue(testNow.Add(3*time.Second), mustReceipt(
		t, testProofID, request, testNow.Add(-time.Minute), testNow,
	)); !errors.Is(err, ErrStrongAuthProofReplayed) {
		t.Fatalf("proof-based renewal error = %v", err)
	}

	expiringLedger := mustLedger(t, administrator)
	expiringRequest := mustRequest(
		t, "elv_01JADMIN00000000000000004", administrator, principal,
		authorization.ActionWorkRedrive, target, time.Second,
	)
	expiringGrant, err := expiringLedger.Issue(
		testNow,
		mustReceipt(t, "prf_01JADMIN00000000000000004", expiringRequest, testNow, testNow),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := expiringLedger.StateAt(expiringGrant.ExpiresAt(), expiringGrant); err != nil || state != GrantStateExpired {
		t.Fatalf("StateAt(exact expiry) = %v, %v", state, err)
	}
	if _, err := expiringLedger.Consume(
		expiringGrant.ExpiresAt(), expiringGrant, authorization.ActionWorkRedrive, target,
	); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("Consume(exact expiry) error = %v", err)
	}
}

func TestLedgerRevokeAndClockRegressionFailClosed(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	ledger := mustLedger(t, administrator)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, time.Minute,
	)
	grant, err := ledger.Issue(
		testNow,
		mustReceipt(t, testProofID, request, testNow, testNow),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.StateAt(testNow.Add(5*time.Second), grant); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Revoke(testNow.Add(4*time.Second), grant); !errors.Is(err, ErrClockRegressed) {
		t.Fatalf("Revoke(regressed clock) error = %v", err)
	}
	// The failed regression changes neither authority nor high-water time.
	revocation, err := ledger.Revoke(testNow.Add(5*time.Second), grant)
	if err != nil {
		t.Fatal(err)
	}
	if revocation.RevokedAt() != testNow.Add(5*time.Second) || revocation.Reason() != testReason ||
		revocation.IssuedAt() != grant.IssuedAt() || revocation.ExpiresAt() != grant.ExpiresAt() {
		t.Fatal("revocation receipt lost bounded evidence")
	}
	if _, err := ledger.Consume(
		testNow.Add(6*time.Second), grant, authorization.ActionAuditExport, target,
	); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("Consume(revoked) error = %v", err)
	}
	if _, err := ledger.StateAt(time.Time{}, grant); !errors.Is(err, ErrInvalidClock) {
		t.Fatalf("StateAt(zero clock) error = %v", err)
	}
}

func TestLedgerConcurrentConsumeHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	ledger := mustLedger(t, administrator)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, time.Minute,
	)
	grant, err := ledger.Issue(
		testNow,
		mustReceipt(t, testProofID, request, testNow, testNow),
	)
	if err != nil {
		t.Fatal(err)
	}

	alias := ledger
	const contenders = 64
	var successes atomic.Int32
	var failures atomic.Int32
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(contenders)
	for range contenders {
		go func() {
			defer wait.Done()
			<-start
			_, consumeErr := alias.Consume(
				testNow.Add(time.Second), grant, authorization.ActionAuditExport, target,
			)
			switch {
			case consumeErr == nil:
				successes.Add(1)
			case errors.Is(consumeErr, ErrGrantConsumed):
				failures.Add(1)
			default:
				t.Errorf("Consume() error = %v", consumeErr)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || failures.Load() != contenders-1 {
		t.Fatalf("concurrent consume successes/failures = %d/%d", successes.Load(), failures.Load())
	}
	if state, err := ledger.StateAt(testNow.Add(time.Second), grant); err != nil || state != GrantStateConsumed {
		t.Fatalf("original Ledger did not observe copied-handle transition: %v, %v", state, err)
	}
}

func TestLedgerRetainsTerminalTombstonesToFixedCapacity(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	ledger := mustLedger(t, administrator)
	target := ResolvePlatformAuditExportTarget()
	for index := range MaxTrackedElevations {
		request := mustRequest(
			t, generatedID("elv", index), administrator, principal,
			authorization.ActionAuditExport, target, time.Minute,
		)
		receipt := mustReceipt(t, generatedID("prf", index), request, testNow, testNow)
		grant, err := ledger.Issue(testNow, receipt)
		if err != nil {
			t.Fatalf("Issue(%d) error = %v", index, err)
		}
		if _, err := ledger.Consume(
			testNow, grant, authorization.ActionAuditExport, target,
		); err != nil {
			t.Fatalf("Consume(%d) error = %v", index, err)
		}
	}
	extraRequest := mustRequest(
		t, generatedID("elv", MaxTrackedElevations), administrator, principal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	extraReceipt := mustReceipt(
		t, generatedID("prf", MaxTrackedElevations), extraRequest, testNow, testNow,
	)
	if _, err := ledger.Issue(testNow, extraReceipt); !errors.Is(err, ErrElevationLedgerFull) {
		t.Fatalf("Issue(over retained bound) error = %v", err)
	}
}

func TestBreakGlassRecoveryExercise(t *testing.T) {
	fixture := newHierarchyFixture(t)
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	ledger := mustLedger(t, administrator)
	target, err := ResolveOperationTarget(fixture.snapshot, fixture.operation)
	if err != nil {
		t.Fatal(err)
	}

	quarantineRequest := mustRequest(
		t, "elv_01JADMIN00000000000000101", administrator, principal,
		authorization.ActionOperationQuarantine, target, 5*time.Minute,
	)
	quarantineGrant, err := ledger.Issue(
		testNow,
		mustReceipt(
			t, "prf_01JADMIN00000000000000101", quarantineRequest,
			testNow.Add(-time.Minute), testNow,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Consume(
		testNow.Add(time.Second), quarantineGrant,
		authorization.ActionOperationQuarantine, target,
	); err != nil {
		t.Fatalf("quarantine elevation failed: %v", err)
	}
	if _, err := ledger.Consume(
		testNow.Add(time.Second), quarantineGrant,
		authorization.ActionOperationQuarantine, target,
	); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("quarantine replay error = %v", err)
	}

	// Recovery requires a distinct, fresh proof and a separately scoped
	// one-use grant; quarantine authority cannot be treated as redrive power.
	redriveRequest, err := NewElevationRequest(
		"elv_01JADMIN00000000000000102",
		administrator,
		principal,
		authorization.ActionWorkRedrive,
		target,
		"Redrive isolated delivery after quarantine inspection",
		"INC-1042",
		testNow.Add(2*time.Second),
		5*time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	redriveProof := mustReceipt(
		t, "prf_01JADMIN00000000000000102", redriveRequest,
		testNow.Add(2*time.Second), testNow.Add(2*time.Second),
	)
	redriveGrant, err := ledger.Issue(testNow.Add(2*time.Second), redriveProof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Consume(
		testNow.Add(3*time.Second), redriveGrant,
		authorization.ActionOperationQuarantine, target,
	); !errors.Is(err, ErrGrantScopeMismatch) {
		t.Fatalf("cross-action use error = %v", err)
	}
	redriveReceipt, err := ledger.Consume(
		testNow.Add(3*time.Second), redriveGrant,
		authorization.ActionWorkRedrive, target,
	)
	if err != nil {
		t.Fatalf("redrive elevation failed: %v", err)
	}
	if redriveReceipt.AdministratorID() != testAdministratorID ||
		redriveReceipt.Reason() != "Redrive isolated delivery after quarantine inspection" {
		t.Fatal("recovery evidence lost administrator or reason")
	}
}

func assertOptionalID(t testing.TB, id resource.ID, present bool, want resource.ID) {
	t.Helper()
	if !present || id != want {
		t.Fatalf("optional ID = %q, %t, want %q, true", id, present, want)
	}
}
