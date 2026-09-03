package authorization

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestVocabularyAndMatrixAreClosed(t *testing.T) {
	t.Parallel()

	wantActions := []Action{
		ActionResourceList, ActionResourceGet, ActionResourceCreate, ActionResourceReplace,
		ActionResourceDelete, ActionResourceStatusReplace, ActionPlanList, ActionPlanGet,
		ActionPlanPreview, ActionOperationList, ActionOperationGet, ActionOperationCancel,
		ActionOperationRetry, ActionOperationQuarantine, ActionMembershipList,
		ActionMembershipGet, ActionMembershipCreate, ActionMembershipReplace,
		ActionMembershipDelete, ActionAuditList, ActionAuditExport, ActionApprovalApprove,
		ActionApprovalReject, ActionApprovalOverride, ActionWorkPublish, ActionWorkConsume,
		ActionWorkRedrive, ActionReconcilePlan, ActionReconcileExecute,
		ActionOperationTransition, ActionCredentialResolve, ActionProviderDiscover,
		ActionProviderApply, ActionProviderObserve, ActionProviderDelete, ActionAuditAppend,
	}
	if got := Actions(); !slices.Equal(got, wantActions) {
		t.Fatalf("Actions() = %v", got)
	}
	for _, action := range wantActions {
		if parsed, err := ParseAction(action.String()); err != nil || parsed != action {
			t.Fatalf("ParseAction(%q) = %q, %v", action, parsed, err)
		}
	}
	if _, err := ParseAction("resource.Get"); !errors.Is(err, ErrInvalidAction) {
		t.Fatalf("ParseAction(open value) error = %v", err)
	}

	wantRoles := []Role{RoleViewer, RoleDeveloper, RoleOperator, RoleWorkspaceAdministrator}
	if !slices.Equal(Roles(), wantRoles) {
		t.Fatalf("Roles() = %v", Roles())
	}
	inheritance := map[Role][]Role{
		RoleViewer:                 {RoleViewer},
		RoleDeveloper:              {RoleViewer, RoleDeveloper},
		RoleOperator:               {RoleViewer, RoleOperator},
		RoleWorkspaceAdministrator: {RoleViewer, RoleWorkspaceAdministrator},
	}
	for role, want := range inheritance {
		if parsed, err := ParseRole(role.String()); err != nil || parsed != role {
			t.Fatalf("ParseRole(%q) = %q, %v", role, parsed, err)
		}
		if got := InheritedRoles(role); !slices.Equal(got, want) {
			t.Fatalf("InheritedRoles(%s) = %v, want %v", role, got, want)
		}
	}
	if _, err := ParseRole("Owner"); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("ParseRole(open value) error = %v", err)
	}
	if got := InheritedRoles(Role("Owner")); got != nil {
		t.Fatalf("InheritedRoles(invalid) = %v", got)
	}

	if !slices.Equal(ScopeKinds(), []ScopeKind{ScopeKindWorkspace, ScopeKindEnvironment}) ||
		!reflect.DeepEqual(ObjectKinds(), []ObjectKind{
			ObjectKindResource, ObjectKindOperation, ObjectKindPlan, ObjectKindMembership, ObjectKindAudit,
		}) ||
		!reflect.DeepEqual(Effects(), []Effect{EffectAllow, EffectDeny}) ||
		!reflect.DeepEqual(Reasons(), []Reason{
			ReasonCrossWorkspace, ReasonReservedAction, ReasonNoMembership, ReasonNoRoleBinding,
			ReasonScopeNotGranted, ReasonActionNotGranted, ReasonRoleGranted,
		}) {
		t.Fatal("closed vocabulary order drifted")
	}
	if DefaultEffect != EffectDeny ||
		!slices.Equal(ScopeDescendants(ScopeKindWorkspace), []ScopeKind{ScopeKindWorkspace, ScopeKindEnvironment}) ||
		!slices.Equal(ScopeDescendants(ScopeKindEnvironment), []ScopeKind{ScopeKindEnvironment}) ||
		ScopeDescendants(ScopeKind("Unknown")) != nil {
		t.Fatal("default effect or scope descent drifted")
	}

	actionOrder := make(map[Action]int, len(wantActions))
	for index, action := range wantActions {
		actionOrder[action] = index
	}
	granted := make(map[Action]bool)
	wantGrantKeys := map[Role][]string{
		RoleViewer: {
			"resource.list|Resource|Application,Component,Environment,ProviderConnection,Workspace",
			"resource.get|Resource|Application,Component,Environment,ProviderConnection,Workspace",
			"plan.list|Plan|Application,Component,Environment,ProviderConnection,Workspace",
			"plan.get|Plan|Application,Component,Environment,ProviderConnection,Workspace",
			"operation.list|Operation|Application,Component,Environment,ProviderConnection,Workspace",
			"operation.get|Operation|Application,Component,Environment,ProviderConnection,Workspace",
			"audit.list|Audit|Application,Component,Environment,ProviderConnection,Workspace",
		},
		RoleDeveloper: {
			"resource.create|Resource|Application,Component",
			"resource.replace|Resource|Application,Component",
			"resource.delete|Resource|Application,Component",
			"plan.preview|Plan|Application,Component",
			"operation.cancel|Operation|Application,Component",
		},
		RoleOperator: {
			"resource.create|Resource|Environment,ProviderConnection",
			"resource.replace|Resource|Environment,ProviderConnection",
			"resource.delete|Resource|Environment,ProviderConnection",
			"plan.preview|Plan|Environment,ProviderConnection",
			"operation.cancel|Operation|Application,Component,Environment,ProviderConnection",
			"operation.retry|Operation|Application,Component,Environment,ProviderConnection",
		},
		RoleWorkspaceAdministrator: {
			"resource.list|Resource|Policy",
			"resource.get|Resource|Policy",
			"resource.create|Resource|Policy",
			"resource.replace|Resource|Policy,Workspace",
			"resource.delete|Resource|Policy,Workspace",
			"plan.list|Plan|Policy,Workspace",
			"plan.get|Plan|Policy,Workspace",
			"plan.preview|Plan|Policy,Workspace",
			"operation.list|Operation|Policy,Workspace",
			"operation.get|Operation|Policy,Workspace",
			"operation.cancel|Operation|Policy,Workspace",
			"membership.list|Membership|",
			"membership.get|Membership|",
			"membership.create|Membership|",
			"membership.replace|Membership|",
			"membership.delete|Membership|",
		},
	}
	for _, role := range Roles() {
		grants := RoleGrants(role)
		keys := make([]string, len(grants))
		for index, item := range grants {
			kindNames := make([]string, len(item.ResourceKinds))
			for kindIndex, kind := range item.ResourceKinds {
				kindNames[kindIndex] = kind.String()
			}
			keys[index] = item.Action.String() + "|" + item.ObjectKind.String() + "|" + strings.Join(kindNames, ",")
			if _, err := ParseAction(item.Action.String()); err != nil {
				t.Fatalf("RoleGrants(%s) has invalid action", role)
			}
			if _, err := ParseObjectKind(item.ObjectKind.String()); err != nil {
				t.Fatalf("RoleGrants(%s) has invalid object", role)
			}
			if index > 0 && actionOrder[grants[index-1].Action] > actionOrder[item.Action] {
				t.Fatalf("RoleGrants(%s) is not in action order", role)
			}
			for kindIndex, kind := range item.ResourceKinds {
				if _, err := hierarchy.ParseKind(kind.String()); err != nil {
					t.Fatalf("RoleGrants(%s) has invalid resource kind", role)
				}
				if kindIndex > 0 && item.ResourceKinds[kindIndex-1].String() >= kind.String() {
					t.Fatalf("RoleGrants(%s) resource kinds are not lexical: %v", role, item.ResourceKinds)
				}
			}
			granted[item.Action] = true
		}
		if !slices.Equal(keys, wantGrantKeys[role]) {
			t.Fatalf("RoleGrants(%s) = %#v, want %#v", role, keys, wantGrantKeys[role])
		}
		if len(grants) != 0 {
			grants[0].ResourceKinds = append(grants[0].ResourceKinds, hierarchy.KindPolicy)
			if reflect.DeepEqual(grants, RoleGrants(role)) {
				t.Fatalf("RoleGrants(%s) retained a caller slice", role)
			}
		}
	}
	reserved := make(map[Action]bool)
	for _, action := range ReservedActions() {
		reserved[action] = true
		if granted[action] {
			t.Fatalf("globally reserved action %q is granted", action)
		}
	}
	for _, action := range wantActions {
		if !granted[action] && !reserved[action] {
			t.Fatalf("action %q is absent from both grant and reservation matrices", action)
		}
	}
	wantTargetReserved := []ReservedResourceAction{{
		Action: ActionResourceCreate, ResourceKind: hierarchy.KindWorkspace,
	}}
	if !reflect.DeepEqual(ReservedResourceActions(), wantTargetReserved) {
		t.Fatalf("ReservedResourceActions() = %#v", ReservedResourceActions())
	}
}

func TestMemberDirectoryExactIdentityAndPrivacy(t *testing.T) {
	t.Parallel()

	member := mustMember(t, testViewerID, testWorkspaceAID, identity.KindHuman, "Case-Sensitive-Subject")
	directory := mustDirectory(t, testWorkspaceAID, member)
	principal := mustPrincipal(t, identity.KindHuman, "Case-Sensitive-Subject")
	matched, ok := directory.Match(principal)
	if !ok || matched.ID() != member.ID() {
		t.Fatalf("Match(exact) = %#v, %t", matched, ok)
	}
	changedClaims, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: testIssuer, Subject: "Case-Sensitive-Subject",
		Audiences: []string{"other-audience"}, Groups: []string{"other-group"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := directory.Match(changedClaims); !ok {
		t.Fatal("mutable audience/group claims changed exact logical-identity matching")
	}
	if _, ok := directory.Match(mustPrincipal(t, identity.KindHuman, "case-sensitive-subject")); ok {
		t.Fatal("case-folded subject matched")
	}
	if _, ok := directory.Match(mustPrincipal(t, identity.KindWorkload, "Case-Sensitive-Subject")); ok {
		t.Fatal("different principal kind matched")
	}
	if _, err := directory.Lookup(resource.ID("mem_01J99999999999999999999999")); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("Lookup(missing) error = %v", err)
	}
	if ValidateMemberDirectory(MemberDirectory{}) == nil {
		t.Fatal("zero MemberDirectory validated")
	}

	duplicateID := mustMember(t, testViewerID, testWorkspaceAID, identity.KindHuman, "different")
	if _, err := NewMemberDirectory(testWorkspaceAID, []MemberRecord{member, duplicateID}); !errors.Is(err, ErrDuplicateMemberID) {
		t.Fatalf("duplicate ID error = %v", err)
	}
	duplicateIdentity := mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "Case-Sensitive-Subject")
	if _, err := NewMemberDirectory(testWorkspaceAID, []MemberRecord{member, duplicateIdentity}); !errors.Is(err, ErrDuplicateLogicalIdentity) {
		t.Fatalf("duplicate logical identity error = %v", err)
	}
	foreign := mustMember(t, testDeveloperID, testWorkspaceBID, identity.KindHuman, "foreign")
	if _, err := NewMemberDirectory(testWorkspaceAID, []MemberRecord{foreign}); !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("foreign member error = %v", err)
	}
	if _, err := NewMemberDirectory(testWorkspaceAID, make([]MemberRecord, MaxMembers+1)); !errors.Is(err, ErrTooManyMembers) {
		t.Fatalf("over-limit directory error = %v", err)
	}

	privateCanaries := []string{testIssuer, "Case-Sensitive-Subject"}
	for _, value := range []any{MemberInput{}, member, directory} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSerializationForbidden) {
			t.Fatalf("json.Marshal(%T) error = %v", value, err)
		}
		formatted := fmt.Sprintf("%v %#v %s %q %x", value, value, value, value, value)
		for _, canary := range privateCanaries {
			if strings.Contains(formatted, canary) {
				t.Fatalf("fmt leaked private canary through %T", value)
			}
		}
	}
}

func TestMemberInputGobSerializationForbidden(t *testing.T) {
	t.Parallel()

	const subjectCanary = "member-input-gob-subject-canary"
	input := MemberInput{
		ID:              testViewerID,
		WorkspaceID:     testWorkspaceAID,
		Kind:            identity.KindHuman,
		LogicalIdentity: mustLogical(t, subjectCanary),
	}
	tests := []struct {
		name  string
		value any
	}{
		{name: "value", value: input},
		{name: "pointer", value: &input},
		{name: "nested struct", value: struct{ Member MemberInput }{Member: input}},
		{name: "nested slice", value: []MemberInput{input}},
	}
	canaries := [][]byte{
		[]byte(testIssuer),
		[]byte(subjectCanary),
		[]byte(testViewerID.String()),
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var encoded bytes.Buffer
			err := gob.NewEncoder(&encoded).Encode(test.value)
			if !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("gob.Encode(%s) error = %v", test.name, err)
			}
			observed := append(slices.Clone(encoded.Bytes()), []byte(err.Error())...)
			for _, canary := range canaries {
				if bytes.Contains(observed, canary) {
					t.Fatalf("gob.Encode(%s) leaked canary %q", test.name, canary)
				}
			}
		})
	}
}

func TestInputGobSerializationForbidden(t *testing.T) {
	t.Parallel()

	const subjectCanary = "authorization-input-gob-subject-canary"
	fixture := newHierarchyFixture(t, testWorkspaceAID)
	target, err := ResolveResourceTarget(fixture.snapshot, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Principal: mustPrincipal(t, identity.KindHuman, subjectCanary),
		Action:    ActionResourceGet,
		Target:    target,
	}
	tests := []struct {
		name  string
		value any
	}{
		{name: "value", value: input},
		{name: "pointer", value: &input},
		{name: "nested struct", value: struct{ Input Input }{Input: input}},
		{name: "nested slice", value: []Input{input}},
	}
	canaries := [][]byte{
		[]byte(testIssuer),
		[]byte(subjectCanary),
		[]byte(testApplicationA.String()),
		[]byte(ActionResourceGet.String()),
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var encoded bytes.Buffer
			err := gob.NewEncoder(&encoded).Encode(test.value)
			if !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("gob.Encode(%s) error = %v", test.name, err)
			}
			observed := append(slices.Clone(encoded.Bytes()), []byte(err.Error())...)
			for _, canary := range canaries {
				if bytes.Contains(observed, canary) {
					t.Fatalf("gob.Encode(%s) leaked canary %q", test.name, canary)
				}
			}
		})
	}
}

func TestPolicyValidationCloneReferencesAndVersion(t *testing.T) {
	t.Parallel()

	if err := ValidatePolicySpec(PolicySpec{}); !errors.Is(err, ErrBindingsRequired) {
		t.Fatalf("ValidatePolicySpec(nil) error = %v", err)
	}
	empty := PolicySpec{Bindings: []RoleBinding{}}
	if err := ValidatePolicySpec(empty); err != nil {
		t.Fatalf("ValidatePolicySpec(explicit empty) error = %v", err)
	}
	if EqualPolicySpec(PolicySpec{}, empty) {
		t.Fatal("nil and explicit empty PolicySpec compared equal")
	}
	if clone := ClonePolicySpec(empty); clone.Bindings == nil || !EqualPolicySpec(empty, clone) {
		t.Fatalf("ClonePolicySpec(empty) = %#v", clone)
	}

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	human := mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "developer")
	workloadAdmin := mustMember(t, testAdminID, testWorkspaceAID, identity.KindWorkload, "admin-workload")
	directory := mustDirectory(t, testWorkspaceAID, workloadAdmin, human)
	environmentSpec := canonicalSpec(environmentBinding(testDeveloperID, RoleDeveloper, testEnvironmentA))
	if err := ValidatePolicyReferences(environmentSpec, fixture.snapshot, directory); err != nil {
		t.Fatalf("ValidatePolicyReferences(valid) error = %v", err)
	}

	clone := ClonePolicySpec(environmentSpec)
	*clone.Bindings[0].Scope.EnvironmentID = testEnvironmentB
	if *environmentSpec.Bindings[0].Scope.EnvironmentID != testEnvironmentA {
		t.Fatal("ClonePolicySpec retained EnvironmentID alias")
	}

	assertBindingError(t,
		ValidatePolicyReferences(
			canonicalSpec(workspaceBinding(resource.ID("mem_01J99999999999999999999999"), RoleViewer)),
			fixture.snapshot,
			directory,
		),
		ErrMemberNotFound,
		0,
		BindingFieldMemberID,
	)
	assertBindingError(t,
		ValidatePolicyReferences(
			canonicalSpec(environmentBinding(testDeveloperID, RoleDeveloper, resource.ID("env_01J99999999999999999999999"))),
			fixture.snapshot,
			directory,
		),
		ErrEnvironmentNotFound,
		0,
		BindingFieldEnvironmentID,
	)
	assertBindingError(t,
		ValidatePolicyReferences(
			canonicalSpec(environmentBinding(testDeveloperID, RoleDeveloper, testApplicationA)),
			fixture.snapshot,
			directory,
		),
		ErrReferenceKindMismatch,
		0,
		BindingFieldEnvironmentID,
	)
	assertBindingError(t,
		ValidatePolicyReferences(
			canonicalSpec(workspaceBinding(testAdminID, RoleWorkspaceAdministrator)),
			fixture.snapshot,
			directory,
		),
		ErrPrincipalKindNotAllowed,
		0,
		BindingFieldRole,
	)
	if err := ValidatePolicyReferences(empty, fixture.snapshot, MemberDirectory{}); !errors.Is(err, ErrInvalidMemberDirectory) {
		t.Fatalf("zero directory error = %v", err)
	}
	foreignDirectory := mustDirectory(t, testWorkspaceBID)
	if err := ValidatePolicyReferences(empty, fixture.snapshot, foreignDirectory); !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("foreign directory error = %v", err)
	}

	unsorted := PolicySpec{Bindings: []RoleBinding{
		workspaceBinding(testOperatorID, RoleViewer),
		workspaceBinding(testDeveloperID, RoleViewer),
	}}
	assertBindingError(t, ValidatePolicySpec(unsorted), ErrInvalidBindingOrder, 1, BindingFieldMemberID)
	duplicate := canonicalSpec(workspaceBinding(testDeveloperID, RoleViewer), workspaceBinding(testDeveloperID, RoleViewer))
	assertBindingError(t, ValidatePolicySpec(duplicate), ErrDuplicateBinding, 1, BindingFieldMemberID)
	adminEnvironment := canonicalSpec(environmentBinding(testDeveloperID, RoleWorkspaceAdministrator, testEnvironmentA))
	assertBindingError(t, ValidatePolicySpec(adminEnvironment), ErrInvalidScope, 0, BindingFieldScopeKind)
	if err := ValidatePolicySpec(PolicySpec{Bindings: make([]RoleBinding, MaxBindingsPerPolicy+1)}); !errors.Is(err, ErrTooManyBindings) {
		t.Fatalf("over-limit PolicySpec error = %v", err)
	}

	set, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, human), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 1, environmentSpec),
	})
	if err != nil {
		t.Fatalf("NewPolicySet() error = %v", err)
	}
	if err := ValidatePolicySet(set); err != nil {
		t.Fatalf("ValidatePolicySet() error = %v", err)
	}
	if set.WorkspaceID() != testWorkspaceAID || set.Len() != 1 {
		t.Fatalf("PolicySet metadata = %s, %d", set.WorkspaceID(), set.Len())
	}
	parsed, err := ParsePolicyVersion(set.Version().String())
	if err != nil || !parsed.Equal(set.Version()) {
		t.Fatalf("ParsePolicyVersion() = %v, %v", parsed, err)
	}
	if _, err := ParsePolicyVersion("azv1_not-canonical"); !errors.Is(err, ErrInvalidPolicyVersion) {
		t.Fatalf("ParsePolicyVersion(invalid) error = %v", err)
	}

	same, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, human), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 1, ClonePolicySpec(environmentSpec)),
	})
	if err != nil || !same.Version().Equal(set.Version()) {
		t.Fatal("same canonical inputs produced different PolicyVersion")
	}
	changedGeneration, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, human), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 2, environmentSpec),
	})
	if err != nil || changedGeneration.Version().Equal(set.Version()) {
		t.Fatal("generation change did not change PolicyVersion")
	}
	changedMember := mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "developer-replaced")
	changedDirectory, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, changedMember), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 1, environmentSpec),
	})
	if err != nil || changedDirectory.Version().Equal(set.Version()) {
		t.Fatal("exact member identity change did not change PolicyVersion")
	}

	explicitDeny, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 1, empty),
	})
	if err != nil || explicitDeny.Len() != 1 {
		t.Fatalf("NewPolicySet(explicit empty policy) = %v", err)
	}
	noPolicies, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID), nil)
	if err != nil || explicitDeny.Version().Equal(noPolicies.Version()) {
		t.Fatal("explicit empty Policy revision was lost from version framing")
	}
	if _, err := json.Marshal(set); !errors.Is(err, ErrSerializationForbidden) {
		t.Fatalf("json.Marshal(PolicySet) error = %v", err)
	}
	if text := fmt.Sprintf("%v", set); strings.Contains(text, "developer") || strings.Contains(text, testIssuer) {
		t.Fatalf("PolicySet formatting leaked claims: %s", text)
	}

	if _, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID),
		make([]PolicyRevision, MaxPolicies+1),
	); !errors.Is(err, ErrTooManyPolicies) {
		t.Fatalf("NewPolicySet(over limit) error = %v", err)
	}
	duplicatePolicy := policyRevision(fixture.records[testPolicyAID], 1, empty)
	if _, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID),
		[]PolicyRevision{duplicatePolicy, duplicatePolicy},
	); !errors.Is(err, ErrDuplicatePolicyID) {
		t.Fatalf("NewPolicySet(duplicate Policy ID) error = %v", err)
	}
	if _, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID),
		[]PolicyRevision{policyRevision(fixture.records[testPolicyAID], 0, empty)},
	); !errors.Is(err, ErrInvalidPolicyRevision) {
		t.Fatalf("NewPolicySet(invalid generation) error = %v", err)
	}
	if _, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID),
		[]PolicyRevision{policyRevision(fixture.records[testEnvironmentA], 1, empty)},
	); !errors.Is(err, ErrReferenceKindMismatch) {
		t.Fatalf("NewPolicySet(wrong record kind) error = %v", err)
	}
}

func TestSealedTargetResolution(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	wantEnvironment := map[resource.ID]*resource.ID{
		testWorkspaceAID: nil,
		testPolicyAID:    nil,
		testEnvironmentA: idPointer(testEnvironmentA),
		testApplicationA: idPointer(testEnvironmentA),
		testComponentA:   idPointer(testEnvironmentA),
		testProviderA:    idPointer(testEnvironmentA),
	}
	for id, want := range wantEnvironment {
		target, err := ResolveResourceTarget(fixture.snapshot, id)
		if err != nil {
			t.Fatalf("ResolveResourceTarget(%s): %v", id, err)
		}
		if target.ObjectKind() != ObjectKindResource || target.ObjectID() != id || target.ResourceID() != id ||
			target.WorkspaceID() != testWorkspaceAID || ValidateTarget(target) != nil {
			t.Fatalf("resolved target for %s is invalid", id)
		}
		got, present := target.EnvironmentID()
		if want == nil && present || want != nil && (!present || got != *want) {
			t.Fatalf("target EnvironmentID(%s) = %s, %t, want %v", id, got, present, want)
		}
	}

	rootPlacement, err := hierarchy.DeriveWorkspace(testWorkspaceAID)
	if err != nil {
		t.Fatal(err)
	}
	rootTarget, err := ResolveCreateTarget(hierarchy.Snapshot{}, rootPlacement)
	if err != nil || rootTarget.ResourceKind() != hierarchy.KindWorkspace {
		t.Fatalf("ResolveCreateTarget(root) = %v, %v", rootTarget, err)
	}
	newComponentID := resource.ID("cmp_01J22222222222222222222222")
	componentPlacement, err := fixture.snapshot.DeriveChild(hierarchy.KindComponent, newComponentID, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	componentTarget, err := ResolveCreateTarget(fixture.snapshot, componentPlacement)
	if err != nil {
		t.Fatal(err)
	}
	if environmentID, present := componentTarget.EnvironmentID(); !present || environmentID != testEnvironmentA {
		t.Fatalf("new Component EnvironmentID = %s, %t", environmentID, present)
	}
	if _, err := ResolveCreateTarget(hierarchy.Snapshot{}, componentPlacement); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ResolveCreateTarget(without snapshot) error = %v", err)
	}
	createCases := []struct {
		kind        hierarchy.Kind
		id          resource.ID
		parent      resource.ID
		environment *resource.ID
	}{
		{kind: hierarchy.KindPolicy, id: resource.ID("pol_01J33333333333333333333333"), parent: testWorkspaceAID},
		{kind: hierarchy.KindEnvironment, id: resource.ID("env_01J33333333333333333333333"), parent: testWorkspaceAID, environment: idPointer(resource.ID("env_01J33333333333333333333333"))},
		{kind: hierarchy.KindApplication, id: resource.ID("app_01J33333333333333333333333"), parent: testEnvironmentA, environment: idPointer(testEnvironmentA)},
		{kind: hierarchy.KindProviderConnection, id: resource.ID("prv_01J33333333333333333333333"), parent: testEnvironmentA, environment: idPointer(testEnvironmentA)},
	}
	for _, test := range createCases {
		placement, deriveErr := fixture.snapshot.DeriveChild(test.kind, test.id, test.parent)
		if deriveErr != nil {
			t.Fatal(deriveErr)
		}
		target, resolveErr := ResolveCreateTarget(fixture.snapshot, placement)
		if resolveErr != nil || target.ResourceKind() != test.kind || target.ResourceID() != test.id {
			t.Fatalf("ResolveCreateTarget(%s) = %v, %v", test.kind, target, resolveErr)
		}
		environmentID, present := target.EnvironmentID()
		if test.environment == nil && present ||
			test.environment != nil && (!present || environmentID != *test.environment) {
			t.Fatalf("ResolveCreateTarget(%s) environment = %s, %t", test.kind, environmentID, present)
		}
	}

	operationTarget := syntheticBoundTarget(t, fixture.snapshot, ObjectKindOperation, testOperationA, testComponentA)

	for _, kind := range []ObjectKind{ObjectKindMembership, ObjectKindAudit} {
		target, err := ResolveWorkspaceObjectTarget(fixture.snapshot, kind, testViewerID)
		if err != nil || target.ObjectKind() != kind || target.ResourceID() != testWorkspaceAID {
			t.Fatalf("ResolveWorkspaceObjectTarget(%s) = %v, %v", kind, target, err)
		}
	}
	if _, err := ResolveWorkspaceObjectTarget(fixture.snapshot, ObjectKindPlan, testPlanA); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("ResolveWorkspaceObjectTarget(Plan) error = %v", err)
	}
	if ValidateTarget(Target{}) == nil {
		t.Fatal("zero Target validated")
	}
	if _, err := json.Marshal(operationTarget); !errors.Is(err, ErrSerializationForbidden) {
		t.Fatalf("json.Marshal(Target) error = %v", err)
	}
}

func TestEvaluateDefaultDenyScopeAndOrthogonalRoles(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	members := []MemberRecord{
		mustMember(t, testViewerID, testWorkspaceAID, identity.KindHuman, "viewer"),
		mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "developer"),
		mustMember(t, testOperatorID, testWorkspaceAID, identity.KindHuman, "operator"),
		mustMember(t, testAdminID, testWorkspaceAID, identity.KindHuman, "administrator"),
		mustMember(t, testUnboundID, testWorkspaceAID, identity.KindHuman, "unbound"),
	}
	spec := canonicalSpec(
		workspaceBinding(testViewerID, RoleViewer),
		environmentBinding(testDeveloperID, RoleDeveloper, testEnvironmentA),
		environmentBinding(testOperatorID, RoleOperator, testEnvironmentA),
		workspaceBinding(testAdminID, RoleWorkspaceAdministrator),
	)
	set, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, members...), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 1, spec),
	})
	if err != nil {
		t.Fatal(err)
	}

	resourceTarget := func(id resource.ID) Target {
		target, resolveErr := ResolveResourceTarget(fixture.snapshot, id)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		return target
	}
	boundTarget := func(kind ObjectKind, objectID, resourceID resource.ID) Target {
		return syntheticBoundTarget(t, fixture.snapshot, kind, objectID, resourceID)
	}
	membershipTarget := func(id resource.ID) Target {
		target, resolveErr := ResolveWorkspaceObjectTarget(fixture.snapshot, ObjectKindMembership, id)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		return target
	}

	tests := []struct {
		name      string
		principal identity.Principal
		action    Action
		target    Target
		effect    Effect
		reason    Reason
	}{
		{name: "viewer reads descendant", principal: mustPrincipal(t, identity.KindHuman, "viewer"), action: ActionResourceGet, target: resourceTarget(testComponentA), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "viewer cannot mutate", principal: mustPrincipal(t, identity.KindHuman, "viewer"), action: ActionResourceReplace, target: resourceTarget(testComponentA), effect: EffectDeny, reason: ReasonActionNotGranted},
		{name: "developer manages application", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionResourceReplace, target: resourceTarget(testApplicationA), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "developer scope is exact environment", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionResourceGet, target: resourceTarget(testApplicationB), effect: EffectDeny, reason: ReasonScopeNotGranted},
		{name: "list includes allowed retained row", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionResourceList, target: resourceTarget(testApplicationA), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "list excludes sibling retained row", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionResourceList, target: resourceTarget(testApplicationB), effect: EffectDeny, reason: ReasonScopeNotGranted},
		{name: "developer cannot manage environment", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionResourceReplace, target: resourceTarget(testEnvironmentA), effect: EffectDeny, reason: ReasonActionNotGranted},
		{name: "operator manages provider connection", principal: mustPrincipal(t, identity.KindHuman, "operator"), action: ActionResourceReplace, target: resourceTarget(testProviderA), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "operator does not inherit developer", principal: mustPrincipal(t, identity.KindHuman, "operator"), action: ActionResourceReplace, target: resourceTarget(testApplicationA), effect: EffectDeny, reason: ReasonActionNotGranted},
		{name: "operator retries descendant operation", principal: mustPrincipal(t, identity.KindHuman, "operator"), action: ActionOperationRetry, target: boundTarget(ObjectKindOperation, testOperationA, testComponentA), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "administrator manages policy", principal: mustPrincipal(t, identity.KindHuman, "administrator"), action: ActionResourceReplace, target: resourceTarget(testPolicyAID), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "administrator does not inherit operator", principal: mustPrincipal(t, identity.KindHuman, "administrator"), action: ActionResourceReplace, target: resourceTarget(testProviderA), effect: EffectDeny, reason: ReasonActionNotGranted},
		{name: "administrator manages membership", principal: mustPrincipal(t, identity.KindHuman, "administrator"), action: ActionMembershipCreate, target: membershipTarget(resource.ID("mem_01J99999999999999999999999")), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "scoped member reads self membership", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionMembershipGet, target: membershipTarget(testDeveloperID), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "scoped member cannot read another membership", principal: mustPrincipal(t, identity.KindHuman, "developer"), action: ActionMembershipGet, target: membershipTarget(testViewerID), effect: EffectDeny, reason: ReasonScopeNotGranted},
		{name: "unbound member reads self membership", principal: mustPrincipal(t, identity.KindHuman, "unbound"), action: ActionMembershipGet, target: membershipTarget(testUnboundID), effect: EffectAllow, reason: ReasonRoleGranted},
		{name: "member without binding", principal: mustPrincipal(t, identity.KindHuman, "unbound"), action: ActionResourceGet, target: resourceTarget(testApplicationA), effect: EffectDeny, reason: ReasonNoRoleBinding},
		{name: "authenticated non-member", principal: mustPrincipal(t, identity.KindHuman, "outsider"), action: ActionResourceGet, target: resourceTarget(testApplicationA), effect: EffectDeny, reason: ReasonNoMembership},
		{name: "status write is service reserved", principal: mustPrincipal(t, identity.KindHuman, "viewer"), action: ActionResourceStatusReplace, target: resourceTarget(testApplicationA), effect: EffectDeny, reason: ReasonReservedAction},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := Input{Principal: test.principal, Action: test.action, Target: test.target}
			first, err := set.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			second, err := set.Evaluate(input)
			if err != nil || first.Effect() != test.effect || first.Reason() != test.reason ||
				first.Allowed() != (test.effect == EffectAllow) ||
				first.PolicyVersion() != second.PolicyVersion() || !first.InputDigest().Equal(second.InputDigest()) {
				t.Fatalf("Evaluate() = %s/%s, want %s/%s (second err %v)",
					first.Effect(), first.Reason(), test.effect, test.reason, err)
			}
		})
	}

	workspacePlacement, err := hierarchy.DeriveWorkspace(testWorkspaceAID)
	if err != nil {
		t.Fatal(err)
	}
	workspaceCreate, err := ResolveCreateTarget(hierarchy.Snapshot{}, workspacePlacement)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := set.Evaluate(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "administrator"),
		Action:    ActionResourceCreate, Target: workspaceCreate,
	})
	if err != nil || reserved.Reason() != ReasonReservedAction {
		t.Fatalf("Workspace create = %v, %v", reserved, err)
	}

	foreignFixture := newHierarchyFixture(t, testWorkspaceBID)
	foreignTarget, err := ResolveResourceTarget(foreignFixture.snapshot, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	cross, err := set.Evaluate(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "viewer"),
		Action:    ActionResourceStatusReplace, Target: foreignTarget,
	})
	if err != nil || cross.Reason() != ReasonCrossWorkspace {
		t.Fatalf("cross-workspace reserved action = %v, %v", cross, err)
	}
	if _, err := set.Evaluate(Input{Action: ActionResourceGet, Target: resourceTarget(testApplicationA)}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Evaluate(invalid principal) error = %v", err)
	}
}

func TestDecisionCanonicalGoldenAndStrictDecode(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	member := mustMember(t, testViewerID, testWorkspaceAID, identity.KindHuman, "viewer")
	set, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, member), []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 7, canonicalSpec(workspaceBinding(testViewerID, RoleViewer))),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := ResolveResourceTarget(fixture.snapshot, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := set.Evaluate(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "viewer"),
		Action:    ActionResourceGet,
		Target:    target,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := MarshalCanonical(decision)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/decision.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("decision golden drifted\ngot:  %s\nwant: %s", got, want)
	}
	if bytes.Contains(got, []byte(testIssuer)) || bytes.Contains(got, []byte("viewer")) ||
		bytes.Contains(got, []byte(testApplicationA)) || bytes.Contains(got, []byte(testViewerID)) {
		t.Fatalf("canonical Decision leaked input claims or identifiers: %s", got)
	}
	parsed, err := UnmarshalCanonical(got)
	if err != nil || parsed.Effect() != decision.Effect() || parsed.Reason() != decision.Reason() ||
		!parsed.PolicyVersion().Equal(decision.PolicyVersion()) || !parsed.InputDigest().Equal(decision.InputDigest()) {
		t.Fatalf("UnmarshalCanonical() = %v, %v", parsed, err)
	}
	ordinary, err := json.Marshal(decision)
	if err != nil || !bytes.Equal(ordinary, got) {
		t.Fatalf("json.Marshal(Decision) = %s, %v", ordinary, err)
	}
	var ordinaryRoundTrip Decision
	if err := json.Unmarshal(got, &ordinaryRoundTrip); err != nil ||
		!ordinaryRoundTrip.PolicyVersion().Equal(decision.PolicyVersion()) ||
		!ordinaryRoundTrip.InputDigest().Equal(decision.InputDigest()) {
		t.Fatalf("json.Unmarshal(Decision) = %v, %v", ordinaryRoundTrip, err)
	}

	mutations := [][]byte{
		append([]byte(" "), got...),
		bytes.Replace(got, []byte(`"effect":`), []byte(`"unknown":true,"effect":`), 1),
		bytes.Replace(got, []byte(`"effect":`), []byte(`"effect":"Deny","effect":`), 1),
		bytes.Replace(got, []byte(`"contractVersion":"veer.authorization.v1alpha1"`), []byte(`"contractVersion":"future"`), 1),
	}
	for _, mutation := range mutations {
		if _, err := UnmarshalCanonical(mutation); err == nil {
			t.Fatalf("UnmarshalCanonical(%s) accepted noncanonical input", mutation)
		}
	}
	if _, err := UnmarshalCanonical(make([]byte, MaxDecisionBytes+1)); !errors.Is(err, ErrDecisionTooLarge) {
		t.Fatalf("UnmarshalCanonical(over limit) error = %v", err)
	}
	if ValidateDecision(Decision{}) == nil {
		t.Fatal("zero Decision validated")
	}
	parsedVersion, err := ParsePolicyVersion(decision.PolicyVersion().String())
	if err != nil || !parsedVersion.Equal(decision.PolicyVersion()) {
		t.Fatalf("ParsePolicyVersion(Decision) = %v, %v", parsedVersion, err)
	}
	parsedDigest, err := ParseInputDigest(decision.InputDigest().String())
	if err != nil || !parsedDigest.Equal(decision.InputDigest()) {
		t.Fatalf("ParseInputDigest(Decision) = %v, %v", parsedDigest, err)
	}
	if _, err := ParseInputDigest("azi1_not-canonical"); !errors.Is(err, ErrInvalidInputDigest) {
		t.Fatalf("ParseInputDigest(invalid) error = %v", err)
	}
	if _, err := json.Marshal(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "viewer"),
		Action:    ActionResourceGet,
		Target:    target,
	}); !errors.Is(err, ErrSerializationForbidden) {
		t.Fatalf("json.Marshal(Input) error = %v", err)
	}
	changedAudience, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: testIssuer, Subject: "viewer",
		Audiences: []string{"different-audience"}, Groups: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	audienceDecision, err := set.Evaluate(Input{
		Principal: changedAudience, Action: ActionResourceGet, Target: target,
	})
	if err != nil || audienceDecision.InputDigest().Equal(decision.InputDigest()) {
		t.Fatal("audience change did not change InputDigest")
	}
	actionDecision, err := set.Evaluate(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "viewer"),
		Action:    ActionResourceList,
		Target:    target,
	})
	if err != nil || actionDecision.InputDigest().Equal(decision.InputDigest()) {
		t.Fatal("action change did not change InputDigest")
	}
	otherTarget, err := ResolveResourceTarget(fixture.snapshot, testApplicationB)
	if err != nil {
		t.Fatal(err)
	}
	targetDecision, err := set.Evaluate(Input{
		Principal: mustPrincipal(t, identity.KindHuman, "viewer"),
		Action:    ActionResourceGet,
		Target:    otherTarget,
	})
	if err != nil || targetDecision.InputDigest().Equal(decision.InputDigest()) {
		t.Fatal("target change did not change InputDigest")
	}
}

func TestInputFormattingFailsClosed(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	target, err := ResolveResourceTarget(fixture.snapshot, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	principal := mustPrincipal(t, identity.KindHuman, "input-format-subject-canary")
	valid := Input{Principal: principal, Action: ActionResourceGet, Target: target}
	const wantValid = "authorization-input(principal=redacted,action=resource.get)"
	if valid.String() != wantValid || valid.GoString() != wantValid || fmt.Sprintf("%v", valid) != wantValid {
		t.Fatalf("valid Input formatting = %q / %q / %q", valid.String(), valid.GoString(), fmt.Sprintf("%v", valid))
	}
	for _, canary := range []string{testIssuer, "input-format-subject-canary", testApplicationA.String()} {
		if strings.Contains(fmt.Sprintf("%v %#v %s %q %x", valid, valid, valid, valid, valid), canary) {
			t.Fatalf("valid Input formatting leaked canary %q", canary)
		}
	}

	actionCanary := "ACTION-CANARY-" + strings.Repeat("x", 1<<20) + testViewerID.String()
	invalid := Input{Principal: principal, Action: Action(actionCanary), Target: target}
	const wantInvalid = "authorization-input(invalid)"
	if invalid.String() != wantInvalid || invalid.GoString() != wantInvalid {
		t.Fatalf("invalid Input formatting = %q / %q", invalid.String(), invalid.GoString())
	}
	formatted := fmt.Sprintf("%v|%#v|%s|%q|%x", invalid, invalid, invalid, invalid, invalid)
	if strings.Contains(formatted, "ACTION-CANARY") || strings.Contains(formatted, testViewerID.String()) ||
		len(formatted) > 5*(len(wantInvalid)+1) {
		t.Fatalf("invalid Input formatting was not bounded and redacted: %q", formatted)
	}
}

func TestExplicitEmptyPolicySpecJSONRoundTrip(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile("testdata/policy-spec-empty.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	spec := PolicySpec{Bindings: []RoleBinding{}}
	encoded, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("empty PolicySpec = %s, want %s", encoded, want)
	}
	var restored PolicySpec
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Bindings == nil || ValidatePolicySpec(restored) != nil || !EqualPolicySpec(spec, restored) {
		t.Fatalf("empty PolicySpec round trip = %#v", restored)
	}
	var missing PolicySpec
	if err := json.Unmarshal([]byte(`{}`), &missing); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicySpec(missing); !errors.Is(err, ErrBindingsRequired) {
		t.Fatalf("missing PolicySpec bindings error = %v", err)
	}
}

func assertBindingError(t testing.TB, err error, sentinel error, index int, field BindingField) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
	var binding *BindingError
	if !errors.As(err, &binding) || binding.BindingIndex() != index || binding.Field() != field {
		t.Fatalf("BindingError = %#v, want index %d field %s", binding, index, field)
	}
}
