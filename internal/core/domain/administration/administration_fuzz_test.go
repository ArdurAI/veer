package administration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
)

func FuzzElevationTextBoundsAndRedaction(f *testing.F) {
	f.Add("recovery reason", "INC-1")
	f.Add(strings.Repeat("界", MaxReasonRunes), strings.Repeat("c", MaxCaseReferenceRunes))
	f.Add("", "")
	f.Add("0", "a")
	f.Add("reason\ncanary", "case\x00canary")
	f.Fuzz(func(t *testing.T, reason, caseReference string) {
		if len(reason) > 4_096 || len(caseReference) > 4_096 {
			return
		}
		principal := mustPrincipal(t, testIssuer, testSubject)
		administrator := mustAdministrator(t, testAdministratorID, principal)
		request, err := NewElevationRequest(
			testGrantID,
			administrator,
			principal,
			authorization.ActionAuditExport,
			ResolvePlatformAuditExportTarget(),
			reason,
			caseReference,
			testNow,
			time.Minute,
		)
		wantValid := validBoundedText(reason, 1, MaxReasonRunes) &&
			(caseReference == "" || validBoundedText(caseReference, 1, MaxCaseReferenceRunes))
		if !wantValid {
			if err == nil {
				t.Fatal("invalid elevation text was accepted")
			}
			for _, canary := range []string{reason, caseReference} {
				if len(canary) > 32 && utf8.ValidString(canary) && strings.Contains(err.Error(), canary) {
					t.Fatal("validation error exposed submitted elevation text")
				}
			}
			return
		}
		if err != nil || ValidateElevationRequest(request) != nil {
			t.Fatalf("valid elevation text rejected: %v", err)
		}
		if data, marshalErr := json.Marshal(request); !errors.Is(marshalErr, ErrSerializationForbidden) || len(data) != 0 {
			t.Fatalf("json.Marshal(request) = %q, %v", data, marshalErr)
		}
		if formatted := request.String(); formatted !=
			"elevation-request(identity=redacted,scope=redacted,reason=redacted)" {
			t.Fatalf("request diagnostic is not the fixed redaction: %q", formatted)
		}
	})
}

func FuzzStrongAuthAndElevationTimeBounds(f *testing.F) {
	f.Add(int64(0), int64(time.Minute/time.Millisecond))
	f.Add(int64(MaxStrongAuthProofAge/time.Millisecond), int64(MaxElevationDuration/time.Millisecond))
	f.Add(int64(MaxStrongAuthProofAge/time.Millisecond+1), int64(MaxElevationDuration/time.Millisecond+1))
	f.Add(int64(-1), int64(0))
	f.Fuzz(func(t *testing.T, proofAgeMillis, durationMillis int64) {
		const limit = int64(60 * time.Minute / time.Millisecond)
		if proofAgeMillis < -limit || proofAgeMillis > limit ||
			durationMillis < -limit || durationMillis > limit {
			return
		}
		principal := mustPrincipal(t, testIssuer, testSubject)
		administrator := mustAdministrator(t, testAdministratorID, principal)
		duration := time.Duration(durationMillis) * time.Millisecond
		request, requestErr := NewElevationRequest(
			testGrantID,
			administrator,
			principal,
			authorization.ActionAuditExport,
			ResolvePlatformAuditExportTarget(),
			testReason,
			"",
			testNow,
			duration,
		)
		validDuration := duration > 0 && duration <= MaxElevationDuration
		if !validDuration {
			if !errors.Is(requestErr, ErrInvalidElevationDuration) {
				t.Fatalf("duration %v error = %v", duration, requestErr)
			}
			return
		}
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		age := time.Duration(proofAgeMillis) * time.Millisecond
		receipt, receiptErr := NewStrongAuthReceipt(
			testProofID,
			request,
			testNow.Add(-age),
			testNow,
		)
		switch {
		case age < 0:
			if !errors.Is(receiptErr, ErrClockRegressed) {
				t.Fatalf("future auth time error = %v", receiptErr)
			}
		case age > MaxStrongAuthProofAge:
			if !errors.Is(receiptErr, ErrStrongAuthProofStale) {
				t.Fatalf("stale proof error = %v", receiptErr)
			}
		default:
			if receiptErr != nil {
				t.Fatal(receiptErr)
			}
			ledger := mustLedger(t, administrator)
			grant, issueErr := ledger.Issue(testNow, receipt)
			if issueErr != nil || grant.ExpiresAt().Sub(grant.IssuedAt()) != duration {
				t.Fatalf("Issue() = %v, %v", grant, issueErr)
			}
		}
	})
}

func FuzzTargetValidationRejectsTampering(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(10))
	f.Fuzz(func(t *testing.T, selector uint8) {
		fixture := newHierarchyFixture(t)
		target, err := ResolveOperationTarget(fixture.snapshot, fixture.operation)
		if err != nil {
			t.Fatal(err)
		}
		switch selector % 10 {
		case 0:
			target.initialized = false
		case 1:
			target.kind = TargetKind("unbounded-canary")
		case 2:
			target.objectID = nil
		case 3:
			target.workspaceID = nil
		case 4:
			target.resourceID = nil
		case 5:
			invalid := fixture.workspace
			target.objectID = &invalid
		case 6:
			invalid := fixture.environment
			target.workspaceID = &invalid
		case 7:
			invalid := fixture.connection
			target.resourceID = &invalid
		case 8:
			target.environmentID = nil
		case 9:
			invalid := fixture.workspace
			target.providerConnectionID = &invalid
		}
		// Structurally valid but changed opaque IDs cannot be distinguished from
		// another resolved target by ValidateTarget alone; the ledger's exact
		// stored-target comparison rejects those cases. Shape corruptions must be
		// rejected here.
		shapeCorruption := selector%10 <= 4 || selector%10 == 8
		if shapeCorruption && !errors.Is(ValidateTarget(target), ErrInvalidTarget) {
			t.Fatalf("ValidateTarget(tampered %d) error = %v", selector%10, ValidateTarget(target))
		}
	})
}
