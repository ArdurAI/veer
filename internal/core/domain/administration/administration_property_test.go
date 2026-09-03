package administration

import (
	"errors"
	"math/rand"
	"testing"
	"testing/quick"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
)

func TestPropertyElevationLifetimeNeverExceedsRequestedBound(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	property := func(raw uint32) bool {
		maximum := uint32(MaxElevationDuration / time.Millisecond)
		duration := time.Duration(raw%maximum+1) * time.Millisecond
		ledger, err := NewLedger([]Administrator{administrator})
		if err != nil {
			return false
		}
		request, err := NewElevationRequest(
			testGrantID,
			administrator,
			principal,
			authorization.ActionAuditExport,
			target,
			testReason,
			"",
			testNow,
			duration,
		)
		if err != nil {
			return false
		}
		receipt, err := NewStrongAuthReceipt(testProofID, request, testNow, testNow)
		if err != nil {
			return false
		}
		grant, err := ledger.Issue(testNow, receipt)
		if err != nil || grant.ExpiresAt().Sub(grant.IssuedAt()) != duration ||
			grant.ExpiresAt().Sub(grant.IssuedAt()) > MaxElevationDuration {
			return false
		}
		before := grant.ExpiresAt().Add(-time.Millisecond)
		state, err := ledger.StateAt(before, grant)
		if err != nil || state != GrantStateActive {
			return false
		}
		state, err = ledger.StateAt(grant.ExpiresAt(), grant)
		return err == nil && state == GrantStateExpired
	}
	checkAdministrationProperty(t, property)
}

func TestPropertyStrongAuthAgeBoundaryIsClosedAtMaximum(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(), time.Minute,
	)
	property := func(raw uint32) bool {
		age := time.Duration(raw%uint32(2*MaxStrongAuthProofAge/time.Millisecond+1)) * time.Millisecond
		_, err := NewStrongAuthReceipt(
			testProofID,
			request,
			testNow.Add(-age),
			testNow,
		)
		if age <= MaxStrongAuthProofAge {
			return err == nil
		}
		return errors.Is(err, ErrStrongAuthProofStale)
	}
	checkAdministrationProperty(t, property)
}

func TestPropertyGrantAliasesCannotReplay(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	property := func(offset uint16) bool {
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
			return false
		}
		alias := grant
		when := testNow.Add(time.Duration(offset%30) * time.Millisecond)
		if _, err := ledger.Consume(when, alias, authorization.ActionAuditExport, target); err != nil {
			return false
		}
		_, err = ledger.Consume(when, grant, authorization.ActionAuditExport, target)
		if !errors.Is(err, ErrGrantConsumed) {
			return false
		}
		state, err := ledger.StateAt(when, alias)
		return err == nil && state == GrantStateConsumed
	}
	checkAdministrationProperty(t, property)
}

func checkAdministrationProperty(t *testing.T, property any) {
	t.Helper()
	configuration := &quick.Config{
		MaxCount: 250,
		Rand:     rand.New(rand.NewSource(27)),
	}
	if err := quick.Check(property, configuration); err != nil {
		t.Fatal(err)
	}
}
