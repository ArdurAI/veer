package ports

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	portAdministratorID resource.ID = "adm_01JPORT000000000000000001"
	portGrantID         resource.ID = "elv_01JPORT000000000000000001"
	portProofID         resource.ID = "prf_01JPORT000000000000000001"
)

var portNow = time.Date(2026, time.September, 3, 14, 0, 0, 0, time.UTC)

func TestStrongAuthenticationVerifierIsExplicitAndContextAware(t *testing.T) {
	t.Parallel()
	request := portElevationFixture(t)
	credential, err := NewBearerCredential(tokenCanary)
	if err != nil {
		t.Fatal(err)
	}
	verifier := fakeStrongAuthenticationVerifier{
		proofID:         portProofID,
		authenticatedAt: portNow.Add(-time.Minute),
		requestID:       request.ID(),
	}
	proofID, authenticatedAt, err := verifier.VerifyStrongAuthentication(
		context.Background(), credential, request,
	)
	if err != nil || proofID != portProofID || authenticatedAt != portNow.Add(-time.Minute) {
		t.Fatalf("VerifyStrongAuthentication() = %v, %v, %v", proofID, authenticatedAt, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	proofID, authenticatedAt, err = verifier.VerifyStrongAuthentication(canceled, credential, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyStrongAuthentication(canceled) error = %v", err)
	}
	if proofID != "" || !authenticatedAt.IsZero() {
		t.Fatal("canceled verification returned proof metadata")
	}

	invalidCredential := BearerCredential{}
	if _, _, err := verifier.VerifyStrongAuthentication(
		context.Background(), invalidCredential, request,
	); !errors.Is(err, ErrStrongAuthenticationInvalid) {
		t.Fatalf("VerifyStrongAuthentication(invalid credential) error = %v", err)
	}
}

func TestStrongAuthenticationErrorsAreClosedAndClassifiable(t *testing.T) {
	t.Parallel()
	for _, failure := range []StrongAuthenticationError{
		ErrStrongAuthenticationInvalid,
		ErrStrongAuthenticationUnavailable,
	} {
		if failure.Error() != failure.String() {
			t.Fatalf("failure diagnostics = %q / %q", failure.Error(), failure.String())
		}
		classified, ok := ClassifyStrongAuthenticationError(failure)
		if !ok || classified != failure {
			t.Fatalf("ClassifyStrongAuthenticationError(%v) = %v, %t", failure, classified, ok)
		}
		wrapped := fmt.Errorf("safe verifier boundary: %w", failure)
		classified, ok = ClassifyStrongAuthenticationError(wrapped)
		if !ok || classified != failure {
			t.Fatalf("ClassifyStrongAuthenticationError(wrapped %v) = %v, %t", failure, classified, ok)
		}
	}
	unknown := StrongAuthenticationError(255)
	if unknown.Error() != "strong-authentication-error" ||
		unknown.String() != "strong-authentication-error" ||
		unknown.GoString() != "ports.StrongAuthenticationError(strong-authentication-error)" {
		t.Fatal("unknown strong-authentication error exposed its underlying value")
	}
	for _, err := range []error{nil, context.Canceled, unknown, errors.New("adapter-canary-private")} {
		if _, ok := ClassifyStrongAuthenticationError(err); ok {
			t.Fatalf("ClassifyStrongAuthenticationError(%v) classified an open error", err)
		}
	}
}

type fakeStrongAuthenticationVerifier struct {
	proofID         resource.ID
	authenticatedAt time.Time
	requestID       resource.ID
}

func (fake fakeStrongAuthenticationVerifier) VerifyStrongAuthentication(
	ctx context.Context,
	credential BearerCredential,
	request administration.ElevationRequest,
) (resource.ID, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return "", time.Time{}, err
	}
	if !credential.Valid() || administration.ValidateElevationRequest(request) != nil {
		return "", time.Time{}, ErrStrongAuthenticationInvalid
	}
	if fake.requestID != request.ID() {
		return "", time.Time{}, ErrStrongAuthenticationInvalid
	}
	return fake.proofID, fake.authenticatedAt, nil
}

func portElevationFixture(t testing.TB) administration.ElevationRequest {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    "https://port-identity-canary.example/tenant",
		Subject:   "port-subject-canary",
		Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	administrator, err := administration.NewAdministrator(portAdministratorID, principal)
	if err != nil {
		t.Fatal(err)
	}
	request, err := administration.NewElevationRequest(
		portGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		administration.ResolvePlatformAuditExportTarget(),
		"Verify platform export after incident declaration",
		"INC-PORT-27",
		portNow,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

var _ StrongAuthenticationVerifier = fakeStrongAuthenticationVerifier{}
