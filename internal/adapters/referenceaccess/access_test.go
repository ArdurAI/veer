package referenceaccess

import (
	"context"
	"errors"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
)

func TestAccessAuthenticatesExactCredential(t *testing.T) {
	credential := testCredential(t, "reference-access-token")
	principal := testPrincipal(t, "reference-access")
	access, err := New(credential, principal)
	if err != nil {
		t.Fatal(err)
	}

	got, err := access.Authenticate(context.Background(), credential)
	if err != nil || !identity.EqualPrincipal(got, principal) {
		t.Fatalf("Authenticate() = %v, %v", got, err)
	}
	if _, err := access.Authenticate(context.Background(), testCredential(t, "different-access-token")); !errors.Is(err, ports.ErrAuthenticationInvalid) {
		t.Fatalf("Authenticate(wrong) error = %v", err)
	}
}

func TestAccessHonorsCancellationAndRejectsInvalidConfiguration(t *testing.T) {
	credential := testCredential(t, "reference-access-token")
	principal := testPrincipal(t, "reference-access")
	if _, err := New(ports.BearerCredential{}, principal); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("New(invalid) error = %v", err)
	}
	access, err := New(credential, principal)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := access.Authenticate(ctx, credential); !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate(canceled) error = %v", err)
	}
}

func testCredential(t *testing.T, value string) ports.BearerCredential {
	t.Helper()
	credential, err := ports.NewBearerCredential(value)
	if err != nil {
		t.Fatal(err)
	}
	return credential
}

func testPrincipal(t *testing.T, subject string) identity.Principal {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://reference.example", Subject: subject,
		Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}
