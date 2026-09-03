package ports

import (
	"context"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/credential"
)

func TestCredentialPortEnumsAreClosed(t *testing.T) {
	t.Parallel()
	priorities := []SecretReadPriority{SecretReadGeneral, SecretReadCritical}
	for _, value := range priorities {
		if !value.Valid() || value.String() == "secret-read-priority-invalid" {
			t.Fatalf("valid priority %d was rejected", value)
		}
	}
	outcomes := []SecretReadOutcome{
		SecretReadConsumed,
		SecretReadReleased,
		SecretReadRetained,
	}
	for _, value := range outcomes {
		if !value.Valid() || value.String() == "secret-read-outcome-invalid" {
			t.Fatalf("valid outcome %d was rejected", value)
		}
	}
	revocations := []RevocationResult{
		RevocationNotRequired,
		RevocationProviderConfirmed,
		RevocationExpiryBound,
		RevocationPending,
	}
	for _, value := range revocations {
		if !value.Valid() || value.String() == "revocation-result-invalid" {
			t.Fatalf("valid revocation %d was rejected", value)
		}
	}
	if SecretReadPriority(0).Valid() || SecretReadOutcome(0).Valid() ||
		RevocationResult(0).Valid() {
		t.Fatal("zero enum unexpectedly valid")
	}
}

type credentialPortWitness struct{}

func (credentialPortWitness) Claim(
	context.Context,
	credential.SourceLookup,
	SecretReadPriority,
) (SecretReadClaim, error) {
	return credentialPortWitness{}, nil
}

func (credentialPortWitness) Settle(context.Context, SecretReadOutcome) error { return nil }

func (credentialPortWitness) Resolve(
	context.Context,
	credential.SourceLookup,
) (*credential.SourceMaterial, SecretReadOutcome, error) {
	return nil, SecretReadRetained, nil
}

func (credentialPortWitness) Issue(
	context.Context,
	credential.Request,
	*credential.SourceMaterial,
) (*credential.IssuedSession, error) {
	return nil, nil
}

func (credentialPortWitness) Revoke(
	context.Context,
	credential.Request,
	*credential.IssuedSession,
) (RevocationResult, error) {
	return RevocationExpiryBound, nil
}

var (
	_ SecretReadBudget = credentialPortWitness{}
	_ SecretReadClaim  = credentialPortWitness{}
	_ SecretResolver   = credentialPortWitness{}
	_ SessionIssuer    = credentialPortWitness{}
)
