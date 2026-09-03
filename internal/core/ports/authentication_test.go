package ports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

const tokenCanary = "eyJ0b2tlbiI6InRva2VuLWNhbmFyeS1wcml2YXRlIn0.signature"

func TestBearerCredentialValidationAndExactSizeBound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{"minimum", "a", true},
		{"JWT compact", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature", true},
		{"RFC 6750 alphabet", "AZaz09-._~+/==", true},
		{"exact 8192-byte bound", strings.Repeat("a", MaxBearerTokenBytes), true},
		{"empty", "", false},
		{"8193 bytes", strings.Repeat("a", MaxBearerTokenBytes+1), false},
		{"space", "abc def", false},
		{"tab", "abc\tdef", false},
		{"non ASCII", "abc\u00e9", false},
		{"padding before data", "abc=def", false},
		{"one padding after data", "a=", true},
		{"only one padding", "=", false},
		{"only padding", "==", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			credential, err := NewBearerCredential(test.token)
			if test.valid {
				if err != nil {
					t.Fatalf("NewBearerCredential() error = %v", err)
				}
				if !credential.Valid() {
					t.Fatal("constructed credential is invalid")
				}
				if credential.Token() != test.token {
					t.Fatal("Token() changed credential material")
				}
				return
			}
			if !errors.Is(err, ErrInvalidBearerCredential) {
				t.Fatalf("NewBearerCredential() error = %v, want ErrInvalidBearerCredential", err)
			}
			if credential.Valid() || credential.Token() != "" {
				t.Fatal("invalid constructor result retained credential state")
			}
			if strings.Contains(err.Error(), test.token) && test.token != "" {
				t.Fatal("validation error exposed credential")
			}
		})
	}

	if (BearerCredential{}).Valid() {
		t.Fatal("zero BearerCredential is valid")
	}
}

func TestBearerCredentialDiagnosticsAndSerializationAlwaysRedact(t *testing.T) {
	t.Parallel()

	credential, err := NewBearerCredential(tokenCanary)
	if err != nil {
		t.Fatalf("NewBearerCredential() error = %v", err)
	}
	for _, value := range []any{
		credential,
		&credential,
		error(credential),
		struct{ Credential BearerCredential }{Credential: credential},
		[]BearerCredential{credential},
	} {
		for _, format := range []string{
			"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%o", "%f",
		} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, tokenCanary) {
				t.Fatalf("format %q exposed token: %q", format, formatted)
			}
		}
		encoded, marshalErr := json.Marshal(value)
		if marshalErr == nil {
			t.Fatalf("json.Marshal(%T) = %s, want error", value, encoded)
		}
		if strings.Contains(string(encoded), tokenCanary) ||
			strings.Contains(marshalErr.Error(), tokenCanary) {
			t.Fatal("JSON path exposed token")
		}
	}
	if credential.String() != "bearer-credential(redacted)" ||
		credential.Error() != "bearer-credential(redacted)" ||
		credential.GoString() != "bearer-credential(redacted)" {
		t.Fatal("credential diagnostic methods are not the stable redaction")
	}

	var typedNil *BearerCredential
	for _, formatted := range []string{
		fmt.Sprintf("%v", typedNil),
		fmt.Sprintf("%+v", typedNil),
		fmt.Sprintf("%#v", typedNil),
	} {
		if strings.Contains(formatted, tokenCanary) {
			t.Fatal("typed-nil diagnostic exposed token")
		}
	}
	if encoded, marshalErr := json.Marshal(typedNil); marshalErr != nil || string(encoded) != "null" {
		t.Fatalf("json.Marshal(typed nil) = %q, %v", encoded, marshalErr)
	}
}

func TestAuthenticationErrorsAreClosedStableAndClassifiable(t *testing.T) {
	t.Parallel()

	for _, failure := range []AuthenticationError{
		ErrAuthenticationInvalid,
		ErrAuthenticationUnavailable,
	} {
		if failure.Error() != failure.String() {
			t.Fatalf("failure diagnostic = %q / %q", failure.Error(), failure.String())
		}
		classified, ok := ClassifyAuthenticationError(failure)
		if !ok || classified != failure {
			t.Fatalf("ClassifyAuthenticationError(%v) = %v, %t", failure, classified, ok)
		}
		wrapped := fmt.Errorf("safe adapter boundary: %w", failure)
		classified, ok = ClassifyAuthenticationError(wrapped)
		if !ok || classified != failure {
			t.Fatalf("ClassifyAuthenticationError(wrapped %v) = %v, %t", failure, classified, ok)
		}
	}
	unknown := AuthenticationError(255)
	if unknown.Error() != "authentication-error" ||
		unknown.String() != "authentication-error" ||
		unknown.GoString() != "ports.AuthenticationError(authentication-error)" {
		t.Fatal("unknown AuthenticationError exposed its underlying value")
	}
	if _, ok := ClassifyAuthenticationError(unknown); ok {
		t.Fatal("unknown authentication error was classified")
	}
	if _, ok := ClassifyAuthenticationError(nil); ok {
		t.Fatal("nil error was classified")
	}
	if _, ok := ClassifyAuthenticationError(context.Canceled); ok {
		t.Fatal("context cancellation was classified as authentication failure")
	}
}

func TestAuthenticatorPortIsContextAwareAndReturnsPrincipal(t *testing.T) {
	t.Parallel()

	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind:      identity.KindHuman,
		Issuer:    "https://issuer.example",
		Subject:   "subject",
		Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatalf("identity.NewPrincipal() error = %v", err)
	}
	credential, err := NewBearerCredential(tokenCanary)
	if err != nil {
		t.Fatalf("NewBearerCredential() error = %v", err)
	}
	authenticator := fakeAuthenticator{principal: principal}
	got, err := authenticator.Authenticate(context.Background(), credential)
	if err != nil || !identity.EqualPrincipal(got, principal) {
		t.Fatalf("Authenticate() = %v, %v", got, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err = authenticator.Authenticate(ctx, credential)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authenticate(canceled) error = %v", err)
	}
	if identity.ValidatePrincipal(got) == nil {
		t.Fatal("Authenticate(canceled) returned a valid principal")
	}
}

type fakeAuthenticator struct {
	principal identity.Principal
}

func (fake fakeAuthenticator) Authenticate(
	ctx context.Context,
	credential BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if !credential.Valid() {
		return identity.Principal{}, ErrAuthenticationInvalid
	}
	return identity.ClonePrincipal(fake.principal), nil
}

var _ Authenticator = fakeAuthenticator{}
