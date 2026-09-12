package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

const referenceBearerToken = "reference-http-token"

type referenceTestAccess struct{ principal identity.Principal }

type referenceAuthorizerFunc func(context.Context, identity.Principal, authorization.Action) error

func (function referenceAuthorizerFunc) Authorize(
	ctx context.Context,
	principal identity.Principal,
	action authorization.Action,
) error {
	return function(ctx, principal, action)
}

func (access referenceTestAccess) Authenticate(
	ctx context.Context,
	credential ports.BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if credential.Token() != referenceBearerToken {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	return identity.ClonePrincipal(access.principal), nil
}

func (access referenceTestAccess) Authorize(
	ctx context.Context,
	_ identity.Principal,
	_ authorization.Action,
) error {
	return ctx.Err()
}

type referenceProblem struct {
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

type referenceMutationReceipt struct {
	ResourceID      string `json:"resourceId"`
	ResourceVersion string `json:"resourceVersion"`
}

func TestReferenceHandlerRejectsBoundaryViolations(t *testing.T) {
	handler := referenceFixtureHandler(t)
	created := referenceRequest(t, handler, http.MethodPost, "/api/v1alpha1/workspaces", validWorkspaceBody("initial"), map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "boundary-create-0001",
	})
	if created.Code != http.StatusAccepted {
		t.Fatalf("seed create status = %d, body = %s", created.Code, created.Body.String())
	}
	var receipt referenceMutationReceipt
	if err := json.Unmarshal(created.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	target := "/api/v1alpha1/workspaces/" + receipt.ResourceID

	tests := []struct {
		name    string
		method  string
		target  string
		body    []byte
		headers map[string]string
		status  int
		code    string
	}{
		{
			name: "missing precondition", method: http.MethodPut, target: target, body: validWorkspaceBody("changed"),
			headers: map[string]string{"Content-Type": "application/json", "Idempotency-Key": "missing-etag-0001"},
			status:  http.StatusPreconditionRequired, code: "precondition-required",
		},
		{
			name: "weak precondition", method: http.MethodPut, target: target, body: validWorkspaceBody("changed"),
			headers: map[string]string{
				"Content-Type": "application/json", "Idempotency-Key": "weak-etag-0000001", "If-Match": `W/"` + receipt.ResourceVersion + `"`,
			},
			status: http.StatusBadRequest, code: "validation-failed",
		},
		{
			name: "missing media type", method: http.MethodPost, target: "/api/v1alpha1/workspaces", body: validWorkspaceBody("media"),
			headers: map[string]string{"Idempotency-Key": "missing-media-0001"},
			status:  http.StatusUnsupportedMediaType, code: "unsupported-media-type",
		},
		{
			name: "unknown query", method: http.MethodGet, target: "/api/v1alpha1/workspaces?offset=1",
			status: http.StatusBadRequest, code: "validation-failed",
		},
		{
			name: "empty page size", method: http.MethodGet, target: "/api/v1alpha1/workspaces?pageSize=",
			status: http.StatusBadRequest, code: "validation-failed",
		},
		{
			name: "invalid request id", method: http.MethodGet, target: "/api/v1alpha1/workspaces",
			headers: map[string]string{"Veer-Request-Id": "invalid request id"},
			status:  http.StatusBadRequest, code: "validation-failed",
		},
		{
			name: "oversized body", method: http.MethodPost, target: "/api/v1alpha1/workspaces",
			body:    bytes.Repeat([]byte{'x'}, maxRequestBodyBytes+1),
			headers: map[string]string{"Content-Type": "application/json", "Idempotency-Key": "oversized-body-0001"},
			status:  http.StatusRequestEntityTooLarge, code: "request-too-large",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := referenceRequest(t, handler, test.method, test.target, test.body, test.headers)
			assertReferenceProblem(t, response, test.status, test.code)
			if len(response.Body.Bytes()) > 1_024 {
				t.Fatalf("problem body = %d bytes, want <= 1024", len(response.Body.Bytes()))
			}
		})
	}
}

func TestReferenceHandlerMapsIdempotencyAndObservationConflicts(t *testing.T) {
	handler := referenceFixtureHandler(t)
	headers := map[string]string{"Content-Type": "application/json", "Idempotency-Key": "conflict-create-0001"}
	first := referenceRequest(t, handler, http.MethodPost, "/api/v1alpha1/workspaces", validWorkspaceBody("one"), headers)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first create = %d, %s", first.Code, first.Body.String())
	}
	conflict := referenceRequest(t, handler, http.MethodPost, "/api/v1alpha1/workspaces", validWorkspaceBody("two"), headers)
	assertReferenceProblem(t, conflict, http.StatusConflict, "idempotency-key-reused")

	var receipt referenceMutationReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	target := "/api/v1alpha1/workspaces/" + receipt.ResourceID
	status := referenceRequest(t, handler, http.MethodPut, target+"/status", []byte(
		`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":2,"conditions":[]}}`,
	), map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "future-status-0001",
		"If-Match": `"` + receipt.ResourceVersion + `"`,
	})
	assertReferenceProblem(t, status, http.StatusBadRequest, "validation-failed")
	if !strings.Contains(status.Body.String(), `"code":"future-observation"`) {
		t.Fatalf("future status field violation missing: %s", status.Body.String())
	}
}

func TestReferenceHandlerFailsClosedAtAccessBoundaries(t *testing.T) {
	handler := referenceFixtureHandler(t).(*ReferenceHandler)

	missing := httptest.NewRequest(http.MethodGet, "/api/v1alpha1/workspaces", nil)
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missing)
	assertReferenceProblem(t, missingResponse, http.StatusUnauthorized, "authentication-required")
	if missingResponse.Header().Get("WWW-Authenticate") != `Bearer realm="veer"` {
		t.Fatalf("missing challenge = %q", missingResponse.Header().Get("WWW-Authenticate"))
	}

	invalid := httptest.NewRequest(http.MethodGet, "/api/v1alpha1/workspaces", nil)
	invalid.Header.Set("Authorization", "Bearer wrong-reference-token")
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	assertReferenceProblem(t, invalidResponse, http.StatusUnauthorized, "authentication-required")
	if invalidResponse.Header().Get("WWW-Authenticate") != `Bearer realm="veer", error="invalid_token"` {
		t.Fatalf("invalid challenge = %q", invalidResponse.Header().Get("WWW-Authenticate"))
	}

	deniedHandler := &ReferenceHandler{
		service: handler.service, authenticator: handler.authenticator,
		authorizer: referenceAuthorizerFunc(func(
			context.Context,
			identity.Principal,
			authorization.Action,
		) error {
			return ErrReferenceAuthorizationDenied
		}),
	}
	denied := referenceRequest(t, deniedHandler, http.MethodGet, "/api/v1alpha1/workspaces", nil, nil)
	assertReferenceProblem(t, denied, http.StatusForbidden, "authorization-denied")

	unavailableHandler := &ReferenceHandler{
		service: handler.service, authenticator: handler.authenticator,
		authorizer: referenceAuthorizerFunc(func(
			context.Context,
			identity.Principal,
			authorization.Action,
		) error {
			return ErrReferenceAuthorizationUnavailable
		}),
	}
	unavailable := referenceRequest(t, unavailableHandler, http.MethodGet, "/api/v1alpha1/workspaces", nil, nil)
	assertReferenceProblem(t, unavailable, http.StatusServiceUnavailable, "unavailable")
	if unavailable.Header().Get("Retry-After") != "10" || !strings.Contains(unavailable.Body.String(), `"retryAfterSeconds":10`) {
		t.Fatalf("unavailable retry contract = %q, %s", unavailable.Header().Get("Retry-After"), unavailable.Body.String())
	}
}

func referenceFixtureHandler(t *testing.T) http.Handler {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://issuer.example", Subject: "http-user", Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := reference.New(reference.Config{
		Store: memory.NewStore(), Clock: reference.ClockFunc(func() time.Time {
			return time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
		}),
		Issuer: &reference.SequentialIssuer{}, PageTokenKey: bytes.Repeat([]byte{0x42}, 32),
		MaximumPageTokens: 16, MaximumReplays: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	access := referenceTestAccess{principal: principal}
	handler, err := NewReferenceHandler(service, access, access)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func referenceRequest(
	t *testing.T,
	handler http.Handler,
	method, target string,
	body []byte,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+referenceBearerToken)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertReferenceProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("response status/content-type = %d/%q, want %d/problem; body=%s",
			response.Code, response.Header().Get("Content-Type"), status, response.Body.String())
	}
	var problem referenceProblem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Code != code || problem.RequestID == "" || response.Header().Get("Veer-Request-Id") != problem.RequestID {
		t.Fatalf("problem code/request binding = %q/%q/%q", problem.Code, problem.RequestID, response.Header().Get("Veer-Request-Id"))
	}
}

func validWorkspaceBody(name string) []byte {
	return []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"` + name + `"},"spec":{}}`)
}
