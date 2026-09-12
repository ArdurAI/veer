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
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
	"github.com/ArdurAI/veer/internal/core/service/referenceauthorization"
)

const referenceBearerToken = "reference-http-token"

type referenceTestAccess struct{ principal identity.Principal }

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

type referenceProblem struct {
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

type referenceMutationReceipt struct {
	ResourceID      string `json:"resourceId"`
	ResourceVersion string `json:"resourceVersion"`
}

func TestReferenceHandlerRejectsBoundaryViolations(t *testing.T) {
	fixture := newReferenceFixture(t)
	handler := fixture.handler
	target := "/api/v1alpha1/workspaces/" + fixture.workspaceID.String()

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
				"Content-Type": "application/json", "Idempotency-Key": "weak-etag-0000001", "If-Match": `W/"` + fixture.resourceVersion + `"`,
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
		{
			name: "reserved workspace create", method: http.MethodPost, target: "/api/v1alpha1/workspaces",
			body: validWorkspaceBody("reserved"), headers: map[string]string{
				"Content-Type": "application/json", "Idempotency-Key": "reserved-create-0001",
			},
			status: http.StatusForbidden, code: "authorization-denied",
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

func TestReferenceHandlerMapsIdempotencyAndReservedStatus(t *testing.T) {
	fixture := newReferenceFixture(t)
	handler := fixture.handler
	target := "/api/v1alpha1/workspaces/" + fixture.workspaceID.String()
	headers := map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "conflict-replace-0001",
		"If-Match": `"` + fixture.resourceVersion + `"`,
	}
	first := referenceRequest(t, handler, http.MethodPut, target, validWorkspaceBody("one"), headers)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first replace = %d, %s", first.Code, first.Body.String())
	}
	replay := referenceRequest(t, handler, http.MethodPut, target, validWorkspaceBody("one"), headers)
	if replay.Code != http.StatusAccepted || replay.Body.String() != first.Body.String() {
		t.Fatalf("replace replay = %d/%s, want %d/%s", replay.Code, replay.Body.String(), first.Code, first.Body.String())
	}
	conflict := referenceRequest(t, handler, http.MethodPut, target, validWorkspaceBody("two"), headers)
	assertReferenceProblem(t, conflict, http.StatusConflict, "idempotency-key-reused")

	var receipt referenceMutationReceipt
	if err := json.Unmarshal(first.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	status := referenceRequest(t, handler, http.MethodPut, target+"/status", []byte(
		`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":2,"conditions":[]}}`,
	), map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "future-status-0001",
		"If-Match": `"` + receipt.ResourceVersion + `"`,
	})
	assertReferenceProblem(t, status, http.StatusForbidden, "authorization-denied")
}

func TestReferenceHandlerFailsClosedAtAccessBoundaries(t *testing.T) {
	fixture := newReferenceFixture(t)
	handler := fixture.handler

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

	outsider, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://issuer.example", Subject: "outsider", Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	deniedHandler, err := NewReferenceHandler(handler.service, referenceTestAccess{principal: outsider})
	if err != nil {
		t.Fatal(err)
	}
	denied := referenceRequest(
		t, deniedHandler, http.MethodGet, "/api/v1alpha1/workspaces/"+fixture.workspaceID.String(), nil, nil,
	)
	assertReferenceProblem(t, denied, http.StatusForbidden, "authorization-denied")
}

func TestReferenceProblemFallbackAndETagQuoteUnexpectedInput(t *testing.T) {
	handler := &ReferenceHandler{}
	response := httptest.NewRecorder()
	requestID := `unexpected"request`
	handler.writeProblem(
		response,
		requestID,
		http.StatusBadRequest,
		"validation-failed",
		"Request validation failed",
		[]fieldViolation{{Field: "body", Code: "oversized", Message: strings.Repeat("x", 1_024)}},
	)
	if response.Code != http.StatusInternalServerError || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("fallback status/body = %d/%s", response.Code, response.Body.String())
	}
	var fallback problem
	if err := json.Unmarshal(response.Body.Bytes(), &fallback); err != nil {
		t.Fatal(err)
	}
	if fallback.RequestID != "internal" || fallback.Instance != "urn:veer:request:internal" ||
		response.Header().Get("Veer-Request-Id") != fallback.RequestID {
		t.Fatalf("fallback request binding = %q/%q", fallback.RequestID, fallback.Instance)
	}
	if got := quoteETag(`rv_"unexpected`); got != `"rv_\"unexpected"` {
		t.Fatalf("quoteETag() = %q", got)
	}
	capacity := httptest.NewRecorder()
	handler.writeServiceError(capacity, "req-capacity", reference.ErrCapacity)
	assertReferenceProblem(t, capacity, http.StatusServiceUnavailable, "unavailable")
	if capacity.Header().Get("Retry-After") != "10" {
		t.Fatalf("capacity Retry-After = %q", capacity.Header().Get("Retry-After"))
	}
	unavailable := httptest.NewRecorder()
	handler.writeServiceError(unavailable, "req-unavailable", referenceauthorization.ErrUnavailable)
	assertReferenceProblem(t, unavailable, http.StatusServiceUnavailable, "unavailable")
}

type referenceFixture struct {
	handler         *ReferenceHandler
	workspaceID     resource.ID
	resourceVersion string
}

func newReferenceFixture(t *testing.T) referenceFixture {
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
	workspace, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "reference:test:workspace", IdempotencyKey: "reference-test-workspace-0001",
		Body: validWorkspaceBody("initial"),
	})
	if err != nil {
		t.Fatal(err)
	}
	memberID := resource.ID("mem_reference_test_0001")
	member, err := authorization.NewMemberRecord(authorization.MemberInput{
		ID: memberID, WorkspaceID: workspace.ResourceID, Kind: principal.Kind(),
		LogicalIdentity: principal.LogicalIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := authorization.NewMemberDirectory(workspace.ResourceID, []authorization.MemberRecord{member})
	if err != nil {
		t.Fatal(err)
	}
	parentID := workspace.ResourceID
	policyBody := []byte(`{"apiVersion":"v1alpha1","kind":"Policy","metadata":{"displayName":"test administrator"},"spec":{"bindings":[{"memberId":"` + memberID.String() + `","role":"WorkspaceAdministrator","scope":{"kind":"Workspace"}}]}}`)
	if _, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindPolicy, WorkspaceID: workspace.ResourceID, ParentID: &parentID,
		CanonicalTarget: "reference:test:policy", IdempotencyKey: "reference-test-policy-0001",
		Body: policyBody, Members: directory,
	}); err != nil {
		t.Fatal(err)
	}
	runtime, err := referenceauthorization.New(referenceauthorization.Config{
		Reference: service, MemberDirectories: []authorization.MemberDirectory{directory}, MaximumAdmissions: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	access := referenceTestAccess{principal: principal}
	handler, err := NewReferenceHandler(runtime, access)
	if err != nil {
		t.Fatal(err)
	}
	return referenceFixture{handler: handler, workspaceID: workspace.ResourceID, resourceVersion: workspace.ResourceVersion}
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
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
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
