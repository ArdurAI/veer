package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/api/openapi"
	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
	"github.com/ArdurAI/veer/internal/core/service/referenceauthorization"
	httptransport "github.com/ArdurAI/veer/internal/transport/http"
)

const (
	securityBearerCanary         = "security-route-bearer+canary"
	invalidBearerCanary          = "invalid-security-route-bearer+canary"
	securityResourceCanary       = "security-resource-confidential-canary"
	securityOutsiderCanary       = "security-outsider-workspace-confidential-canary"
	securityPolicyCanary         = "security-policy-confidential-canary"
	securityMemberCanary         = "mem_security_confidential_0001"
	securityIdentityCanary       = "security-identity-confidential-canary"
	securityStaleVersionCanary   = "rv_security_stale_0001"
	maximumSecurityProblemBytes  = 1_024
	maximumSecurityFieldPathSize = 96
)

type securityProblemExpectation struct {
	status             int
	title              string
	requiresRetryAfter bool
}

var (
	securityProblemCodePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	securityRequestIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	securityFieldPathPattern    = regexp.MustCompile(`^(/([^~/]|~0|~1)*)+$`)
	securityProblemExpectations = map[string]securityProblemExpectation{
		"validation-failed":       {status: http.StatusBadRequest, title: "Request validation failed"},
		"authentication-required": {status: http.StatusUnauthorized, title: "Authentication required"},
		"authorization-denied":    {status: http.StatusForbidden, title: "Authorization denied"},
		"not-found":               {status: http.StatusNotFound, title: "Resource not found"},
		"method-not-allowed":      {status: http.StatusMethodNotAllowed, title: "Method not allowed"},
		"idempotency-key-reused":  {status: http.StatusConflict, title: "Request conflicts with a prior mutation"},
		"uniqueness-conflict":     {status: http.StatusConflict, title: "Resource uniqueness conflict"},
		"lifecycle-conflict":      {status: http.StatusConflict, title: "Resource lifecycle conflict"},
		"policy-conflict":         {status: http.StatusConflict, title: "Resource policy conflict"},
		"precondition-failed":     {status: http.StatusPreconditionFailed, title: "Resource version is stale"},
		"request-too-large":       {status: http.StatusRequestEntityTooLarge, title: "Request body is too large"},
		"unsupported-media-type":  {status: http.StatusUnsupportedMediaType, title: "Unsupported request media type"},
		"precondition-required":   {status: http.StatusPreconditionRequired, title: "Mutation precondition required"},
		"rate-limited": {
			status: http.StatusTooManyRequests, title: "Request rate limited", requiresRetryAfter: true,
		},
		"internal-failure": {status: http.StatusInternalServerError, title: "Internal failure"},
		"unavailable": {
			status: http.StatusServiceUnavailable, title: "Service temporarily unavailable", requiresRetryAfter: true,
		},
	}
)

type securityRoute struct {
	operationID         string
	method              string
	pathTemplate        string
	target              func(securityFixture) string
	body                func(securityFixture) []byte
	headers             func(securityFixture) map[string]string
	memberStatus        int
	memberOutcome       string
	memberProblemCode   string
	outsiderStatus      int
	outsiderOutcome     string
	outsiderProblemCode string
	allRolesDenied      bool
	workspaceAdminOnly  bool
	staleOutsiderCheck  bool
	assertMemberBody    func(*testing.T, securityFixture, *httptest.ResponseRecorder)
	assertOutsiderBody  func(*testing.T, securityFixture, *httptest.ResponseRecorder)
}

type securityFixture struct {
	memberHandler       http.Handler
	outsiderHandler     http.Handler
	workspaceID         resource.ID
	outsiderWorkspaceID resource.ID
	resourceVersion     string
	operationID         resource.ID
	policyID            resource.ID
	memberID            resource.ID
}

type securityAccess struct {
	principal identity.Principal
}

func (access securityAccess) Authenticate(
	ctx context.Context,
	credential ports.BearerCredential,
) (identity.Principal, error) {
	if err := ctx.Err(); err != nil {
		return identity.Principal{}, err
	}
	if credential.Token() != securityBearerCanary {
		return identity.Principal{}, ports.ErrAuthenticationInvalid
	}
	return identity.ClonePrincipal(access.principal), nil
}

type securityMatrixReport struct {
	Contract         string                `json:"contract"`
	OpenAPIArtifact  string                `json:"openapiArtifact"`
	OpenAPISHA256    string                `json:"openapiSha256"`
	OpenAPIValidated bool                  `json:"openapiValidated"`
	Routes           []securityRouteResult `json:"routes"`
}

type securityRouteResult struct {
	OperationID             string `json:"operationId"`
	Method                  string `json:"method"`
	PathTemplate            string `json:"pathTemplate"`
	MemberStatus            int    `json:"memberStatus"`
	MemberOutcome           string `json:"memberOutcome"`
	OutsiderStatus          int    `json:"outsiderStatus"`
	OutsiderOutcome         string `json:"outsiderOutcome"`
	MissingCredentialStatus int    `json:"missingCredentialStatus"`
	InvalidCredentialStatus int    `json:"invalidCredentialStatus"`
}

type securityFieldViolation struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type securityProblem struct {
	Type              string                   `json:"type"`
	Title             string                   `json:"title"`
	Status            int                      `json:"status"`
	Detail            string                   `json:"detail,omitempty"`
	Instance          string                   `json:"instance"`
	Code              string                   `json:"code"`
	RequestID         string                   `json:"requestId"`
	Errors            []securityFieldViolation `json:"errors,omitempty"`
	RetryAfterSeconds *int                     `json:"retryAfterSeconds,omitempty"`
}

func TestBearerCanariesAreNotRequestIDs(t *testing.T) {
	for _, canary := range []string{securityBearerCanary, invalidBearerCanary} {
		if _, err := ports.NewBearerCredential(canary); err != nil {
			t.Fatalf("bearer canary is not a valid credential: %v", err)
		}
		if securityRequestIDPattern.MatchString(canary) {
			t.Fatalf("bearer canary overlaps the request-ID grammar: %q", canary)
		}
	}
}

func TestSecurityProblemJSONRejectsDuplicateMembers(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "unique", body: `{"detail":"safe","errors":[{"field":"/spec","code":"invalid","message":"safe"}]}`},
		{name: "duplicate top-level", body: `{"detail":"secret","detail":"safe"}`, wantErr: true},
		{name: "escaped duplicate", body: `{"detail":"secret","\u0064etail":"safe"}`, wantErr: true},
		{name: "duplicate nested", body: `{"errors":[{"message":"secret","message":"safe"}]}`, wantErr: true},
		{name: "malformed", body: `{"detail":`, wantErr: true},
		{name: "trailing value", body: `{} {}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateUniqueJSONMembers([]byte(test.body))
			if (err != nil) != test.wantErr {
				t.Fatalf("validateUniqueJSONMembers() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestSecurityProblemRetryMetadata(t *testing.T) {
	retry := func(value int) *int { return &value }
	tests := []struct {
		name    string
		code    string
		body    *int
		headers []string
		wantErr bool
	}{
		{name: "unavailable", code: "unavailable", body: retry(10), headers: []string{"10"}},
		{name: "rate limited", code: "rate-limited", body: retry(5), headers: []string{"5"}},
		{name: "missing body", code: "unavailable", headers: []string{"10"}, wantErr: true},
		{name: "zero body", code: "unavailable", body: retry(0), headers: []string{"0"}, wantErr: true},
		{name: "missing header", code: "unavailable", body: retry(10), wantErr: true},
		{name: "duplicate header", code: "unavailable", body: retry(10), headers: []string{"10", "10"}, wantErr: true},
		{name: "mismatched header", code: "unavailable", body: retry(10), headers: []string{"11"}, wantErr: true},
		{name: "non-canonical header", code: "unavailable", body: retry(10), headers: []string{"010"}, wantErr: true},
		{name: "ordinary problem", code: "validation-failed"},
		{name: "unexpected body", code: "validation-failed", body: retry(1), wantErr: true},
		{name: "unexpected header", code: "validation-failed", headers: []string{"1"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSecurityRetryAfter(
				securityProblemExpectations[test.code],
				securityProblem{RetryAfterSeconds: test.body},
				test.headers,
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSecurityRetryAfter() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestSecurityProblemMemberPresence(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "minimal", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test"}`},
		{name: "field violation", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","detail":"safe","errors":[{"field":"/spec","code":"invalid","message":"safe"}]}`},
		{name: "missing required", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","requestId":"req-test"}`, wantErr: true},
		{name: "null required", body: `{"type":"urn:veer:problem:validation-failed","title":null,"status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test"}`, wantErr: true},
		{name: "null detail", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","detail":null}`, wantErr: true},
		{name: "null errors", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","errors":null}`, wantErr: true},
		{name: "null retry", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","retryAfterSeconds":null}`, wantErr: true},
		{name: "missing violation member", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","errors":[{"field":"/spec","code":"invalid"}]}`, wantErr: true},
		{name: "null violation member", body: `{"type":"urn:veer:problem:validation-failed","title":"Request validation failed","status":400,"instance":"urn:veer:request:req-test","code":"validation-failed","requestId":"req-test","errors":[{"field":"/spec","code":"invalid","message":null}]}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSecurityProblemMembers([]byte(test.body))
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSecurityProblemMembers() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestPublicRouteSecurityMatrix(t *testing.T) {
	routes := publicSecurityRoutes()
	assertOpenAPIRouteCoverage(t, routes)
	results := make([]securityRouteResult, 0, len(routes))

	for _, route := range routes {
		route := route
		t.Run(route.operationID, func(t *testing.T) {
			fixture := newSecurityFixture(t)
			member := securityRequest(t, fixture.memberHandler, route, fixture, securityBearerCanary)
			assertSecurityResponse(t, member, route.memberStatus, route.memberProblemCode)
			if route.memberStatus >= http.StatusBadRequest {
				assertNoFixtureCanary(t, member, fixture)
			}
			if route.assertMemberBody != nil {
				route.assertMemberBody(t, fixture, member)
			}

			fixture = newSecurityFixture(t)
			outsider := securityRequest(t, fixture.outsiderHandler, route, fixture, securityBearerCanary)
			assertSecurityResponse(t, outsider, route.outsiderStatus, route.outsiderProblemCode)
			if route.outsiderStatus >= http.StatusBadRequest {
				assertNoFixtureCanary(t, outsider, fixture)
			}
			if route.assertOutsiderBody != nil {
				route.assertOutsiderBody(t, fixture, outsider)
			}
			if route.staleOutsiderCheck {
				t.Run("outsider-stale-precondition", func(t *testing.T) {
					staleFixture := newSecurityFixture(t)
					denied := securityRequestWithHeaderOverrides(
						t,
						staleFixture.outsiderHandler,
						route,
						staleFixture,
						securityBearerCanary,
						map[string]string{
							"If-Match":        `"` + securityStaleVersionCanary + `"`,
							"Veer-Request-Id": securityResourceCanary,
						},
					)
					assertSecurityResponse(t, denied, http.StatusForbidden, "authorization-denied")
					assertNoFixtureCanary(t, denied, staleFixture)
				})
			}

			fixture = newSecurityFixture(t)
			missing := securityRequest(t, fixture.memberHandler, route, fixture, "")
			assertAuthenticationDenial(t, missing, `Bearer realm="veer"`)
			assertNoFixtureCanary(t, missing, fixture)

			fixture = newSecurityFixture(t)
			invalid := securityRequest(t, fixture.memberHandler, route, fixture, invalidBearerCanary)
			assertAuthenticationDenial(t, invalid, `Bearer realm="veer", error="invalid_token"`)
			assertNoFixtureCanary(t, invalid, fixture)

			if route.allRolesDenied {
				for _, role := range authorization.Roles() {
					role := role
					t.Run("reserved-"+role.String(), func(t *testing.T) {
						roleFixture := newSecurityFixtureForRole(t, role)
						denied := securityRequest(t, roleFixture.memberHandler, route, roleFixture, securityBearerCanary)
						assertSecurityResponse(t, denied, http.StatusForbidden, "authorization-denied")
						assertNoFixtureCanary(t, denied, roleFixture)
					})
				}
			}
			if route.workspaceAdminOnly {
				for _, role := range authorization.Roles() {
					if role == authorization.RoleWorkspaceAdministrator {
						continue
					}
					role := role
					t.Run("administrator-only-"+role.String(), func(t *testing.T) {
						roleFixture := newSecurityFixtureForRole(t, role)
						denied := securityRequest(t, roleFixture.memberHandler, route, roleFixture, securityBearerCanary)
						assertSecurityResponse(t, denied, http.StatusForbidden, "authorization-denied")
						assertNoFixtureCanary(t, denied, roleFixture)
					})
				}
			}

			results = append(results, securityRouteResult{
				OperationID: route.operationID, Method: route.method, PathTemplate: route.pathTemplate,
				MemberStatus: route.memberStatus, MemberOutcome: route.memberOutcome,
				OutsiderStatus: route.outsiderStatus, OutsiderOutcome: route.outsiderOutcome,
				MissingCredentialStatus: missing.Code, InvalidCredentialStatus: invalid.Code,
			})
		})
	}

	writeOrCompareSecurityMatrix(t, results)
}

func publicSecurityRoutes() []securityRoute {
	workspaceTarget := func(fixture securityFixture) string {
		return "/api/v1alpha1/workspaces/" + fixture.workspaceID.String()
	}
	mutationHeaders := func(fixture securityFixture) map[string]string {
		return map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": "security-route-mutation-0001",
			"If-Match":        `"` + fixture.resourceVersion + `"`,
		}
	}
	return []securityRoute{
		{
			operationID: "listWorkspaces", method: http.MethodGet,
			pathTemplate: "/api/v1alpha1/workspaces",
			target:       func(securityFixture) string { return "/api/v1alpha1/workspaces?pageSize=1" },
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusOK, outsiderOutcome: "denied-rows-filtered-before-pagination",
			assertMemberBody: func(t *testing.T, fixture securityFixture, response *httptest.ResponseRecorder) {
				assertWorkspacePage(t, response, fixture.workspaceID, securityOutsiderCanary)
			},
			assertOutsiderBody: func(t *testing.T, fixture securityFixture, response *httptest.ResponseRecorder) {
				assertWorkspacePage(t, response, fixture.outsiderWorkspaceID, securityResourceCanary)
				assertNoFixtureCanary(t, response, fixture)
			},
		},
		{
			operationID: "createWorkspace", method: http.MethodPost,
			pathTemplate: "/api/v1alpha1/workspaces",
			target:       func(securityFixture) string { return "/api/v1alpha1/workspaces" },
			body:         func(securityFixture) []byte { return validWorkspaceBody("reserved") },
			headers: func(securityFixture) map[string]string {
				return map[string]string{
					"Content-Type":    "application/json",
					"Idempotency-Key": "security-route-create-0001",
				}
			},
			memberStatus: http.StatusForbidden, memberOutcome: "service-reserved-deny", memberProblemCode: "authorization-denied",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "service-reserved-deny", outsiderProblemCode: "authorization-denied",
			allRolesDenied: true,
		},
		{
			operationID: "getWorkspace", method: http.MethodGet,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
			assertMemberBody: func(t *testing.T, fixture securityFixture, response *httptest.ResponseRecorder) {
				assertWorkspaceObject(t, response, fixture.workspaceID)
				assertNoResponseCanary(t, response, fixture.outsiderWorkspaceID.String(), securityOutsiderCanary)
			},
		},
		{
			operationID: "replaceWorkspace", method: http.MethodPut,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			body:         func(securityFixture) []byte { return validWorkspaceBody("replacement") },
			headers:      mutationHeaders,
			memberStatus: http.StatusAccepted, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
			workspaceAdminOnly: true,
			staleOutsiderCheck: true,
		},
		{
			operationID: "deleteWorkspace", method: http.MethodDelete,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			headers:      mutationHeaders,
			memberStatus: http.StatusConflict, memberOutcome: "authorization-allowed-lifecycle-denied", memberProblemCode: "lifecycle-conflict",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
			workspaceAdminOnly: true,
			staleOutsiderCheck: true,
		},
		{
			operationID: "replaceWorkspaceStatus", method: http.MethodPut,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}/status",
			target:       func(fixture securityFixture) string { return workspaceTarget(fixture) + "/status" },
			body: func(securityFixture) []byte {
				return []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":1,"conditions":[]}}`)
			},
			headers:      mutationHeaders,
			memberStatus: http.StatusForbidden, memberOutcome: "service-reserved-deny", memberProblemCode: "authorization-denied",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "service-reserved-deny", outsiderProblemCode: "authorization-denied",
			allRolesDenied: true,
		},
		{
			operationID: "getOperation", method: http.MethodGet,
			pathTemplate: "/api/v1alpha1/operations/{operationId}",
			target: func(fixture securityFixture) string {
				return "/api/v1alpha1/operations/" + fixture.operationID.String()
			},
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
			assertMemberBody: func(t *testing.T, fixture securityFixture, response *httptest.ResponseRecorder) {
				assertOperationObject(t, response, fixture.operationID, fixture.workspaceID, fixture.workspaceID)
			},
		},
	}
}

func newSecurityFixture(t testing.TB) securityFixture {
	return newSecurityFixtureForRole(t, authorization.RoleWorkspaceAdministrator)
}

func newSecurityFixtureForRole(t testing.TB, memberRole authorization.Role) securityFixture {
	t.Helper()
	if _, err := authorization.ParseRole(memberRole.String()); err != nil {
		t.Fatal(err)
	}
	member := securityPrincipal(t, securityIdentityCanary)
	outsider := securityPrincipal(t, "security-outsider")
	service, err := reference.New(reference.Config{
		Store: memory.NewStore(), Clock: reference.ClockFunc(func() time.Time {
			return time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC)
		}),
		Issuer: &reference.SequentialIssuer{}, PageTokenKey: bytes.Repeat([]byte{0x28}, 32),
		MaximumPageTokens: 16, MaximumReplays: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: member, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "security:bootstrap:workspace", IdempotencyKey: "security-bootstrap-workspace-0001",
		Body: validWorkspaceBody(securityResourceCanary),
	})
	if err != nil {
		t.Fatal(err)
	}
	outsiderWorkspace, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: outsider, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "security:bootstrap:outsider-workspace", IdempotencyKey: "security-bootstrap-workspace-0002",
		Body: validWorkspaceBody(securityOutsiderCanary),
	})
	if err != nil {
		t.Fatal(err)
	}
	memberDirectory, memberPolicy := createSecurityPolicy(
		t, service, member, workspace.ResourceID, resource.ID(securityMemberCanary),
		memberRole, securityPolicyCanary, "security:bootstrap:policy", "security-bootstrap-policy-0001",
	)
	outsiderDirectory, _ := createSecurityPolicy(
		t, service, outsider, outsiderWorkspace.ResourceID, resource.ID("mem_security_matrix_0002"),
		authorization.RoleWorkspaceAdministrator, "security outsider policy",
		"security:bootstrap:outsider-policy", "security-bootstrap-policy-0002",
	)
	runtime, err := referenceauthorization.New(referenceauthorization.Config{
		Reference:         service,
		MemberDirectories: []authorization.MemberDirectory{memberDirectory, outsiderDirectory},
		MaximumAdmissions: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberHandler, err := httptransport.NewReferenceHandler(runtime, securityAccess{principal: member})
	if err != nil {
		t.Fatal(err)
	}
	outsiderHandler, err := httptransport.NewReferenceHandler(runtime, securityAccess{principal: outsider})
	if err != nil {
		t.Fatal(err)
	}
	return securityFixture{
		memberHandler: memberHandler, outsiderHandler: outsiderHandler,
		workspaceID: workspace.ResourceID, outsiderWorkspaceID: outsiderWorkspace.ResourceID,
		resourceVersion: workspace.ResourceVersion, operationID: workspace.OperationID,
		policyID: memberPolicy.ResourceID, memberID: resource.ID(securityMemberCanary),
	}
}

func createSecurityPolicy(
	t testing.TB,
	service *reference.Service,
	principal identity.Principal,
	workspaceID resource.ID,
	memberID resource.ID,
	role authorization.Role,
	displayName, canonicalTarget, idempotencyKey string,
) (authorization.MemberDirectory, reference.MutationReceipt) {
	t.Helper()
	record, err := authorization.NewMemberRecord(authorization.MemberInput{
		ID: memberID, WorkspaceID: workspaceID, Kind: principal.Kind(),
		LogicalIdentity: principal.LogicalIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := authorization.NewMemberDirectory(
		workspaceID,
		[]authorization.MemberRecord{record},
	)
	if err != nil {
		t.Fatal(err)
	}
	parentID := workspaceID
	policyBody, err := json.Marshal(map[string]any{
		"apiVersion": "v1alpha1",
		"kind":       "Policy",
		"metadata":   map[string]any{"displayName": displayName},
		"spec": map[string]any{"bindings": []any{map[string]any{
			"memberId": memberID.String(), "role": role.String(),
			"scope": map[string]any{"kind": "Workspace"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindPolicy, WorkspaceID: workspaceID, ParentID: &parentID,
		CanonicalTarget: canonicalTarget, IdempotencyKey: idempotencyKey,
		Body: policyBody, Members: directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	return directory, receipt
}

func securityPrincipal(t testing.TB, subject string) identity.Principal {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://security.example", Subject: subject,
		Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return principal
}

func securityRequest(
	t testing.TB,
	handler http.Handler,
	route securityRoute,
	fixture securityFixture,
	token string,
) *httptest.ResponseRecorder {
	t.Helper()
	return securityRequestWithHeaderOverrides(t, handler, route, fixture, token, nil)
}

func securityRequestWithHeaderOverrides(
	t testing.TB,
	handler http.Handler,
	route securityRoute,
	fixture securityFixture,
	token string,
	overrides map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if route.body != nil {
		body = route.body(fixture)
	}
	request := httptest.NewRequest(route.method, route.target(fixture), bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if route.headers != nil {
		for name, value := range route.headers(fixture) {
			request.Header.Set(name, value)
		}
	}
	for name, value := range overrides {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertSecurityResponse(
	t testing.TB,
	response *httptest.ResponseRecorder,
	status int,
	problemCode string,
) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("response status = %d, want %d; body=%s", response.Code, status, response.Body.String())
	}
	requestIDs := response.Header().Values("Veer-Request-Id")
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		len(requestIDs) != 1 || requestIDs[0] == "" {
		t.Fatalf("security headers = %#v", response.Header())
	}
	if !json.Valid(response.Body.Bytes()) {
		t.Fatalf("response is not JSON: %q", response.Body.Bytes())
	}
	if problemCode != "" {
		problem := assertSecurityProblemContract(t, response)
		if problem.Code != problemCode {
			t.Fatalf("problem code = %q, want %q; body=%s", problem.Code, problemCode, response.Body.String())
		}
	} else if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", response.Header().Get("Content-Type"))
	}
	assertNoBearerCanary(t, response)
}

func assertNoBearerCanary(t testing.TB, response *httptest.ResponseRecorder) {
	t.Helper()
	assertNoResponseCanary(t, response, securityBearerCanary, invalidBearerCanary)
}

func assertNoFixtureCanary(t testing.TB, response *httptest.ResponseRecorder, fixture securityFixture) {
	t.Helper()
	outputs := []string{response.Body.String()}
	problemResponse := response.Header().Get("Content-Type") == "application/problem+json"
	if problemResponse {
		if err := validateUniqueJSONMembers(response.Body.Bytes()); err != nil {
			t.Fatalf("validate problem for confidentiality scan: %v; body=%s", err, response.Body.String())
		}
		decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
		decoder.DisallowUnknownFields()
		var problem securityProblem
		if err := decoder.Decode(&problem); err != nil {
			t.Fatalf("decode problem for confidentiality scan: %v; body=%s", err, response.Body.String())
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			t.Fatalf("problem has trailing JSON during confidentiality scan: %v; body=%s", err, response.Body.String())
		}
		requestIDs := response.Header().Values("Veer-Request-Id")
		if len(requestIDs) != 1 || problem.RequestID != requestIDs[0] ||
			problem.Instance != "urn:veer:request:"+problem.RequestID {
			t.Fatalf("problem correlation fields are not uniquely bound: body=%s headers=%#v", response.Body.String(), response.Header())
		}
		problem.RequestID = ""
		problem.Instance = ""
		encoded, err := json.Marshal(problem)
		if err != nil {
			t.Fatalf("encode problem for confidentiality scan: %v", err)
		}
		outputs[0] = string(encoded)
	}
	for name, values := range response.Header() {
		if problemResponse && strings.EqualFold(name, "Veer-Request-Id") {
			continue
		}
		outputs = append(outputs, values...)
	}
	assertOutputsDoNotContainCanaries(
		t,
		outputs,
		securityResourceCanary,
		securityPolicyCanary,
		securityMemberCanary,
		securityIdentityCanary,
		securityStaleVersionCanary,
		fixture.workspaceID.String(),
		fixture.resourceVersion,
		fixture.operationID.String(),
		fixture.policyID.String(),
		fixture.memberID.String(),
	)
}

func assertNoResponseCanary(t testing.TB, response *httptest.ResponseRecorder, canaries ...string) {
	t.Helper()
	outputs := []string{response.Body.String()}
	for _, values := range response.Header() {
		outputs = append(outputs, values...)
	}
	assertOutputsDoNotContainCanaries(t, outputs, canaries...)
}

func assertOutputsDoNotContainCanaries(t testing.TB, outputs []string, canaries ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, canary := range canaries {
			if canary != "" && strings.Contains(output, canary) {
				t.Fatalf("response disclosed confidentiality canary %q in %q", canary, output)
			}
		}
	}
}

func assertAuthenticationDenial(t testing.TB, response *httptest.ResponseRecorder, challenge string) {
	t.Helper()
	assertSecurityResponse(t, response, http.StatusUnauthorized, "authentication-required")
	assertSecurityAuthenticationChallenge(t, response, challenge)
}

func assertSecurityAuthenticationChallenge(
	t testing.TB,
	response *httptest.ResponseRecorder,
	want string,
) {
	t.Helper()
	challenges := response.Header().Values("WWW-Authenticate")
	if len(challenges) != 1 {
		t.Fatalf("WWW-Authenticate values = %q, want exactly one", challenges)
	}
	if want != "" && challenges[0] != want {
		t.Fatalf("WWW-Authenticate = %q, want %q", challenges[0], want)
	}
	if want == "" {
		switch challenges[0] {
		case `Bearer realm="veer"`,
			`Bearer realm="veer", error="invalid_request"`,
			`Bearer realm="veer", error="invalid_token"`:
		default:
			t.Fatalf("WWW-Authenticate = %q, want a canonical bearer challenge", challenges[0])
		}
	}
}

func assertWorkspacePage(
	t testing.TB,
	response *httptest.ResponseRecorder,
	wantID resource.ID,
	forbiddenCanary string,
) {
	t.Helper()
	var page struct {
		Items []struct {
			Metadata struct {
				ID string `json:"id"`
			} `json:"metadata"`
		} `json:"items"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode workspace page: %v; body=%s", err, response.Body.String())
	}
	var firstID string
	if len(page.Items) > 0 {
		firstID = page.Items[0].Metadata.ID
	}
	if len(page.Items) != 1 || firstID != wantID.String() || page.NextPageToken != "" {
		t.Fatalf(
			"workspace page = items:%d id:%q next:%q, want 1/%q/empty; body=%s",
			len(page.Items), firstID, page.NextPageToken, wantID, response.Body.String(),
		)
	}
	assertNoResponseCanary(t, response, forbiddenCanary)
}

func assertWorkspaceObject(t testing.TB, response *httptest.ResponseRecorder, wantID resource.ID) {
	t.Helper()
	var workspace struct {
		Metadata struct {
			ID string `json:"id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &workspace); err != nil {
		t.Fatalf("decode workspace: %v; body=%s", err, response.Body.String())
	}
	if workspace.Metadata.ID != wantID.String() {
		t.Fatalf("workspace ID = %q, want %q; body=%s", workspace.Metadata.ID, wantID, response.Body.String())
	}
}

func assertOperationObject(
	t testing.TB,
	response *httptest.ResponseRecorder,
	wantID, wantWorkspaceID, wantResourceID resource.ID,
) {
	t.Helper()
	var operation struct {
		ID          string `json:"id"`
		WorkspaceID string `json:"workspaceId"`
		ResourceID  string `json:"resourceId"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatalf("decode operation: %v; body=%s", err, response.Body.String())
	}
	if operation.ID != wantID.String() || operation.WorkspaceID != wantWorkspaceID.String() ||
		operation.ResourceID != wantResourceID.String() {
		t.Fatalf(
			"operation identity = id:%q workspace:%q resource:%q, want %q/%q/%q; body=%s",
			operation.ID, operation.WorkspaceID, operation.ResourceID,
			wantID, wantWorkspaceID, wantResourceID, response.Body.String(),
		)
	}
}

func assertSecurityProblemContract(t testing.TB, response *httptest.ResponseRecorder) securityProblem {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", response.Header().Get("Content-Type"))
	}
	if response.Body.Len() == 0 || response.Body.Len() > maximumSecurityProblemBytes {
		t.Fatalf("problem body bytes = %d, want 1..%d", response.Body.Len(), maximumSecurityProblemBytes)
	}
	if err := validateUniqueJSONMembers(response.Body.Bytes()); err != nil {
		t.Fatalf("runtime problem JSON members: %v; body=%s", err, response.Body.String())
	}
	if err := validateSecurityProblemMembers(response.Body.Bytes()); err != nil {
		t.Fatalf("runtime problem required members: %v; body=%s", err, response.Body.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	decoder.DisallowUnknownFields()
	var problem securityProblem
	if err := decoder.Decode(&problem); err != nil {
		t.Fatalf("decode runtime problem: %v; body=%s", err, response.Body.String())
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("runtime problem has trailing JSON: %v; body=%s", err, response.Body.String())
	}
	want, codeKnown := securityProblemExpectations[problem.Code]
	if !codeKnown || want.status != response.Code || problem.Status != response.Code {
		t.Fatalf(
			"runtime problem code/status = %q/%d/%d, want a closed code for HTTP %d",
			problem.Code, problem.Status, want.status, response.Code,
		)
	}
	if problem.Title != want.title {
		t.Fatalf("runtime problem title = %q, want %q for code %q", problem.Title, want.title, problem.Code)
	}
	requestIDs := response.Header().Values("Veer-Request-Id")
	if len(requestIDs) != 1 {
		t.Fatalf("Veer-Request-Id values = %q, want exactly one", requestIDs)
	}
	requestID := requestIDs[0]
	if !securityRequestIDPattern.MatchString(problem.RequestID) || problem.RequestID != requestID ||
		problem.Instance != "urn:veer:request:"+problem.RequestID ||
		problem.Type != "urn:veer:problem:"+problem.Code {
		t.Fatalf(
			"runtime problem identity = type:%q instance:%q request:%q header:%q",
			problem.Type, problem.Instance, problem.RequestID, requestID,
		)
	}
	if len(problem.Type) > 81 || !safeSecurityProblemText(problem.Title, 64, true) ||
		!safeSecurityProblemText(problem.Detail, 192, false) || len(problem.Instance) > 81 ||
		len(problem.Code) > 64 || !securityProblemCodePattern.MatchString(problem.Code) {
		t.Fatalf("runtime problem primitive bounds failed: %#v", problem)
	}
	if len(problem.Errors) > 1 {
		t.Fatalf("runtime problem errors = %d, want at most 1", len(problem.Errors))
	}
	for _, violation := range problem.Errors {
		if len(violation.Field) == 0 || len(violation.Field) > maximumSecurityFieldPathSize ||
			!securityFieldPathPattern.MatchString(violation.Field) ||
			len(violation.Code) == 0 || len(violation.Code) > 32 ||
			!securityProblemCodePattern.MatchString(violation.Code) ||
			!safeSecurityProblemText(violation.Message, 96, false) {
			t.Fatalf("runtime field violation bounds failed: %#v", violation)
		}
	}
	if err := validateSecurityRetryAfter(want, problem, response.Header().Values("Retry-After")); err != nil {
		t.Fatalf("runtime retry metadata: %v", err)
	}
	return problem
}

func validateSecurityRetryAfter(
	want securityProblemExpectation,
	problem securityProblem,
	headers []string,
) error {
	if !want.requiresRetryAfter {
		if problem.RetryAfterSeconds != nil || len(headers) != 0 {
			return errors.New("non-retryable problem declared retry metadata")
		}
		return nil
	}
	if problem.RetryAfterSeconds == nil || *problem.RetryAfterSeconds < 1 || *problem.RetryAfterSeconds > 86_400 {
		return errors.New("retryable problem requires retryAfterSeconds in 1..86400")
	}
	if len(headers) != 1 || headers[0] != strconv.Itoa(*problem.RetryAfterSeconds) {
		return fmt.Errorf("Retry-After values %q do not match retryAfterSeconds %d", headers, *problem.RetryAfterSeconds)
	}
	return nil
}

func validateSecurityProblemMembers(data []byte) error {
	var problem map[string]json.RawMessage
	if err := json.Unmarshal(data, &problem); err != nil {
		return err
	}
	if err := requireNonNullJSONMembers(
		problem,
		[]string{"type", "title", "status", "instance", "code", "requestId"},
	); err != nil {
		return err
	}
	for _, optional := range []string{"detail", "errors", "retryAfterSeconds"} {
		if raw, exists := problem[optional]; exists && isJSONNull(raw) {
			return fmt.Errorf("problem member %q is null", optional)
		}
	}
	rawErrors, exists := problem["errors"]
	if !exists {
		return nil
	}
	var violations []map[string]json.RawMessage
	if err := json.Unmarshal(rawErrors, &violations); err != nil {
		return fmt.Errorf("decode problem errors: %w", err)
	}
	for index, violation := range violations {
		if err := requireNonNullJSONMembers(violation, []string{"field", "code", "message"}); err != nil {
			return fmt.Errorf("problem errors[%d]: %w", index, err)
		}
	}
	return nil
}

func requireNonNullJSONMembers(object map[string]json.RawMessage, names []string) error {
	for _, name := range names {
		raw, exists := object[name]
		if !exists {
			return fmt.Errorf("required member %q is missing", name)
		}
		if isJSONNull(raw) {
			return fmt.Errorf("required member %q is null", name)
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateUniqueJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanUniqueJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON has a trailing value")
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object member name is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func safeSecurityProblemText(value string, maximum int, required bool) bool {
	if len(value) > maximum || required && value == "" {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character < 0x20 || character > 0x7e || strings.ContainsRune(`"&<>\`, rune(character)) {
			return false
		}
	}
	return true
}

func assertOpenAPIRouteCoverage(t *testing.T, routes []securityRoute) {
	t.Helper()
	data, err := openapi.Load(filepath.Join(repositoryRoot(t), "api/openapi/veer-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := openapi.Validate(data); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var got []string
	for path, item := range document.Paths {
		for method, raw := range item {
			if !isHTTPMethod(method) {
				continue
			}
			var operation struct {
				OperationID string `json:"operationId"`
			}
			if err := json.Unmarshal(raw, &operation); err != nil || operation.OperationID == "" {
				t.Fatalf("decode %s %s operation: %v", method, path, err)
			}
			got = append(got, operation.OperationID+"\t"+strings.ToUpper(method)+"\t"+path)
		}
	}
	want := make([]string, len(routes))
	for index, route := range routes {
		want[index] = route.operationID + "\t" + route.method + "\t" + route.pathTemplate
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("public route security coverage drifted:\n got %q\nwant %q", got, want)
	}
}

func isHTTPMethod(value string) bool {
	switch strings.ToUpper(value) {
	case http.MethodConnect, http.MethodDelete, http.MethodGet, http.MethodHead,
		http.MethodOptions, http.MethodPatch, http.MethodPost, http.MethodPut, http.MethodTrace:
		return true
	default:
		return false
	}
}

func writeOrCompareSecurityMatrix(t *testing.T, results []securityRouteResult) {
	t.Helper()
	root := repositoryRoot(t)
	artifact := "api/openapi/veer-v1alpha1.json"
	data, err := openapi.Load(filepath.Join(root, artifact))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	report := securityMatrixReport{
		Contract: "veer-security-regression-v1alpha1", OpenAPIArtifact: artifact,
		OpenAPISHA256: hex.EncodeToString(digest[:]), OpenAPIValidated: true, Routes: results,
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join(root, "test/security/testdata/security-regression-v1alpha1.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if t.Failed() {
			t.Log("skipping security matrix update after a failed route observation")
			return
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read security matrix: %v\ngenerated:\n%s", err, got)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("security matrix drifted:\n generated:\n%s\nchecked in:\n%s", got, want)
	}
}

func validWorkspaceBody(name string) []byte {
	encoded, err := json.Marshal(map[string]any{
		"apiVersion": "v1alpha1",
		"kind":       "Workspace",
		"metadata":   map[string]any{"displayName": name},
		"spec":       map[string]any{},
	})
	if err != nil {
		panic(err)
	}
	return encoded
}

func repositoryRoot(t testing.TB) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		contents, readErr := os.ReadFile(filepath.Join(directory, "go.mod"))
		if readErr == nil && bytes.Contains(contents, []byte("module github.com/ArdurAI/veer\n")) {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal(errors.New("repository root containing canonical go.mod was not found"))
		}
		directory = parent
	}
}
