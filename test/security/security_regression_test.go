package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
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
	securityBearerCanary         = "security-route-bearer-canary"
	invalidBearerCanary          = "invalid-security-route-bearer-canary"
	securityResourceCanary       = "security-resource-confidential-canary"
	securityPolicyCanary         = "security-policy-confidential-canary"
	securityMemberCanary         = "mem_security_confidential_0001"
	securityIdentityCanary       = "security-identity-confidential-canary"
	maximumSecurityProblemBytes  = 1_024
	maximumSecurityFieldPathSize = 96
)

var (
	securityProblemCodePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	securityRequestIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	securityFieldPathPattern   = regexp.MustCompile(`^(/([^~/]|~0|~1)*)+$`)
	securityProblemStatuses    = map[string]int{
		"validation-failed":       http.StatusBadRequest,
		"authentication-required": http.StatusUnauthorized,
		"authorization-denied":    http.StatusForbidden,
		"not-found":               http.StatusNotFound,
		"method-not-allowed":      http.StatusMethodNotAllowed,
		"idempotency-key-reused":  http.StatusConflict,
		"uniqueness-conflict":     http.StatusConflict,
		"lifecycle-conflict":      http.StatusConflict,
		"policy-conflict":         http.StatusConflict,
		"precondition-failed":     http.StatusPreconditionFailed,
		"request-too-large":       http.StatusRequestEntityTooLarge,
		"unsupported-media-type":  http.StatusUnsupportedMediaType,
		"precondition-required":   http.StatusPreconditionRequired,
		"rate-limited":            http.StatusTooManyRequests,
		"internal-failure":        http.StatusInternalServerError,
		"unavailable":             http.StatusServiceUnavailable,
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
	RetryAfterSeconds int                      `json:"retryAfterSeconds,omitempty"`
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
				assertWorkspacePage(t, response, fixture.workspaceID, "security outsider workspace")
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
		},
		{
			operationID: "replaceWorkspace", method: http.MethodPut,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			body:         func(securityFixture) []byte { return validWorkspaceBody("replacement") },
			headers:      mutationHeaders,
			memberStatus: http.StatusAccepted, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
		},
		{
			operationID: "deleteWorkspace", method: http.MethodDelete,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			headers:      mutationHeaders,
			memberStatus: http.StatusConflict, memberOutcome: "authorization-allowed-lifecycle-denied", memberProblemCode: "lifecycle-conflict",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied", outsiderProblemCode: "authorization-denied",
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
		Body: validWorkspaceBody("security outsider workspace"),
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
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("Veer-Request-Id") == "" {
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
	assertNoResponseCanary(
		t,
		response,
		securityResourceCanary,
		securityPolicyCanary,
		securityMemberCanary,
		securityIdentityCanary,
		fixture.workspaceID.String(),
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
	if response.Header().Get("WWW-Authenticate") != challenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", response.Header().Get("WWW-Authenticate"), challenge)
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
	if len(page.Items) != 1 || page.Items[0].Metadata.ID != wantID.String() || page.NextPageToken != "" {
		t.Fatalf(
			"workspace page = items:%d id:%q next:%q, want 1/%q/empty; body=%s",
			len(page.Items), page.Items[0].Metadata.ID, page.NextPageToken, wantID, response.Body.String(),
		)
	}
	assertNoResponseCanary(t, response, forbiddenCanary)
}

func assertSecurityProblemContract(t testing.TB, response *httptest.ResponseRecorder) securityProblem {
	t.Helper()
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", response.Header().Get("Content-Type"))
	}
	if response.Body.Len() == 0 || response.Body.Len() > maximumSecurityProblemBytes {
		t.Fatalf("problem body bytes = %d, want 1..%d", response.Body.Len(), maximumSecurityProblemBytes)
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
	wantStatus, codeKnown := securityProblemStatuses[problem.Code]
	if !codeKnown || wantStatus != response.Code || problem.Status != response.Code {
		t.Fatalf(
			"runtime problem code/status = %q/%d/%d, want a closed code for HTTP %d",
			problem.Code, problem.Status, wantStatus, response.Code,
		)
	}
	requestID := response.Header().Get("Veer-Request-Id")
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
	if problem.RetryAfterSeconds < 0 || problem.RetryAfterSeconds > 86_400 {
		t.Fatalf("runtime retryAfterSeconds = %d, want 0 or 1..86400", problem.RetryAfterSeconds)
	}
	return problem
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
