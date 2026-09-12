package security_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	securityBearerCanary = "security-route-bearer-canary"
	invalidBearerCanary  = "invalid-security-route-bearer-canary"
)

type securityRoute struct {
	operationID        string
	method             string
	pathTemplate       string
	target             func(securityFixture) string
	body               func(securityFixture) []byte
	headers            func(securityFixture) map[string]string
	memberStatus       int
	memberOutcome      string
	outsiderStatus     int
	outsiderOutcome    string
	assertMemberBody   func(*testing.T, *httptest.ResponseRecorder)
	assertOutsiderBody func(*testing.T, *httptest.ResponseRecorder)
}

type securityFixture struct {
	memberHandler   http.Handler
	outsiderHandler http.Handler
	workspaceID     resource.ID
	resourceVersion string
	operationID     resource.ID
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

func TestPublicRouteSecurityMatrix(t *testing.T) {
	routes := publicSecurityRoutes()
	assertOpenAPIRouteCoverage(t, routes)
	results := make([]securityRouteResult, 0, len(routes))

	for _, route := range routes {
		route := route
		t.Run(route.operationID, func(t *testing.T) {
			fixture := newSecurityFixture(t)
			member := securityRequest(t, fixture.memberHandler, route, fixture, securityBearerCanary)
			assertSecurityResponse(t, member, route.memberStatus)
			if route.assertMemberBody != nil {
				route.assertMemberBody(t, member)
			}

			fixture = newSecurityFixture(t)
			outsider := securityRequest(t, fixture.outsiderHandler, route, fixture, securityBearerCanary)
			assertSecurityResponse(t, outsider, route.outsiderStatus)
			if route.assertOutsiderBody != nil {
				route.assertOutsiderBody(t, outsider)
			}

			fixture = newSecurityFixture(t)
			missing := securityRequest(t, fixture.memberHandler, route, fixture, "")
			assertAuthenticationDenial(t, missing, `Bearer realm="veer"`)

			fixture = newSecurityFixture(t)
			invalid := securityRequest(t, fixture.memberHandler, route, fixture, invalidBearerCanary)
			assertAuthenticationDenial(t, invalid, `Bearer realm="veer", error="invalid_token"`)

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
			target:       func(securityFixture) string { return "/api/v1alpha1/workspaces" },
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusOK, outsiderOutcome: "denied-by-row-filter",
			assertMemberBody: func(t *testing.T, response *httptest.ResponseRecorder) {
				assertWorkspacePageLength(t, response, 1)
			},
			assertOutsiderBody: func(t *testing.T, response *httptest.ResponseRecorder) {
				assertWorkspacePageLength(t, response, 0)
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
			memberStatus: http.StatusForbidden, memberOutcome: "service-reserved-deny",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "service-reserved-deny",
		},
		{
			operationID: "getWorkspace", method: http.MethodGet,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied",
		},
		{
			operationID: "replaceWorkspace", method: http.MethodPut,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			body:         func(securityFixture) []byte { return validWorkspaceBody("replacement") },
			headers:      mutationHeaders,
			memberStatus: http.StatusAccepted, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied",
		},
		{
			operationID: "deleteWorkspace", method: http.MethodDelete,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}", target: workspaceTarget,
			headers:      mutationHeaders,
			memberStatus: http.StatusConflict, memberOutcome: "authorization-allowed-lifecycle-denied",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied",
		},
		{
			operationID: "replaceWorkspaceStatus", method: http.MethodPut,
			pathTemplate: "/api/v1alpha1/workspaces/{workspaceId}/status",
			target:       func(fixture securityFixture) string { return workspaceTarget(fixture) + "/status" },
			body: func(securityFixture) []byte {
				return []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":1,"conditions":[]}}`)
			},
			headers:      mutationHeaders,
			memberStatus: http.StatusForbidden, memberOutcome: "service-reserved-deny",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "service-reserved-deny",
		},
		{
			operationID: "getOperation", method: http.MethodGet,
			pathTemplate: "/api/v1alpha1/operations/{operationId}",
			target: func(fixture securityFixture) string {
				return "/api/v1alpha1/operations/" + fixture.operationID.String()
			},
			memberStatus: http.StatusOK, memberOutcome: "allowed",
			outsiderStatus: http.StatusForbidden, outsiderOutcome: "authorization-denied",
		},
	}
}

func newSecurityFixture(t testing.TB) securityFixture {
	t.Helper()
	member := securityPrincipal(t, "security-member")
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
		Body: validWorkspaceBody("security workspace"),
	})
	if err != nil {
		t.Fatal(err)
	}
	memberID := resource.ID("mem_security_matrix_0001")
	record, err := authorization.NewMemberRecord(authorization.MemberInput{
		ID: memberID, WorkspaceID: workspace.ResourceID, Kind: member.Kind(),
		LogicalIdentity: member.LogicalIdentity(),
	})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := authorization.NewMemberDirectory(
		workspace.ResourceID,
		[]authorization.MemberRecord{record},
	)
	if err != nil {
		t.Fatal(err)
	}
	parentID := workspace.ResourceID
	policyBody := []byte(`{"apiVersion":"v1alpha1","kind":"Policy","metadata":{"displayName":"security matrix administrator"},"spec":{"bindings":[{"memberId":"` + memberID.String() + `","role":"WorkspaceAdministrator","scope":{"kind":"Workspace"}}]}}`)
	if _, err := service.Create(context.Background(), reference.CreateCommand{
		Principal: member, Kind: hierarchy.KindPolicy, WorkspaceID: workspace.ResourceID, ParentID: &parentID,
		CanonicalTarget: "security:bootstrap:policy", IdempotencyKey: "security-bootstrap-policy-0001",
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
		workspaceID: workspace.ResourceID, resourceVersion: workspace.ResourceVersion,
		operationID: workspace.OperationID,
	}
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

func assertSecurityResponse(t testing.TB, response *httptest.ResponseRecorder, status int) {
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
	assertNoBearerCanary(t, response)
}

func assertNoBearerCanary(t testing.TB, response *httptest.ResponseRecorder) {
	t.Helper()
	outputs := []string{response.Body.String()}
	for _, values := range response.Header() {
		outputs = append(outputs, values...)
	}
	for _, output := range outputs {
		if strings.Contains(output, securityBearerCanary) || strings.Contains(output, invalidBearerCanary) {
			t.Fatalf("response disclosed a bearer canary: %q", output)
		}
	}
}

func assertAuthenticationDenial(t testing.TB, response *httptest.ResponseRecorder, challenge string) {
	t.Helper()
	assertSecurityResponse(t, response, http.StatusUnauthorized)
	if response.Header().Get("WWW-Authenticate") != challenge {
		t.Fatalf("WWW-Authenticate = %q, want %q", response.Header().Get("WWW-Authenticate"), challenge)
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != "authentication-required" {
		t.Fatalf("authentication problem = %q, %v", response.Body.Bytes(), err)
	}
}

func assertWorkspacePageLength(t testing.TB, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Items) != want {
		t.Fatalf("workspace page length = %d, want %d; error=%v body=%s", len(page.Items), want, err, response.Body.String())
	}
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
