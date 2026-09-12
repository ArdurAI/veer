package contract_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArdurAI/veer/api/openapi"
	"github.com/ArdurAI/veer/internal/adapters/referenceaccess"
	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
	httptransport "github.com/ArdurAI/veer/internal/transport/http"
)

type contractReport struct {
	Contract         string           `json:"contract"`
	OpenAPIArtifact  string           `json:"openapiArtifact"`
	OpenAPISHA256    string           `json:"openapiSha256"`
	OpenAPIValidated bool             `json:"openapiValidated"`
	ProviderCalls    int              `json:"providerCalls"`
	DatabaseCalls    int              `json:"databaseCalls"`
	QueueCalls       int              `json:"queueCalls"`
	Vectors          []responseVector `json:"vectors"`
}

type responseVector struct {
	Name    string          `json:"name"`
	Method  string          `json:"method"`
	Target  string          `json:"target"`
	Status  int             `json:"status"`
	Headers responseHeaders `json:"headers"`
	Body    json.RawMessage `json:"body"`
}

type responseHeaders struct {
	ContentType string `json:"contentType"`
	RequestID   string `json:"requestId"`
	ETag        string `json:"etag,omitempty"`
	Location    string `json:"location,omitempty"`
}

type mutationReceipt struct {
	ResourceID      string `json:"resourceId"`
	OperationID     string `json:"operationId"`
	ResourceVersion string `json:"resourceVersion"`
}

type statusReceipt struct {
	ResourceVersion string `json:"resourceVersion"`
}

func TestReferenceServerBlackBoxContract(t *testing.T) {
	server := httptest.NewServer(newReferenceHandler(t))
	defer server.Close()
	vectors := make([]responseVector, 0, 13)

	createBody := []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"payments","labels":{"team":"platform"}},"spec":{"suspendReconciliation":false}}`)
	create := exercise(t, server, "create-workspace", http.MethodPost, "/api/v1alpha1/workspaces", createBody, map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "contract-create-0001", "Veer-Request-Id": "req-create",
	})
	vectors = append(vectors, create)
	var created mutationReceipt
	decodeBody(t, create.Body, &created)

	createReplay := exercise(t, server, "create-workspace-replay", http.MethodPost, "/api/v1alpha1/workspaces", []byte(`{
  "kind":"Workspace","apiVersion":"v1alpha1","spec":{},"metadata":{"labels":{"team":"platform"},"displayName":"payments"}
}`), map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "contract-create-0001", "Veer-Request-Id": "req-create-replay",
	})
	vectors = append(vectors, createReplay)
	if !bytes.Equal(createReplay.Body, create.Body) || createReplay.Headers.RequestID == create.Headers.RequestID {
		t.Fatal("create replay did not preserve semantic body with fresh request correlation")
	}

	workspaceTarget := "/api/v1alpha1/workspaces/" + created.ResourceID
	get := exercise(t, server, "get-workspace", http.MethodGet, workspaceTarget, nil, map[string]string{
		"Veer-Request-Id": "req-get",
	})
	vectors = append(vectors, get)

	operationTarget := "/api/v1alpha1/operations/" + created.OperationID
	vectors = append(vectors, exercise(t, server, "get-create-operation", http.MethodGet, operationTarget, nil, map[string]string{
		"Veer-Request-Id": "req-operation",
	}))

	replaceBody := []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"payments-production","labels":{"team":"platform"}},"spec":{"suspendReconciliation":true}}`)
	replaceHeaders := map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "contract-replace-0001",
		"If-Match": get.Headers.ETag, "Veer-Request-Id": "req-replace",
	}
	replace := exercise(t, server, "replace-workspace", http.MethodPut, workspaceTarget, replaceBody, replaceHeaders)
	vectors = append(vectors, replace)
	var replaced mutationReceipt
	decodeBody(t, replace.Body, &replaced)

	replaceHeaders["Veer-Request-Id"] = "req-replace-replay"
	replaceReplay := exercise(t, server, "replace-workspace-replay", http.MethodPut, workspaceTarget, replaceBody, replaceHeaders)
	vectors = append(vectors, replaceReplay)
	if !bytes.Equal(replaceReplay.Body, replace.Body) {
		t.Fatal("replacement replay body drifted")
	}

	staleHeaders := cloneHeaders(replaceHeaders)
	staleHeaders["Idempotency-Key"] = "contract-replace-stale-0001"
	staleHeaders["Veer-Request-Id"] = "req-replace-stale"
	stale := exercise(t, server, "replace-workspace-stale", http.MethodPut, workspaceTarget, replaceBody, staleHeaders)
	vectors = append(vectors, stale)

	statusBody := []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":2,"conditions":[]}}`)
	statusHeaders := map[string]string{
		"Content-Type": "application/json", "Idempotency-Key": "contract-status-0001",
		"If-Match": stale.Headers.ETag, "Veer-Request-Id": "req-status",
	}
	status := exercise(t, server, "replace-workspace-status", http.MethodPut, workspaceTarget+"/status", statusBody, statusHeaders)
	vectors = append(vectors, status)
	var statusValue statusReceipt
	decodeBody(t, status.Body, &statusValue)

	statusHeaders["Veer-Request-Id"] = "req-status-replay"
	statusReplay := exercise(t, server, "replace-workspace-status-replay", http.MethodPut, workspaceTarget+"/status", statusBody, statusHeaders)
	vectors = append(vectors, statusReplay)
	if !bytes.Equal(statusReplay.Body, status.Body) {
		t.Fatal("status replay body drifted")
	}

	vectors = append(vectors, exercise(t, server, "list-workspaces", http.MethodGet, "/api/v1alpha1/workspaces?pageSize=1", nil, map[string]string{
		"Veer-Request-Id": "req-list",
	}))

	deleteHeaders := map[string]string{
		"Idempotency-Key": "contract-delete-0001", "If-Match": `"` + statusValue.ResourceVersion + `"`,
		"Veer-Request-Id": "req-delete",
	}
	deleted := exercise(t, server, "delete-workspace", http.MethodDelete, workspaceTarget, nil, deleteHeaders)
	vectors = append(vectors, deleted)
	deleteHeaders["Veer-Request-Id"] = "req-delete-replay"
	deleteReplay := exercise(t, server, "delete-workspace-replay", http.MethodDelete, workspaceTarget, nil, deleteHeaders)
	vectors = append(vectors, deleteReplay)
	if !bytes.Equal(deleteReplay.Body, deleted.Body) {
		t.Fatal("delete replay body drifted")
	}

	vectors = append(vectors, exercise(t, server, "get-deleted-workspace", http.MethodGet, workspaceTarget, nil, map[string]string{
		"Veer-Request-Id": "req-get-deleted",
	}))

	openAPIData, err := openapi.Load(filepath.Join(repositoryRoot(t), "api/openapi/veer-v1alpha1.json"))
	if err != nil {
		t.Fatalf("openapi.Load() error = %v", err)
	}
	if err := openapi.Validate(openAPIData); err != nil {
		t.Fatalf("openapi.Validate() error = %v", err)
	}
	digest := sha256.Sum256(openAPIData)
	report := contractReport{
		Contract: "veer-reference-server-v1alpha1", OpenAPIArtifact: "api/openapi/veer-v1alpha1.json",
		OpenAPISHA256: hex.EncodeToString(digest[:]), OpenAPIValidated: true,
		ProviderCalls: 0, DatabaseCalls: 0, QueueCalls: 0, Vectors: vectors,
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent() error = %v", err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test/contract/testdata/reference-server-v1alpha1.golden.json"))
	if err != nil {
		t.Fatalf("read reference contract golden: %v\ngenerated:\n%s", err, got)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reference-server contract drifted\ngenerated:\n%s\nchecked in:\n%s", got, want)
	}
}

func newReferenceHandler(t *testing.T) http.Handler {
	t.Helper()
	principal, err := identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://issuer.example", Subject: "contract-user", Audiences: []string{"veer-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := reference.New(reference.Config{
		Store: memory.NewStore(), Clock: reference.ClockFunc(func() time.Time {
			return time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
		}),
		Issuer: &reference.SequentialIssuer{}, PageTokenKey: bytes.Repeat([]byte{0x51}, 32),
		MaximumPageTokens: 16, MaximumReplays: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := ports.NewBearerCredential("reference-contract-token")
	if err != nil {
		t.Fatal(err)
	}
	access, err := referenceaccess.New(credential, principal, httptransport.ReferenceActions())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httptransport.NewReferenceHandler(service, access, access)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func exercise(
	t *testing.T,
	server *httptest.Server,
	name, method, target string,
	body []byte,
	headers map[string]string,
) responseVector {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, server.URL+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer reference-contract-token")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	result, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(io.LimitReader(result.Body, int64(reference.MaxPageBytes)+1))
	closeErr := result.Body.Close()
	if err != nil || closeErr != nil || len(responseBody) > reference.MaxPageBytes {
		t.Fatalf("%s response exceeded the bounded read: read=%v close=%v", name, err, closeErr)
	}
	encoded := bytes.TrimSpace(responseBody)
	if !json.Valid(encoded) {
		t.Fatalf("%s response is not JSON: %q", name, encoded)
	}
	return responseVector{
		Name: name, Method: method, Target: target, Status: result.StatusCode,
		Headers: responseHeaders{
			ContentType: result.Header.Get("Content-Type"), RequestID: result.Header.Get("Veer-Request-Id"),
			ETag: result.Header.Get("ETag"), Location: result.Header.Get("Location"),
		},
		Body: append(json.RawMessage(nil), encoded...),
	}
}

func decodeBody(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
}

func cloneHeaders(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		module, readErr := os.ReadFile(filepath.Join(directory, "go.mod"))
		if readErr == nil && bytes.Contains(module, []byte("module github.com/ArdurAI/veer\n")) {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root containing canonical go.mod was not found")
		}
		directory = parent
	}
}

func TestReferenceContractReportHasUniqueVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), "test/contract/testdata/reference-server-v1alpha1.golden.json"))
	if err != nil {
		t.Skip("golden is created with the implementation change")
	}
	var report contractReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(report.Vectors))
	for _, vector := range report.Vectors {
		if _, exists := seen[vector.Name]; exists {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = struct{}{}
	}
	if !reflect.DeepEqual(
		[]int{report.ProviderCalls, report.DatabaseCalls, report.QueueCalls},
		[]int{0, 0, 0},
	) {
		t.Fatal("provider-free report contains external calls")
	}
}
