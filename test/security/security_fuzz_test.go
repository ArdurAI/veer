package security_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/service/reference"
)

const (
	fuzzWorkspaceTarget        = "/__security_fixture_workspace__"
	fuzzWorkspaceResourceMatch = "__security_fixture_resource_version__"
)

type securityFuzzSeed struct {
	method, target, authorization, contentType, idempotencyKey, ifMatch, requestID string
	body                                                                           []byte
	rejectionStatus                                                                int
}

func FuzzReferencePublicBoundary(f *testing.F) {
	seeds := []securityFuzzSeed{
		{http.MethodGet, "/api/v1alpha1/workspaces", "Bearer " + securityBearerCanary, "", "", "", "req-fuzz-list", nil, 0},
		{http.MethodGet, "/api/v1alpha1/workspaces?access_token=" + url.QueryEscape(invalidBearerCanary), "Bearer " + securityBearerCanary, "", "", "", "req-fuzz-query-token", nil, http.StatusUnauthorized},
		{http.MethodGet, "/api/v1alpha1/workspaces/%2e%2e", "Bearer " + securityBearerCanary, "", "", "", "req-fuzz-encoded-path", nil, http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-duplicate-0001", fuzzWorkspaceResourceMatch, "req-fuzz-duplicate", []byte(`{"apiVersion":"v1alpha1","apiVersion":"v2","kind":"Workspace","metadata":{"displayName":"x"},"spec":{}}`), http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-unknown-0001", fuzzWorkspaceResourceMatch, "req-fuzz-unknown", []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"x"},"spec":{"credential":"` + invalidBearerCanary + `"}}`), http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-trailing-0001", fuzzWorkspaceResourceMatch, "req-fuzz-trailing", []byte(`{} {}`), http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-unicode-0001", fuzzWorkspaceResourceMatch, "req-fuzz-unicode", []byte{'{', '"', 0xff, '"', ':', '0', '}'}, http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-depth-0000001", fuzzWorkspaceResourceMatch, "req-fuzz-depth", []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)), http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-webhook-0001", fuzzWorkspaceResourceMatch, "req-fuzz-webhook", []byte(`{"webhooks":{"escape":{"post":{"requestBody":{"$ref":"https://attacker.invalid/schema"}}}}}`), http.StatusBadRequest},
		{http.MethodPut, fuzzWorkspaceTarget, "Bearer " + securityBearerCanary, "application/json", "fuzz-oversized-0001", fuzzWorkspaceResourceMatch, "req-fuzz-oversized", bytes.Repeat([]byte{'x'}, resource.MaxCanonicalBytes+1), http.StatusRequestEntityTooLarge},
		{http.MethodDelete, "/api/v1alpha1/workspaces/wsp_0000000000000001", "Bearer " + invalidBearerCanary, "", "fuzz-delete-00001", `"rv_0000000000000001"`, "req-fuzz-delete", nil, 0},
	}
	for _, seed := range seeds {
		f.Add(seed.method, seed.target, seed.authorization, seed.contentType, seed.idempotencyKey, seed.ifMatch, seed.requestID, seed.body)
	}

	f.Fuzz(func(
		t *testing.T,
		method, target, authorization, contentType, idempotencyKey, ifMatch, requestID string,
		body []byte,
	) {
		if len(method) > 32 || len(target) > 4*1024 || len(authorization) > 16*1024 ||
			len(contentType) > 512 || len(idempotencyKey) > 2*1024 || len(ifMatch) > 512 ||
			len(requestID) > 512 || len(body) > 2*resource.MaxCanonicalBytes {
			t.Skip()
		}
		retainedRejectionStatus := retainedSecurityFuzzRejectionStatus(
			seeds, method, target, authorization, contentType, idempotencyKey, ifMatch, requestID, body,
		)
		fixture := newSecurityFixture(t)
		authorizedFixtureMutation := method == http.MethodPut && target == fuzzWorkspaceTarget &&
			authorization == "Bearer "+securityBearerCanary && ifMatch == fuzzWorkspaceResourceMatch
		if target == fuzzWorkspaceTarget {
			target = "/api/v1alpha1/workspaces/" + fixture.workspaceID.String()
		}
		if ifMatch == fuzzWorkspaceResourceMatch {
			ifMatch = `"` + fixture.resourceVersion + `"`
		}
		request, err := http.NewRequestWithContext(context.Background(), method, target, bytes.NewReader(body))
		if err != nil {
			return
		}
		request.RequestURI = target
		for name, value := range map[string]string{
			"Authorization":   authorization,
			"Content-Type":    contentType,
			"Idempotency-Key": idempotencyKey,
			"If-Match":        ifMatch,
			"Veer-Request-Id": requestID,
		} {
			if value != "" {
				request.Header.Set(name, value)
			}
		}
		response := httptest.NewRecorder()
		fixture.memberHandler.ServeHTTP(response, request)
		if requestID != "" && securityRequestIDPattern.MatchString(requestID) &&
			response.Header().Get("Veer-Request-Id") != requestID {
			t.Fatalf(
				"response request ID = %q, want echoed client value %q",
				response.Header().Get("Veer-Request-Id"), requestID,
			)
		}
		if authorizedFixtureMutation && response.Code == http.StatusForbidden {
			t.Fatalf("authorized fixture mutation was denied before reaching admission: body=%s", response.Body.String())
		}
		if retainedRejectionStatus != 0 && response.Code != retainedRejectionStatus {
			t.Fatalf(
				"retained negative seed status = %d, want %d; body=%s",
				response.Code, retainedRejectionStatus, response.Body.String(),
			)
		}

		if response.Header().Get("Cache-Control") != "no-store" ||
			response.Header().Get("X-Content-Type-Options") != "nosniff" ||
			response.Header().Get("Veer-Request-Id") == "" {
			t.Fatalf("security headers = %#v", response.Header())
		}
		switch {
		case response.Code >= http.StatusOK && response.Code < http.StatusMultipleChoices:
			if response.Header().Get("Content-Type") != "application/json" ||
				response.Body.Len() > reference.MaxPageBytes || !json.Valid(response.Body.Bytes()) {
				t.Fatalf("success response contract failed: status=%d bytes=%d headers=%#v", response.Code, response.Body.Len(), response.Header())
			}
		case response.Code >= http.StatusBadRequest && response.Code <= 599:
			assertSecurityProblemContract(t, response)
			assertNoFixtureCanary(t, response, fixture)
		default:
			t.Fatalf("unexpected HTTP status %d", response.Code)
		}
		assertNoBearerCanary(t, response)
	})
}

func retainedSecurityFuzzRejectionStatus(
	seeds []securityFuzzSeed,
	method, target, authorization, contentType, idempotencyKey, ifMatch, requestID string,
	body []byte,
) int {
	for _, seed := range seeds {
		if seed.rejectionStatus != 0 && method == seed.method && target == seed.target &&
			authorization == seed.authorization && contentType == seed.contentType &&
			idempotencyKey == seed.idempotencyKey && ifMatch == seed.ifMatch && requestID == seed.requestID &&
			bytes.Equal(body, seed.body) {
			return seed.rejectionStatus
		}
	}
	return 0
}
