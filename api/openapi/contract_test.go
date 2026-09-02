package openapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBaselineContract(t *testing.T) {
	t.Parallel()
	data, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := Validate(data); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestContractRejectsSemanticDrift(t *testing.T) {
	t.Parallel()
	baseline, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(map[string]any)
		message string
	}{
		{
			name: "OpenAPI version",
			mutate: func(root map[string]any) {
				root["openapi"] = "3.2.0"
			},
			message: "openapi must be 3.1.2",
		},
		{
			name: "schema dialect",
			mutate: func(root map[string]any) {
				root["jsonSchemaDialect"] = "https://json-schema.org/draft/2020-12/schema"
			},
			message: "jsonSchemaDialect",
		},
		{
			name: "anonymous root security",
			mutate: func(root map[string]any) {
				root["security"] = []any{}
			},
			message: "root security",
		},
		{
			name: "anonymous operation security override",
			mutate: func(root map[string]any) {
				post := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post")
				post["security"] = []any{}
			},
			message: "security override: must contain exactly one BearerAuth requirement",
		},
		{
			name: "BearerAuth reclassified",
			mutate: func(root map[string]any) {
				bearer := nestedMap(t, root, "components", "securitySchemes", "BearerAuth")
				bearer["type"] = "apiKey"
				bearer["in"] = "header"
				bearer["name"] = "Authorization"
			},
			message: "BearerAuth must remain an HTTP bearer scheme",
		},
		{
			name: "absolute deployment server",
			mutate: func(root map[string]any) {
				root["servers"] = []any{map[string]any{"url": "https://developer.example.invalid"}}
			},
			message: "server URL must remain relative",
		},
		{
			name: "path server override",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces")
				item["servers"] = []any{map[string]any{"url": "https://example.invalid"}}
			},
			message: "must inherit the root-relative server",
		},
		{
			name: "operation server override",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "get")
				operation["servers"] = []any{map[string]any{"url": "https://example.invalid"}}
			},
			message: "must not define servers",
		},
		{
			name: "webhook surface",
			mutate: func(root map[string]any) {
				root["webhooks"] = map[string]any{}
			},
			message: "webhooks are not selected for v1alpha1",
		},
		{
			name: "external reference",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "Problem", "properties")
				properties["requestId"] = map[string]any{"$ref": "https://example.invalid/request-id.json"}
			},
			message: "external or malformed reference",
		},
		{
			name: "referenced path item",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces")
				item["$ref"] = "#/components/pathItems/Workspaces"
			},
			message: "must define its operations directly",
		},
		{
			name: "unversioned route",
			mutate: func(root map[string]any) {
				paths := nestedMap(t, root, "paths")
				paths["/workspaces"] = paths["/api/v1alpha1/workspaces"]
				delete(paths, "/api/v1alpha1/workspaces")
			},
			message: "outside /api/v1alpha1",
		},
		{
			name: "duplicate operation ID",
			mutate: func(root map[string]any) {
				get := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get")
				get["operationId"] = "listWorkspaces"
			},
			message: "operationId",
		},
		{
			name: "missing baseline operation",
			mutate: func(root map[string]any) {
				paths := nestedMap(t, root, "paths")
				delete(paths, "/api/v1alpha1/operations/{operationId}")
			},
			message: `operationId "getOperation" must remain at GET /api/v1alpha1/operations/{operationId}`,
		},
		{
			name: "unselected trace method",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces")
				item["trace"] = map[string]any{}
			},
			message: "TRACE /api/v1alpha1/workspaces is not selected for v1alpha1",
		},
		{
			name: "wrong success response reference",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get", "responses")
				responses["200"] = map[string]any{"$ref": "#/components/responses/WorkspaceList"}
			},
			message: `operationId "getWorkspace" must use 200 response Workspace`,
		},
		{
			name: "status response exceeds non-read contract",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "responses")
				responses["200"] = map[string]any{"$ref": "#/components/responses/Workspace"}
			},
			message: `operationId "replaceWorkspaceStatus" must use 200 response StatusUpdated`,
		},
		{
			name: "unexpected second success response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get", "responses")
				responses["204"] = map[string]any{"description": "No content"}
			},
			message: "declares unexpected success response 204",
		},
		{
			name: "missing idempotency header",
			mutate: func(root map[string]any) {
				post := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post")
				post["parameters"] = []any{}
			},
			message: "omits IdempotencyKey",
		},
		{
			name: "mutation header inherited by GET",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces")
				parameters := item["parameters"].([]any)
				item["parameters"] = append(parameters, map[string]any{
					"$ref": "#/components/parameters/IdempotencyKey",
				})
			},
			message: "GET /api/v1alpha1/workspaces carries mutation headers",
		},
		{
			name: "missing validation response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/operations/{operationId}", "get", "responses")
				delete(responses, "400")
			},
			message: "omits required response 400",
		},
		{
			name: "point read omits not found response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get", "responses")
				delete(responses, "404")
			},
			message: "operationId \"getWorkspace\" omits required response 404",
		},
		{
			name: "operation read omits not found response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/operations/{operationId}", "get", "responses")
				delete(responses, "404")
			},
			message: "operationId \"getOperation\" omits required response 404",
		},
		{
			name: "addressed mutation omits not found response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put", "responses")
				delete(responses, "404")
			},
			message: "operationId \"replaceWorkspace\" omits required response 404",
		},
		{
			name: "create omits request too large response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post", "responses")
				delete(responses, "413")
			},
			message: "POST /api/v1alpha1/workspaces omits request-body response 413",
		},
		{
			name: "replace omits unsupported media response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put", "responses")
				delete(responses, "415")
			},
			message: "PUT /api/v1alpha1/workspaces/{workspaceId} omits request-body response 415",
		},
		{
			name: "status write omits request too large response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "responses")
				delete(responses, "413")
			},
			message: "PUT /api/v1alpha1/workspaces/{workspaceId}/status omits request-body response 413",
		},
		{
			name: "unreviewed error response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "get", "responses")
				responses["422"] = map[string]any{"description": "Unreviewed"}
			},
			message: "declares unreviewed error response 422",
		},
		{
			name: "missing optimistic concurrency header",
			mutate: func(root map[string]any) {
				put := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put")
				put["parameters"] = []any{
					map[string]any{"$ref": "#/components/parameters/IdempotencyKey"},
				}
			},
			message: "omits IfMatch",
		},
		{
			name: "operation route omits path identifier",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/operations/{operationId}")
				item["parameters"] = []any{
					map[string]any{"$ref": "#/components/parameters/VeerRequestId"},
				}
			},
			message: "operationId \"getOperation\" parameter set drifted",
		},
		{
			name: "missing stale precondition response",
			mutate: func(root map[string]any) {
				responses := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put", "responses")
				delete(responses, "412")
			},
			message: "omits precondition response 412",
		},
		{
			name: "delete request body",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "delete")
				operation["requestBody"] = map[string]any{}
			},
			message: "must not define a request body",
		},
		{
			name: "status route reclassified",
			mutate: func(root map[string]any) {
				put := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put")
				put["x-veer-write-class"] = "spec"
			},
			message: "operationId \"replaceWorkspaceStatus\" write class must be \"status\"",
		},
		{
			name: "spec replacement reclassified",
			mutate: func(root map[string]any) {
				put := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put")
				put["x-veer-write-class"] = "delete"
			},
			message: "operationId \"replaceWorkspace\" write class must be \"spec\"",
		},
		{
			name: "delete reclassified",
			mutate: func(root map[string]any) {
				deleteOperation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "delete")
				deleteOperation["x-veer-write-class"] = "status"
			},
			message: "operationId \"deleteWorkspace\" write class must be \"delete\"",
		},
		{
			name: "status payload can mutate spec",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "WorkspaceStatusWrite", "properties")
				properties["spec"] = map[string]any{"$ref": "#/components/schemas/WorkspaceSpec"}
			},
			message: "WorkspaceStatusWrite exposes spec",
		},
		{
			name: "status payload loses object type",
			mutate: func(root map[string]any) {
				statusWrite := nestedMap(t, root, "components", "schemas", "WorkspaceStatusWrite")
				delete(statusWrite, "type")
			},
			message: "schema with properties must declare type object",
		},
		{
			name: "status payload makes status optional",
			mutate: func(root map[string]any) {
				statusWrite := nestedMap(t, root, "components", "schemas", "WorkspaceStatusWrite")
				statusWrite["required"] = []any{"apiVersion", "kind"}
			},
			message: "WorkspaceStatusWrite shape drifted",
		},
		{
			name: "status payload changes status schema",
			mutate: func(root map[string]any) {
				status := nestedMap(t, root, "components", "schemas", "WorkspaceStatusWrite", "properties", "status")
				status["$ref"] = "#/components/schemas/WorkspaceSpec"
			},
			message: "status must reference #/components/schemas/WorkspaceStatus",
		},
		{
			name: "status payload changes identity",
			mutate: func(root map[string]any) {
				kind := nestedMap(t, root, "components", "schemas", "WorkspaceStatusWrite", "properties", "kind")
				kind["const"] = "Operation"
			},
			message: "WorkspaceStatusWrite identity drifted",
		},
		{
			name: "status route uses desired-state schema",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "requestBody", "content", "application/json", "schema")
				schema["$ref"] = "#/components/schemas/WorkspaceReplace"
			},
			message: `operationId "replaceWorkspaceStatus" must use request schema WorkspaceStatusWrite`,
		},
		{
			name: "unbounded status receipt",
			mutate: func(root map[string]any) {
				resourceVersion := nestedMap(t, root, "components", "schemas", "StatusReceipt", "properties", "resourceVersion")
				resourceVersion["maxLength"] = json.Number("4096")
			},
			message: "StatusReceipt resourceVersion contract drifted",
		},
		{
			name: "generation status semantics",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "x-veer-evolution", "generation")
				generation["unchanged"] = []any{"metadata-only-write", "idempotent-replay"}
			},
			message: "rules drifted",
		},
		{
			name: "resource version stale status",
			mutate: func(root map[string]any) {
				version := nestedMap(t, root, "x-veer-evolution", "resourceVersion")
				version["stalePreconditionStatus"] = json.Number("409")
			},
			message: "rules drifted",
		},
		{
			name: "unbounded pagination",
			mutate: func(root map[string]any) {
				pagination := nestedMap(t, root, "x-veer-evolution", "pagination")
				pagination["maximumPageSize"] = json.Number("1000")
			},
			message: "rules drifted",
		},
		{
			name: "pagination snapshot omitted",
			mutate: func(root map[string]any) {
				pagination := nestedMap(t, root, "x-veer-evolution", "pagination")
				delete(pagination, "snapshot")
			},
			message: "rules drifted",
		},
		{
			name: "request-specific correlation replayed",
			mutate: func(root map[string]any) {
				idempotency := nestedMap(t, root, "x-veer-evolution", "idempotency")
				idempotency["replay"] = "original-status-headers-body"
			},
			message: "rules drifted",
		},
		{
			name: "unbounded page token",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "parameters", "PageToken", "schema")
				schema["maxLength"] = json.Number("4096")
			},
			message: "PageToken parameter contract drifted",
		},
		{
			name: "missing page token",
			mutate: func(root map[string]any) {
				list := nestedMap(t, root, "components", "schemas", "WorkspaceList", "properties")
				delete(list, "nextPageToken")
			},
			message: "WorkspaceList shape drifted",
		},
		{
			name: "deprecation notice shortened",
			mutate: func(root map[string]any) {
				deprecation := nestedMap(t, root, "x-veer-evolution", "deprecation")
				deprecation["minimumNoticeDays"] = json.Number("30")
			},
			message: "rules drifted",
		},
		{
			name: "missing deprecation response header",
			mutate: func(root map[string]any) {
				headers := nestedMap(t, root, "components", "responses", "Workspace", "headers")
				delete(headers, "Link")
			},
			message: "success response Workspace: Link is missing",
		},
		{
			name: "wrong request ID response header reference",
			mutate: func(root map[string]any) {
				headers := nestedMap(t, root, "components", "responses", "Conflict", "headers")
				headers["Veer-Request-Id"] = map[string]any{"$ref": "#/components/headers/Sunset"}
			},
			message: "Veer-Request-Id must reference #/components/headers/VeerRequestId",
		},
		{
			name: "wrong retry response header reference",
			mutate: func(root map[string]any) {
				headers := nestedMap(t, root, "components", "responses", "Throttled", "headers")
				headers["Retry-After"] = map[string]any{"$ref": "#/components/headers/Sunset"}
			},
			message: "Retry-After must reference #/components/headers/RetryAfter",
		},
		{
			name: "ETag header schema reference",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "ETag", "schema")
				schema["$ref"] = "#/components/schemas/RequestId"
			},
			message: "ETag header contract drifted",
		},
		{
			name: "response request ID header schema reference",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "VeerRequestId", "schema")
				schema["$ref"] = "#/components/schemas/StrongETag"
			},
			message: "VeerRequestId header contract drifted",
		},
		{
			name: "retry after header pattern",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "RetryAfter", "schema")
				delete(schema, "pattern")
			},
			message: "RetryAfter header contract drifted",
		},
		{
			name: "deprecation header pattern",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Deprecation", "schema")
				delete(schema, "pattern")
			},
			message: "Deprecation header contract drifted",
		},
		{
			name: "sunset header pattern",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Sunset", "schema")
				delete(schema, "pattern")
			},
			message: "Sunset header contract drifted",
		},
		{
			name: "sunset header impossible example",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Sunset", "schema")
				schema["example"] = "Sun, 31 Feb 2026 99:99:99 GMT"
			},
			message: "sunset header calendar contract drifted",
		},
		{
			name: "short operation Location ID",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Location", "schema")
				schema["pattern"] = "^/api/v1alpha1/operations/[A-Za-z0-9][A-Za-z0-9_-]{0,127}$"
			},
			message: "Location header contract drifted",
		},
		{
			name: "unbounded authentication challenge",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "WWWAuthenticate", "schema")
				delete(schema, "maxLength")
			},
			message: "WWWAuthenticate header contract drifted",
		},
		{
			name: "deprecation link without relation",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "DeprecationLink", "schema")
				delete(schema, "pattern")
			},
			message: "DeprecationLink header contract drifted",
		},
		{
			name: "missing validation example",
			mutate: func(root map[string]any) {
				examples := nestedMap(t, root, "components", "examples")
				delete(examples, "ValidationFailure")
			},
			message: "canonical problem examples",
		},
		{
			name: "detached validation example",
			mutate: func(root map[string]any) {
				media := nestedMap(t, root, "components", "responses", "ValidationFailure", "content", "application/problem+json")
				delete(media, "examples")
			},
			message: "error response ValidationFailure: examples is missing",
		},
		{
			name: "mismatched authentication example",
			mutate: func(root map[string]any) {
				value := nestedMap(t, root, "components", "examples", "AuthenticationRequired", "value")
				value["status"] = json.Number("403")
			},
			message: "status or code drifted",
		},
		{
			name: "mismatched inline not found example",
			mutate: func(root map[string]any) {
				example := nestedMap(t, root, "components", "responses", "NotFound", "content", "application/problem+json", "example")
				example["status"] = json.Number("500")
			},
			message: "example NotFound status or code drifted",
		},
		{
			name: "detached inline unavailable request ID",
			mutate: func(root map[string]any) {
				example := nestedMap(t, root, "components", "responses", "Unavailable", "content", "application/problem+json", "example")
				example["instance"] = "urn:veer:request:req_01J00000000000000000000012"
			},
			message: "example Unavailable requestId and instance are not bound",
		},
		{
			name: "idempotency key loses bound",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "IdempotencyKey")
				delete(schema, "maxLength")
			},
			message: "IdempotencyKey schema contract drifted",
		},
		{
			name: "request ID grammar relaxed",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "RequestId")
				delete(schema, "pattern")
			},
			message: "RequestId schema contract drifted",
		},
		{
			name: "strong ETag bound relaxed",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "StrongETag")
				schema["maxLength"] = json.Number("1024")
			},
			message: "StrongETag schema contract drifted",
		},
		{
			name: "opaque ID minimum relaxed",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "OpaqueId")
				schema["minLength"] = json.Number("1")
			},
			message: "OpaqueId schema contract drifted",
		},
		{
			name: "workspace response byte ceiling removed",
			mutate: func(root map[string]any) {
				workspace := nestedMap(t, root, "components", "schemas", "Workspace")
				delete(workspace, "x-veer-maximum-json-bytes")
			},
			message: "workspace read shape or encoded-size contract drifted",
		},
		{
			name: "resource metadata identity becomes optional",
			mutate: func(root map[string]any) {
				metadata := nestedMap(t, root, "components", "schemas", "ResourceMetadata")
				metadata["required"] = []any{"displayName", "generation", "resourceVersion", "createdAt", "updatedAt"}
			},
			message: "ResourceMetadata shape drifted",
		},
		{
			name: "workspace status generation fence becomes optional",
			mutate: func(root map[string]any) {
				status := nestedMap(t, root, "components", "schemas", "WorkspaceStatus")
				status["required"] = []any{"conditions"}
			},
			message: "WorkspaceStatus shape drifted",
		},
		{
			name: "condition truth-state enum narrows",
			mutate: func(root map[string]any) {
				status := nestedMap(t, root, "components", "schemas", "Condition", "properties", "status")
				status["enum"] = []any{"True", "False"}
			},
			message: "condition.status contract drifted",
		},
		{
			name: "workspace page byte ceiling removed",
			mutate: func(root map[string]any) {
				list := nestedMap(t, root, "components", "schemas", "WorkspaceList")
				delete(list, "x-veer-maximum-json-bytes")
			},
			message: "WorkspaceList encoded-size contract drifted",
		},
		{
			name: "workspace page byte policy relaxed",
			mutate: func(root map[string]any) {
				list := nestedMap(t, root, "components", "schemas", "WorkspaceList")
				list["x-veer-page-byte-policy"] = "truncate-after-limit"
			},
			message: "WorkspaceList encoded-size contract drifted",
		},
		{
			name: "create payload becomes partial",
			mutate: func(root map[string]any) {
				create := nestedMap(t, root, "components", "schemas", "WorkspaceCreate")
				create["required"] = []any{"apiVersion", "kind", "metadata"}
			},
			message: "WorkspaceCreate complete-write shape drifted",
		},
		{
			name: "replacement metadata becomes server owned",
			mutate: func(root map[string]any) {
				metadata := nestedMap(t, root, "components", "schemas", "WorkspaceReplace", "properties", "metadata")
				metadata["$ref"] = "#/components/schemas/ResourceMetadata"
			},
			message: "WorkspaceReplace: metadata must reference #/components/schemas/WritableMetadata",
		},
		{
			name: "resource generation upper bound removed",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "generation")
				delete(generation, "maximum")
			},
			message: "ResourceMetadata.generation int64 contract drifted",
		},
		{
			name: "mutation receipt generation upper bound removed",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "MutationReceipt", "properties", "generation")
				delete(generation, "maximum")
			},
			message: "MutationReceipt.generation int64 contract drifted",
		},
		{
			name: "operation generation upper bound removed",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "Operation", "properties", "generation")
				delete(generation, "maximum")
			},
			message: "Operation.generation int64 contract drifted",
		},
		{
			name: "resource ID loses read only marker",
			mutate: func(root map[string]any) {
				id := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "id")
				delete(id, "readOnly")
			},
			message: "ResourceMetadata.id must be readOnly",
		},
		{
			name: "creation time loses read only marker",
			mutate: func(root map[string]any) {
				createdAt := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "createdAt")
				delete(createdAt, "readOnly")
			},
			message: "ResourceMetadata.createdAt must be readOnly",
		},
		{
			name: "update time loses read only marker",
			mutate: func(root map[string]any) {
				updatedAt := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "updatedAt")
				delete(updatedAt, "readOnly")
			},
			message: "ResourceMetadata.updatedAt must be readOnly",
		},
		{
			name: "next page token loses encoding grammar",
			mutate: func(root map[string]any) {
				token := nestedMap(t, root, "components", "schemas", "WorkspaceList", "properties", "nextPageToken")
				delete(token, "pattern")
			},
			message: "WorkspaceList nextPageToken contract drifted",
		},
		{
			name: "status receipt byte ceiling removed",
			mutate: func(root map[string]any) {
				receipt := nestedMap(t, root, "components", "schemas", "StatusReceipt")
				delete(receipt, "x-veer-maximum-json-bytes")
			},
			message: "status receipt encoded-size contract drifted",
		},
		{
			name: "mutation receipt byte ceiling removed",
			mutate: func(root map[string]any) {
				receipt := nestedMap(t, root, "components", "schemas", "MutationReceipt")
				delete(receipt, "x-veer-maximum-json-bytes")
			},
			message: "mutation receipt encoded-size contract drifted",
		},
		{
			name: "mutation receipt operation identity becomes optional",
			mutate: func(root map[string]any) {
				receipt := nestedMap(t, root, "components", "schemas", "MutationReceipt")
				receipt["required"] = []any{"resourceId", "generation", "resourceVersion", "acceptedAt"}
			},
			message: "MutationReceipt shape drifted",
		},
		{
			name: "mutation receipt operation identity changes type",
			mutate: func(root map[string]any) {
				operationID := nestedMap(t, root, "components", "schemas", "MutationReceipt", "properties", "operationId")
				operationID["$ref"] = "#/components/schemas/Timestamp"
			},
			message: "MutationReceipt: operationId must reference #/components/schemas/OpaqueId",
		},
		{
			name: "operation phase becomes optional",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "components", "schemas", "Operation")
				operation["required"] = []any{"id", "resourceId", "generation", "resourceVersion", "createdAt", "updatedAt"}
			},
			message: "operation shape drifted",
		},
		{
			name: "operation terminal phase narrows",
			mutate: func(root map[string]any) {
				phase := nestedMap(t, root, "components", "schemas", "Operation", "properties", "phase")
				phase["enum"] = []any{"Pending", "Running", "Failed", "Canceled"}
			},
			message: "operation.phase contract drifted",
		},
		{
			name: "problem field violations become unbounded aggregate",
			mutate: func(root map[string]any) {
				errors := nestedMap(t, root, "components", "schemas", "Problem", "properties", "errors")
				errors["maxItems"] = json.Number("64")
			},
			message: "problem.errors aggregate bound drifted",
		},
		{
			name: "field violation message exceeds problem budget",
			mutate: func(root map[string]any) {
				message := nestedMap(t, root, "components", "schemas", "FieldViolation", "properties", "message")
				message["maxLength"] = json.Number("512")
			},
			message: "FieldViolation.message bound drifted",
		},
		{
			name: "problem encoded byte ceiling removed",
			mutate: func(root map[string]any) {
				problem := nestedMap(t, root, "components", "schemas", "Problem")
				delete(problem, "x-veer-maximum-json-bytes")
			},
			message: "problem encoded-size contract drifted",
		},
		{
			name: "problem instance becomes optional",
			mutate: func(root map[string]any) {
				problem := nestedMap(t, root, "components", "schemas", "Problem")
				problem["required"] = []any{"type", "title", "status", "code", "requestId"}
			},
			message: "problem required fields drifted",
		},
		{
			name: "problem instance correlation binding removed",
			mutate: func(root map[string]any) {
				problem := nestedMap(t, root, "components", "schemas", "Problem")
				delete(problem, "x-veer-instance-request-id-template")
			},
			message: "problem instance/request-ID binding drifted",
		},
		{
			name: "problem diagnostic text admits escaping Unicode",
			mutate: func(root map[string]any) {
				title := nestedMap(t, root, "components", "schemas", "Problem", "properties", "title")
				title["pattern"] = ".*"
			},
			message: "problem primitive contract drifted",
		},
		{
			name: "timestamp calendar assertion removed",
			mutate: func(root map[string]any) {
				timestamp := nestedMap(t, root, "components", "schemas", "Timestamp")
				delete(timestamp, "x-veer-calendar-validation")
			},
			message: "timestamp format or precision drifted",
		},
		{
			name: "timestamp example is impossible",
			mutate: func(root map[string]any) {
				timestamp := nestedMap(t, root, "components", "schemas", "Timestamp")
				timestamp["example"] = "2026-02-31T12:00:00.000Z"
			},
			message: "timestamp format or precision drifted",
		},
		{
			name: "unknown problem members allowed",
			mutate: func(root map[string]any) {
				problem := nestedMap(t, root, "components", "schemas", "Problem")
				problem["additionalProperties"] = true
			},
			message: "permits unconstrained additional properties",
		},
		{
			name: "non-camel-case schema property",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "Problem", "properties")
				properties["resource_version"] = map[string]any{"type": "string"}
			},
			message: `schema property "resource_version" is not lowerCamelCase`,
		},
		{
			name: "acronym run schema property",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "Operation", "properties")
				properties["requestID"] = map[string]any{"type": "string"}
			},
			message: `schema property "requestID" is not lowerCamelCase`,
		},
		{
			name: "map marker removed",
			mutate: func(root map[string]any) {
				labels := nestedMap(t, root, "components", "schemas", "Labels")
				delete(labels, "x-veer-free-form-map")
			},
			message: "map schema lacks x-veer-free-form-map",
		},
		{
			name: "labels property count bound removed",
			mutate: func(root map[string]any) {
				labels := nestedMap(t, root, "components", "schemas", "Labels")
				delete(labels, "maxProperties")
			},
			message: "labels map bound drifted",
		},
		{
			name: "labels key grammar relaxed",
			mutate: func(root map[string]any) {
				propertyNames := nestedMap(t, root, "components", "schemas", "Labels", "propertyNames")
				delete(propertyNames, "pattern")
			},
			message: "labels key contract drifted",
		},
		{
			name: "labels value bound relaxed",
			mutate: func(root map[string]any) {
				values := nestedMap(t, root, "components", "schemas", "Labels", "additionalProperties")
				values["maxLength"] = json.Number("4096")
			},
			message: "labels value contract drifted",
		},
		{
			name: "error media type",
			mutate: func(root map[string]any) {
				content := nestedMap(t, root, "components", "responses", "Conflict", "content")
				content["application/json"] = content["application/problem+json"]
				delete(content, "application/problem+json")
			},
			message: "must use application/problem+json",
		},
		{
			name: "error response schema",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "responses", "Conflict", "content", "application/problem+json", "schema")
				schema["$ref"] = "#/components/schemas/Workspace"
			},
			message: "error response Conflict must reference ConflictProblem",
		},
		{
			name: "conflict response status schema mismatched",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "IdempotencyConflictProblem")
				allOf := schema["allOf"].([]any)
				refinement := allOf[1].(map[string]any)
				property := nestedMap(t, refinement, "properties", "status")
				property["const"] = json.Number("412")
			},
			message: "IdempotencyConflictProblem constants drifted for response Conflict",
		},
		{
			name: "conflict response drops lifecycle variant",
			mutate: func(root map[string]any) {
				conflict := nestedMap(t, root, "components", "schemas", "ConflictProblem")
				oneOf := conflict["oneOf"].([]any)
				conflict["oneOf"] = oneOf[:len(oneOf)-1]
			},
			message: "ConflictProblem conflict variants drifted",
		},
		{
			name: "mandatory response header contract removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "MutationAccepted")
				delete(response, "x-veer-required-headers")
			},
			message: "response MutationAccepted required-header contract drifted",
		},
		{
			name: "deprecation header set becomes partial",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Workspace")
				response["x-veer-required-header-sets"] = []any{[]any{"Deprecation", "Sunset"}}
			},
			message: "success response Workspace deprecation-header contract drifted",
		},
		{
			name: "workspace ETag body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Workspace")
				delete(response, "x-veer-etag-resource-version-pointer")
			},
			message: "success response Workspace ETag binding drifted",
		},
		{
			name: "status receipt ETag body binding points at generation",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "StatusUpdated")
				response["x-veer-etag-resource-version-pointer"] = "/observedGeneration"
			},
			message: "success response StatusUpdated ETag binding drifted",
		},
		{
			name: "operation ETag body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Operation")
				delete(response, "x-veer-etag-resource-version-pointer")
			},
			message: "success response Operation ETag binding drifted",
		},
		{
			name: "mutation Location body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "MutationAccepted")
				delete(response, "x-veer-location-operation-id-pointer")
			},
			message: "success response MutationAccepted Location binding drifted",
		},
		{
			name: "error request ID body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Conflict")
				delete(response, "x-veer-request-id-body-pointer")
			},
			message: "error response Conflict request-ID body binding drifted",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, marshalErr := json.Marshal(root)
			if marshalErr != nil {
				t.Fatalf("json.Marshal() error = %v", marshalErr)
			}
			err := Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want message containing %q", err, test.message)
			}
		})
	}
}

func TestMaximumProblemEncoding(t *testing.T) {
	t.Parallel()
	safeText := regexp.MustCompile(safeProblemTextPattern)
	for _, value := range []string{"safe diagnostic text", strings.Repeat("A", 192)} {
		if !safeText.MatchString(value) {
			t.Fatalf("safe problem pattern rejected %q", value)
		}
	}
	for _, value := range []string{"emoji 🚨", `quoted "text"`, `path\\value`, "html <tag> & value"} {
		if safeText.MatchString(value) {
			t.Fatalf("safe problem pattern accepted escaping value %q", value)
		}
	}

	problem := map[string]any{
		"type":      "urn:veer:problem:" + strings.Repeat("a", 64),
		"title":     strings.Repeat("A", 64),
		"status":    599,
		"detail":    strings.Repeat("A", 192),
		"instance":  "urn:veer:request:" + strings.Repeat("A", 64),
		"code":      strings.Repeat("a", 64),
		"requestId": strings.Repeat("A", 64),
		"errors": []any{map[string]any{
			"field":   "/" + strings.Repeat("a", 95),
			"code":    strings.Repeat("a", 32),
			"message": strings.Repeat("A", 96),
		}},
		"retryAfterSeconds": 86400,
	}
	encoded, err := json.Marshal(problem)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if len(encoded) > 1024 {
		t.Fatalf("maximal problem encoding is %d bytes, want at most 1024", len(encoded))
	}
}

func TestTimestampValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "ordinary date", value: "2026-09-01T21:00:00.000Z", valid: true},
		{name: "leap day divisible by four", value: "2024-02-29T00:00:00.000Z", valid: true},
		{name: "leap day divisible by four hundred", value: "2000-02-29T00:00:00.000Z", valid: true},
		{name: "February thirty first", value: "2026-02-31T12:00:00.000Z", valid: false},
		{name: "non-leap February twenty ninth", value: "2025-02-29T00:00:00.000Z", valid: false},
		{name: "century not divisible by four hundred", value: "1900-02-29T00:00:00.000Z", valid: false},
		{name: "offset", value: "2026-09-01T16:00:00.000-05:00", valid: false},
		{name: "excess precision", value: "2026-09-01T21:00:00.0001Z", valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validTimestamp(test.value); got != test.valid {
				t.Fatalf("validTimestamp(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestSunsetValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "ordinary date", value: "Tue, 01 Sep 2026 21:00:00 GMT", valid: true},
		{name: "leap day", value: "Sat, 29 Feb 2020 00:00:00 GMT", valid: true},
		{name: "weekday mismatch", value: "Mon, 01 Sep 2026 21:00:00 GMT", valid: false},
		{name: "impossible February date", value: "Tue, 31 Feb 2026 21:00:00 GMT", valid: false},
		{name: "invalid day zero", value: "Sun, 00 Feb 2026 21:00:00 GMT", valid: false},
		{name: "invalid clock", value: "Tue, 01 Sep 2026 99:99:99 GMT", valid: false},
		{name: "obsolete HTTP date", value: "Tuesday, 01-Sep-26 21:00:00 GMT", valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validSunset(test.value); got != test.valid {
				t.Fatalf("validSunset(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestContractRejectsDuplicateKeysAndTrailingData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string
		message string
	}{
		{
			name:    "duplicate key",
			data:    `{"openapi":"3.1.2","openapi":"3.0.0"}`,
			message: `duplicate object key "openapi"`,
		},
		{
			name:    "trailing object",
			data:    `{}` + `{}`,
			message: "more than one JSON value",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := Validate([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want message containing %q", err, test.message)
			}
		})
	}
}

func TestContractSizeAndFileTypeBounds(t *testing.T) {
	t.Parallel()
	oversized := make([]byte, maxContractBytes+1)
	if err := Validate(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Validate(oversized) error = %v, want size error", err)
	}

	temporary := t.TempDir()
	target := filepath.Join(temporary, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	link := filepath.Join(temporary, "contract.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink() error = %v", err)
	}
	if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("Load(symlink) error = %v, want file-type error", err)
	}
}

func decodeForMutation(t *testing.T, data []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("json.Decode() error = %v", err)
	}
	return root
}

func nestedMap(t *testing.T, root map[string]any, path ...string) map[string]any {
	t.Helper()
	current := root
	for _, part := range path {
		next, ok := current[part].(map[string]any)
		if !ok {
			t.Fatalf("path %s is not an object", strings.Join(path, "/"))
		}
		current = next
	}
	return current
}
