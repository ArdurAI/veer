// Package openapi verifies Veer's checked-in transport and evolution contract.
package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	maxContractBytes = 1 << 20
	maxJSONDepth     = 64
	maxJSONNodes     = 50000
	timestampPattern = `^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$`
)

var httpMethods = map[string]bool{
	"delete": true,
	"get":    true,
	"post":   true,
	"put":    true,
}

var pathItemMetadata = map[string]bool{
	"$ref":        true,
	"description": true,
	"parameters":  true,
	"servers":     true,
	"summary":     true,
}

var lowerCamelCaseProperty = regexp.MustCompile(`^[a-z][A-Za-z0-9]*$`)

// Load reads one bounded, regular, non-symlink contract file.
func Load(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat contract: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("contract must be a regular non-symlink file: %s", path)
	}
	if info.Size() > maxContractBytes {
		return nil, fmt.Errorf("contract exceeds %d bytes", maxContractBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open contract: %w", err)
	}

	data, readErr := io.ReadAll(io.LimitReader(file, maxContractBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read contract: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close contract: %w", closeErr)
	}
	if len(data) > maxContractBytes {
		return nil, fmt.Errorf("contract exceeds %d bytes", maxContractBytes)
	}
	return data, nil
}

// Validate checks bounded JSON syntax and Veer's exact API conventions.
func Validate(data []byte) error {
	if len(data) == 0 {
		return errors.New("contract is empty")
	}
	if len(data) > maxContractBytes {
		return fmt.Errorf("contract exceeds %d bytes", maxContractBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("decode contract: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}

	checks := []struct {
		name string
		fn   func(map[string]any) error
	}{
		{name: "bounded tree", fn: validateTree},
		{name: "root", fn: validateRoot},
		{name: "evolution", fn: validateEvolution},
		{name: "operations", fn: validateOperations},
		{name: "components", fn: validateComponents},
		{name: "examples", fn: validateExamples},
	}
	for _, check := range checks {
		if err := check.fn(root); err != nil {
			return fmt.Errorf("%s contract: %w", check.name, err)
		}
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	nodes := 0
	if err := scanJSONValue(decoder, 0, &nodes); err != nil {
		return fmt.Errorf("scan contract JSON: %w", err)
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int, nodes *int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return fmt.Errorf("JSON node count exceeds %d", maxJSONNodes)
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil {
			return endErr
		}
		if end != json.Delim('}') {
			return errors.New("object did not terminate")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1, nodes); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil {
			return endErr
		}
		if end != json.Delim(']') {
			return errors.New("array did not terminate")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("contract contains more than one JSON value")
		}
		return fmt.Errorf("decode trailing contract data: %w", err)
	}
	return nil
}

func validateTree(root map[string]any) error {
	nodes := 0
	refs := 0
	return walkTree(root, "$", 0, &nodes, &refs)
}

func walkTree(value any, path string, depth int, nodes, refs *int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%s exceeds nesting depth %d", path, maxJSONDepth)
	}
	*nodes++
	if *nodes > maxJSONNodes {
		return fmt.Errorf("node count exceeds %d", maxJSONNodes)
	}

	switch typed := value.(type) {
	case map[string]any:
		if rawProperties, hasProperties := typed["properties"]; hasProperties {
			if typed["type"] != "object" {
				return fmt.Errorf("%s schema with properties must declare type object", path)
			}
			properties, ok := rawProperties.(map[string]any)
			if !ok {
				return fmt.Errorf("%s schema properties is not an object", path)
			}
			for name := range properties {
				if !lowerCamelCaseProperty.MatchString(name) {
					return fmt.Errorf("%s schema property %q is not lowerCamelCase", path, name)
				}
			}
		}
		if _, hasAdditionalProperties := typed["additionalProperties"]; hasAdditionalProperties && typed["type"] != "object" {
			return fmt.Errorf("%s schema with additionalProperties must declare type object", path)
		}
		if schemaType, ok := typed["type"].(string); ok && schemaType == "object" {
			additional, exists := typed["additionalProperties"]
			if !exists {
				return fmt.Errorf("%s object schema omits additionalProperties", path)
			}
			if allowed, boolean := additional.(bool); boolean {
				if allowed {
					return fmt.Errorf("%s permits unconstrained additional properties", path)
				}
			} else {
				if typed["x-veer-free-form-map"] != true {
					return fmt.Errorf("%s map schema lacks x-veer-free-form-map", path)
				}
				if _, schema := additional.(map[string]any); !schema {
					return fmt.Errorf("%s map additionalProperties is not a schema", path)
				}
			}
		}
		if reference, exists := typed["$ref"]; exists {
			ref, ok := reference.(string)
			if !ok || !strings.HasPrefix(ref, "#/components/") {
				return fmt.Errorf("%s has external or malformed reference", path)
			}
			*refs++
			if *refs > 2048 {
				return errors.New("reference count exceeds 2048")
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := walkTree(typed[key], path+"/"+key, depth+1, nodes, refs); err != nil {
				return err
			}
		}
	case []any:
		for index, item := range typed {
			if err := walkTree(item, fmt.Sprintf("%s/%d", path, index), depth+1, nodes, refs); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRoot(root map[string]any) error {
	if root["openapi"] != "3.1.2" {
		return fmt.Errorf("openapi must be 3.1.2, got %v", root["openapi"])
	}
	if root["jsonSchemaDialect"] != "https://spec.openapis.org/oas/3.1/dialect/base" {
		return errors.New("jsonSchemaDialect is not the pinned OAS 3.1 base dialect")
	}
	info, err := mapField(root, "info")
	if err != nil {
		return err
	}
	if info["title"] != "Veer Control Plane API" || info["version"] != "v1alpha1" {
		return errors.New("info title or transport version drifted")
	}

	servers, ok := root["servers"].([]any)
	if !ok || len(servers) != 1 {
		return errors.New("servers must contain exactly one relative deployment origin")
	}
	server, ok := servers[0].(map[string]any)
	if !ok || server["url"] != "/" {
		return errors.New("server URL must remain relative")
	}

	if err := validateBearerSecurity(root["security"]); err != nil {
		return fmt.Errorf("root security: %w", err)
	}
	if _, exists := root["webhooks"]; exists {
		return errors.New("webhooks are not selected for v1alpha1")
	}
	return nil
}

type evolutionContract struct {
	TransportVersion            string                  `json:"transportVersion"`
	RoutePrefix                 string                  `json:"routePrefix"`
	FieldNaming                 string                  `json:"fieldNaming"`
	SuccessMediaType            string                  `json:"successMediaType"`
	ErrorMediaType              string                  `json:"errorMediaType"`
	UnknownRequestFields        string                  `json:"unknownRequestFields"`
	UnknownResponseFields       string                  `json:"unknownResponseFields"`
	TimestampFormat             string                  `json:"timestampFormat"`
	TimestampPattern            string                  `json:"timestampPattern"`
	MaximumRequestBytes         int                     `json:"maximumRequestBytes"`
	MaximumResponsePageBytes    int                     `json:"maximumResponsePageBytes"`
	MaximumNonReadResponseBytes int                     `json:"maximumNonReadResponseBytes"`
	CorrelationHeader           string                  `json:"correlationHeader"`
	Generation                  generationContract      `json:"generation"`
	ResourceVersion             resourceVersionContract `json:"resourceVersion"`
	Idempotency                 idempotencyContract     `json:"idempotency"`
	Pagination                  paginationContract      `json:"pagination"`
	Deprecation                 deprecationContract     `json:"deprecation"`
}

type generationContract struct {
	Initial   int      `json:"initial"`
	Advance   string   `json:"advance"`
	Unchanged []string `json:"unchanged"`
}

type resourceVersionContract struct {
	Representation            string `json:"representation"`
	Advance                   string `json:"advance"`
	Compare                   string `json:"compare"`
	MissingPreconditionStatus int    `json:"missingPreconditionStatus"`
	StalePreconditionStatus   int    `json:"stalePreconditionStatus"`
}

type idempotencyContract struct {
	Header                string   `json:"header"`
	RequiredOn            []string `json:"requiredOn"`
	MinimumRetentionHours int      `json:"minimumRetentionHours"`
	Scope                 string   `json:"scope"`
	Replay                string   `json:"replay"`
	MismatchStatus        int      `json:"mismatchStatus"`
}

type paginationContract struct {
	Strategy             string   `json:"strategy"`
	Ordering             []string `json:"ordering"`
	DefaultPageSize      int      `json:"defaultPageSize"`
	MaximumPageSize      int      `json:"maximumPageSize"`
	TokenLifetimeSeconds int      `json:"tokenLifetimeSeconds"`
	Snapshot             *bool    `json:"snapshot"`
	TokenBinding         []string `json:"tokenBinding"`
}

type deprecationContract struct {
	MinimumNoticeDays int      `json:"minimumNoticeDays"`
	Headers           []string `json:"headers"`
	BreakingChange    string   `json:"breakingChange"`
}

func validateEvolution(root map[string]any) error {
	raw, exists := root["x-veer-evolution"]
	if !exists {
		return errors.New("x-veer-evolution is missing")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encode evolution rules: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var got evolutionContract
	if err := decoder.Decode(&got); err != nil {
		return fmt.Errorf("decode evolution rules: %w", err)
	}

	noSnapshot := false
	want := evolutionContract{
		TransportVersion:            "v1alpha1",
		RoutePrefix:                 "/api/v1alpha1",
		FieldNaming:                 "lowerCamelCase",
		SuccessMediaType:            "application/json",
		ErrorMediaType:              "application/problem+json",
		UnknownRequestFields:        "reject",
		UnknownResponseFields:       "ignore",
		TimestampFormat:             "RFC3339-UTC-milliseconds",
		TimestampPattern:            timestampPattern,
		MaximumRequestBytes:         262144,
		MaximumResponsePageBytes:    262144,
		MaximumNonReadResponseBytes: 1024,
		CorrelationHeader:           "Veer-Request-Id",
		Generation: generationContract{
			Initial:   1,
			Advance:   "once-per-semantic-spec-change",
			Unchanged: []string{"metadata-only-write", "status-only-write", "idempotent-replay"},
		},
		ResourceVersion: resourceVersionContract{
			Representation:            "opaque",
			Advance:                   "every-persisted-observable-write",
			Compare:                   "strong-etag-if-match",
			MissingPreconditionStatus: 428,
			StalePreconditionStatus:   412,
		},
		Idempotency: idempotencyContract{
			Header:                "Idempotency-Key",
			RequiredOn:            []string{"POST", "PUT", "PATCH", "DELETE"},
			MinimumRetentionHours: 24,
			Scope:                 "principal-method-canonical-target",
			Replay:                "original-status-body-semantic-headers-current-request-id",
			MismatchStatus:        409,
		},
		Pagination: paginationContract{
			Strategy:             "opaque-keyset-token",
			Ordering:             []string{"createdAt", "id"},
			DefaultPageSize:      50,
			MaximumPageSize:      100,
			TokenLifetimeSeconds: 900,
			Snapshot:             &noSnapshot,
			TokenBinding:         []string{"principal", "workspace", "route", "filter", "ordering"},
		},
		Deprecation: deprecationContract{
			MinimumNoticeDays: 90,
			Headers:           []string{"Deprecation", "Sunset", "Link"},
			BreakingChange:    "new-route-version",
		},
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("rules drifted\n got: %#v\nwant: %#v", got, want)
	}
	return nil
}

func validateOperations(root map[string]any) error {
	paths, err := mapField(root, "paths")
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("paths is empty")
	}

	operationIDs := make(map[string]string)
	for route, rawItem := range paths {
		if !strings.HasPrefix(route, "/api/v1alpha1/") {
			return fmt.Errorf("route %q is outside /api/v1alpha1", route)
		}
		item, ok := rawItem.(map[string]any)
		if !ok {
			return fmt.Errorf("path %q is not an object", route)
		}
		if _, exists := item["$ref"]; exists {
			return fmt.Errorf("path %q must define its operations directly", route)
		}
		if _, exists := item["servers"]; exists {
			return fmt.Errorf("path %q must inherit the root-relative server", route)
		}
		pathParameters, err := parameterReferences(item["parameters"])
		if err != nil {
			return fmt.Errorf("path %q parameters: %w", route, err)
		}
		if !pathParameters["VeerRequestId"] {
			return fmt.Errorf("path %q omits VeerRequestId", route)
		}

		for method, rawOperation := range item {
			if pathItemMetadata[method] || strings.HasPrefix(method, "x-") {
				continue
			}
			if method == "head" || method == "options" || method == "patch" || method == "trace" {
				return fmt.Errorf("%s %s is not selected for v1alpha1", strings.ToUpper(method), route)
			}
			if !httpMethods[method] {
				return fmt.Errorf("path %q has unsupported field %q", route, method)
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				return fmt.Errorf("%s %s is not an operation object", strings.ToUpper(method), route)
			}
			operationID, ok := operation["operationId"].(string)
			if !ok || operationID == "" {
				return fmt.Errorf("%s %s omits operationId", strings.ToUpper(method), route)
			}
			if previous, duplicate := operationIDs[operationID]; duplicate {
				return fmt.Errorf("operationId %q duplicates %s", operationID, previous)
			}
			operationIDs[operationID] = strings.ToUpper(method) + " " + route
			for _, forbidden := range []string{"callbacks", "servers"} {
				if _, exists := operation[forbidden]; exists {
					return fmt.Errorf("%s %s must not define %s", strings.ToUpper(method), route, forbidden)
				}
			}
			if operationSecurity, exists := operation["security"]; exists {
				if err := validateBearerSecurity(operationSecurity); err != nil {
					return fmt.Errorf("%s %s security override: %w", strings.ToUpper(method), route, err)
				}
			}

			responses, err := mapField(operation, "responses")
			if err != nil {
				return fmt.Errorf("%s %s: %w", strings.ToUpper(method), route, err)
			}
			for _, status := range []string{"400", "401", "403", "429", "500", "503"} {
				if _, exists := responses[status]; !exists {
					return fmt.Errorf("%s %s omits required response %s", strings.ToUpper(method), route, status)
				}
			}
			if err := validateResponseReferences(route, method, responses); err != nil {
				return err
			}
			if err := validateSuccessResponse(operationID, responses); err != nil {
				return err
			}

			operationParameters, err := parameterReferences(operation["parameters"])
			if err != nil {
				return fmt.Errorf("%s %s parameters: %w", strings.ToUpper(method), route, err)
			}
			if method == "get" {
				if _, exists := operation["x-veer-write-class"]; exists {
					return fmt.Errorf("GET %s declares a write class", route)
				}
				if _, exists := operation["requestBody"]; exists {
					return fmt.Errorf("GET %s must not define a request body", route)
				}
				if operationParameters["IdempotencyKey"] || operationParameters["IfMatch"] {
					return fmt.Errorf("GET %s carries mutation headers", route)
				}
				continue
			}

			writeClass, ok := operation["x-veer-write-class"].(string)
			if !ok || (writeClass != "spec" && writeClass != "status" && writeClass != "delete") {
				return fmt.Errorf("%s %s has invalid write class", strings.ToUpper(method), route)
			}
			if !operationParameters["IdempotencyKey"] {
				return fmt.Errorf("%s %s omits IdempotencyKey", strings.ToUpper(method), route)
			}
			if _, exists := responses["409"]; !exists {
				return fmt.Errorf("%s %s omits conflict response 409", strings.ToUpper(method), route)
			}
			if method != "post" && !operationParameters["IfMatch"] {
				return fmt.Errorf("%s %s omits IfMatch", strings.ToUpper(method), route)
			}
			if method != "post" {
				for _, status := range []string{"412", "428"} {
					if _, exists := responses[status]; !exists {
						return fmt.Errorf("%s %s omits precondition response %s", strings.ToUpper(method), route, status)
					}
				}
			}
			if method == "post" || method == "put" || method == "patch" {
				if err := validateJSONRequestBody(operationID, operation); err != nil {
					return fmt.Errorf("%s %s: %w", strings.ToUpper(method), route, err)
				}
			}
			if method == "delete" {
				if _, exists := operation["requestBody"]; exists {
					return fmt.Errorf("DELETE %s must not define a request body", route)
				}
			}
		}
	}

	for operationID, wantLocation := range map[string]string{
		"createWorkspace":        "POST /api/v1alpha1/workspaces",
		"deleteWorkspace":        "DELETE /api/v1alpha1/workspaces/{workspaceId}",
		"getOperation":           "GET /api/v1alpha1/operations/{operationId}",
		"getWorkspace":           "GET /api/v1alpha1/workspaces/{workspaceId}",
		"listWorkspaces":         "GET /api/v1alpha1/workspaces",
		"replaceWorkspace":       "PUT /api/v1alpha1/workspaces/{workspaceId}",
		"replaceWorkspaceStatus": "PUT /api/v1alpha1/workspaces/{workspaceId}/status",
	} {
		if gotLocation := operationIDs[operationID]; gotLocation != wantLocation {
			return fmt.Errorf("operationId %q must remain at %s, got %q", operationID, wantLocation, gotLocation)
		}
	}

	listItem, err := mapField(paths, "/api/v1alpha1/workspaces")
	if err != nil {
		return err
	}
	listOperation, err := mapField(listItem, "get")
	if err != nil {
		return err
	}
	listParameters, err := parameterReferences(listOperation["parameters"])
	if err != nil {
		return err
	}
	if !listParameters["PageSize"] || !listParameters["PageToken"] {
		return errors.New("listWorkspaces omits keyset pagination parameters")
	}

	statusItem, err := mapField(paths, "/api/v1alpha1/workspaces/{workspaceId}/status")
	if err != nil {
		return err
	}
	statusOperation, err := mapField(statusItem, "put")
	if err != nil {
		return err
	}
	if statusOperation["x-veer-write-class"] != "status" {
		return errors.New("status route is not classified as status-only")
	}
	return nil
}

func validateBearerSecurity(raw any) error {
	security, ok := raw.([]any)
	if !ok || len(security) != 1 {
		return errors.New("must contain exactly one BearerAuth requirement")
	}
	requirement, ok := security[0].(map[string]any)
	if !ok || len(requirement) != 1 {
		return errors.New("BearerAuth requirement is malformed")
	}
	scopes, ok := requirement["BearerAuth"].([]any)
	if !ok || len(scopes) != 0 {
		return errors.New("must require BearerAuth without OAuth scopes")
	}
	return nil
}

func validateSuccessResponse(operationID string, responses map[string]any) error {
	want := map[string]struct {
		status    string
		component string
	}{
		"createWorkspace":        {status: "202", component: "MutationAccepted"},
		"deleteWorkspace":        {status: "202", component: "MutationAccepted"},
		"getOperation":           {status: "200", component: "Operation"},
		"getWorkspace":           {status: "200", component: "Workspace"},
		"listWorkspaces":         {status: "200", component: "WorkspaceList"},
		"replaceWorkspace":       {status: "202", component: "MutationAccepted"},
		"replaceWorkspaceStatus": {status: "200", component: "StatusUpdated"},
	}
	expected, exists := want[operationID]
	if !exists {
		return fmt.Errorf("operationId %q has no reviewed success contract", operationID)
	}
	response, ok := responses[expected.status].(map[string]any)
	if !ok || response["$ref"] != "#/components/responses/"+expected.component {
		return fmt.Errorf("operationId %q must use %s response %s", operationID, expected.status, expected.component)
	}
	for status := range responses {
		if len(status) == 3 && status[0] == '2' && status != expected.status {
			return fmt.Errorf("operationId %q declares unexpected success response %s", operationID, status)
		}
	}
	return nil
}

func validateResponseReferences(route, method string, responses map[string]any) error {
	want := map[string]string{
		"400": "ValidationFailure",
		"401": "AuthenticationRequired",
		"403": "AuthorizationDenied",
		"404": "NotFound",
		"409": "Conflict",
		"412": "PreconditionFailed",
		"413": "RequestTooLarge",
		"415": "UnsupportedMediaType",
		"428": "PreconditionRequired",
		"429": "Throttled",
		"500": "InternalFailure",
		"503": "Unavailable",
	}
	for status, raw := range responses {
		if len(status) == 3 && status[0] == '2' {
			continue
		}
		component, exists := want[status]
		if !exists {
			return fmt.Errorf("%s %s declares unreviewed error response %s", strings.ToUpper(method), route, status)
		}
		response, ok := raw.(map[string]any)
		if !ok || response["$ref"] != "#/components/responses/"+component {
			return fmt.Errorf("%s %s response %s must reference %s", strings.ToUpper(method), route, status, component)
		}
	}
	return nil
}

func parameterReferences(raw any) (map[string]bool, error) {
	result := make(map[string]bool)
	if raw == nil {
		return result, nil
	}
	parameters, ok := raw.([]any)
	if !ok {
		return nil, errors.New("parameters is not an array")
	}
	for _, rawParameter := range parameters {
		parameter, ok := rawParameter.(map[string]any)
		if !ok {
			return nil, errors.New("parameter entry is not an object")
		}
		ref, ok := parameter["$ref"].(string)
		if !ok || !strings.HasPrefix(ref, "#/components/parameters/") {
			return nil, errors.New("parameter is not a local component reference")
		}
		name := strings.TrimPrefix(ref, "#/components/parameters/")
		if result[name] {
			return nil, fmt.Errorf("duplicate parameter reference %s", name)
		}
		result[name] = true
	}
	return result, nil
}

func validateJSONRequestBody(operationID string, operation map[string]any) error {
	requestBody, err := mapField(operation, "requestBody")
	if err != nil {
		return err
	}
	if requestBody["required"] != true {
		return errors.New("requestBody is not required")
	}
	content, err := mapField(requestBody, "content")
	if err != nil {
		return err
	}
	if len(content) != 1 || content["application/json"] == nil {
		return errors.New("requestBody media type must be exactly application/json")
	}
	media, err := mapField(content, "application/json")
	if err != nil {
		return err
	}
	schema, err := mapField(media, "schema")
	if err != nil {
		return err
	}
	want := map[string]string{
		"createWorkspace":        "WorkspaceCreate",
		"replaceWorkspace":       "WorkspaceReplace",
		"replaceWorkspaceStatus": "WorkspaceStatusWrite",
	}[operationID]
	if want == "" || schema["$ref"] != "#/components/schemas/"+want {
		return fmt.Errorf("operationId %q must use request schema %s", operationID, want)
	}
	return nil
}

func validateComponents(root map[string]any) error {
	components, err := mapField(root, "components")
	if err != nil {
		return err
	}
	securitySchemes, err := mapField(components, "securitySchemes")
	if err != nil {
		return err
	}
	bearer, err := mapField(securitySchemes, "BearerAuth")
	if err != nil {
		return err
	}
	if bearer["type"] != "http" || bearer["scheme"] != "bearer" {
		return errors.New("BearerAuth must remain an HTTP bearer scheme")
	}
	parameters, err := mapField(components, "parameters")
	if err != nil {
		return err
	}
	if err := validateParameters(parameters); err != nil {
		return err
	}
	headers, err := mapField(components, "headers")
	if err != nil {
		return err
	}
	if err := validateHeaders(headers); err != nil {
		return err
	}
	responses, err := mapField(components, "responses")
	if err != nil {
		return err
	}
	if err := validateResponses(responses); err != nil {
		return err
	}
	schemas, err := mapField(components, "schemas")
	if err != nil {
		return err
	}
	return validateSchemas(schemas)
}

func validateParameters(parameters map[string]any) error {
	required := []string{"VeerRequestId", "IdempotencyKey", "IfMatch", "WorkspaceId", "OperationId", "PageSize", "PageToken"}
	for _, name := range required {
		if _, exists := parameters[name]; !exists {
			return fmt.Errorf("parameter %s is missing", name)
		}
	}

	idempotency, err := mapField(parameters, "IdempotencyKey")
	if err != nil {
		return err
	}
	if idempotency["name"] != "Idempotency-Key" || idempotency["in"] != "header" || idempotency["required"] != true {
		return errors.New("IdempotencyKey header contract drifted")
	}
	if err := requireSchemaReference(idempotency, "#/components/schemas/IdempotencyKey"); err != nil {
		return fmt.Errorf("IdempotencyKey: %w", err)
	}
	ifMatch, err := mapField(parameters, "IfMatch")
	if err != nil {
		return err
	}
	if ifMatch["name"] != "If-Match" || ifMatch["in"] != "header" || ifMatch["required"] != true {
		return errors.New("IfMatch header contract drifted")
	}
	if err := requireSchemaReference(ifMatch, "#/components/schemas/StrongETag"); err != nil {
		return fmt.Errorf("IfMatch: %w", err)
	}
	requestID, err := mapField(parameters, "VeerRequestId")
	if err != nil {
		return err
	}
	if requestID["name"] != "Veer-Request-Id" || requestID["in"] != "header" || requestID["required"] != false {
		return errors.New("VeerRequestId header contract drifted")
	}
	if err := requireSchemaReference(requestID, "#/components/schemas/RequestId"); err != nil {
		return fmt.Errorf("VeerRequestId: %w", err)
	}
	pageSize, err := mapField(parameters, "PageSize")
	if err != nil {
		return err
	}
	pageSizeSchema, err := mapField(pageSize, "schema")
	if err != nil {
		return err
	}
	if pageSize["name"] != "pageSize" || pageSize["in"] != "query" || pageSize["required"] != false ||
		pageSizeSchema["type"] != "integer" || !numberEquals(pageSizeSchema["minimum"], "1") ||
		!numberEquals(pageSizeSchema["default"], "50") || !numberEquals(pageSizeSchema["maximum"], "100") {
		return errors.New("PageSize parameter contract drifted")
	}
	pageToken, err := mapField(parameters, "PageToken")
	if err != nil {
		return err
	}
	pageTokenSchema, err := mapField(pageToken, "schema")
	if err != nil {
		return err
	}
	if pageToken["name"] != "pageToken" || pageToken["in"] != "query" || pageToken["required"] != false ||
		pageTokenSchema["type"] != "string" || !numberEquals(pageTokenSchema["minLength"], "16") ||
		!numberEquals(pageTokenSchema["maxLength"], "1024") || pageTokenSchema["pattern"] != "^[A-Za-z0-9_-]+$" {
		return errors.New("PageToken parameter contract drifted")
	}
	for name, wantSchema := range map[string]string{
		"OperationId": "OpaqueId",
		"WorkspaceId": "OpaqueId",
	} {
		parameter, err := mapField(parameters, name)
		if err != nil {
			return err
		}
		if parameter["in"] != "path" || parameter["required"] != true {
			return fmt.Errorf("%s path parameter contract drifted", name)
		}
		if err := requireSchemaReference(parameter, "#/components/schemas/"+wantSchema); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func requireSchemaReference(parent map[string]any, want string) error {
	schema, err := mapField(parent, "schema")
	if err != nil {
		return err
	}
	if schema["$ref"] != want {
		return fmt.Errorf("schema must reference %s", want)
	}
	return nil
}

func validateHeaders(headers map[string]any) error {
	for _, name := range []string{
		"Deprecation", "DeprecationLink", "ETag", "Location", "RetryAfter", "Sunset",
		"VeerRequestId", "WWWAuthenticate",
	} {
		if _, exists := headers[name]; !exists {
			return fmt.Errorf("header %s is missing", name)
		}
	}

	for name, want := range map[string]struct {
		minimum string
		maximum string
		pattern string
	}{
		"Location": {
			pattern: `^/api/v1alpha1/operations/[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`,
		},
		"WWWAuthenticate": {
			maximum: "64",
			pattern: `^Bearer realm="veer"(?:, error="(?:invalid_request|invalid_token)")?$`,
		},
		"DeprecationLink": {
			minimum: "1",
			maximum: "1024",
			pattern: `^<[^<>\r\n]{1,900}>; rel="deprecation"(?:, <[^<>\r\n]{1,900}>; rel="sunset")?$`,
		},
	} {
		header, err := mapField(headers, name)
		if err != nil {
			return err
		}
		schema, err := mapField(header, "schema")
		if err != nil {
			return err
		}
		if schema["type"] != "string" || schema["pattern"] != want.pattern ||
			(want.minimum != "" && !numberEquals(schema["minLength"], want.minimum)) ||
			(want.maximum != "" && !numberEquals(schema["maxLength"], want.maximum)) {
			return fmt.Errorf("%s header contract drifted", name)
		}
	}
	return nil
}

func validateResponses(responses map[string]any) error {
	successNames := map[string]bool{
		"MutationAccepted": true,
		"Operation":        true,
		"StatusUpdated":    true,
		"Workspace":        true,
		"WorkspaceList":    true,
	}
	errorNames := map[string]bool{
		"AuthenticationRequired": true,
		"AuthorizationDenied":    true,
		"Conflict":               true,
		"InternalFailure":        true,
		"NotFound":               true,
		"PreconditionFailed":     true,
		"PreconditionRequired":   true,
		"RequestTooLarge":        true,
		"Throttled":              true,
		"Unavailable":            true,
		"UnsupportedMediaType":   true,
		"ValidationFailure":      true,
	}
	for name := range successNames {
		if _, exists := responses[name]; !exists {
			return fmt.Errorf("success response %s is missing", name)
		}
	}
	for name := range errorNames {
		if _, exists := responses[name]; !exists {
			return fmt.Errorf("error response %s is missing", name)
		}
	}

	for name, raw := range responses {
		response, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("response %s is not an object", name)
		}
		headers, err := mapField(response, "headers")
		if err != nil {
			return fmt.Errorf("response %s: %w", name, err)
		}
		if err := requireReference(headers, "Veer-Request-Id", "#/components/headers/VeerRequestId"); err != nil {
			return fmt.Errorf("response %s: %w", name, err)
		}
		content, err := mapField(response, "content")
		if err != nil {
			return fmt.Errorf("response %s: %w", name, err)
		}
		if successNames[name] {
			if len(content) != 1 || content["application/json"] == nil {
				return fmt.Errorf("success response %s must use application/json", name)
			}
			for _, header := range []string{"Deprecation", "Sunset", "Link"} {
				component := map[string]string{
					"Deprecation": "Deprecation",
					"Link":        "DeprecationLink",
					"Sunset":      "Sunset",
				}[header]
				if err := requireReference(headers, header, "#/components/headers/"+component); err != nil {
					return fmt.Errorf("success response %s: %w", name, err)
				}
			}
			media, _ := mapField(content, "application/json")
			schema, err := mapField(media, "schema")
			if err != nil {
				return fmt.Errorf("success response %s: %w", name, err)
			}
			wantSchema := map[string]string{
				"MutationAccepted": "MutationReceipt",
				"Operation":        "Operation",
				"StatusUpdated":    "StatusReceipt",
				"Workspace":        "Workspace",
				"WorkspaceList":    "WorkspaceList",
			}[name]
			if schema["$ref"] != "#/components/schemas/"+wantSchema {
				return fmt.Errorf("success response %s uses the wrong schema", name)
			}
		}
		if errorNames[name] {
			if len(content) != 1 || content["application/problem+json"] == nil {
				return fmt.Errorf("error response %s must use application/problem+json", name)
			}
			media, _ := mapField(content, "application/problem+json")
			schema, err := mapField(media, "schema")
			if err != nil {
				return fmt.Errorf("error response %s: %w", name, err)
			}
			if schema["$ref"] != "#/components/schemas/Problem" {
				return fmt.Errorf("error response %s must reference Problem", name)
			}
		}
		for header, component := range map[string]map[string]string{
			"AuthenticationRequired": {"WWW-Authenticate": "WWWAuthenticate"},
			"MutationAccepted":       {"Location": "Location"},
			"Operation":              {"ETag": "ETag"},
			"PreconditionFailed":     {"ETag": "ETag"},
			"StatusUpdated":          {"ETag": "ETag"},
			"Throttled":              {"Retry-After": "RetryAfter"},
			"Unavailable":            {"Retry-After": "RetryAfter"},
			"Workspace":              {"ETag": "ETag"},
		}[name] {
			if err := requireReference(headers, header, "#/components/headers/"+component); err != nil {
				return fmt.Errorf("response %s: %w", name, err)
			}
		}

		exampleContract, hasCanonicalExample := map[string]struct {
			entry     string
			component string
		}{
			"AuthenticationRequired": {entry: "authentication", component: "AuthenticationRequired"},
			"AuthorizationDenied":    {entry: "authorization", component: "AuthorizationDenied"},
			"Conflict":               {entry: "conflict", component: "Conflict"},
			"InternalFailure":        {entry: "internal", component: "InternalFailure"},
			"Throttled":              {entry: "throttling", component: "Throttled"},
			"ValidationFailure":      {entry: "validation", component: "ValidationFailure"},
		}[name]
		if hasCanonicalExample {
			media, _ := mapField(content, "application/problem+json")
			examples, err := mapField(media, "examples")
			if err != nil {
				return fmt.Errorf("error response %s: %w", name, err)
			}
			if len(examples) != 1 {
				return fmt.Errorf("error response %s must bind exactly one canonical example", name)
			}
			if err := requireReference(examples, exampleContract.entry, "#/components/examples/"+exampleContract.component); err != nil {
				return fmt.Errorf("error response %s: %w", name, err)
			}
		}
	}
	return nil
}

func requireReference(parent map[string]any, name, want string) error {
	value, err := mapField(parent, name)
	if err != nil {
		return fmt.Errorf("%s is missing", name)
	}
	if value["$ref"] != want {
		return fmt.Errorf("%s must reference %s", name, want)
	}
	return nil
}

func validateSchemas(schemas map[string]any) error {
	required := []string{
		"Condition", "FieldViolation", "IdempotencyKey", "Labels", "MutationReceipt",
		"OpaqueId", "Operation", "Problem", "RequestId", "ResourceMetadata", "StatusReceipt", "StrongETag",
		"Timestamp", "Workspace", "WorkspaceCreate", "WorkspaceList", "WorkspaceReplace",
		"WorkspaceSpec", "WorkspaceStatus", "WorkspaceStatusWrite", "WritableMetadata",
	}
	for _, name := range required {
		if _, exists := schemas[name]; !exists {
			return fmt.Errorf("schema %s is missing", name)
		}
	}

	timestamp, err := mapField(schemas, "Timestamp")
	if err != nil {
		return err
	}
	if timestamp["format"] != "date-time" || timestamp["pattern"] != timestampPattern {
		return errors.New("timestamp format or precision drifted")
	}

	metadata, err := mapField(schemas, "ResourceMetadata")
	if err != nil {
		return err
	}
	metadataProperties, err := mapField(metadata, "properties")
	if err != nil {
		return err
	}
	for _, name := range []string{"generation", "resourceVersion"} {
		property, err := mapField(metadataProperties, name)
		if err != nil {
			return err
		}
		if property["readOnly"] != true {
			return fmt.Errorf("ResourceMetadata.%s must be readOnly", name)
		}
	}
	generation, _ := mapField(metadataProperties, "generation")
	if !numberEquals(generation["minimum"], "1") {
		return errors.New("generation must start at 1")
	}

	writable, err := mapField(schemas, "WritableMetadata")
	if err != nil {
		return err
	}
	writableProperties, err := mapField(writable, "properties")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"id", "generation", "resourceVersion", "createdAt", "updatedAt"} {
		if _, exists := writableProperties[forbidden]; exists {
			return fmt.Errorf("WritableMetadata exposes server-owned field %s", forbidden)
		}
	}

	statusWrite, err := mapField(schemas, "WorkspaceStatusWrite")
	if err != nil {
		return err
	}
	statusProperties, err := mapField(statusWrite, "properties")
	if err != nil {
		return err
	}
	for _, forbidden := range []string{"metadata", "spec", "generation", "resourceVersion"} {
		if _, exists := statusProperties[forbidden]; exists {
			return fmt.Errorf("WorkspaceStatusWrite exposes %s", forbidden)
		}
	}
	if _, exists := statusProperties["status"]; !exists {
		return errors.New("WorkspaceStatusWrite omits status")
	}

	statusReceipt, err := mapField(schemas, "StatusReceipt")
	if err != nil {
		return err
	}
	if !stringSetEquals(statusReceipt["required"], []string{"resourceId", "observedGeneration", "resourceVersion", "updatedAt"}) {
		return errors.New("StatusReceipt required fields drifted")
	}
	statusReceiptProperties, err := mapField(statusReceipt, "properties")
	if err != nil {
		return err
	}
	if len(statusReceiptProperties) != 4 {
		return errors.New("StatusReceipt must remain a four-field bounded response")
	}
	if err := requireReference(statusReceiptProperties, "resourceId", "#/components/schemas/OpaqueId"); err != nil {
		return fmt.Errorf("StatusReceipt: %w", err)
	}
	if err := requireReference(statusReceiptProperties, "updatedAt", "#/components/schemas/Timestamp"); err != nil {
		return fmt.Errorf("StatusReceipt: %w", err)
	}
	observedGeneration, err := mapField(statusReceiptProperties, "observedGeneration")
	if err != nil {
		return err
	}
	if observedGeneration["type"] != "integer" || observedGeneration["format"] != "int64" ||
		!numberEquals(observedGeneration["minimum"], "0") ||
		!numberEquals(observedGeneration["maximum"], "9223372036854775807") {
		return errors.New("StatusReceipt observedGeneration contract drifted")
	}
	statusResourceVersion, err := mapField(statusReceiptProperties, "resourceVersion")
	if err != nil {
		return err
	}
	if statusResourceVersion["type"] != "string" || !numberEquals(statusResourceVersion["minLength"], "1") ||
		!numberEquals(statusResourceVersion["maxLength"], "128") || statusResourceVersion["pattern"] != "^[A-Za-z0-9_-]+$" {
		return errors.New("StatusReceipt resourceVersion contract drifted")
	}

	list, err := mapField(schemas, "WorkspaceList")
	if err != nil {
		return err
	}
	listProperties, err := mapField(list, "properties")
	if err != nil {
		return err
	}
	items, err := mapField(listProperties, "items")
	if err != nil {
		return err
	}
	if !numberEquals(items["maxItems"], "100") {
		return errors.New("WorkspaceList item bound drifted")
	}
	if _, exists := listProperties["nextPageToken"]; !exists {
		return errors.New("WorkspaceList omits nextPageToken")
	}

	problem, err := mapField(schemas, "Problem")
	if err != nil {
		return err
	}
	if problem["additionalProperties"] != false {
		return errors.New("problem must reject undeclared extensions")
	}
	if !stringSetEquals(problem["required"], []string{"type", "title", "status", "code", "requestId"}) {
		return errors.New("problem required fields drifted")
	}
	return nil
}

func validateExamples(root map[string]any) error {
	components, err := mapField(root, "components")
	if err != nil {
		return err
	}
	examples, err := mapField(components, "examples")
	if err != nil {
		return err
	}
	want := map[string]struct {
		status string
		code   string
	}{
		"ValidationFailure":      {status: "400", code: "validation-failed"},
		"AuthenticationRequired": {status: "401", code: "authentication-required"},
		"AuthorizationDenied":    {status: "403", code: "authorization-denied"},
		"Conflict":               {status: "409", code: "idempotency-key-reused"},
		"Throttled":              {status: "429", code: "rate-limited"},
		"InternalFailure":        {status: "500", code: "internal-failure"},
	}
	if len(examples) != len(want) {
		return fmt.Errorf("expected %d canonical problem examples, got %d", len(want), len(examples))
	}
	for name, expected := range want {
		example, err := mapField(examples, name)
		if err != nil {
			return err
		}
		value, err := mapField(example, "value")
		if err != nil {
			return err
		}
		if !numberEquals(value["status"], expected.status) || value["code"] != expected.code {
			return fmt.Errorf("example %s status or code drifted", name)
		}
		if value["type"] != "urn:veer:problem:"+expected.code {
			return fmt.Errorf("example %s type is not bound to its code", name)
		}
		requestID, requestOK := value["requestId"].(string)
		instance, instanceOK := value["instance"].(string)
		if !requestOK || !instanceOK || instance != "urn:veer:request:"+requestID {
			return fmt.Errorf("example %s requestId and instance are not bound", name)
		}
	}
	return nil
}

func mapField(parent map[string]any, name string) (map[string]any, error) {
	raw, exists := parent[name]
	if !exists {
		return nil, fmt.Errorf("%s is missing", name)
	}
	result, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an object", name)
	}
	return result, nil
}

func numberEquals(value any, want string) bool {
	number, ok := value.(json.Number)
	return ok && number.String() == want
}

func stringSetEquals(value any, want []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(want) {
		return false
	}
	got := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return false
		}
		got = append(got, text)
	}
	sort.Strings(got)
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	return reflect.DeepEqual(got, sortedWant)
}
