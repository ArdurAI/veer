// Package openapi verifies Veer's checked-in transport and evolution contract.
package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxContractBytes             = 1 << 20
	maxJSONDepth                 = 64
	maxJSONNodes                 = 50000
	minimumDeprecationNoticeDays = 90
	deprecationPattern           = `^@[0-9]{10,12}$`
	deprecationLinkTargetPattern = `[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,900}`
	deprecationLinkPattern       = `^<` + deprecationLinkTargetPattern + `>; rel="deprecation"(, <` + deprecationLinkTargetPattern + `>; rel="sunset")?$`
	fieldPointerPattern          = `^(/([^~/]|~0|~1)*)+$`
	retryAfterPattern            = `^([1-9][0-9]{0,3}|[1-7][0-9]{4}|8[0-5][0-9]{3}|86[0-3][0-9]{2}|86400)$`
	safeProblemTextPattern       = `^[\x20-\x21\x23-\x25\x27-\x3B\x3D\x3F-\x5B\x5D-\x7E]*$`
	sunsetPattern                = `^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), (0[1-9]|[12][0-9]|3[01]) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} ([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] GMT$`
	timestampPattern             = `^((\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\d|3[01])|(0[469]|11)-(0[1-9]|[12]\d|30)|02-(0[1-9]|1\d|2[0-8])))|((\d{2}(0[48]|[2468][048]|[13579][26])|([02468][048]|[13579][26])00)-02-29))T([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$`
)

type operationContract struct {
	location   string
	writeClass string
	parameters []string
	responses  []string
}

type problemVariant struct {
	schema   string
	code     string
	title    string
	required []string
}

type problemContract struct {
	schema   string
	status   string
	code     string
	title    string
	required []string
	variants []problemVariant
}

var operationContracts = map[string]operationContract{
	"listWorkspaces": {
		location:   "GET /api/v1alpha1/workspaces",
		parameters: []string{"VeerRequestId", "PageSize", "PageToken"},
		responses:  []string{"200", "400", "401", "403", "429", "500", "503"},
	},
	"createWorkspace": {
		location:   "POST /api/v1alpha1/workspaces",
		writeClass: "spec",
		parameters: []string{"VeerRequestId", "IdempotencyKey"},
		responses:  []string{"202", "400", "401", "403", "409", "413", "415", "429", "500", "503"},
	},
	"getWorkspace": {
		location:   "GET /api/v1alpha1/workspaces/{workspaceId}",
		parameters: []string{"VeerRequestId", "WorkspaceId"},
		responses:  []string{"200", "400", "401", "403", "404", "429", "500", "503"},
	},
	"replaceWorkspace": {
		location:   "PUT /api/v1alpha1/workspaces/{workspaceId}",
		writeClass: "spec",
		parameters: []string{"VeerRequestId", "WorkspaceId", "IdempotencyKey", "IfMatch"},
		responses:  []string{"202", "400", "401", "403", "404", "409", "412", "413", "415", "428", "429", "500", "503"},
	},
	"deleteWorkspace": {
		location:   "DELETE /api/v1alpha1/workspaces/{workspaceId}",
		writeClass: "delete",
		parameters: []string{"VeerRequestId", "WorkspaceId", "IdempotencyKey", "IfMatch"},
		responses:  []string{"202", "400", "401", "403", "404", "409", "412", "428", "429", "500", "503"},
	},
	"replaceWorkspaceStatus": {
		location:   "PUT /api/v1alpha1/workspaces/{workspaceId}/status",
		writeClass: "status",
		parameters: []string{"VeerRequestId", "WorkspaceId", "IdempotencyKey", "IfMatch"},
		responses:  []string{"200", "400", "401", "403", "404", "409", "412", "413", "415", "428", "429", "500", "503"},
	},
	"getOperation": {
		location:   "GET /api/v1alpha1/operations/{operationId}",
		parameters: []string{"VeerRequestId", "OperationId"},
		responses:  []string{"200", "400", "401", "403", "404", "429", "500", "503"},
	},
}

var problemContracts = map[string]problemContract{
	"ValidationFailure": {
		schema: "ValidationProblem", status: "400", code: "validation-failed", title: "Request validation failed",
	},
	"AuthenticationRequired": {
		schema: "AuthenticationProblem", status: "401", code: "authentication-required", title: "Authentication required",
	},
	"AuthorizationDenied": {
		schema: "AuthorizationProblem", status: "403", code: "authorization-denied", title: "Authorization denied",
	},
	"NotFound": {schema: "NotFoundProblem", status: "404", code: "not-found", title: "Resource not found"},
	"Conflict": {
		schema: "ConflictProblem",
		status: "409",
		variants: []problemVariant{
			{
				schema: "IdempotencyConflictProblem", code: "idempotency-key-reused",
				title: "Request conflicts with a prior mutation",
			},
			{
				schema: "UniquenessConflictProblem", code: "uniqueness-conflict", title: "Resource uniqueness conflict",
			},
			{
				schema: "LifecycleConflictProblem", code: "lifecycle-conflict", title: "Resource lifecycle conflict",
			},
			{schema: "PolicyConflictProblem", code: "policy-conflict", title: "Resource policy conflict"},
		},
	},
	"PreconditionFailed": {
		schema: "PreconditionFailedProblem", status: "412", code: "precondition-failed", title: "Resource version is stale",
	},
	"RequestTooLarge": {
		schema: "RequestTooLargeProblem", status: "413", code: "request-too-large", title: "Request body is too large",
	},
	"UnsupportedMediaType": {
		schema: "UnsupportedMediaTypeProblem", status: "415", code: "unsupported-media-type",
		title: "Unsupported request media type",
	},
	"PreconditionRequired": {
		schema: "PreconditionRequiredProblem", status: "428", code: "precondition-required",
		title: "Mutation precondition required",
	},
	"Throttled": {
		schema: "ThrottledProblem", status: "429", code: "rate-limited", title: "Request rate limited",
		required: []string{"retryAfterSeconds"},
	},
	"InternalFailure": {
		schema: "InternalFailureProblem", status: "500", code: "internal-failure", title: "Internal failure",
	},
	"Unavailable": {
		schema: "UnavailableProblem", status: "503", code: "unavailable", title: "Service temporarily unavailable",
		required: []string{"retryAfterSeconds"},
	},
}

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

var (
	deprecationLinkValuePattern = regexp.MustCompile(deprecationLinkPattern)
	deprecationValuePattern     = regexp.MustCompile(deprecationPattern)
	lowerCamelCaseProperty      = regexp.MustCompile(`^[a-z][a-z0-9]*([A-Z][a-z0-9]+)*$`)
	timestampValuePattern       = regexp.MustCompile(timestampPattern)
)

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
		for key := range typed {
			if len(key) >= 2 && strings.EqualFold(key[:2], "x-") && !isReviewedExtension(path, key) {
				return fmt.Errorf("%s uses unreviewed extension %q", path, key)
			}
		}
		if _, exists := typed["patternProperties"]; exists {
			return fmt.Errorf("%s uses unreviewed patternProperties", path)
		}
		if _, markedFreeForm := typed["x-veer-free-form-map"]; markedFreeForm &&
			!isReviewedFreeFormMap(path, typed) {
			return fmt.Errorf("%s is not the reviewed free-form Labels map", path)
		}
		if rawProperties, hasProperties := typed["properties"]; hasProperties {
			if typed["type"] != "object" && !isReviewedProblemRefinement(path, typed) {
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
				if !isReviewedFreeFormMap(path, typed) {
					return fmt.Errorf("%s is not the reviewed free-form Labels map", path)
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

func isReviewedProblemRefinement(path string, schema map[string]any) bool {
	if schema["x-veer-refinement"] != true {
		return false
	}
	for _, contract := range problemContracts {
		for _, variant := range problemVariantsFor(contract) {
			if path == "$/components/schemas/"+variant.schema+"/allOf/1" {
				return true
			}
		}
	}
	return false
}

func isReviewedFreeFormMap(path string, schema map[string]any) bool {
	return path == "$/components/schemas/Labels" && schema["x-veer-free-form-map"] == true
}

func isReviewedExtension(path, name string) bool {
	switch name {
	case "x-veer-evolution":
		return path == "$"
	case "x-veer-write-class":
		return strings.HasPrefix(path, "$/paths/") &&
			(strings.HasSuffix(path, "/post") ||
				strings.HasSuffix(path, "/put") ||
				strings.HasSuffix(path, "/patch") ||
				strings.HasSuffix(path, "/delete"))
	case "x-veer-calendar-validation":
		switch path {
		case "$/components/headers/Deprecation/schema",
			"$/components/headers/Sunset/schema",
			"$/components/schemas/Timestamp":
			return true
		default:
			return false
		}
	case "x-veer-link-target-validation":
		return path == "$/components/headers/DeprecationLink/schema"
	case "x-veer-request-id-binding":
		return path == "$/components/headers/VeerRequestId"
	case "x-veer-deprecation-sunset-minimum-notice-days",
		"x-veer-etag-resource-version-pointer",
		"x-veer-location-operation-id-pointer",
		"x-veer-request-id-body-pointer",
		"x-veer-required-header-sets",
		"x-veer-required-headers",
		"x-veer-retry-after-body-pointer":
		return isResponseComponentPath(path)
	case "x-veer-free-form-map":
		return true
	case "x-veer-instance-request-id-template":
		return path == "$/components/schemas/Problem"
	case "x-veer-maximum-encoded-json-bytes":
		return path == "$/components/schemas/FieldViolation/properties/field"
	case "x-veer-maximum-json-bytes":
		switch path {
		case "$/components/schemas/MutationReceipt",
			"$/components/schemas/Problem",
			"$/components/schemas/StatusReceipt",
			"$/components/schemas/Workspace",
			"$/components/schemas/WorkspaceList":
			return true
		default:
			return false
		}
	case "x-veer-page-byte-policy":
		return path == "$/components/schemas/WorkspaceList"
	case "x-veer-refinement":
		for _, contract := range problemContracts {
			for _, variant := range problemVariantsFor(contract) {
				if path == "$/components/schemas/"+variant.schema+"/allOf/1" {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

func isResponseComponentPath(path string) bool {
	const prefix = "$/components/responses/"
	name := strings.TrimPrefix(path, prefix)
	return name != path && name != "" && !strings.Contains(name, "/")
}

func problemVariantsFor(contract problemContract) []problemVariant {
	if len(contract.variants) > 0 {
		return contract.variants
	}
	return []problemVariant{{
		schema: contract.schema, code: contract.code, title: contract.title, required: contract.required,
	}}
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
			Initial: 1,
			Advance: "once-per-semantic-spec-change",
			Unchanged: []string{
				"metadata-only-write",
				"status-only-write",
				"lifecycle-only-write",
				"deletion-write",
				"idempotent-replay",
			},
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
			location := strings.ToUpper(method) + " " + route
			expected, reviewed := operationContracts[operationID]
			if !reviewed {
				return fmt.Errorf("operationId %q has no reviewed contract", operationID)
			}
			if location != expected.location {
				return fmt.Errorf("operationId %q must remain at %s, got %q", operationID, expected.location, location)
			}
			operationIDs[operationID] = location
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
			effectiveParameters := make(map[string]bool, len(pathParameters)+len(operationParameters))
			for name := range pathParameters {
				effectiveParameters[name] = true
			}
			for name := range operationParameters {
				effectiveParameters[name] = true
			}
			if method == "get" {
				if _, exists := operation["x-veer-write-class"]; exists {
					return fmt.Errorf("GET %s declares a write class", route)
				}
				if _, exists := operation["requestBody"]; exists {
					return fmt.Errorf("GET %s must not define a request body", route)
				}
				if effectiveParameters["IdempotencyKey"] || effectiveParameters["IfMatch"] {
					return fmt.Errorf("GET %s carries mutation headers", route)
				}
				if !boolKeySetEquals(effectiveParameters, expected.parameters) {
					return fmt.Errorf("operationId %q parameter set drifted", operationID)
				}
				if err := validateResponseSet(operationID, responses, expected.responses); err != nil {
					return err
				}
				continue
			}

			writeClass, ok := operation["x-veer-write-class"].(string)
			if !ok || writeClass != expected.writeClass {
				return fmt.Errorf("operationId %q write class must be %q", operationID, expected.writeClass)
			}
			if !effectiveParameters["IdempotencyKey"] {
				return fmt.Errorf("%s %s omits IdempotencyKey", strings.ToUpper(method), route)
			}
			if _, exists := responses["409"]; !exists {
				return fmt.Errorf("%s %s omits conflict response 409", strings.ToUpper(method), route)
			}
			if method != "post" && !effectiveParameters["IfMatch"] {
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
				for _, status := range []string{"413", "415"} {
					if _, exists := responses[status]; !exists {
						return fmt.Errorf("%s %s omits request-body response %s", strings.ToUpper(method), route, status)
					}
				}
				if err := validateJSONRequestBody(operationID, operation); err != nil {
					return fmt.Errorf("%s %s: %w", strings.ToUpper(method), route, err)
				}
			}
			if method == "delete" {
				if _, exists := operation["requestBody"]; exists {
					return fmt.Errorf("DELETE %s must not define a request body", route)
				}
			}
			if !boolKeySetEquals(effectiveParameters, expected.parameters) {
				return fmt.Errorf("operationId %q parameter set drifted", operationID)
			}
			if err := validateResponseSet(operationID, responses, expected.responses); err != nil {
				return err
			}
		}
	}

	for operationID, expected := range operationContracts {
		if gotLocation := operationIDs[operationID]; gotLocation != expected.location {
			return fmt.Errorf("operationId %q must remain at %s, got %q", operationID, expected.location, gotLocation)
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
	if err := requireReference(
		responses,
		expected.status,
		"#/components/responses/"+expected.component,
	); err != nil {
		return fmt.Errorf(
			"operationId %q must use %s response %s: %w",
			operationID,
			expected.status,
			expected.component,
			err,
		)
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
	for status := range responses {
		if len(status) == 3 && status[0] == '2' {
			continue
		}
		component, exists := want[status]
		if !exists {
			return fmt.Errorf("%s %s declares unreviewed error response %s", strings.ToUpper(method), route, status)
		}
		if err := requireReference(responses, status, "#/components/responses/"+component); err != nil {
			return fmt.Errorf(
				"%s %s response %s must reference %s: %w",
				strings.ToUpper(method),
				route,
				status,
				component,
				err,
			)
		}
	}
	return nil
}

func validateResponseSet(operationID string, responses map[string]any, want []string) error {
	for _, status := range want {
		if _, exists := responses[status]; !exists {
			return fmt.Errorf("operationId %q omits required response %s", operationID, status)
		}
	}
	if len(responses) != len(want) {
		return fmt.Errorf("operationId %q response set drifted", operationID)
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
		if !mapKeySetEquals(parameter, []string{"$ref"}) {
			return nil, errors.New("parameter reference has unreviewed keywords")
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
	want := map[string]string{
		"createWorkspace":        "WorkspaceCreate",
		"replaceWorkspace":       "WorkspaceReplace",
		"replaceWorkspaceStatus": "WorkspaceStatusWrite",
	}[operationID]
	if want == "" {
		return fmt.Errorf("operationId %q must use request schema %s", operationID, want)
	}
	if err := requireReference(media, "schema", "#/components/schemas/"+want); err != nil {
		return fmt.Errorf("operationId %q must use request schema %s: %w", operationID, want, err)
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
		pageSizeSchema["type"] != "integer" || pageSizeSchema["format"] != "int32" ||
		!numberEquals(pageSizeSchema["minimum"], "1") ||
		!numberEquals(pageSizeSchema["default"], "50") || !numberEquals(pageSizeSchema["maximum"], "100") {
		return errors.New("PageSize parameter contract drifted")
	}
	if !mapKeySetEquals(pageSizeSchema, []string{"type", "format", "minimum", "maximum", "default"}) {
		return errors.New("PageSize schema has unreviewed keywords")
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
	if !mapKeySetEquals(pageTokenSchema, []string{"type", "minLength", "maxLength", "pattern"}) {
		return errors.New("PageToken schema has unreviewed keywords")
	}
	for _, contract := range []struct {
		component string
		wireName  string
		schema    string
	}{
		{component: "OperationId", wireName: "operationId", schema: "OpaqueId"},
		{component: "WorkspaceId", wireName: "workspaceId", schema: "OpaqueId"},
	} {
		parameter, err := mapField(parameters, contract.component)
		if err != nil {
			return err
		}
		if parameter["name"] != contract.wireName || parameter["in"] != "path" || parameter["required"] != true {
			return fmt.Errorf("%s path parameter contract drifted", contract.component)
		}
		if err := requireSchemaReference(parameter, "#/components/schemas/"+contract.schema); err != nil {
			return fmt.Errorf("%s: %w", contract.component, err)
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
	if !mapKeySetEquals(schema, []string{"$ref"}) {
		return errors.New("schema has unreviewed keywords")
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
	for name, want := range map[string]string{
		"ETag":          "#/components/schemas/StrongETag",
		"VeerRequestId": "#/components/schemas/RequestId",
	} {
		header, err := mapField(headers, name)
		if err != nil {
			return err
		}
		if err := requireSchemaReference(header, want); err != nil {
			return fmt.Errorf("%s header contract drifted: %w", name, err)
		}
	}
	requestIDHeader, err := mapField(headers, "VeerRequestId")
	if err != nil {
		return err
	}
	requestIDBinding, err := mapField(requestIDHeader, "x-veer-request-id-binding")
	if err != nil || !mapKeySetEquals(requestIDBinding, []string{"requestHeader", "whenPresent", "whenAbsent"}) ||
		requestIDBinding["requestHeader"] != "Veer-Request-Id" || requestIDBinding["whenPresent"] != "echo" ||
		requestIDBinding["whenAbsent"] != "generate" {
		return errors.New("VeerRequestId header request binding drifted")
	}

	for name, want := range map[string]struct {
		minimum string
		maximum string
		pattern string
	}{
		"Location": {
			pattern: `^/api/v1alpha1/operations/[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`,
		},
		"RetryAfter": {
			pattern: retryAfterPattern,
		},
		"WWWAuthenticate": {
			maximum: "64",
			pattern: `^Bearer realm="veer"(?:, error="(?:invalid_request|invalid_token)")?$`,
		},
		"Deprecation": {
			pattern: deprecationPattern,
		},
		"Sunset": {
			pattern: sunsetPattern,
		},
		"DeprecationLink": {
			minimum: "1",
			maximum: "1024",
			pattern: deprecationLinkPattern,
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
	deprecation, err := mapField(headers, "Deprecation")
	if err != nil {
		return err
	}
	deprecationSchema, err := mapField(deprecation, "schema")
	if err != nil {
		return err
	}
	deprecationExample, exampleOK := deprecationSchema["example"].(string)
	if deprecationSchema["x-veer-calendar-validation"] != "sf-date" ||
		!exampleOK || !validDeprecationDate(deprecationExample) {
		return errors.New("deprecation header calendar contract drifted")
	}
	sunset, err := mapField(headers, "Sunset")
	if err != nil {
		return err
	}
	sunsetSchema, err := mapField(sunset, "schema")
	if err != nil {
		return err
	}
	sunsetExample, exampleOK := sunsetSchema["example"].(string)
	if sunsetSchema["x-veer-calendar-validation"] != "http-date" || !exampleOK || !validSunset(sunsetExample) {
		return errors.New("sunset header calendar contract drifted")
	}
	if !validDeprecationWindow(deprecationExample, sunsetExample, minimumDeprecationNoticeDays) {
		return errors.New("deprecation/sunset example notice window drifted")
	}
	link, err := mapField(headers, "DeprecationLink")
	if err != nil {
		return err
	}
	linkSchema, err := mapField(link, "schema")
	if err != nil {
		return err
	}
	linkExample, exampleOK := linkSchema["example"].(string)
	if linkSchema["x-veer-link-target-validation"] != "rfc3986-https-or-origin-relative" ||
		!exampleOK || !validDeprecationLink(linkExample) {
		return errors.New("DeprecationLink header URI-reference contract drifted")
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
	errorNames := make(map[string]bool, len(problemContracts))
	for name := range problemContracts {
		errorNames[name] = true
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

	requiredHeaders := map[string][]string{
		"WorkspaceList":          {"Veer-Request-Id"},
		"Workspace":              {"Veer-Request-Id", "ETag"},
		"StatusUpdated":          {"Veer-Request-Id", "ETag"},
		"Operation":              {"Veer-Request-Id", "ETag"},
		"MutationAccepted":       {"Veer-Request-Id", "Location"},
		"ValidationFailure":      {"Veer-Request-Id"},
		"AuthenticationRequired": {"Veer-Request-Id", "WWW-Authenticate"},
		"AuthorizationDenied":    {"Veer-Request-Id"},
		"NotFound":               {"Veer-Request-Id"},
		"Conflict":               {"Veer-Request-Id"},
		"PreconditionFailed":     {"Veer-Request-Id", "ETag"},
		"PreconditionRequired":   {"Veer-Request-Id"},
		"RequestTooLarge":        {"Veer-Request-Id"},
		"UnsupportedMediaType":   {"Veer-Request-Id"},
		"Throttled":              {"Veer-Request-Id", "Retry-After"},
		"InternalFailure":        {"Veer-Request-Id"},
		"Unavailable":            {"Veer-Request-Id", "Retry-After"},
	}
	etagResourceVersionPointers := map[string]string{
		"Operation":     "/resourceVersion",
		"StatusUpdated": "/resourceVersion",
		"Workspace":     "/metadata/resourceVersion",
	}
	retryAfterPointers := map[string]string{
		"Throttled":   "/retryAfterSeconds",
		"Unavailable": "/retryAfterSeconds",
	}

	for name, raw := range responses {
		if !successNames[name] && !errorNames[name] {
			return fmt.Errorf("response component %s has no reviewed contract", name)
		}
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
		if !stringSetEquals(response["x-veer-required-headers"], requiredHeaders[name]) {
			return fmt.Errorf("response %s required-header contract drifted", name)
		}
		content, err := mapField(response, "content")
		if err != nil {
			return fmt.Errorf("response %s: %w", name, err)
		}
		if successNames[name] {
			if !stringMatrixEquals(
				response["x-veer-required-header-sets"],
				[][]string{{"Deprecation", "Sunset", "Link"}},
			) {
				return fmt.Errorf("success response %s deprecation-header contract drifted", name)
			}
			if !numberEquals(
				response["x-veer-deprecation-sunset-minimum-notice-days"],
				strconv.Itoa(minimumDeprecationNoticeDays),
			) {
				return fmt.Errorf("success response %s deprecation notice binding drifted", name)
			}
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
			wantSchema := map[string]string{
				"MutationAccepted": "MutationReceipt",
				"Operation":        "Operation",
				"StatusUpdated":    "StatusReceipt",
				"Workspace":        "Workspace",
				"WorkspaceList":    "WorkspaceList",
			}[name]
			if err := requireReference(media, "schema", "#/components/schemas/"+wantSchema); err != nil {
				return fmt.Errorf("success response %s uses the wrong schema: %w", name, err)
			}
			if pointer, mustBind := etagResourceVersionPointers[name]; mustBind {
				if response["x-veer-etag-resource-version-pointer"] != pointer {
					return fmt.Errorf("success response %s ETag binding drifted", name)
				}
			} else if _, exists := response["x-veer-etag-resource-version-pointer"]; exists {
				return fmt.Errorf("success response %s declares an unexpected ETag binding", name)
			}
			if name == "MutationAccepted" {
				if response["x-veer-location-operation-id-pointer"] != "/operationId" {
					return errors.New("success response MutationAccepted Location binding drifted")
				}
			} else if _, exists := response["x-veer-location-operation-id-pointer"]; exists {
				return fmt.Errorf("success response %s declares an unexpected Location binding", name)
			}
			if _, exists := response["x-veer-request-id-body-pointer"]; exists {
				return fmt.Errorf("success response %s declares an unexpected request-ID body binding", name)
			}
		}
		if errorNames[name] {
			if _, exists := response["x-veer-required-header-sets"]; exists {
				return fmt.Errorf("error response %s declares a conditional header set", name)
			}
			if _, exists := response["x-veer-deprecation-sunset-minimum-notice-days"]; exists {
				return fmt.Errorf("error response %s declares a deprecation notice binding", name)
			}
			if len(content) != 1 || content["application/problem+json"] == nil {
				return fmt.Errorf("error response %s must use application/problem+json", name)
			}
			media, _ := mapField(content, "application/problem+json")
			wantSchema := problemContracts[name].schema
			if err := requireReference(media, "schema", "#/components/schemas/"+wantSchema); err != nil {
				return fmt.Errorf("error response %s must reference %s: %w", name, wantSchema, err)
			}
			if response["x-veer-request-id-body-pointer"] != "/requestId" {
				return fmt.Errorf("error response %s request-ID body binding drifted", name)
			}
			if pointer, mustBind := retryAfterPointers[name]; mustBind {
				if response["x-veer-retry-after-body-pointer"] != pointer {
					return fmt.Errorf("error response %s Retry-After body binding drifted", name)
				}
			} else if _, exists := response["x-veer-retry-after-body-pointer"]; exists {
				return fmt.Errorf("error response %s declares an unexpected Retry-After binding", name)
			}
			for _, forbidden := range []string{
				"x-veer-etag-resource-version-pointer",
				"x-veer-location-operation-id-pointer",
			} {
				if _, exists := response[forbidden]; exists {
					return fmt.Errorf("error response %s declares success-body binding %s", name, forbidden)
				}
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
	return requireAnnotatedReference(parent, name, want, nil)
}

func requireAnnotatedReference(
	parent map[string]any,
	name, want string,
	reviewedSiblings map[string]any,
) error {
	value, err := mapField(parent, name)
	if err != nil {
		return fmt.Errorf("%s is missing", name)
	}
	if value["$ref"] != want {
		return fmt.Errorf("%s must reference %s", name, want)
	}
	keywords := make([]string, 0, len(reviewedSiblings)+1)
	keywords = append(keywords, "$ref")
	for key := range reviewedSiblings {
		keywords = append(keywords, key)
	}
	sort.Strings(keywords[1:])
	if !mapKeySetEquals(value, keywords) {
		return fmt.Errorf("%s reference has unreviewed keywords", name)
	}
	for _, key := range keywords[1:] {
		if !reflect.DeepEqual(value[key], reviewedSiblings[key]) {
			return fmt.Errorf("%s reference %s drifted", name, key)
		}
	}
	return nil
}

func validateTopLevelSchemaKeywords(schemas map[string]any) error {
	objectKeywords := []string{"type", "description", "required", "properties", "additionalProperties"}
	for _, contract := range []struct {
		name   string
		extras []string
	}{
		{name: "Condition"},
		{name: "FieldViolation"},
		{name: "MutationReceipt", extras: []string{"x-veer-maximum-json-bytes"}},
		{name: "Operation"},
		{name: "Problem", extras: []string{"x-veer-instance-request-id-template", "x-veer-maximum-json-bytes"}},
		{name: "ResourceMetadata", extras: []string{"example"}},
		{name: "StatusReceipt", extras: []string{"x-veer-maximum-json-bytes"}},
		{name: "Workspace", extras: []string{"x-veer-maximum-json-bytes"}},
		{name: "WorkspaceCreate"},
		{name: "WorkspaceList", extras: []string{"x-veer-maximum-json-bytes", "x-veer-page-byte-policy"}},
		{name: "WorkspaceReplace"},
		{name: "WorkspaceSpec"},
		{name: "WorkspaceStatus", extras: []string{"example"}},
		{name: "WorkspaceStatusWrite"},
		{name: "WritableMetadata", extras: []string{"example"}},
	} {
		schema, err := mapField(schemas, contract.name)
		if err != nil {
			return err
		}
		keywords := append([]string(nil), objectKeywords...)
		keywords = append(keywords, contract.extras...)
		if !mapKeysAllowed(schema, keywords) {
			return fmt.Errorf("%s schema has unreviewed keywords", contract.name)
		}
	}

	labels, err := mapField(schemas, "Labels")
	if err != nil {
		return err
	}
	if !mapKeysAllowed(labels, []string{
		"type", "description", "example", "maxProperties", "propertyNames",
		"additionalProperties", "x-veer-free-form-map",
	}) {
		return errors.New("labels schema has unreviewed keywords")
	}

	for _, contract := range problemContracts {
		variants := problemVariantsFor(contract)
		if len(variants) > 1 {
			aggregate, err := mapField(schemas, contract.schema)
			if err != nil {
				return err
			}
			if !mapKeysAllowed(aggregate, []string{"description", "oneOf"}) {
				return fmt.Errorf("%s schema has unreviewed keywords", contract.schema)
			}
		}
		for _, variant := range variants {
			schema, err := mapField(schemas, variant.schema)
			if err != nil {
				return err
			}
			if !mapKeysAllowed(schema, []string{"description", "allOf"}) {
				return fmt.Errorf("%s schema has unreviewed keywords", variant.schema)
			}
		}
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
	for _, contract := range problemContracts {
		if _, exists := schemas[contract.schema]; !exists {
			return fmt.Errorf("schema %s is missing", contract.schema)
		}
		for _, variant := range problemVariantsFor(contract) {
			if _, exists := schemas[variant.schema]; !exists {
				return fmt.Errorf("schema %s is missing", variant.schema)
			}
		}
	}
	if err := validateTopLevelSchemaKeywords(schemas); err != nil {
		return err
	}
	for name, want := range map[string]struct {
		minimum string
		maximum string
		pattern string
	}{
		"RequestId": {
			minimum: "1",
			maximum: "64",
			pattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`,
		},
		"IdempotencyKey": {
			minimum: "16",
			maximum: "128",
			pattern: `^[A-Za-z0-9][A-Za-z0-9._~:+/-]{15,127}$`,
		},
		"StrongETag": {
			minimum: "3",
			maximum: "130",
			pattern: `^"[A-Za-z0-9_-]{1,128}"$`,
		},
		"OpaqueId": {
			minimum: "16",
			maximum: "128",
			pattern: `^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`,
		},
	} {
		schema, err := mapField(schemas, name)
		if err != nil {
			return err
		}
		if schema["type"] != "string" || !numberEquals(schema["minLength"], want.minimum) ||
			!numberEquals(schema["maxLength"], want.maximum) || schema["pattern"] != want.pattern {
			return fmt.Errorf("%s schema contract drifted", name)
		}
		keywords := []string{"type", "description", "minLength", "maxLength", "pattern"}
		if name == "RequestId" || name == "OpaqueId" {
			keywords = append(keywords, "example")
		}
		if !mapKeySetEquals(schema, keywords) {
			return fmt.Errorf("%s schema has unreviewed keywords", name)
		}
	}

	timestamp, err := mapField(schemas, "Timestamp")
	if err != nil {
		return err
	}
	timestampExample, exampleOK := timestamp["example"].(string)
	if timestamp["type"] != "string" || timestamp["format"] != "date-time" ||
		timestamp["pattern"] != timestampPattern || timestamp["x-veer-calendar-validation"] != "rfc3339-calendar" ||
		!exampleOK || !validTimestamp(timestampExample) {
		return errors.New("timestamp format or precision drifted")
	}
	if !mapKeySetEquals(timestamp, []string{
		"type", "format", "description", "example", "pattern", "x-veer-calendar-validation",
	}) {
		return errors.New("timestamp schema has unreviewed keywords")
	}

	metadata, err := mapField(schemas, "ResourceMetadata")
	if err != nil {
		return err
	}
	metadataProperties, err := mapField(metadata, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(metadata["required"], []string{
		"id", "displayName", "generation", "resourceVersion", "createdAt", "updatedAt",
	}) || len(metadataProperties) != 7 {
		return errors.New("ResourceMetadata shape drifted")
	}
	for _, name := range []string{"id", "generation", "resourceVersion", "createdAt", "updatedAt"} {
		property, err := mapField(metadataProperties, name)
		if err != nil {
			return err
		}
		if property["readOnly"] != true {
			return fmt.Errorf("ResourceMetadata.%s must be readOnly", name)
		}
	}
	for _, contract := range []struct {
		property string
		target   string
		siblings map[string]any
	}{
		{
			property: "id",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "readOnly": true},
		},
		{property: "labels", target: "Labels"},
		{
			property: "createdAt",
			target:   "Timestamp",
			siblings: map[string]any{"type": "string", "readOnly": true},
		},
		{
			property: "updatedAt",
			target:   "Timestamp",
			siblings: map[string]any{"type": "string", "readOnly": true},
		},
	} {
		if err := requireAnnotatedReference(
			metadataProperties,
			contract.property,
			"#/components/schemas/"+contract.target,
			contract.siblings,
		); err != nil {
			return fmt.Errorf("ResourceMetadata: %w", err)
		}
	}
	metadataDisplayName, err := mapField(metadataProperties, "displayName")
	if err != nil {
		return err
	}
	if metadataDisplayName["type"] != "string" || !numberEquals(metadataDisplayName["minLength"], "1") ||
		!numberEquals(metadataDisplayName["maxLength"], "128") {
		return errors.New("ResourceMetadata displayName contract drifted")
	}
	metadataResourceVersion, err := mapField(metadataProperties, "resourceVersion")
	if err != nil {
		return err
	}
	if err := validateResourceVersionProperty(
		metadataResourceVersion,
		"ResourceMetadata",
		[]string{"type", "example", "minLength", "maxLength", "pattern", "readOnly", "description"},
	); err != nil {
		return err
	}
	for _, contract := range []struct {
		schema   string
		property string
		minimum  string
		keywords []string
	}{
		{
			schema:   "ResourceMetadata",
			property: "generation",
			minimum:  "1",
			keywords: []string{"type", "format", "minimum", "maximum", "readOnly", "description"},
		},
		{
			schema:   "MutationReceipt",
			property: "generation",
			minimum:  "1",
			keywords: []string{"type", "format", "example", "minimum", "maximum"},
		},
		{
			schema:   "Operation",
			property: "generation",
			minimum:  "1",
			keywords: []string{"type", "format", "example", "minimum", "maximum"},
		},
		{
			schema:   "Condition",
			property: "observedGeneration",
			minimum:  "0",
			keywords: []string{"type", "format", "example", "minimum", "maximum"},
		},
		{
			schema:   "WorkspaceStatus",
			property: "observedGeneration",
			minimum:  "0",
			keywords: []string{"type", "format", "minimum", "maximum"},
		},
	} {
		if err := validateInt64Property(
			schemas,
			contract.schema,
			contract.property,
			contract.minimum,
			contract.keywords,
		); err != nil {
			return err
		}
	}

	for _, name := range []string{"WorkspaceCreate", "WorkspaceReplace"} {
		if err := validateWorkspaceWriteSchema(schemas, name); err != nil {
			return err
		}
	}
	if err := validateWorkspaceReadSchema(schemas); err != nil {
		return err
	}
	if err := validateWorkspaceStatusSchema(schemas); err != nil {
		return err
	}
	if err := validateConditionSchema(schemas); err != nil {
		return err
	}
	if err := validateOperationSchema(schemas); err != nil {
		return err
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
	if !stringSetEquals(writable["required"], []string{"displayName"}) || len(writableProperties) != 2 {
		return errors.New("WritableMetadata shape drifted")
	}
	displayName, err := mapField(writableProperties, "displayName")
	if err != nil {
		return err
	}
	if displayName["type"] != "string" || !numberEquals(displayName["minLength"], "1") ||
		!numberEquals(displayName["maxLength"], "128") {
		return errors.New("WritableMetadata displayName contract drifted")
	}
	if err := requireReference(writableProperties, "labels", "#/components/schemas/Labels"); err != nil {
		return fmt.Errorf("WritableMetadata: %w", err)
	}
	workspaceSpec, err := mapField(schemas, "WorkspaceSpec")
	if err != nil {
		return err
	}
	specProperties, err := mapField(workspaceSpec, "properties")
	if err != nil {
		return err
	}
	suspend, err := mapField(specProperties, "suspendReconciliation")
	if err != nil {
		return err
	}
	if !stringSetEquals(workspaceSpec["required"], []string{"suspendReconciliation"}) ||
		len(specProperties) != 1 || suspend["type"] != "boolean" || suspend["default"] != false {
		return errors.New("WorkspaceSpec contract drifted")
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
	if !stringSetEquals(statusWrite["required"], []string{"apiVersion", "kind", "status"}) || len(statusProperties) != 3 {
		return errors.New("WorkspaceStatusWrite shape drifted")
	}
	apiVersion, err := mapField(statusProperties, "apiVersion")
	if err != nil {
		return err
	}
	kind, err := mapField(statusProperties, "kind")
	if err != nil {
		return err
	}
	if apiVersion["type"] != "string" || apiVersion["const"] != "v1alpha1" ||
		kind["type"] != "string" || kind["const"] != "Workspace" {
		return errors.New("WorkspaceStatusWrite identity drifted")
	}
	if err := requireReference(statusProperties, "status", "#/components/schemas/WorkspaceStatus"); err != nil {
		return fmt.Errorf("WorkspaceStatusWrite: %w", err)
	}

	labels, err := mapField(schemas, "Labels")
	if err != nil {
		return err
	}
	if labels["type"] != "object" || labels["x-veer-free-form-map"] != true ||
		!numberEquals(labels["maxProperties"], "64") {
		return errors.New("labels map bound drifted")
	}
	propertyNames, err := mapField(labels, "propertyNames")
	if err != nil {
		return err
	}
	if propertyNames["type"] != "string" || !numberEquals(propertyNames["minLength"], "1") ||
		!numberEquals(propertyNames["maxLength"], "63") || propertyNames["pattern"] != "^[a-z][a-z0-9.-]*$" {
		return errors.New("labels key contract drifted")
	}
	labelValues, err := mapField(labels, "additionalProperties")
	if err != nil {
		return err
	}
	if labelValues["type"] != "string" || !numberEquals(labelValues["maxLength"], "256") {
		return errors.New("labels value contract drifted")
	}

	statusReceipt, err := mapField(schemas, "StatusReceipt")
	if err != nil {
		return err
	}
	if !numberEquals(statusReceipt["x-veer-maximum-json-bytes"], "1024") {
		return errors.New("status receipt encoded-size contract drifted")
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
	if !mapKeySetEquals(observedGeneration, []string{"type", "format", "example", "minimum", "maximum"}) {
		return errors.New("StatusReceipt observedGeneration has unreviewed keywords")
	}
	statusResourceVersion, err := mapField(statusReceiptProperties, "resourceVersion")
	if err != nil {
		return err
	}
	if err := validateResourceVersionProperty(
		statusResourceVersion,
		"StatusReceipt",
		[]string{"type", "example", "minLength", "maxLength", "pattern"},
	); err != nil {
		return err
	}
	mutationReceipt, err := mapField(schemas, "MutationReceipt")
	if err != nil {
		return err
	}
	if !numberEquals(mutationReceipt["x-veer-maximum-json-bytes"], "1024") {
		return errors.New("mutation receipt encoded-size contract drifted")
	}
	mutationReceiptProperties, err := mapField(mutationReceipt, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(mutationReceipt["required"], []string{
		"resourceId", "operationId", "generation", "resourceVersion", "acceptedAt",
	}) || len(mutationReceiptProperties) != 5 {
		return errors.New("MutationReceipt shape drifted")
	}
	for property, target := range map[string]string{
		"resourceId":  "OpaqueId",
		"operationId": "OpaqueId",
		"acceptedAt":  "Timestamp",
	} {
		if err := requireReference(mutationReceiptProperties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("MutationReceipt: %w", err)
		}
	}
	mutationResourceVersion, err := mapField(mutationReceiptProperties, "resourceVersion")
	if err != nil {
		return err
	}
	if err := validateResourceVersionProperty(
		mutationResourceVersion,
		"MutationReceipt",
		[]string{"type", "example", "minLength", "maxLength", "pattern"},
	); err != nil {
		return err
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
	if !stringSetEquals(list["required"], []string{"items"}) || len(listProperties) != 2 {
		return errors.New("WorkspaceList shape drifted")
	}
	if !numberEquals(list["x-veer-maximum-json-bytes"], "262144") ||
		list["x-veer-page-byte-policy"] != "stop-before-limit" {
		return errors.New("WorkspaceList encoded-size contract drifted")
	}
	if items["type"] != "array" || !numberEquals(items["maxItems"], "100") {
		return errors.New("WorkspaceList item bound drifted")
	}
	if err := requireReference(items, "items", "#/components/schemas/Workspace"); err != nil {
		return fmt.Errorf("WorkspaceList.items: %w", err)
	}
	nextPageToken, err := mapField(listProperties, "nextPageToken")
	if err != nil {
		return err
	}
	if nextPageToken["type"] != "string" || !numberEquals(nextPageToken["minLength"], "16") ||
		!numberEquals(nextPageToken["maxLength"], "1024") || nextPageToken["pattern"] != "^[A-Za-z0-9_-]+$" {
		return errors.New("WorkspaceList nextPageToken contract drifted")
	}
	if !mapKeySetEquals(nextPageToken, []string{"type", "example", "minLength", "maxLength", "pattern"}) {
		return errors.New("WorkspaceList nextPageToken has unreviewed keywords")
	}

	problem, err := mapField(schemas, "Problem")
	if err != nil {
		return err
	}
	if problem["additionalProperties"] != false {
		return errors.New("problem must reject undeclared extensions")
	}
	if !stringSetEquals(problem["required"], []string{"type", "title", "status", "instance", "code", "requestId"}) {
		return errors.New("problem required fields drifted")
	}
	if problem["x-veer-instance-request-id-template"] != "urn:veer:request:{requestId}" {
		return errors.New("problem instance/request-ID binding drifted")
	}
	if !numberEquals(problem["x-veer-maximum-json-bytes"], "1024") {
		return errors.New("problem encoded-size contract drifted")
	}
	problemProperties, err := mapField(problem, "properties")
	if err != nil {
		return err
	}
	if !mapKeySetEquals(problemProperties, []string{
		"type", "title", "status", "detail", "instance", "code", "requestId", "errors", "retryAfterSeconds",
	}) {
		return errors.New("problem property set drifted")
	}
	for name, wantMaximum := range map[string]string{
		"type":     "81",
		"title":    "64",
		"detail":   "192",
		"instance": "81",
		"code":     "64",
	} {
		property, err := mapField(problemProperties, name)
		if err != nil {
			return err
		}
		if !numberEquals(property["maxLength"], wantMaximum) {
			return fmt.Errorf("problem.%s bound drifted", name)
		}
	}
	problemType, _ := mapField(problemProperties, "type")
	title, _ := mapField(problemProperties, "title")
	status, _ := mapField(problemProperties, "status")
	detail, _ := mapField(problemProperties, "detail")
	instance, _ := mapField(problemProperties, "instance")
	code, _ := mapField(problemProperties, "code")
	if problemType["type"] != "string" || problemType["format"] != "uri" ||
		problemType["pattern"] != "^urn:veer:problem:[a-z][a-z0-9-]*$" ||
		title["type"] != "string" || !numberEquals(title["minLength"], "1") ||
		title["pattern"] != safeProblemTextPattern ||
		status["type"] != "integer" || status["format"] != "int32" ||
		!numberEquals(status["minimum"], "400") || !numberEquals(status["maximum"], "599") ||
		detail["type"] != "string" || detail["pattern"] != safeProblemTextPattern ||
		instance["type"] != "string" || instance["format"] != "uri" ||
		instance["pattern"] != "^urn:veer:request:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" ||
		code["type"] != "string" || !numberEquals(code["minLength"], "1") ||
		code["pattern"] != "^[a-z][a-z0-9-]*$" {
		return errors.New("problem primitive contract drifted")
	}
	if err := requireReference(problemProperties, "requestId", "#/components/schemas/RequestId"); err != nil {
		return fmt.Errorf("problem: %w", err)
	}
	errorsProperty, err := mapField(problemProperties, "errors")
	if err != nil {
		return err
	}
	if errorsProperty["type"] != "array" || !numberEquals(errorsProperty["maxItems"], "1") {
		return errors.New("problem.errors aggregate bound drifted")
	}
	if err := requireReference(errorsProperty, "items", "#/components/schemas/FieldViolation"); err != nil {
		return fmt.Errorf("problem.errors: %w", err)
	}
	retryAfterSeconds, err := mapField(problemProperties, "retryAfterSeconds")
	if err != nil {
		return err
	}
	if retryAfterSeconds["type"] != "integer" || retryAfterSeconds["format"] != "int32" ||
		!numberEquals(retryAfterSeconds["minimum"], "1") ||
		!numberEquals(retryAfterSeconds["maximum"], "86400") {
		return errors.New("problem.retryAfterSeconds contract drifted")
	}
	fieldViolation, err := mapField(schemas, "FieldViolation")
	if err != nil {
		return err
	}
	fieldProperties, err := mapField(fieldViolation, "properties")
	if err != nil {
		return err
	}
	for name, wantMaximum := range map[string]string{"field": "96", "code": "32", "message": "96"} {
		property, err := mapField(fieldProperties, name)
		if err != nil {
			return err
		}
		if !numberEquals(property["maxLength"], wantMaximum) {
			return fmt.Errorf("FieldViolation.%s bound drifted", name)
		}
	}
	if !stringSetEquals(fieldViolation["required"], []string{"field", "code", "message"}) ||
		len(fieldProperties) != 3 {
		return errors.New("FieldViolation shape drifted")
	}
	field, _ := mapField(fieldProperties, "field")
	fieldCode, _ := mapField(fieldProperties, "code")
	fieldMessage, _ := mapField(fieldProperties, "message")
	if field["type"] != "string" || !numberEquals(field["minLength"], "1") ||
		field["pattern"] != fieldPointerPattern ||
		!numberEquals(field["x-veer-maximum-encoded-json-bytes"], "98") ||
		fieldCode["type"] != "string" || !numberEquals(fieldCode["minLength"], "1") ||
		fieldCode["pattern"] != "^[a-z][a-z0-9-]*$" ||
		fieldMessage["type"] != "string" || fieldMessage["pattern"] != safeProblemTextPattern {
		return errors.New("FieldViolation primitive contract drifted")
	}
	if err := validateSpecificProblemSchemas(schemas); err != nil {
		return err
	}
	return nil
}

func validateInt64Property(
	schemas map[string]any,
	schemaName, propertyName, minimum string,
	keywords []string,
) error {
	schema, err := mapField(schemas, schemaName)
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	property, err := mapField(properties, propertyName)
	if err != nil {
		return err
	}
	if property["type"] != "integer" || property["format"] != "int64" ||
		!numberEquals(property["minimum"], minimum) ||
		!numberEquals(property["maximum"], "9223372036854775807") {
		return fmt.Errorf("%s.%s int64 contract drifted", schemaName, propertyName)
	}
	if !mapKeySetEquals(property, keywords) {
		return fmt.Errorf("%s.%s has unreviewed keywords", schemaName, propertyName)
	}
	return nil
}

func validateResourceVersionProperty(property map[string]any, context string, keywords []string) error {
	if property["type"] != "string" || !numberEquals(property["minLength"], "1") ||
		!numberEquals(property["maxLength"], "128") || property["pattern"] != "^[A-Za-z0-9_-]+$" {
		return fmt.Errorf("%s resourceVersion contract drifted", context)
	}
	if !mapKeySetEquals(property, keywords) {
		return fmt.Errorf("%s resourceVersion has unreviewed keywords", context)
	}
	return nil
}

func validateWorkspaceStatusSchema(schemas map[string]any) error {
	status, err := mapField(schemas, "WorkspaceStatus")
	if err != nil {
		return err
	}
	properties, err := mapField(status, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(status["required"], []string{"observedGeneration", "conditions"}) ||
		len(properties) != 2 {
		return errors.New("WorkspaceStatus shape drifted")
	}
	conditions, err := mapField(properties, "conditions")
	if err != nil {
		return err
	}
	if conditions["type"] != "array" || !numberEquals(conditions["maxItems"], "32") {
		return errors.New("WorkspaceStatus conditions contract drifted")
	}
	if err := requireReference(conditions, "items", "#/components/schemas/Condition"); err != nil {
		return fmt.Errorf("WorkspaceStatus.conditions: %w", err)
	}
	return nil
}

func validateConditionSchema(schemas map[string]any) error {
	condition, err := mapField(schemas, "Condition")
	if err != nil {
		return err
	}
	properties, err := mapField(condition, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(condition["required"], []string{
		"type", "status", "reason", "message", "observedGeneration", "lastTransitionAt",
	}) || len(properties) != 6 {
		return errors.New("condition shape drifted")
	}
	for _, name := range []string{"type", "reason"} {
		property, err := mapField(properties, name)
		if err != nil {
			return err
		}
		if property["type"] != "string" || !numberEquals(property["minLength"], "1") ||
			!numberEquals(property["maxLength"], "64") || property["pattern"] != "^[A-Z][A-Za-z0-9]*$" {
			return fmt.Errorf("condition.%s contract drifted", name)
		}
	}
	status, err := mapField(properties, "status")
	if err != nil {
		return err
	}
	if status["type"] != "string" || !stringSetEquals(status["enum"], []string{"True", "False", "Unknown"}) {
		return errors.New("condition.status contract drifted")
	}
	message, err := mapField(properties, "message")
	if err != nil {
		return err
	}
	if message["type"] != "string" || !numberEquals(message["maxLength"], "512") {
		return errors.New("condition.message contract drifted")
	}
	if err := requireReference(properties, "lastTransitionAt", "#/components/schemas/Timestamp"); err != nil {
		return fmt.Errorf("condition: %w", err)
	}
	return nil
}

func validateOperationSchema(schemas map[string]any) error {
	operation, err := mapField(schemas, "Operation")
	if err != nil {
		return err
	}
	properties, err := mapField(operation, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(operation["required"], []string{
		"id", "resourceId", "generation", "resourceVersion", "phase", "createdAt", "updatedAt",
	}) || len(properties) != 9 {
		return errors.New("operation shape drifted")
	}
	for _, contract := range []struct {
		property string
		target   string
		siblings map[string]any
	}{
		{
			property: "id",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "op_01J000000000000000000000000"},
		},
		{
			property: "resourceId",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "wsp_01J00000000000000000000000"},
		},
		{property: "createdAt", target: "Timestamp"},
		{property: "updatedAt", target: "Timestamp"},
	} {
		if err := requireAnnotatedReference(
			properties,
			contract.property,
			"#/components/schemas/"+contract.target,
			contract.siblings,
		); err != nil {
			return fmt.Errorf("operation: %w", err)
		}
	}
	resourceVersion, err := mapField(properties, "resourceVersion")
	if err != nil {
		return err
	}
	if err := validateResourceVersionProperty(
		resourceVersion,
		"Operation",
		[]string{"type", "example", "minLength", "maxLength", "pattern"},
	); err != nil {
		return err
	}
	phase, err := mapField(properties, "phase")
	if err != nil {
		return err
	}
	if phase["type"] != "string" || !stringSetEquals(
		phase["enum"],
		[]string{"Pending", "Running", "Succeeded", "Failed", "Canceled"},
	) {
		return errors.New("operation.phase contract drifted")
	}
	reason, err := mapField(properties, "reason")
	if err != nil {
		return err
	}
	if reason["type"] != "string" || !numberEquals(reason["maxLength"], "64") ||
		reason["pattern"] != "^[A-Z][A-Za-z0-9]*$" {
		return errors.New("operation.reason contract drifted")
	}
	message, err := mapField(properties, "message")
	if err != nil {
		return err
	}
	if message["type"] != "string" || !numberEquals(message["maxLength"], "512") {
		return errors.New("operation.message contract drifted")
	}
	return nil
}

func validateWorkspaceWriteSchema(schemas map[string]any, name string) error {
	schema, err := mapField(schemas, name)
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(schema["required"], []string{"apiVersion", "kind", "metadata", "spec"}) ||
		len(properties) != 4 {
		return fmt.Errorf("%s complete-write shape drifted", name)
	}
	if err := validateWorkspaceIdentity(properties, name); err != nil {
		return err
	}
	for property, target := range map[string]string{
		"metadata": "WritableMetadata",
		"spec":     "WorkspaceSpec",
	} {
		if err := requireReference(properties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateWorkspaceReadSchema(schemas map[string]any) error {
	schema, err := mapField(schemas, "Workspace")
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(schema["required"], []string{"apiVersion", "kind", "metadata", "spec", "status"}) ||
		len(properties) != 5 || !numberEquals(schema["x-veer-maximum-json-bytes"], "262144") {
		return errors.New("workspace read shape or encoded-size contract drifted")
	}
	if err := validateWorkspaceIdentity(properties, "Workspace"); err != nil {
		return err
	}
	for property, target := range map[string]string{
		"metadata": "ResourceMetadata",
		"spec":     "WorkspaceSpec",
		"status":   "WorkspaceStatus",
	} {
		if err := requireReference(properties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
	}
	return nil
}

func validateWorkspaceIdentity(properties map[string]any, context string) error {
	apiVersion, err := mapField(properties, "apiVersion")
	if err != nil {
		return err
	}
	kind, err := mapField(properties, "kind")
	if err != nil {
		return err
	}
	if apiVersion["type"] != "string" || apiVersion["const"] != "v1alpha1" ||
		kind["type"] != "string" || kind["const"] != "Workspace" {
		return fmt.Errorf("%s identity contract drifted", context)
	}
	return nil
}

func validateSpecificProblemSchemas(schemas map[string]any) error {
	for responseName, contract := range problemContracts {
		variants := problemVariantsFor(contract)
		if len(variants) > 1 {
			aggregate, err := mapField(schemas, contract.schema)
			if err != nil {
				return err
			}
			want := make([]string, 0, len(variants))
			for _, variant := range variants {
				want = append(want, "#/components/schemas/"+variant.schema)
			}
			if !referenceSetEquals(aggregate["oneOf"], want) {
				return fmt.Errorf("%s conflict variants drifted", contract.schema)
			}
		}
		for _, variant := range variants {
			if err := validateProblemVariant(schemas, responseName, contract.status, variant); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateProblemVariant(
	schemas map[string]any,
	responseName string,
	statusCode string,
	variant problemVariant,
) error {
	schema, err := mapField(schemas, variant.schema)
	if err != nil {
		return err
	}
	allOf, ok := schema["allOf"].([]any)
	if !ok || len(allOf) != 2 {
		return fmt.Errorf("%s must contain the reviewed allOf contract", variant.schema)
	}
	base, baseOK := allOf[0].(map[string]any)
	constraints, constraintsOK := allOf[1].(map[string]any)
	wantConstraintFields := 2
	if len(variant.required) > 0 {
		wantConstraintFields = 3
	}
	if !baseOK || base["$ref"] != "#/components/schemas/Problem" ||
		!mapKeySetEquals(base, []string{"$ref"}) || !constraintsOK ||
		len(constraints) != wantConstraintFields || constraints["x-veer-refinement"] != true {
		return fmt.Errorf("%s does not refine Problem", variant.schema)
	}
	if len(variant.required) > 0 {
		if !stringSetEquals(constraints["required"], variant.required) {
			return fmt.Errorf("%s refinement required fields drifted", variant.schema)
		}
	} else if _, exists := constraints["required"]; exists {
		return fmt.Errorf("%s declares unexpected refinement required fields", variant.schema)
	}
	properties, err := mapField(constraints, "properties")
	if err != nil {
		return fmt.Errorf("%s: %w", variant.schema, err)
	}
	if len(properties) != 4 {
		return fmt.Errorf("%s must constrain exactly type, title, status, and code", variant.schema)
	}
	problemType, err := mapField(properties, "type")
	if err != nil {
		return err
	}
	title, err := mapField(properties, "title")
	if err != nil {
		return err
	}
	status, err := mapField(properties, "status")
	if err != nil {
		return err
	}
	code, err := mapField(properties, "code")
	if err != nil {
		return err
	}
	if problemType["const"] != "urn:veer:problem:"+variant.code || title["const"] != variant.title ||
		!numberEquals(status["const"], statusCode) || code["const"] != variant.code {
		return fmt.Errorf("%s constants drifted for response %s", variant.schema, responseName)
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
	type exampleContract struct {
		status            string
		code              string
		title             string
		retryAfterSeconds string
	}
	want := map[string]exampleContract{
		"ValidationFailure":      {status: "400", code: "validation-failed", title: "Request validation failed"},
		"AuthenticationRequired": {status: "401", code: "authentication-required", title: "Authentication required"},
		"AuthorizationDenied":    {status: "403", code: "authorization-denied", title: "Authorization denied"},
		"Conflict":               {status: "409", code: "idempotency-key-reused", title: "Request conflicts with a prior mutation"},
		"Throttled":              {status: "429", code: "rate-limited", title: "Request rate limited", retryAfterSeconds: "5"},
		"InternalFailure":        {status: "500", code: "internal-failure", title: "Internal failure"},
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
		if err := validateProblemExample(name, value, expected.status, expected.code, expected.title); err != nil {
			return err
		}
		if expected.retryAfterSeconds != "" && !numberEquals(value["retryAfterSeconds"], expected.retryAfterSeconds) {
			return fmt.Errorf("example %s retryAfterSeconds drifted", name)
		}
	}

	responses, err := mapField(components, "responses")
	if err != nil {
		return err
	}
	inline := map[string]exampleContract{
		"NotFound":             {status: "404", code: "not-found", title: "Resource not found"},
		"PreconditionFailed":   {status: "412", code: "precondition-failed", title: "Resource version is stale"},
		"PreconditionRequired": {status: "428", code: "precondition-required", title: "Mutation precondition required"},
		"RequestTooLarge":      {status: "413", code: "request-too-large", title: "Request body is too large"},
		"UnsupportedMediaType": {status: "415", code: "unsupported-media-type", title: "Unsupported request media type"},
		"Unavailable":          {status: "503", code: "unavailable", title: "Service temporarily unavailable", retryAfterSeconds: "10"},
	}
	for name, expected := range inline {
		response, err := mapField(responses, name)
		if err != nil {
			return err
		}
		content, err := mapField(response, "content")
		if err != nil {
			return err
		}
		media, err := mapField(content, "application/problem+json")
		if err != nil {
			return err
		}
		value, err := mapField(media, "example")
		if err != nil {
			return fmt.Errorf("inline example %s: %w", name, err)
		}
		if err := validateProblemExample(name, value, expected.status, expected.code, expected.title); err != nil {
			return err
		}
		if expected.retryAfterSeconds != "" && !numberEquals(value["retryAfterSeconds"], expected.retryAfterSeconds) {
			return fmt.Errorf("example %s retryAfterSeconds drifted", name)
		}
	}
	return nil
}

func validateProblemExample(name string, value map[string]any, status, code, title string) error {
	if !numberEquals(value["status"], status) || value["code"] != code {
		return fmt.Errorf("example %s status or code drifted", name)
	}
	if value["type"] != "urn:veer:problem:"+code {
		return fmt.Errorf("example %s type is not bound to its code", name)
	}
	if value["title"] != title {
		return fmt.Errorf("example %s title drifted", name)
	}
	requestID, requestOK := value["requestId"].(string)
	instance, instanceOK := value["instance"].(string)
	if !requestOK || !instanceOK || instance != "urn:veer:request:"+requestID {
		return fmt.Errorf("example %s requestId and instance are not bound", name)
	}
	return nil
}

func validTimestamp(value string) bool {
	if !timestampValuePattern.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05.000Z", value)
	return err == nil
}

func validDeprecationDate(value string) bool {
	_, ok := parseDeprecationDate(value)
	return ok
}

func parseDeprecationDate(value string) (int64, bool) {
	if !deprecationValuePattern.MatchString(value) {
		return 0, false
	}
	seconds, err := strconv.ParseInt(strings.TrimPrefix(value, "@"), 10, 64)
	return seconds, err == nil
}

func validDeprecationWindow(deprecation, sunset string, minimumDays int) bool {
	deprecationSeconds, ok := parseDeprecationDate(deprecation)
	if !ok || minimumDays <= 0 || !validSunset(sunset) {
		return false
	}
	sunsetTime, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", sunset)
	if err != nil {
		return false
	}
	minimumSeconds := int64(minimumDays) * 24 * 60 * 60
	return sunsetTime.Unix()-deprecationSeconds >= minimumSeconds
}

func validDeprecationLink(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !deprecationLinkValuePattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ", ")
	if len(parts) > 2 || !validLinkValue(parts[0], "deprecation") {
		return false
	}
	return len(parts) == 1 || validLinkValue(parts[1], "sunset")
}

func validLinkValue(value, relation string) bool {
	const prefix = "<"
	suffix := `>; rel="` + relation + `"`
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return false
	}
	target := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	if len(target) == 0 || len(target) > 900 {
		return false
	}
	if _, err := url.PathUnescape(target); err != nil {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.User != nil {
		return false
	}
	if parsed.IsAbs() {
		return parsed.Scheme == "https" && parsed.Host != "" && parsed.Opaque == ""
	}
	return parsed.Host == "" && strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//")
}

func validSunset(value string) bool {
	parsed, err := time.Parse("Mon, 02 Jan 2006 15:04:05 GMT", value)
	if err != nil {
		return false
	}
	return parsed.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") == value
}

func boolKeySetEquals(got map[string]bool, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, key := range want {
		if !got[key] {
			return false
		}
	}
	return true
}

func mapKeySetEquals(got map[string]any, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, key := range want {
		if _, exists := got[key]; !exists {
			return false
		}
	}
	return true
}

func mapKeysAllowed(got map[string]any, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range got {
		if _, exists := allowedSet[key]; !exists {
			return false
		}
	}
	return true
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

func referenceSetEquals(value any, want []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(want) {
		return false
	}
	references := make([]any, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok || len(object) != 1 {
			return false
		}
		reference, ok := object["$ref"].(string)
		if !ok {
			return false
		}
		references = append(references, reference)
	}
	return stringSetEquals(references, want)
}

func stringMatrixEquals(value any, want [][]string) bool {
	rows, ok := value.([]any)
	if !ok || len(rows) != len(want) {
		return false
	}
	for index, expected := range want {
		if !stringSetEquals(rows[index], expected) {
			return false
		}
	}
	return true
}
