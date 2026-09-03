// Package openapi verifies Veer's checked-in transport and evolution contract.
package openapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxContractBytes             = 1 << 20
	maxJSONDepth                 = 64
	maxJSONNodes                 = 50000
	expectedSchemaCount          = 81
	minimumDeprecationNoticeDays = 90
	canonicalDecimalPattern      = `^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$`
	providerTokenPattern         = `^[a-z][a-z0-9.-]*$`
	conditionReasonPattern       = `^[A-Z][A-Za-z0-9]*$`
	currencyPattern              = `^[A-Z]{3}$`
	regionPattern                = `^[a-z0-9][a-z0-9-]{0,62}$`
	opaqueVersionPattern         = `^[A-Za-z0-9_-]+$`
	conditionSchemaSHA256        = "000a505985f5d58cd805721c687ab85e98dc98db606e5c6a0777fbcdf6ec123f"
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

type hierarchyContract struct {
	WorkspaceOwnership  hierarchyWorkspaceOwnership  `json:"workspaceOwnership"`
	ParentReference     hierarchyParentReference     `json:"parentReference"`
	ReferenceValidation hierarchyReferenceValidation `json:"referenceValidation"`
	Deletion            hierarchyDeletion            `json:"deletion"`
	Resources           []hierarchyResource          `json:"resources"`
}

type hierarchyWorkspaceOwnership struct {
	WorkspaceIDPointer string `json:"workspaceIdPointer"`
	RootDerivation     string `json:"rootDerivation"`
	ChildDerivation    string `json:"childDerivation"`
	ClientWritable     bool   `json:"clientWritable"`
	Mutable            bool   `json:"mutable"`
}

type hierarchyParentReference struct {
	Pointer string `json:"pointer"`
	Source  string `json:"source"`
	Mutable bool   `json:"mutable"`
}

type hierarchyReferenceValidation struct {
	Orphan         string `json:"orphan"`
	CrossWorkspace string `json:"crossWorkspace"`
	Cycle          string `json:"cycle"`
}

type hierarchyDeletion struct {
	Policy    string `json:"policy"`
	BlockedBy string `json:"blockedBy"`
}

type hierarchyReference struct {
	Ref string `json:"$ref"`
}

type hierarchyResource struct {
	Kind              string             `json:"kind"`
	ParentKind        *string            `json:"parentKind"`
	Schema            hierarchyReference `json:"schema"`
	MetadataSchema    hierarchyReference `json:"metadataSchema"`
	CreateSchema      hierarchyReference `json:"createSchema"`
	ReplaceSchema     hierarchyReference `json:"replaceSchema"`
	StatusWriteSchema hierarchyReference `json:"statusWriteSchema"`
	ListSchema        hierarchyReference `json:"listSchema"`
}

type operationTransitionContract struct {
	PhasePointer   string              `json:"phasePointer"`
	Transitions    map[string][]string `json:"transitions"`
	TerminalPhases []string            `json:"terminalPhases"`
	TerminalReplay string              `json:"terminalReplay"`
	UnknownPhase   string              `json:"unknownPhase"`
}

type conditionTransitionContract struct {
	IdentityPointer           string   `json:"identityPointer"`
	StatusPointer             string   `json:"statusPointer"`
	ObservedGenerationPointer string   `json:"observedGenerationPointer"`
	TransitionTimePointer     string   `json:"transitionTimePointer"`
	Statuses                  []string `json:"statuses"`
	SameStatusTimestamp       string   `json:"sameStatusTimestamp"`
	ChangedStatusTimestamp    string   `json:"changedStatusTimestamp"`
	ObservedGeneration        string   `json:"observedGeneration"`
	SetOrder                  string   `json:"setOrder"`
}

type admissionContract struct {
	Stages         []admissionStage        `json:"stages"`
	ErrorSelection admissionErrorSelection `json:"errorSelection"`
	FieldPath      admissionFieldPath      `json:"fieldPath"`
	FailureEffects admissionFailureEffects `json:"failureEffects"`
	Defaulting     admissionDefaulting     `json:"defaulting"`
	VersionHub     admissionVersionHub     `json:"versionHub"`
}

type admissionStage struct {
	Name              string                        `json:"name"`
	Codes             []string                      `json:"codes"`
	DefaultResponse   hierarchyReference            `json:"defaultResponse"`
	ResponseOverrides map[string]hierarchyReference `json:"responseOverrides,omitempty"`
}

type admissionErrorSelection struct {
	Maximum              int      `json:"maximum"`
	Precedence           []string `json:"precedence"`
	TerminalSyntaxErrors []string `json:"terminalSyntaxErrors"`
	TerminalWorkCeilings []string `json:"terminalWorkCeilings"`
}

type admissionFieldPath struct {
	Syntax               string             `json:"syntax"`
	WholeDocument        string             `json:"wholeDocument"`
	Unrepresentable      string             `json:"unrepresentable"`
	Truncation           string             `json:"truncation"`
	FieldViolationSchema hierarchyReference `json:"fieldViolationSchema"`
}

type admissionFailureEffects struct {
	StateMutation      string `json:"stateMutation"`
	QueueMutation      string `json:"queueMutation"`
	CallbackInvocation string `json:"callbackInvocation"`
}

type admissionDefaulting struct {
	Mode          string                 `json:"mode"`
	Deterministic bool                   `json:"deterministic"`
	Idempotent    bool                   `json:"idempotent"`
	Rules         []admissionDefaultRule `json:"rules"`
}

type admissionDefaultRule struct {
	APIVersion          string             `json:"apiVersion"`
	Kind                string             `json:"kind"`
	RequestPointer      string             `json:"requestPointer"`
	When                string             `json:"when"`
	Value               bool               `json:"value"`
	WriteSpecSchema     hierarchyReference `json:"writeSpecSchema"`
	CanonicalSpecSchema hierarchyReference `json:"canonicalSpecSchema"`
}

type admissionVersionHub struct {
	Hub                    string   `json:"hub"`
	Scope                  string   `json:"scope"`
	ServedVersions         []string `json:"servedVersions"`
	StorageVersion         string   `json:"storageVersion"`
	Kinds                  []string `json:"kinds"`
	Conversion             string   `json:"conversion"`
	RoundTrip              string   `json:"roundTrip"`
	UnsupportedVersionCode string   `json:"unsupportedVersionCode"`
	UnsupportedKindCode    string   `json:"unsupportedKindCode"`
}

type resourceSpecShape uint8

const (
	resourceSpecWorkspace resourceSpecShape = iota
	resourceSpecEmpty
	resourceSpecPolicy
	resourceSpecProviderConnection
)

type resourceStatusShape uint8

const (
	resourceStatusConditions resourceStatusShape = iota
	resourceStatusProviderConnection
)

type resourceSchemaContract struct {
	kind           string
	parentKind     string
	metadataSchema string
	specShape      resourceSpecShape
	statusShape    resourceStatusShape
}

func (contract resourceSchemaContract) schema(suffix string) string {
	return contract.kind + suffix
}

var resourceSchemaContracts = []resourceSchemaContract{
	{kind: "Workspace", metadataSchema: "RootResourceMetadata", specShape: resourceSpecWorkspace},
	{kind: "Policy", parentKind: "Workspace", metadataSchema: "ChildResourceMetadata", specShape: resourceSpecPolicy},
	{kind: "Environment", parentKind: "Workspace", metadataSchema: "ChildResourceMetadata", specShape: resourceSpecEmpty},
	{
		kind: "ProviderConnection", parentKind: "Environment", metadataSchema: "ChildResourceMetadata",
		specShape: resourceSpecProviderConnection, statusShape: resourceStatusProviderConnection,
	},
	{kind: "Application", parentKind: "Environment", metadataSchema: "ChildResourceMetadata", specShape: resourceSpecEmpty},
	{kind: "Component", parentKind: "Application", metadataSchema: "ChildResourceMetadata", specShape: resourceSpecEmpty},
}

type credentialReferenceWire struct {
	ReferenceID string `json:"referenceId"`
	Version     string `json:"version"`
}

type providerConnectionSpecWire struct {
	Provider      string                  `json:"provider"`
	CredentialRef credentialReferenceWire `json:"credentialRef"`
}

type providerCapabilityWire struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Source     string `json:"source"`
	ObservedAt string `json:"observedAt"`
	Reason     string `json:"reason"`
}

type quotaCheckWire struct {
	Name       string  `json:"name"`
	State      string  `json:"state"`
	Requested  *string `json:"requested,omitempty"`
	Available  *string `json:"available,omitempty"`
	Source     string  `json:"source"`
	ObservedAt string  `json:"observedAt"`
	Reason     string  `json:"reason"`
}

type costEstimateWire struct {
	State      string  `json:"state"`
	Amount     *string `json:"amount,omitempty"`
	Currency   string  `json:"currency"`
	Region     string  `json:"region"`
	Source     string  `json:"source"`
	ObservedAt string  `json:"observedAt"`
	Confidence string  `json:"confidence"`
	Reason     string  `json:"reason"`
}

type providerConnectionStatusWire struct {
	ObservedGeneration int64                    `json:"observedGeneration"`
	Conditions         []json.RawMessage        `json:"conditions"`
	Capabilities       []providerCapabilityWire `json:"capabilities"`
	QuotaChecks        []quotaCheckWire         `json:"quotaChecks"`
}

type operationWire struct {
	ID                   string            `json:"id"`
	WorkspaceID          string            `json:"workspaceId"`
	EnvironmentID        *string           `json:"environmentId,omitempty"`
	ProviderConnectionID *string           `json:"providerConnectionId,omitempty"`
	ResourceID           string            `json:"resourceId"`
	Generation           int64             `json:"generation"`
	ResourceVersion      string            `json:"resourceVersion"`
	Phase                string            `json:"phase"`
	Reason               *string           `json:"reason,omitempty"`
	Message              *string           `json:"message,omitempty"`
	CostEstimate         *costEstimateWire `json:"costEstimate,omitempty"`
	CreatedAt            string            `json:"createdAt"`
	UpdatedAt            string            `json:"updatedAt"`
}

type conditionWire struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason"`
	Message            string `json:"message"`
	ObservedGeneration int64  `json:"observedGeneration"`
	LastTransitionAt   string `json:"lastTransitionAt"`
}

type policySpecWire struct {
	Bindings []policyBindingWire `json:"bindings"`
}

type policyBindingWire struct {
	MemberID string          `json:"memberId"`
	Role     string          `json:"role"`
	Scope    policyScopeWire `json:"scope"`
}

type policyScopeWire struct {
	Kind          string  `json:"kind"`
	EnvironmentID *string `json:"environmentId,omitempty"`
}

type authorizationContract struct {
	ContractVersion         string                        `json:"contractVersion"`
	DefaultEffect           string                        `json:"defaultEffect"`
	PolicyVersionPrefix     string                        `json:"policyVersionPrefix"`
	InputDigestPrefix       string                        `json:"inputDigestPrefix"`
	MaxDecisionBytes        int                           `json:"maxDecisionBytes"`
	ListEvaluation          string                        `json:"listEvaluation"`
	Actions                 []string                      `json:"actions"`
	Objects                 []string                      `json:"objects"`
	Scopes                  []authorizationScopeContract  `json:"scopes"`
	Roles                   []authorizationRoleContract   `json:"roles"`
	ReservedActions         []string                      `json:"reservedActions"`
	ReservedResourceActions []authorizationResourceAction `json:"reservedResourceActions"`
	Effects                 []string                      `json:"effects"`
	Reasons                 []string                      `json:"reasons"`
}

type authorizationScopeContract struct {
	Kind       string   `json:"kind"`
	DescendsTo []string `json:"descendsTo"`
}

type authorizationRoleContract struct {
	Name     string                       `json:"name"`
	Inherits []string                     `json:"inherits"`
	Grants   []authorizationGrantContract `json:"grants"`
}

type authorizationGrantContract struct {
	Action        string   `json:"action"`
	ObjectKind    string   `json:"objectKind"`
	ResourceKinds []string `json:"resourceKinds"`
}

type authorizationResourceAction struct {
	Action       string `json:"action"`
	ResourceKind string `json:"resourceKind"`
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
	deprecationLinkValuePattern  = regexp.MustCompile(deprecationLinkPattern)
	deprecationValuePattern      = regexp.MustCompile(deprecationPattern)
	canonicalDecimalValuePattern = regexp.MustCompile(canonicalDecimalPattern)
	conditionReasonValuePattern  = regexp.MustCompile(conditionReasonPattern)
	currencyValuePattern         = regexp.MustCompile(currencyPattern)
	lowerCamelCaseProperty       = regexp.MustCompile(`^[a-z][a-z0-9]*([A-Z][a-z0-9]+)*$`)
	opaqueIDValuePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`)
	opaqueVersionValuePattern    = regexp.MustCompile(opaqueVersionPattern)
	providerTokenValuePattern    = regexp.MustCompile(providerTokenPattern)
	regionValuePattern           = regexp.MustCompile(regionPattern)
	timestampValuePattern        = regexp.MustCompile(timestampPattern)
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
		{name: "hierarchy", fn: validateHierarchy},
		{name: "admission", fn: validateAdmission},
		{name: "operation transitions", fn: validateOperationTransitions},
		{name: "condition transitions", fn: validateConditionTransitions},
		{name: "operations", fn: validateOperations},
		{name: "authorization", fn: validateAuthorization},
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
				if allowed && !isReviewedOpenObjectRefinement(path, typed) {
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

func isReviewedRootParentExclusion(path string, schema map[string]any) bool {
	return path == "$/components/schemas/RootResourceMetadata/allOf/1/not" &&
		schema["type"] == "object" && schema["additionalProperties"] == true &&
		stringSetEquals(schema["required"], []string{"parent"})
}

func isReviewedOpenObjectRefinement(path string, schema map[string]any) bool {
	if isReviewedRootParentExclusion(path, schema) {
		return true
	}
	if path == "$/components/schemas/PolicyScope/oneOf/0/not" {
		return schema["type"] == "object" && schema["additionalProperties"] == true &&
			stringSetEquals(schema["required"], []string{"environmentId"})
	}
	return path == "$/components/schemas/CostEstimate/oneOf/1/not" &&
		schema["type"] == "object" && schema["additionalProperties"] == true &&
		stringSetEquals(schema["required"], []string{"amount"})
}

func isReviewedProblemRefinement(path string, schema map[string]any) bool {
	if schema["x-veer-refinement"] != true {
		return isReviewedControlRefinement(path)
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

func isReviewedControlRefinement(path string) bool {
	for _, prefix := range []string{
		"$/components/schemas/QuotaCheck/oneOf/",
		"$/components/schemas/CostEstimate/oneOf/",
		"$/components/schemas/PolicyScope/oneOf/",
	} {
		if strings.HasPrefix(path, prefix) && !strings.Contains(strings.TrimPrefix(path, prefix), "/") {
			return true
		}
	}
	return false
}

func isReviewedFreeFormMap(path string, schema map[string]any) bool {
	return path == "$/components/schemas/Labels" && schema["x-veer-free-form-map"] == true
}

func isReviewedExtension(path, name string) bool {
	switch name {
	case "x-veer-evolution", "x-veer-hierarchy", "x-veer-admission", "x-veer-authorization", "x-veer-operation-transitions", "x-veer-condition-transitions":
		return path == "$"
	case "x-veer-authorization-action":
		return strings.HasPrefix(path, "$/paths/") &&
			(strings.HasSuffix(path, "/get") ||
				strings.HasSuffix(path, "/post") ||
				strings.HasSuffix(path, "/put") ||
				strings.HasSuffix(path, "/delete"))
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
	case "x-veer-path-response-id-binding":
		switch path {
		case "$/paths//api/v1alpha1/workspaces/{workspaceId}/get",
			"$/paths//api/v1alpha1/workspaces/{workspaceId}/put",
			"$/paths//api/v1alpha1/workspaces/{workspaceId}/delete",
			"$/paths//api/v1alpha1/workspaces/{workspaceId}/status/put",
			"$/paths//api/v1alpha1/operations/{operationId}/get":
			return true
		default:
			return false
		}
	case "x-veer-response-generation-constant":
		return path == "$/paths//api/v1alpha1/workspaces/post"
	case "x-veer-request-response-body-binding":
		return path == "$/paths//api/v1alpha1/workspaces/{workspaceId}/status/put"
	case "x-veer-observed-generation-upper-bound":
		return path == "$/paths//api/v1alpha1/workspaces/{workspaceId}/status/put" ||
			isResourceSchemaPath(path, "")
	case "x-veer-deprecation-sunset-minimum-notice-days",
		"x-veer-etag-resource-version-pointer",
		"x-veer-location-operation-id-pointer",
		"x-veer-request-id-body-pointer",
		"x-veer-required-header-sets",
		"x-veer-required-headers":
		return isResponseComponentPath(path)
	case "x-veer-retry-after-body-pointer":
		return path == "$/components/responses/Throttled" ||
			path == "$/components/responses/Unavailable"
	case "x-veer-free-form-map":
		return true
	case "x-veer-instance-request-id-template":
		return path == "$/components/schemas/Problem"
	case "x-veer-maximum-encoded-json-bytes":
		return path == "$/components/schemas/FieldViolation/properties/field"
	case "x-veer-maximum-json-bytes":
		switch path {
		case "$/components/schemas/MutationReceipt",
			"$/components/schemas/Operation",
			"$/components/schemas/Problem",
			"$/components/schemas/StatusReceipt",
			"$/components/schemas/WorkspaceList":
			return true
		default:
			return isResourceSchemaPath(path, "") || isResourceSchemaPath(path, "List")
		}
	case "x-veer-page-byte-policy":
		return isResourceSchemaPath(path, "List")
	case "x-veer-list-order", "x-veer-list-unique-key":
		return path == "$/components/schemas/ProviderConnectionStatus/properties/capabilities" ||
			path == "$/components/schemas/ProviderConnectionStatus/properties/quotaChecks"
	case "x-veer-quota-comparison":
		return path == "$/components/schemas/QuotaCheck"
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

func isResourceSchemaPath(path, suffix string) bool {
	for _, contract := range resourceSchemaContracts {
		if path == "$/components/schemas/"+contract.schema(suffix) {
			return true
		}
	}
	return false
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

func validateHierarchy(root map[string]any) error {
	raw, exists := root["x-veer-hierarchy"]
	if !exists {
		return errors.New("x-veer-hierarchy is missing")
	}

	var hierarchy hierarchyContract
	if err := decodeStrictValue(raw, &hierarchy); err != nil {
		return fmt.Errorf("x-veer-hierarchy shape: %w", err)
	}
	if err := validateHierarchyFieldSets(raw); err != nil {
		return err
	}
	if hierarchy.WorkspaceOwnership != (hierarchyWorkspaceOwnership{
		WorkspaceIDPointer: "/metadata/workspaceId",
		RootDerivation:     "resource-id",
		ChildDerivation:    "resolved-parent-workspace-id",
		ClientWritable:     false,
		Mutable:            false,
	}) {
		return errors.New("workspace ownership policy drifted")
	}
	if hierarchy.ParentReference != (hierarchyParentReference{
		Pointer: "/metadata/parent",
		Source:  "server-derived",
		Mutable: false,
	}) {
		return errors.New("parent reference policy drifted")
	}
	if hierarchy.ReferenceValidation != (hierarchyReferenceValidation{
		Orphan:         "reject",
		CrossWorkspace: "reject",
		Cycle:          "reject",
	}) {
		return errors.New("hierarchy reference validation policy drifted")
	}
	if hierarchy.Deletion != (hierarchyDeletion{Policy: "RESTRICT", BlockedBy: "retained-direct-child"}) {
		return errors.New("hierarchy deletion policy drifted")
	}
	if len(hierarchy.Resources) != len(resourceSchemaContracts) {
		return fmt.Errorf("hierarchy must contain exactly %d resource kinds", len(resourceSchemaContracts))
	}
	for index, want := range resourceSchemaContracts {
		got := hierarchy.Resources[index]
		if got.Kind != want.kind {
			return fmt.Errorf("hierarchy resource %d kind must be %s", index, want.kind)
		}
		if want.parentKind == "" {
			if got.ParentKind != nil {
				return fmt.Errorf("hierarchy resource %s must be a root", want.kind)
			}
		} else if got.ParentKind == nil || *got.ParentKind != want.parentKind {
			return fmt.Errorf("hierarchy resource %s parent kind must be %s", want.kind, want.parentKind)
		}
		if got.Schema.Ref != "#/components/schemas/"+want.kind {
			return fmt.Errorf("hierarchy resource %s schema reference drifted", want.kind)
		}
		if got.MetadataSchema.Ref != "#/components/schemas/"+want.metadataSchema {
			return fmt.Errorf("hierarchy resource %s metadata schema reference drifted", want.kind)
		}
		for _, role := range []struct {
			name      string
			suffix    string
			reference hierarchyReference
		}{
			{name: "create", suffix: "Create", reference: got.CreateSchema},
			{name: "replace", suffix: "Replace", reference: got.ReplaceSchema},
			{name: "status write", suffix: "StatusWrite", reference: got.StatusWriteSchema},
			{name: "list", suffix: "List", reference: got.ListSchema},
		} {
			if role.reference.Ref != "#/components/schemas/"+want.schema(role.suffix) {
				return fmt.Errorf("hierarchy resource %s %s schema reference drifted", want.kind, role.name)
			}
		}
	}
	return nil
}

func validateHierarchyFieldSets(raw any) error {
	hierarchy, ok := raw.(map[string]any)
	if !ok || !mapKeySetEquals(hierarchy, []string{
		"workspaceOwnership", "parentReference", "referenceValidation", "deletion", "resources",
	}) {
		return errors.New("x-veer-hierarchy field set drifted")
	}
	for name, fields := range map[string][]string{
		"workspaceOwnership": {
			"workspaceIdPointer", "rootDerivation", "childDerivation", "clientWritable", "mutable",
		},
		"parentReference":     {"pointer", "source", "mutable"},
		"referenceValidation": {"orphan", "crossWorkspace", "cycle"},
		"deletion":            {"policy", "blockedBy"},
	} {
		object, err := mapField(hierarchy, name)
		if err != nil || !mapKeySetEquals(object, fields) {
			return fmt.Errorf("x-veer-hierarchy.%s field set drifted", name)
		}
	}
	resources, ok := hierarchy["resources"].([]any)
	if !ok {
		return errors.New("x-veer-hierarchy.resources is not an array")
	}
	for index, rawResource := range resources {
		resource, ok := rawResource.(map[string]any)
		if !ok || !mapKeySetEquals(resource, []string{
			"kind", "parentKind", "schema", "metadataSchema", "createSchema", "replaceSchema",
			"statusWriteSchema", "listSchema",
		}) {
			return fmt.Errorf("x-veer-hierarchy.resources[%d] field set drifted", index)
		}
		for _, name := range []string{
			"schema", "metadataSchema", "createSchema", "replaceSchema", "statusWriteSchema", "listSchema",
		} {
			reference, err := mapField(resource, name)
			if err != nil || !mapKeySetEquals(reference, []string{"$ref"}) {
				return fmt.Errorf("x-veer-hierarchy.resources[%d].%s field set drifted", index, name)
			}
		}
	}
	return nil
}

func validateAdmission(root map[string]any) error {
	raw, exists := root["x-veer-admission"]
	if !exists {
		return errors.New("x-veer-admission is missing")
	}
	if err := validateAdmissionFieldSets(raw); err != nil {
		return err
	}

	var got admissionContract
	if err := decodeStrictValue(raw, &got); err != nil {
		return fmt.Errorf("x-veer-admission shape: %w", err)
	}
	validationFailure := hierarchyReference{Ref: "#/components/responses/ValidationFailure"}
	internalFailure := hierarchyReference{Ref: "#/components/responses/InternalFailure"}
	wantStages := []admissionStage{
		{
			Name: "schema",
			Codes: []string{
				"request-too-large", "invalid-json", "json-too-deep", "too-many-json-nodes",
				"duplicate-field", "unknown-field", "missing-field", "invalid-type", "invalid-value",
				"unsupported-version", "unsupported-kind",
			},
			DefaultResponse: validationFailure,
			ResponseOverrides: map[string]hierarchyReference{
				"request-too-large": {Ref: "#/components/responses/RequestTooLarge"},
			},
		},
		{
			Name:            "semantic",
			Codes:           []string{"invalid-spec", "invalid-status", "invalid-order", "duplicate-item", "future-observation"},
			DefaultResponse: validationFailure,
		},
		{Name: "immutable", Codes: []string{"immutable-field"}, DefaultResponse: validationFailure},
		{
			Name: "reference",
			Codes: []string{
				"invalid-placement", "parent-not-found", "parent-kind-mismatch", "reference-not-found",
				"reference-kind-mismatch", "workspace-mismatch",
			},
			DefaultResponse: validationFailure,
		},
		{Name: "default", Codes: []string{"default-failed"}, DefaultResponse: internalFailure},
		{Name: "conversion", Codes: []string{"conversion-failed"}, DefaultResponse: internalFailure},
	}
	if !reflect.DeepEqual(got.Stages, wantStages) {
		return errors.New("admission stage order, codes, or response mapping drifted")
	}
	if !reflect.DeepEqual(got.ErrorSelection, admissionErrorSelection{
		Maximum: 1,
		Precedence: []string{
			"stage-order", "lexicographic-bounded-rfc6901-pointer-or-empty", "lexicographic-code",
		},
		TerminalSyntaxErrors: []string{"invalid-json"},
		TerminalWorkCeilings: []string{
			"request-too-large", "json-too-deep", "too-many-json-nodes",
		},
	}) {
		return errors.New("admission error selection policy drifted")
	}
	if got.FieldPath != (admissionFieldPath{
		Syntax:               "rfc6901-json-pointer",
		WholeDocument:        "",
		Unrepresentable:      "empty-and-omit-field-violation",
		Truncation:           "forbidden",
		FieldViolationSchema: hierarchyReference{Ref: "#/components/schemas/FieldViolation"},
	}) {
		return errors.New("admission field path policy drifted")
	}
	if got.FailureEffects != (admissionFailureEffects{
		StateMutation: "none", QueueMutation: "none", CallbackInvocation: "none",
	}) {
		return errors.New("admission failure effects drifted")
	}
	wantDefaulting := admissionDefaulting{
		Mode: "copy-returning", Deterministic: true, Idempotent: true,
		Rules: []admissionDefaultRule{{
			APIVersion:     "v1alpha1",
			Kind:           "Workspace",
			RequestPointer: "/spec/suspendReconciliation",
			When:           "absent",
			Value:          false,
			WriteSpecSchema: hierarchyReference{
				Ref: "#/components/schemas/WorkspaceSpecWrite",
			},
			CanonicalSpecSchema: hierarchyReference{Ref: "#/components/schemas/WorkspaceSpec"},
		}},
	}
	if !reflect.DeepEqual(got.Defaulting, wantDefaulting) {
		return errors.New("admission defaulting policy drifted")
	}
	wantKinds := make([]string, 0, len(resourceSchemaContracts))
	for _, contract := range resourceSchemaContracts {
		wantKinds = append(wantKinds, contract.kind)
	}
	wantVersionHub := admissionVersionHub{
		Hub:                    "internal",
		Scope:                  "spec-and-status-commands",
		ServedVersions:         []string{"v1alpha1"},
		StorageVersion:         "v1alpha1",
		Kinds:                  wantKinds,
		Conversion:             "defaulted-source-to-hub",
		RoundTrip:              "semantic-equivalence-after-defaulting",
		UnsupportedVersionCode: "unsupported-version",
		UnsupportedKindCode:    "unsupported-kind",
	}
	if !reflect.DeepEqual(got.VersionHub, wantVersionHub) {
		return errors.New("admission version hub policy drifted")
	}
	info, err := mapField(root, "info")
	if err != nil {
		return err
	}
	evolution, err := mapField(root, "x-veer-evolution")
	if err != nil {
		return err
	}
	if info["version"] != got.VersionHub.StorageVersion ||
		evolution["transportVersion"] != got.VersionHub.ServedVersions[0] {
		return errors.New("admission version hub is not bound to the transport contract")
	}
	return nil
}

func validateAdmissionFieldSets(raw any) error {
	manifest, ok := raw.(map[string]any)
	if !ok || !mapKeySetEquals(manifest, []string{
		"stages", "errorSelection", "fieldPath", "failureEffects", "defaulting", "versionHub",
	}) {
		return errors.New("x-veer-admission field set drifted")
	}
	stages, ok := manifest["stages"].([]any)
	if !ok || len(stages) != 6 {
		return errors.New("x-veer-admission.stages must contain exactly six entries")
	}
	for index, rawStage := range stages {
		stage, ok := rawStage.(map[string]any)
		wantFields := []string{"name", "codes", "defaultResponse"}
		if index == 0 {
			wantFields = append(wantFields, "responseOverrides")
		}
		if !ok || !mapKeySetEquals(stage, wantFields) {
			return fmt.Errorf("x-veer-admission.stages[%d] field set drifted", index)
		}
		response, err := mapField(stage, "defaultResponse")
		if err != nil || !mapKeySetEquals(response, []string{"$ref"}) {
			return fmt.Errorf("x-veer-admission.stages[%d].defaultResponse field set drifted", index)
		}
		if index == 0 {
			overrides, err := mapField(stage, "responseOverrides")
			if err != nil || !mapKeySetEquals(overrides, []string{"request-too-large"}) {
				return errors.New("x-veer-admission schema response overrides drifted")
			}
			override, err := mapField(overrides, "request-too-large")
			if err != nil || !mapKeySetEquals(override, []string{"$ref"}) {
				return errors.New("x-veer-admission request-too-large response field set drifted")
			}
		}
	}
	for name, fields := range map[string][]string{
		"errorSelection": {"maximum", "precedence", "terminalSyntaxErrors", "terminalWorkCeilings"},
		"fieldPath": {
			"syntax", "wholeDocument", "unrepresentable", "truncation", "fieldViolationSchema",
		},
		"failureEffects": {"stateMutation", "queueMutation", "callbackInvocation"},
		"defaulting":     {"mode", "deterministic", "idempotent", "rules"},
		"versionHub": {
			"hub", "scope", "servedVersions", "storageVersion", "kinds", "conversion", "roundTrip",
			"unsupportedVersionCode", "unsupportedKindCode",
		},
	} {
		object, err := mapField(manifest, name)
		if err != nil || !mapKeySetEquals(object, fields) {
			return fmt.Errorf("x-veer-admission.%s field set drifted", name)
		}
	}
	fieldPath, _ := mapField(manifest, "fieldPath")
	fieldViolation, err := mapField(fieldPath, "fieldViolationSchema")
	if err != nil || !mapKeySetEquals(fieldViolation, []string{"$ref"}) {
		return errors.New("x-veer-admission.fieldPath.fieldViolationSchema field set drifted")
	}
	defaulting, _ := mapField(manifest, "defaulting")
	rules, ok := defaulting["rules"].([]any)
	if !ok || len(rules) != 1 {
		return errors.New("x-veer-admission.defaulting.rules must contain exactly one rule")
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || !mapKeySetEquals(rule, []string{
		"apiVersion", "kind", "requestPointer", "when", "value", "writeSpecSchema", "canonicalSpecSchema",
	}) {
		return errors.New("x-veer-admission.defaulting.rules[0] field set drifted")
	}
	for _, name := range []string{"writeSpecSchema", "canonicalSpecSchema"} {
		reference, err := mapField(rule, name)
		if err != nil || !mapKeySetEquals(reference, []string{"$ref"}) {
			return fmt.Errorf("x-veer-admission.defaulting.rules[0].%s field set drifted", name)
		}
	}
	return nil
}

func validateAuthorization(root map[string]any) error {
	raw, exists := root["x-veer-authorization"]
	if !exists {
		return errors.New("x-veer-authorization is missing")
	}
	var got authorizationContract
	if err := decodeStrictValue(raw, &got); err != nil {
		return fmt.Errorf("x-veer-authorization shape: %w", err)
	}
	if !reflect.DeepEqual(got, authorizationManifestContract()) {
		return errors.New("x-veer-authorization contract drifted")
	}

	paths, err := mapField(root, "paths")
	if err != nil {
		return err
	}
	wantActions := map[string]string{
		"listWorkspaces":         "resource.list",
		"createWorkspace":        "resource.create",
		"getWorkspace":           "resource.get",
		"replaceWorkspace":       "resource.replace",
		"deleteWorkspace":        "resource.delete",
		"replaceWorkspaceStatus": "resource.status.replace",
		"getOperation":           "operation.get",
	}
	seen := make(map[string]struct{}, len(wantActions))
	for route, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			return fmt.Errorf("path %q is not an object", route)
		}
		for method, rawOperation := range item {
			if pathItemMetadata[method] || strings.HasPrefix(method, "x-") {
				continue
			}
			operation, ok := rawOperation.(map[string]any)
			if !ok {
				return fmt.Errorf("%s %s is not an operation object", strings.ToUpper(method), route)
			}
			operationID, ok := operation["operationId"].(string)
			if !ok || operationID == "" {
				return fmt.Errorf("%s %s omits operationId", strings.ToUpper(method), route)
			}
			wantAction, reviewed := wantActions[operationID]
			if !reviewed {
				return fmt.Errorf("operationId %q has no authorization annotation contract", operationID)
			}
			if operation["x-veer-authorization-action"] != wantAction {
				return fmt.Errorf("operationId %q authorization action must be %q", operationID, wantAction)
			}
			seen[operationID] = struct{}{}
		}
	}
	if len(seen) != len(wantActions) {
		return errors.New("authorization operation annotation set drifted")
	}
	return nil
}

func authorizationManifestContract() authorizationContract {
	allResourceKinds := []string{"Application", "Component", "Environment", "ProviderConnection", "Workspace"}
	return authorizationContract{
		ContractVersion:     "veer.authorization.v1alpha1",
		DefaultEffect:       "Deny",
		PolicyVersionPrefix: "azv1_",
		InputDigestPrefix:   "azi1_",
		MaxDecisionBytes:    1024,
		ListEvaluation:      "per-retained-row",
		Actions: []string{
			"resource.list", "resource.get", "resource.create", "resource.replace", "resource.delete",
			"resource.status.replace", "plan.list", "plan.get", "plan.preview", "operation.list",
			"operation.get", "operation.cancel", "operation.retry", "operation.quarantine", "membership.list",
			"membership.get", "membership.create", "membership.replace", "membership.delete", "audit.list",
			"audit.export", "approval.approve", "approval.reject", "approval.override", "work.publish",
			"work.consume", "work.redrive", "reconcile.plan", "reconcile.execute", "operation.transition",
			"credential.resolve", "provider.discover", "provider.apply", "provider.observe", "provider.delete",
			"audit.append",
		},
		Objects: []string{"Resource", "Operation", "Plan", "Membership", "Audit"},
		Scopes: []authorizationScopeContract{
			{Kind: "Workspace", DescendsTo: []string{"Workspace", "Environment"}},
			{Kind: "Environment", DescendsTo: []string{"Environment"}},
		},
		Roles: []authorizationRoleContract{
			{
				Name: "Viewer", Inherits: []string{},
				Grants: []authorizationGrantContract{
					{Action: "resource.list", ObjectKind: "Resource", ResourceKinds: allResourceKinds},
					{Action: "resource.get", ObjectKind: "Resource", ResourceKinds: allResourceKinds},
					{Action: "plan.list", ObjectKind: "Plan", ResourceKinds: allResourceKinds},
					{Action: "plan.get", ObjectKind: "Plan", ResourceKinds: allResourceKinds},
					{Action: "operation.list", ObjectKind: "Operation", ResourceKinds: allResourceKinds},
					{Action: "operation.get", ObjectKind: "Operation", ResourceKinds: allResourceKinds},
					{Action: "audit.list", ObjectKind: "Audit", ResourceKinds: allResourceKinds},
				},
			},
			{
				Name: "Developer", Inherits: []string{"Viewer"},
				Grants: []authorizationGrantContract{
					{Action: "resource.create", ObjectKind: "Resource", ResourceKinds: []string{"Application", "Component"}},
					{Action: "resource.replace", ObjectKind: "Resource", ResourceKinds: []string{"Application", "Component"}},
					{Action: "resource.delete", ObjectKind: "Resource", ResourceKinds: []string{"Application", "Component"}},
					{Action: "plan.preview", ObjectKind: "Plan", ResourceKinds: []string{"Application", "Component"}},
					{Action: "operation.cancel", ObjectKind: "Operation", ResourceKinds: []string{"Application", "Component"}},
				},
			},
			{
				Name: "Operator", Inherits: []string{"Viewer"},
				Grants: []authorizationGrantContract{
					{Action: "resource.create", ObjectKind: "Resource", ResourceKinds: []string{"Environment", "ProviderConnection"}},
					{Action: "resource.replace", ObjectKind: "Resource", ResourceKinds: []string{"Environment", "ProviderConnection"}},
					{Action: "resource.delete", ObjectKind: "Resource", ResourceKinds: []string{"Environment", "ProviderConnection"}},
					{Action: "plan.preview", ObjectKind: "Plan", ResourceKinds: []string{"Environment", "ProviderConnection"}},
					{Action: "operation.cancel", ObjectKind: "Operation", ResourceKinds: []string{"Application", "Component", "Environment", "ProviderConnection"}},
					{Action: "operation.retry", ObjectKind: "Operation", ResourceKinds: []string{"Application", "Component", "Environment", "ProviderConnection"}},
				},
			},
			{
				Name: "WorkspaceAdministrator", Inherits: []string{"Viewer"},
				Grants: []authorizationGrantContract{
					{Action: "resource.list", ObjectKind: "Resource", ResourceKinds: []string{"Policy"}},
					{Action: "resource.get", ObjectKind: "Resource", ResourceKinds: []string{"Policy"}},
					{Action: "resource.create", ObjectKind: "Resource", ResourceKinds: []string{"Policy"}},
					{Action: "resource.replace", ObjectKind: "Resource", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "resource.delete", ObjectKind: "Resource", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "plan.list", ObjectKind: "Plan", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "plan.get", ObjectKind: "Plan", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "plan.preview", ObjectKind: "Plan", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "operation.list", ObjectKind: "Operation", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "operation.get", ObjectKind: "Operation", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "operation.cancel", ObjectKind: "Operation", ResourceKinds: []string{"Policy", "Workspace"}},
					{Action: "membership.list", ObjectKind: "Membership", ResourceKinds: []string{}},
					{Action: "membership.get", ObjectKind: "Membership", ResourceKinds: []string{}},
					{Action: "membership.create", ObjectKind: "Membership", ResourceKinds: []string{}},
					{Action: "membership.replace", ObjectKind: "Membership", ResourceKinds: []string{}},
					{Action: "membership.delete", ObjectKind: "Membership", ResourceKinds: []string{}},
				},
			},
		},
		ReservedActions: []string{
			"resource.status.replace", "operation.quarantine", "audit.export", "approval.approve", "approval.reject",
			"approval.override", "work.publish", "work.consume", "work.redrive", "reconcile.plan", "reconcile.execute",
			"operation.transition", "credential.resolve", "provider.discover", "provider.apply", "provider.observe",
			"provider.delete", "audit.append",
		},
		ReservedResourceActions: []authorizationResourceAction{
			{Action: "resource.create", ResourceKind: "Workspace"},
		},
		Effects: []string{"Allow", "Deny"},
		Reasons: []string{
			"CrossWorkspace", "ReservedAction", "NoMembership", "NoRoleBinding",
			"ScopeNotGranted", "ActionNotGranted", "RoleGranted",
		},
	}
}

func validateOperationTransitions(root map[string]any) error {
	raw, exists := root["x-veer-operation-transitions"]
	if !exists {
		return errors.New("x-veer-operation-transitions is missing")
	}
	manifest, ok := raw.(map[string]any)
	if !ok || !mapKeySetEquals(manifest, []string{
		"phasePointer", "transitions", "terminalPhases", "terminalReplay", "unknownPhase",
	}) {
		return errors.New("operation transition manifest field set drifted")
	}
	var contract operationTransitionContract
	if err := decodeStrictValue(raw, &contract); err != nil {
		return fmt.Errorf("operation transition manifest shape: %w", err)
	}
	if contract.PhasePointer != "/phase" || contract.TerminalReplay != "exact-only" ||
		contract.UnknownPhase != "nonterminal-no-side-effects" ||
		!reflect.DeepEqual(contract.TerminalPhases, []string{"Succeeded", "Failed", "Canceled"}) {
		return errors.New("operation terminal transition policy drifted")
	}
	want := map[string][]string{
		"Pending": {"Waiting", "Running", "Succeeded", "Failed", "Canceled"},
		"Waiting": {"Pending", "Running", "Succeeded", "Failed", "Canceled"},
		"Running": {"Waiting", "Succeeded", "Failed", "Canceled"},
	}
	if !reflect.DeepEqual(contract.Transitions, want) {
		return errors.New("operation transition graph drifted")
	}
	return nil
}

func validateConditionTransitions(root map[string]any) error {
	raw, exists := root["x-veer-condition-transitions"]
	if !exists {
		return errors.New("x-veer-condition-transitions is missing")
	}
	manifest, ok := raw.(map[string]any)
	if !ok || !mapKeySetEquals(manifest, []string{
		"identityPointer", "statusPointer", "observedGenerationPointer", "transitionTimePointer",
		"statuses", "sameStatusTimestamp", "changedStatusTimestamp", "observedGeneration", "setOrder",
	}) {
		return errors.New("condition transition manifest field set drifted")
	}
	var contract conditionTransitionContract
	if err := decodeStrictValue(raw, &contract); err != nil {
		return fmt.Errorf("condition transition manifest shape: %w", err)
	}
	want := conditionTransitionContract{
		IdentityPointer:           "/type",
		StatusPointer:             "/status",
		ObservedGenerationPointer: "/observedGeneration",
		TransitionTimePointer:     "/lastTransitionAt",
		Statuses:                  []string{"True", "False", "Unknown"},
		SameStatusTimestamp:       "preserve",
		ChangedStatusTimestamp:    "advance",
		ObservedGeneration:        "nondecreasing-and-not-above-resource-generation",
		SetOrder:                  "ascending-unique-type",
	}
	if !reflect.DeepEqual(contract, want) {
		return errors.New("condition transition policy drifted")
	}
	return nil
}

func decodeStrictValue(value any, target any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode value: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
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
			if err := validatePathResponseIDBinding(operationID, operation); err != nil {
				return err
			}
			if err := validateOperationGenerationContracts(operationID, operation); err != nil {
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

func validatePathResponseIDBinding(operationID string, operation map[string]any) error {
	want, required := map[string]struct {
		pathParameter string
		bodyPointer   string
	}{
		"deleteWorkspace":        {pathParameter: "workspaceId", bodyPointer: "/resourceId"},
		"getOperation":           {pathParameter: "operationId", bodyPointer: "/id"},
		"getWorkspace":           {pathParameter: "workspaceId", bodyPointer: "/metadata/id"},
		"replaceWorkspace":       {pathParameter: "workspaceId", bodyPointer: "/resourceId"},
		"replaceWorkspaceStatus": {pathParameter: "workspaceId", bodyPointer: "/resourceId"},
	}[operationID]
	raw, exists := operation["x-veer-path-response-id-binding"]
	if !required {
		if exists {
			return fmt.Errorf("operationId %q declares an unexpected path-response identity binding", operationID)
		}
		return nil
	}
	binding, ok := raw.(map[string]any)
	if !exists || !ok || !mapKeySetEquals(binding, []string{"pathParameter", "bodyPointer"}) ||
		binding["pathParameter"] != want.pathParameter || binding["bodyPointer"] != want.bodyPointer {
		return fmt.Errorf("operationId %q path-response identity binding drifted", operationID)
	}
	return nil
}

func validateOperationGenerationContracts(operationID string, operation map[string]any) error {
	constant, hasConstant := operation["x-veer-response-generation-constant"]
	if operationID == "createWorkspace" {
		contract, ok := constant.(map[string]any)
		if !hasConstant || !ok || !mapKeySetEquals(contract, []string{"responseBodyPointer", "value"}) ||
			contract["responseBodyPointer"] != "/generation" || !numberEquals(contract["value"], "1") {
			return errors.New("operationId \"createWorkspace\" response generation constant drifted")
		}
	} else if hasConstant {
		return fmt.Errorf("operationId %q declares an unexpected response generation constant", operationID)
	}

	binding, hasBinding := operation["x-veer-request-response-body-binding"]
	upperBound, hasUpperBound := operation["x-veer-observed-generation-upper-bound"]
	if operationID == "replaceWorkspaceStatus" {
		contract, ok := binding.(map[string]any)
		if !hasBinding || !ok || !mapKeySetEquals(contract, []string{"requestBodyPointer", "responseBodyPointer"}) ||
			contract["requestBodyPointer"] != "/status/observedGeneration" ||
			contract["responseBodyPointer"] != "/observedGeneration" {
			return errors.New("operationId \"replaceWorkspaceStatus\" request-response generation binding drifted")
		}
		if !hasUpperBound || !validObservedGenerationUpperBound(upperBound) {
			return errors.New("operationId \"replaceWorkspaceStatus\" observed-generation upper bound drifted")
		}
	} else {
		if hasBinding {
			return fmt.Errorf("operationId %q declares an unexpected request-response body binding", operationID)
		}
		if hasUpperBound {
			return fmt.Errorf("operationId %q declares an unexpected observed-generation upper bound", operationID)
		}
	}
	return nil
}

func validObservedGenerationUpperBound(raw any) bool {
	contract, ok := raw.(map[string]any)
	return ok && mapKeySetEquals(contract, []string{
		"conditionObservedGenerationPointerTemplate", "observedGenerationPointer",
		"resourceGenerationPointer",
	}) && contract["observedGenerationPointer"] == "/status/observedGeneration" &&
		contract["conditionObservedGenerationPointerTemplate"] == "/status/conditions/{index}/observedGeneration" &&
		contract["resourceGenerationPointer"] == "/metadata/generation"
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
		if parameter["name"] != contract.wireName || parameter["in"] != "path" || parameter["required"] != true ||
			parameter["style"] != "simple" || parameter["explode"] != false {
			return fmt.Errorf("%s path parameter contract drifted", contract.component)
		}
		if !mapKeySetEquals(parameter, []string{
			"name", "in", "required", "style", "explode", "description", "schema",
		}) {
			return fmt.Errorf("%s path parameter has unreviewed keywords", contract.component)
		}
		if err := requireSchemaReference(parameter, "#/components/schemas/"+contract.schema); err != nil {
			return fmt.Errorf("%s: %w", contract.component, err)
		}
	}
	for _, contract := range []struct {
		name     string
		keywords []string
	}{
		{name: "VeerRequestId", keywords: []string{"name", "in", "required", "description", "schema"}},
		{name: "IdempotencyKey", keywords: []string{"name", "in", "required", "description", "schema"}},
		{name: "IfMatch", keywords: []string{"name", "in", "required", "description", "schema"}},
		{name: "PageSize", keywords: []string{"name", "in", "required", "description", "schema"}},
		{name: "PageToken", keywords: []string{"name", "in", "required", "description", "schema"}},
	} {
		parameter, err := mapField(parameters, contract.name)
		if err != nil {
			return err
		}
		if !mapKeySetEquals(parameter, contract.keywords) {
			return fmt.Errorf("%s parameter has unreviewed keywords", contract.name)
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
	for name, keywords := range map[string][]string{
		"Deprecation":     {"type", "pattern", "example", "x-veer-calendar-validation"},
		"DeprecationLink": {"type", "minLength", "maxLength", "pattern", "example", "x-veer-link-target-validation"},
		"Location":        {"type", "pattern"},
		"RetryAfter":      {"type", "pattern"},
		"Sunset":          {"type", "pattern", "example", "x-veer-calendar-validation"},
		"WWWAuthenticate": {"type", "maxLength", "pattern"},
	} {
		header, err := mapField(headers, name)
		if err != nil {
			return err
		}
		schema, err := mapField(header, "schema")
		if err != nil {
			return err
		}
		if !mapKeySetEquals(schema, keywords) {
			return fmt.Errorf("%s header schema has unreviewed keywords", name)
		}
	}
	for _, contract := range []struct {
		name     string
		keywords []string
	}{
		{name: "Deprecation", keywords: []string{"description", "schema"}},
		{name: "DeprecationLink", keywords: []string{"description", "schema"}},
		{name: "ETag", keywords: []string{"description", "schema"}},
		{name: "Location", keywords: []string{"description", "schema"}},
		{name: "RetryAfter", keywords: []string{"description", "schema"}},
		{name: "Sunset", keywords: []string{"description", "schema"}},
		{name: "VeerRequestId", keywords: []string{"description", "schema", "x-veer-request-id-binding"}},
		{name: "WWWAuthenticate", keywords: []string{"description", "schema"}},
	} {
		header, err := mapField(headers, contract.name)
		if err != nil {
			return err
		}
		if !mapKeySetEquals(header, contract.keywords) {
			return fmt.Errorf("%s header has unreviewed keywords", contract.name)
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
			if name == "MutationAccepted" {
				example, err := mapField(media, "example")
				if err != nil || !numberEquals(example["generation"], "1") {
					return errors.New("success response MutationAccepted generation example drifted")
				}
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
		{name: "Operation", extras: []string{"example", "oneOf", "x-veer-maximum-json-bytes"}},
		{name: "Problem", extras: []string{"x-veer-instance-request-id-template", "x-veer-maximum-json-bytes"}},
		{name: "ResourceMetadata", extras: []string{"example"}},
		{name: "StatusReceipt", extras: []string{"x-veer-maximum-json-bytes"}},
		{name: "Workspace", extras: []string{
			"example", "x-veer-maximum-json-bytes", "x-veer-observed-generation-upper-bound",
		}},
		{name: "WorkspaceCreate"},
		{name: "WorkspaceList", extras: []string{"x-veer-maximum-json-bytes", "x-veer-page-byte-policy"}},
		{name: "WorkspaceReplace"},
		{name: "WorkspaceSpec"},
		{name: "WorkspaceSpecWrite"},
		{name: "WorkspaceStatus", extras: []string{"example"}},
		{name: "WorkspaceStatusWrite"},
		{name: "WritableMetadata", extras: []string{"example"}},
		{name: "CredentialReference", extras: []string{"example"}},
		{name: "ProviderCapability", extras: []string{"example"}},
		{name: "QuotaCheck", extras: []string{"example", "oneOf", "x-veer-quota-comparison"}},
		{name: "CostEstimate", extras: []string{"example", "oneOf"}},
		{name: "PolicyBinding"},
		{name: "PolicyScope", extras: []string{"oneOf"}},
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
	for _, contract := range resourceSchemaContracts[1:] {
		for _, schemaContract := range []struct {
			suffix string
			extra  []string
		}{
			{extra: []string{"example", "x-veer-maximum-json-bytes", "x-veer-observed-generation-upper-bound"}},
			{suffix: "Create"},
			{suffix: "List", extra: []string{"x-veer-maximum-json-bytes", "x-veer-page-byte-policy"}},
			{suffix: "Replace"},
			{suffix: "Spec"},
			{suffix: "Status", extra: []string{"example"}},
			{suffix: "StatusWrite"},
		} {
			schema, err := mapField(schemas, contract.schema(schemaContract.suffix))
			if err != nil {
				return err
			}
			keywords := append([]string(nil), objectKeywords...)
			keywords = append(keywords, schemaContract.extra...)
			if !mapKeysAllowed(schema, keywords) {
				return fmt.Errorf("%s schema has unreviewed keywords", contract.schema(schemaContract.suffix))
			}
		}
	}
	for _, name := range []string{"RootResourceMetadata", "ChildResourceMetadata"} {
		schema, err := mapField(schemas, name)
		if err != nil {
			return err
		}
		if !mapKeySetEquals(schema, []string{"description", "allOf"}) {
			return fmt.Errorf("%s schema has unreviewed keywords", name)
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
	if len(schemas) != expectedSchemaCount {
		return fmt.Errorf("expected exactly %d schemas, got %d", expectedSchemaCount, len(schemas))
	}
	required := []string{
		"Condition", "CostEstimate", "CredentialReference", "FieldViolation", "IdempotencyKey", "Labels", "MutationReceipt",
		"OpaqueId", "Operation", "Problem", "RequestId", "ResourceMetadata", "StatusReceipt", "StrongETag",
		"Timestamp", "ProviderCapability", "QuotaCheck", "Workspace", "WorkspaceCreate", "WorkspaceList", "WorkspaceReplace",
		"WorkspaceSpec", "WorkspaceSpecWrite", "WorkspaceStatus", "WorkspaceStatusWrite", "WritableMetadata",
		"RootResourceMetadata", "ChildResourceMetadata", "PolicyBinding", "PolicyScope",
	}
	for _, contract := range resourceSchemaContracts[1:] {
		for _, suffix := range []string{"", "Create", "List", "Replace", "Spec", "Status", "StatusWrite"} {
			required = append(required, contract.schema(suffix))
		}
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
		"id", "workspaceId", "displayName", "generation", "resourceVersion", "createdAt", "updatedAt",
	}) || len(metadataProperties) != 9 {
		return errors.New("ResourceMetadata shape drifted")
	}
	for _, name := range []string{"id", "workspaceId", "parent", "generation", "resourceVersion", "createdAt", "updatedAt"} {
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
		{
			property: "workspaceId",
			target:   "OpaqueId",
			siblings: map[string]any{
				"type":        "string",
				"readOnly":    true,
				"description": "Immutable server-derived workspace ownership key used for authorization.",
				"example":     "wsp_01J00000000000000000000000",
			},
		},
		{
			property: "parent",
			target:   "OpaqueId",
			siblings: map[string]any{
				"type":        "string",
				"readOnly":    true,
				"description": "Stable ID of the immediate parent. Absent only for a root resource.",
				"example":     "wsp_01J00000000000000000000000",
			},
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
	if err := validateControlValueSchemas(schemas); err != nil {
		return err
	}
	if err := validateMetadataRefinements(schemas); err != nil {
		return err
	}
	for _, contract := range resourceSchemaContracts[1:] {
		if err := validateResourceSchemaFamily(schemas, contract); err != nil {
			return err
		}
	}
	if err := validateResourceExamples(schemas); err != nil {
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
	for _, forbidden := range []string{"id", "workspaceId", "parent", "generation", "resourceVersion", "createdAt", "updatedAt"} {
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
		len(specProperties) != 1 || suspend["type"] != "boolean" {
		return errors.New("WorkspaceSpec contract drifted")
	}
	if !mapKeySetEquals(suspend, []string{"type", "description"}) {
		return errors.New("WorkspaceSpec.suspendReconciliation has unreviewed keywords")
	}
	workspaceSpecWrite, err := mapField(schemas, "WorkspaceSpecWrite")
	if err != nil {
		return err
	}
	writeSpecProperties, err := mapField(workspaceSpecWrite, "properties")
	if err != nil {
		return err
	}
	writeSuspend, err := mapField(writeSpecProperties, "suspendReconciliation")
	if err != nil {
		return err
	}
	if _, required := workspaceSpecWrite["required"]; required || len(writeSpecProperties) != 1 ||
		writeSuspend["type"] != "boolean" || writeSuspend["default"] != false {
		return errors.New("WorkspaceSpecWrite contract drifted")
	}
	if !mapKeySetEquals(workspaceSpecWrite, []string{"type", "description", "additionalProperties", "properties"}) ||
		!mapKeySetEquals(writeSuspend, []string{"type", "default", "description"}) {
		return errors.New("WorkspaceSpecWrite schema has unreviewed keywords")
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
	if !mapKeySetEquals(propertyNames, []string{"type", "minLength", "maxLength", "pattern"}) {
		return errors.New("labels propertyNames schema has unreviewed keywords")
	}
	if !mapKeySetEquals(labelValues, []string{"type", "maxLength"}) {
		return errors.New("labels value schema has unreviewed keywords")
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
	return validateNestedSchemaKeywords(schemas)
}

func validateNestedSchemaKeywords(schemas map[string]any) error {
	contracts := []struct {
		schema   string
		property string
		keywords []string
	}{
		{schema: "ResourceMetadata", property: "id", keywords: []string{"$ref", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "workspaceId", keywords: []string{"$ref", "description", "example", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "displayName", keywords: []string{"maxLength", "minLength", "type"}},
		{schema: "ResourceMetadata", property: "parent", keywords: []string{"$ref", "description", "example", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "labels", keywords: []string{"$ref"}},
		{schema: "ResourceMetadata", property: "generation", keywords: []string{"description", "format", "maximum", "minimum", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "resourceVersion", keywords: []string{"description", "example", "maxLength", "minLength", "pattern", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "createdAt", keywords: []string{"$ref", "readOnly", "type"}},
		{schema: "ResourceMetadata", property: "updatedAt", keywords: []string{"$ref", "readOnly", "type"}},
		{schema: "WritableMetadata", property: "displayName", keywords: []string{"maxLength", "minLength", "type"}},
		{schema: "WritableMetadata", property: "labels", keywords: []string{"$ref"}},
		{schema: "WorkspaceSpec", property: "suspendReconciliation", keywords: []string{"description", "type"}},
		{schema: "WorkspaceSpecWrite", property: "suspendReconciliation", keywords: []string{"default", "description", "type"}},
		{schema: "Condition", property: "type", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "Condition", property: "status", keywords: []string{"enum", "type"}},
		{schema: "Condition", property: "reason", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "Condition", property: "message", keywords: []string{"description", "maxLength", "type"}},
		{schema: "Condition", property: "observedGeneration", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
		{schema: "Condition", property: "lastTransitionAt", keywords: []string{"$ref"}},
		{schema: "WorkspaceStatus", property: "observedGeneration", keywords: []string{"format", "maximum", "minimum", "type"}},
		{schema: "WorkspaceStatus", property: "conditions", keywords: []string{"example", "items", "maxItems", "type"}},
		{schema: "Workspace", property: "apiVersion", keywords: []string{"const", "type"}},
		{schema: "Workspace", property: "kind", keywords: []string{"const", "type"}},
		{schema: "Workspace", property: "metadata", keywords: []string{"$ref"}},
		{schema: "Workspace", property: "spec", keywords: []string{"$ref"}},
		{schema: "Workspace", property: "status", keywords: []string{"$ref"}},
		{schema: "WorkspaceCreate", property: "apiVersion", keywords: []string{"const", "type"}},
		{schema: "WorkspaceCreate", property: "kind", keywords: []string{"const", "type"}},
		{schema: "WorkspaceCreate", property: "metadata", keywords: []string{"$ref"}},
		{schema: "WorkspaceCreate", property: "spec", keywords: []string{"$ref"}},
		{schema: "WorkspaceReplace", property: "apiVersion", keywords: []string{"const", "type"}},
		{schema: "WorkspaceReplace", property: "kind", keywords: []string{"const", "type"}},
		{schema: "WorkspaceReplace", property: "metadata", keywords: []string{"$ref"}},
		{schema: "WorkspaceReplace", property: "spec", keywords: []string{"$ref"}},
		{schema: "WorkspaceStatusWrite", property: "apiVersion", keywords: []string{"const", "type"}},
		{schema: "WorkspaceStatusWrite", property: "kind", keywords: []string{"const", "type"}},
		{schema: "WorkspaceStatusWrite", property: "status", keywords: []string{"$ref"}},
		{schema: "StatusReceipt", property: "resourceId", keywords: []string{"$ref"}},
		{schema: "StatusReceipt", property: "observedGeneration", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
		{schema: "StatusReceipt", property: "resourceVersion", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "StatusReceipt", property: "updatedAt", keywords: []string{"$ref"}},
		{schema: "WorkspaceList", property: "items", keywords: []string{"example", "items", "maxItems", "type"}},
		{schema: "WorkspaceList", property: "nextPageToken", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "MutationReceipt", property: "resourceId", keywords: []string{"$ref"}},
		{schema: "MutationReceipt", property: "operationId", keywords: []string{"$ref"}},
		{schema: "MutationReceipt", property: "generation", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
		{schema: "MutationReceipt", property: "resourceVersion", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "MutationReceipt", property: "acceptedAt", keywords: []string{"$ref"}},
		{schema: "Operation", property: "id", keywords: []string{"$ref", "example", "type"}},
		{schema: "Operation", property: "workspaceId", keywords: []string{"$ref", "example", "type"}},
		{schema: "Operation", property: "environmentId", keywords: []string{"$ref", "example", "type"}},
		{schema: "Operation", property: "providerConnectionId", keywords: []string{"$ref", "example", "type"}},
		{schema: "Operation", property: "resourceId", keywords: []string{"$ref", "example", "type"}},
		{schema: "Operation", property: "generation", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
		{schema: "Operation", property: "resourceVersion", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "Operation", property: "phase", keywords: []string{"enum", "example", "type"}},
		{schema: "Operation", property: "reason", keywords: []string{"example", "maxLength", "pattern", "type"}},
		{schema: "Operation", property: "message", keywords: []string{"description", "example", "maxLength", "type"}},
		{schema: "Operation", property: "costEstimate", keywords: []string{"$ref"}},
		{schema: "Operation", property: "createdAt", keywords: []string{"$ref"}},
		{schema: "Operation", property: "updatedAt", keywords: []string{"$ref"}},
		{schema: "CredentialReference", property: "referenceId", keywords: []string{"$ref", "example", "type"}},
		{schema: "CredentialReference", property: "version", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "ProviderCapability", property: "name", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "ProviderCapability", property: "state", keywords: []string{"enum", "type"}},
		{schema: "ProviderCapability", property: "source", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "ProviderCapability", property: "observedAt", keywords: []string{"$ref"}},
		{schema: "ProviderCapability", property: "reason", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "QuotaCheck", property: "name", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "QuotaCheck", property: "state", keywords: []string{"enum", "type"}},
		{schema: "QuotaCheck", property: "requested", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "QuotaCheck", property: "available", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "QuotaCheck", property: "source", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "QuotaCheck", property: "observedAt", keywords: []string{"$ref"}},
		{schema: "QuotaCheck", property: "reason", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "CostEstimate", property: "state", keywords: []string{"enum", "type"}},
		{schema: "CostEstimate", property: "amount", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "CostEstimate", property: "currency", keywords: []string{"pattern", "type"}},
		{schema: "CostEstimate", property: "region", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "CostEstimate", property: "source", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "CostEstimate", property: "observedAt", keywords: []string{"$ref"}},
		{schema: "CostEstimate", property: "confidence", keywords: []string{"enum", "type"}},
		{schema: "CostEstimate", property: "reason", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		{schema: "FieldViolation", property: "field", keywords: []string{"example", "maxLength", "minLength", "pattern", "type", "x-veer-maximum-encoded-json-bytes"}},
		{schema: "FieldViolation", property: "code", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "FieldViolation", property: "message", keywords: []string{"example", "maxLength", "pattern", "type"}},
		{schema: "Problem", property: "type", keywords: []string{"example", "format", "maxLength", "pattern", "type"}},
		{schema: "Problem", property: "title", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "Problem", property: "status", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
		{schema: "Problem", property: "detail", keywords: []string{"example", "maxLength", "pattern", "type"}},
		{schema: "Problem", property: "instance", keywords: []string{"example", "format", "maxLength", "pattern", "type"}},
		{schema: "Problem", property: "code", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		{schema: "Problem", property: "requestId", keywords: []string{"$ref"}},
		{schema: "Problem", property: "errors", keywords: []string{"example", "items", "maxItems", "type"}},
		{schema: "Problem", property: "retryAfterSeconds", keywords: []string{"example", "format", "maximum", "minimum", "type"}},
	}
	for _, contract := range resourceSchemaContracts[1:] {
		for _, property := range []string{"apiVersion", "kind"} {
			contracts = append(contracts,
				struct {
					schema   string
					property string
					keywords []string
				}{schema: contract.kind, property: property, keywords: []string{"const", "type"}},
				struct {
					schema   string
					property string
					keywords []string
				}{schema: contract.schema("Create"), property: property, keywords: []string{"const", "type"}},
				struct {
					schema   string
					property string
					keywords []string
				}{schema: contract.schema("Replace"), property: property, keywords: []string{"const", "type"}},
				struct {
					schema   string
					property string
					keywords []string
				}{schema: contract.schema("StatusWrite"), property: property, keywords: []string{"const", "type"}},
			)
		}
		for _, property := range []string{"metadata", "spec", "status"} {
			contracts = append(contracts, struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.kind, property: property, keywords: []string{"$ref"}})
		}
		for _, schema := range []string{contract.schema("Create"), contract.schema("Replace")} {
			for _, property := range []string{"metadata", "spec"} {
				contracts = append(contracts, struct {
					schema   string
					property string
					keywords []string
				}{schema: schema, property: property, keywords: []string{"$ref"}})
			}
		}
		contracts = append(contracts,
			struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.schema("StatusWrite"), property: "status", keywords: []string{"$ref"}},
			struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.schema("Status"), property: "observedGeneration", keywords: []string{"format", "maximum", "minimum", "type"}},
			struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.schema("Status"), property: "conditions", keywords: []string{"example", "items", "maxItems", "type"}},
			struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.schema("List"), property: "items", keywords: []string{"example", "items", "maxItems", "type"}},
			struct {
				schema   string
				property string
				keywords []string
			}{schema: contract.schema("List"), property: "nextPageToken", keywords: []string{"example", "maxLength", "minLength", "pattern", "type"}},
		)
	}
	contracts = append(contracts,
		struct {
			schema   string
			property string
			keywords []string
		}{schema: "ProviderConnectionSpec", property: "provider", keywords: []string{"maxLength", "minLength", "pattern", "type"}},
		struct {
			schema   string
			property string
			keywords []string
		}{schema: "ProviderConnectionSpec", property: "credentialRef", keywords: []string{"$ref"}},
		struct {
			schema   string
			property string
			keywords []string
		}{schema: "ProviderConnectionStatus", property: "capabilities", keywords: []string{
			"items", "maxItems", "type", "uniqueItems", "x-veer-list-order", "x-veer-list-unique-key",
		}},
		struct {
			schema   string
			property string
			keywords []string
		}{schema: "ProviderConnectionStatus", property: "quotaChecks", keywords: []string{
			"items", "maxItems", "type", "uniqueItems", "x-veer-list-order", "x-veer-list-unique-key",
		}},
	)

	for _, contract := range contracts {
		schema, err := mapField(schemas, contract.schema)
		if err != nil {
			return err
		}
		properties, err := mapField(schema, "properties")
		if err != nil {
			return err
		}
		property, err := mapField(properties, contract.property)
		if err != nil {
			return err
		}
		if !mapKeySetEquals(property, contract.keywords) {
			return fmt.Errorf("%s.%s schema has unreviewed keywords", contract.schema, contract.property)
		}
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

func validateMetadataRefinements(schemas map[string]any) error {
	for _, contract := range []struct {
		name       string
		constraint string
	}{
		{name: "RootResourceMetadata", constraint: "not"},
		{name: "ChildResourceMetadata", constraint: "required"},
	} {
		schema, err := mapField(schemas, contract.name)
		if err != nil {
			return err
		}
		allOf, ok := schema["allOf"].([]any)
		if !ok || len(allOf) != 2 {
			return fmt.Errorf("%s must contain exactly two allOf members", contract.name)
		}
		base, ok := allOf[0].(map[string]any)
		if !ok || !mapKeySetEquals(base, []string{"$ref"}) ||
			base["$ref"] != "#/components/schemas/ResourceMetadata" {
			return fmt.Errorf("%s base reference drifted", contract.name)
		}
		refinement, ok := allOf[1].(map[string]any)
		if !ok || !mapKeySetEquals(refinement, []string{contract.constraint}) {
			return fmt.Errorf("%s refinement shape drifted", contract.name)
		}
		if contract.constraint == "required" {
			if !stringSetEquals(refinement["required"], []string{"parent"}) {
				return errors.New("ChildResourceMetadata must require parent")
			}
			continue
		}
		not, err := mapField(refinement, "not")
		if err != nil || !mapKeySetEquals(not, []string{"type", "additionalProperties", "required"}) ||
			!isReviewedRootParentExclusion("$/components/schemas/RootResourceMetadata/allOf/1/not", not) {
			return errors.New("RootResourceMetadata must forbid parent")
		}
	}
	return nil
}

func validateResourceSchemaFamily(schemas map[string]any, contract resourceSchemaContract) error {
	spec, err := mapField(schemas, contract.schema("Spec"))
	if err != nil {
		return err
	}
	properties, err := mapField(spec, "properties")
	if err != nil {
		return err
	}
	switch contract.specShape {
	case resourceSpecEmpty:
		if len(properties) != 0 {
			return fmt.Errorf("%s must remain a closed empty provider-neutral object", contract.schema("Spec"))
		}
		if _, exists := spec["required"]; exists {
			return fmt.Errorf("%s must not declare required properties", contract.schema("Spec"))
		}
	case resourceSpecPolicy:
		if err := validatePolicySpecSchema(schemas, spec, properties); err != nil {
			return err
		}
	case resourceSpecProviderConnection:
		if err := validateProviderConnectionSpecSchema(schemas, spec, properties); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s uses an unsupported resource spec shape", contract.kind)
	}

	if contract.statusShape == resourceStatusProviderConnection {
		if err := validateProviderConnectionStatusSchema(schemas); err != nil {
			return err
		}
	} else if err := validateResourceStatusSchema(schemas, contract); err != nil {
		return err
	}
	if err := validateResourceReadSchema(schemas, contract); err != nil {
		return err
	}
	for _, suffix := range []string{"Create", "Replace"} {
		if err := validateResourceWriteSchema(schemas, contract, suffix); err != nil {
			return err
		}
	}
	if err := validateResourceStatusWriteSchema(schemas, contract); err != nil {
		return err
	}
	return validateResourceListSchema(schemas, contract)
}

func validateResourceStatusSchema(schemas map[string]any, contract resourceSchemaContract) error {
	name := contract.schema("Status")
	status, err := mapField(schemas, name)
	if err != nil {
		return err
	}
	properties, err := mapField(status, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(status["required"], []string{"observedGeneration", "conditions"}) ||
		len(properties) != 2 {
		return fmt.Errorf("%s shape drifted", name)
	}
	if !reflect.DeepEqual(status["example"], map[string]any{
		"observedGeneration": json.Number("0"),
		"conditions":         []any{},
	}) {
		return fmt.Errorf("%s canonical example drifted", name)
	}
	if err := validateInt64Property(
		schemas,
		name,
		"observedGeneration",
		"0",
		[]string{"type", "format", "minimum", "maximum"},
	); err != nil {
		return err
	}
	conditions, err := mapField(properties, "conditions")
	if err != nil {
		return err
	}
	if conditions["type"] != "array" || !numberEquals(conditions["maxItems"], "32") {
		return fmt.Errorf("%s conditions contract drifted", name)
	}
	if err := requireReference(conditions, "items", "#/components/schemas/Condition"); err != nil {
		return fmt.Errorf("%s.conditions: %w", name, err)
	}
	return nil
}

func validatePolicySpecSchema(schemas, spec, properties map[string]any) error {
	if spec["type"] != "object" || spec["additionalProperties"] != false ||
		!stringSetEquals(spec["required"], []string{"bindings"}) || len(properties) != 1 {
		return errors.New("PolicySpec shape drifted")
	}
	bindings, err := mapField(properties, "bindings")
	if err != nil {
		return err
	}
	if !mapKeySetEquals(bindings, []string{"type", "maxItems", "uniqueItems", "items"}) ||
		bindings["type"] != "array" ||
		!numberEquals(bindings["maxItems"], "128") || bindings["uniqueItems"] != true {
		return errors.New("PolicySpec.bindings list contract drifted")
	}
	if err := requireReference(bindings, "items", "#/components/schemas/PolicyBinding"); err != nil {
		return fmt.Errorf("PolicySpec.bindings: %w", err)
	}

	binding, err := mapField(schemas, "PolicyBinding")
	if err != nil {
		return err
	}
	bindingProperties, err := mapField(binding, "properties")
	if err != nil {
		return err
	}
	if binding["type"] != "object" || binding["additionalProperties"] != false ||
		!stringSetEquals(binding["required"], []string{"memberId", "role", "scope"}) ||
		len(bindingProperties) != 3 {
		return errors.New("PolicyBinding shape drifted")
	}
	if err := requireReference(bindingProperties, "memberId", "#/components/schemas/OpaqueId"); err != nil {
		return fmt.Errorf("PolicyBinding: %w", err)
	}
	role, err := mapField(bindingProperties, "role")
	if err != nil {
		return err
	}
	if !mapKeySetEquals(role, []string{"type", "enum"}) || role["type"] != "string" ||
		!stringSetEquals(role["enum"], []string{"Viewer", "Developer", "Operator", "WorkspaceAdministrator"}) {
		return errors.New("PolicyBinding.role contract drifted")
	}
	if err := requireReference(bindingProperties, "scope", "#/components/schemas/PolicyScope"); err != nil {
		return fmt.Errorf("PolicyBinding: %w", err)
	}

	scope, err := mapField(schemas, "PolicyScope")
	if err != nil {
		return err
	}
	scopeProperties, err := mapField(scope, "properties")
	if err != nil {
		return err
	}
	if scope["type"] != "object" || scope["additionalProperties"] != false ||
		!stringSetEquals(scope["required"], []string{"kind"}) || len(scopeProperties) != 2 {
		return errors.New("PolicyScope shape drifted")
	}
	kind, err := mapField(scopeProperties, "kind")
	if err != nil {
		return err
	}
	if !mapKeySetEquals(kind, []string{"type", "enum"}) || kind["type"] != "string" ||
		!stringSetEquals(kind["enum"], []string{"Workspace", "Environment"}) {
		return errors.New("PolicyScope.kind contract drifted")
	}
	if err := requireReference(scopeProperties, "environmentId", "#/components/schemas/OpaqueId"); err != nil {
		return fmt.Errorf("PolicyScope: %w", err)
	}
	return validatePolicyScopeRefinement(scope["oneOf"])
}

func validatePolicyScopeRefinement(raw any) error {
	branches, ok := raw.([]any)
	if !ok || len(branches) != 2 {
		return errors.New("PolicyScope must contain exactly two tagged oneOf branches")
	}
	workspace, ok := branches[0].(map[string]any)
	if !ok || !mapKeySetEquals(workspace, []string{"properties", "not"}) {
		return errors.New("PolicyScope Workspace refinement drifted")
	}
	workspaceProperties, err := mapField(workspace, "properties")
	if err != nil || !mapKeySetEquals(workspaceProperties, []string{"kind"}) {
		return errors.New("PolicyScope Workspace tag drifted")
	}
	workspaceKind, err := mapField(workspaceProperties, "kind")
	if err != nil || !mapKeySetEquals(workspaceKind, []string{"const"}) || workspaceKind["const"] != "Workspace" {
		return errors.New("PolicyScope Workspace tag drifted")
	}
	workspaceNot, err := mapField(workspace, "not")
	if err != nil || !mapKeySetEquals(workspaceNot, []string{"type", "additionalProperties", "required"}) ||
		workspaceNot["type"] != "object" || workspaceNot["additionalProperties"] != true ||
		!stringSetEquals(workspaceNot["required"], []string{"environmentId"}) {
		return errors.New("PolicyScope Workspace environment exclusion drifted")
	}

	environment, ok := branches[1].(map[string]any)
	if !ok || !mapKeySetEquals(environment, []string{"required", "properties"}) ||
		!stringSetEquals(environment["required"], []string{"environmentId"}) {
		return errors.New("PolicyScope Environment refinement drifted")
	}
	environmentProperties, err := mapField(environment, "properties")
	if err != nil || !mapKeySetEquals(environmentProperties, []string{"kind"}) {
		return errors.New("PolicyScope Environment tag drifted")
	}
	environmentKind, err := mapField(environmentProperties, "kind")
	if err != nil || !mapKeySetEquals(environmentKind, []string{"const"}) ||
		environmentKind["const"] != "Environment" {
		return errors.New("PolicyScope Environment tag drifted")
	}
	return nil
}

func validateProviderConnectionSpecSchema(
	schemas, spec, properties map[string]any,
) error {
	if spec["type"] != "object" || spec["additionalProperties"] != false ||
		!stringSetEquals(spec["required"], []string{"provider", "credentialRef"}) || len(properties) != 2 {
		return errors.New("providerConnectionSpec shape drifted")
	}
	provider, err := mapField(properties, "provider")
	if err != nil {
		return err
	}
	if provider["type"] != "string" || !numberEquals(provider["minLength"], "1") ||
		!numberEquals(provider["maxLength"], "64") || provider["pattern"] != providerTokenPattern {
		return errors.New("providerConnectionSpec.provider contract drifted")
	}
	if err := requireReference(properties, "credentialRef", "#/components/schemas/CredentialReference"); err != nil {
		return fmt.Errorf("providerConnectionSpec: %w", err)
	}
	if _, err := mapField(schemas, "CredentialReference"); err != nil {
		return err
	}
	return nil
}

func validateProviderConnectionStatusSchema(schemas map[string]any) error {
	status, err := mapField(schemas, "ProviderConnectionStatus")
	if err != nil {
		return err
	}
	properties, err := mapField(status, "properties")
	if err != nil {
		return err
	}
	if status["type"] != "object" || status["additionalProperties"] != false ||
		!stringSetEquals(status["required"], []string{
			"observedGeneration", "conditions", "capabilities", "quotaChecks",
		}) || len(properties) != 4 {
		return errors.New("providerConnectionStatus shape drifted")
	}
	if err := validateInt64Property(
		schemas,
		"ProviderConnectionStatus",
		"observedGeneration",
		"0",
		[]string{"type", "format", "minimum", "maximum"},
	); err != nil {
		return err
	}
	conditions, err := mapField(properties, "conditions")
	if err != nil {
		return err
	}
	if conditions["type"] != "array" || !numberEquals(conditions["maxItems"], "32") {
		return errors.New("providerConnectionStatus.conditions contract drifted")
	}
	if err := requireReference(conditions, "items", "#/components/schemas/Condition"); err != nil {
		return fmt.Errorf("providerConnectionStatus.conditions: %w", err)
	}
	for _, contract := range []struct {
		property string
		target   string
	}{
		{property: "capabilities", target: "ProviderCapability"},
		{property: "quotaChecks", target: "QuotaCheck"},
	} {
		list, err := mapField(properties, contract.property)
		if err != nil {
			return err
		}
		if list["type"] != "array" || !numberEquals(list["maxItems"], "128") ||
			list["uniqueItems"] != true || list["x-veer-list-unique-key"] != "/name" ||
			list["x-veer-list-order"] != "ascending" {
			return fmt.Errorf("providerConnectionStatus.%s list contract drifted", contract.property)
		}
		if err := requireReference(list, "items", "#/components/schemas/"+contract.target); err != nil {
			return fmt.Errorf("providerConnectionStatus.%s: %w", contract.property, err)
		}
	}
	example, err := mapField(status, "example")
	if err != nil {
		return err
	}
	if err := validateProviderConnectionStatusValue(example, 1); err != nil {
		return fmt.Errorf("providerConnectionStatus example: %w", err)
	}
	return nil
}

func validateControlValueSchemas(schemas map[string]any) error {
	if err := validateCredentialReferenceSchema(schemas); err != nil {
		return err
	}
	if err := validateProviderCapabilitySchema(schemas); err != nil {
		return err
	}
	if err := validateQuotaCheckSchema(schemas); err != nil {
		return err
	}
	return validateCostEstimateSchema(schemas)
}

func validateCredentialReferenceSchema(schemas map[string]any) error {
	schema, err := mapField(schemas, "CredentialReference")
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		!stringSetEquals(schema["required"], []string{"referenceId", "version"}) || len(properties) != 2 {
		return errors.New("credentialReference shape drifted")
	}
	if err := requireAnnotatedReference(
		properties,
		"referenceId",
		"#/components/schemas/OpaqueId",
		map[string]any{"type": "string", "example": "cred_01J0000000000000000000000"},
	); err != nil {
		return fmt.Errorf("credentialReference: %w", err)
	}
	version, err := mapField(properties, "version")
	if err != nil {
		return err
	}
	if version["type"] != "string" || !numberEquals(version["minLength"], "1") ||
		!numberEquals(version["maxLength"], "128") || version["pattern"] != "^[A-Za-z0-9_-]+$" ||
		version["example"] != "ver_01J00000000000000000000000" {
		return errors.New("credentialReference.version contract drifted")
	}
	example, err := mapField(schema, "example")
	if err != nil {
		return err
	}
	return validateCredentialReferenceValue(example)
}

func validateProviderCapabilitySchema(schemas map[string]any) error {
	schema, err := mapField(schemas, "ProviderCapability")
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		!stringSetEquals(schema["required"], []string{"name", "state", "source", "observedAt", "reason"}) ||
		len(properties) != 5 {
		return errors.New("providerCapability shape drifted")
	}
	if err := validateObservationSchemaFields(
		properties,
		"ProviderCapability",
		[]string{"Supported", "Unsupported", "Unknown"},
	); err != nil {
		return err
	}
	example, err := mapField(schema, "example")
	if err != nil {
		return err
	}
	return validateProviderCapabilityValue(example)
}

func validateQuotaCheckSchema(schemas map[string]any) error {
	schema, err := mapField(schemas, "QuotaCheck")
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		!stringSetEquals(schema["required"], []string{"name", "state", "source", "observedAt", "reason"}) ||
		len(properties) != 7 {
		return errors.New("quotaCheck shape drifted")
	}
	if err := validateObservationSchemaFields(
		properties,
		"QuotaCheck",
		[]string{"WithinLimit", "Exceeded", "Unknown"},
	); err != nil {
		return err
	}
	for _, name := range []string{"requested", "available"} {
		property, err := mapField(properties, name)
		if err != nil {
			return err
		}
		if property["type"] != "string" || !numberEquals(property["minLength"], "1") ||
			!numberEquals(property["maxLength"], "64") || property["pattern"] != canonicalDecimalPattern {
			return fmt.Errorf("quotaCheck.%s decimal contract drifted", name)
		}
	}
	comparison, err := mapField(schema, "x-veer-quota-comparison")
	if err != nil || !reflect.DeepEqual(comparison, map[string]any{
		"WithinLimit": "requested<=available",
		"Exceeded":    "requested>available",
		"Unknown":     "operands-absent",
	}) {
		return errors.New("quotaCheck comparison manifest drifted")
	}
	if err := validateQuotaCheckRefinement(schema["oneOf"]); err != nil {
		return err
	}
	example, err := mapField(schema, "example")
	if err != nil {
		return err
	}
	return validateQuotaCheckValue(example)
}

func validateCostEstimateSchema(schemas map[string]any) error {
	schema, err := mapField(schemas, "CostEstimate")
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false ||
		!stringSetEquals(schema["required"], []string{
			"state", "currency", "region", "source", "observedAt", "confidence", "reason",
		}) || len(properties) != 8 {
		return errors.New("costEstimate shape drifted")
	}
	state, err := mapField(properties, "state")
	if err != nil {
		return err
	}
	confidence, err := mapField(properties, "confidence")
	if err != nil {
		return err
	}
	if state["type"] != "string" || !stringSetEquals(state["enum"], []string{"Known", "Unknown"}) ||
		confidence["type"] != "string" || !stringSetEquals(
		confidence["enum"], []string{"Low", "Medium", "High", "Unknown"},
	) {
		return errors.New("costEstimate tagged state contract drifted")
	}
	amount, err := mapField(properties, "amount")
	if err != nil {
		return err
	}
	if amount["type"] != "string" || !numberEquals(amount["minLength"], "1") ||
		!numberEquals(amount["maxLength"], "64") || amount["pattern"] != canonicalDecimalPattern {
		return errors.New("costEstimate.amount contract drifted")
	}
	currency, err := mapField(properties, "currency")
	if err != nil {
		return err
	}
	if currency["type"] != "string" || currency["pattern"] != currencyPattern {
		return errors.New("costEstimate.currency contract drifted")
	}
	region, err := mapField(properties, "region")
	if err != nil {
		return err
	}
	if region["type"] != "string" || !numberEquals(region["minLength"], "1") ||
		!numberEquals(region["maxLength"], "63") || region["pattern"] != regionPattern {
		return errors.New("costEstimate.region contract drifted")
	}
	if err := validateSourceReasonTimestampSchema(properties, "CostEstimate"); err != nil {
		return err
	}
	if err := validateCostEstimateRefinement(schema["oneOf"]); err != nil {
		return err
	}
	example, err := mapField(schema, "example")
	if err != nil {
		return err
	}
	return validateCostEstimateValue(example)
}

func validateObservationSchemaFields(
	properties map[string]any,
	context string,
	states []string,
) error {
	name, err := mapField(properties, "name")
	if err != nil {
		return err
	}
	if name["type"] != "string" || !numberEquals(name["minLength"], "1") ||
		!numberEquals(name["maxLength"], "128") || name["pattern"] != providerTokenPattern {
		return fmt.Errorf("%s.name contract drifted", context)
	}
	state, err := mapField(properties, "state")
	if err != nil {
		return err
	}
	if state["type"] != "string" || !stringSetEquals(state["enum"], states) {
		return fmt.Errorf("%s.state contract drifted", context)
	}
	return validateSourceReasonTimestampSchema(properties, context)
}

func validateSourceReasonTimestampSchema(properties map[string]any, context string) error {
	source, err := mapField(properties, "source")
	if err != nil {
		return err
	}
	if source["type"] != "string" || !numberEquals(source["minLength"], "1") ||
		!numberEquals(source["maxLength"], "64") || source["pattern"] != providerTokenPattern {
		return fmt.Errorf("%s.source contract drifted", context)
	}
	reason, err := mapField(properties, "reason")
	if err != nil {
		return err
	}
	if reason["type"] != "string" || !numberEquals(reason["minLength"], "1") ||
		!numberEquals(reason["maxLength"], "64") || reason["pattern"] != conditionReasonPattern {
		return fmt.Errorf("%s.reason contract drifted", context)
	}
	if err := requireReference(properties, "observedAt", "#/components/schemas/Timestamp"); err != nil {
		return fmt.Errorf("%s.observedAt: %w", context, err)
	}
	return nil
}

func validateQuotaCheckRefinement(raw any) error {
	branches, ok := raw.([]any)
	if !ok || len(branches) != 2 {
		return errors.New("quotaCheck must contain exactly two tagged oneOf branches")
	}
	known, ok := branches[0].(map[string]any)
	if !ok || !mapKeySetEquals(known, []string{"required", "properties"}) ||
		!stringSetEquals(known["required"], []string{"requested", "available"}) {
		return errors.New("quotaCheck known-state refinement drifted")
	}
	knownProperties, err := mapField(known, "properties")
	if err != nil || !mapKeySetEquals(knownProperties, []string{"state"}) {
		return errors.New("quotaCheck known-state properties drifted")
	}
	knownState, err := mapField(knownProperties, "state")
	if err != nil || !mapKeySetEquals(knownState, []string{"enum"}) ||
		!stringSetEquals(knownState["enum"], []string{"WithinLimit", "Exceeded"}) {
		return errors.New("quotaCheck known-state tag drifted")
	}
	unknown, ok := branches[1].(map[string]any)
	if !ok || !mapKeySetEquals(unknown, []string{"properties", "not"}) {
		return errors.New("quotaCheck unknown-state refinement drifted")
	}
	unknownProperties, err := mapField(unknown, "properties")
	if err != nil || !mapKeySetEquals(unknownProperties, []string{"state"}) {
		return errors.New("quotaCheck unknown-state properties drifted")
	}
	unknownState, err := mapField(unknownProperties, "state")
	if err != nil || !mapKeySetEquals(unknownState, []string{"const"}) || unknownState["const"] != "Unknown" {
		return errors.New("quotaCheck unknown-state tag drifted")
	}
	not, err := mapField(unknown, "not")
	if err != nil || !mapKeySetEquals(not, []string{"anyOf"}) ||
		!requiredBranchSetEquals(not["anyOf"], [][]string{{"requested"}, {"available"}}) {
		return errors.New("quotaCheck unknown-state operand exclusion drifted")
	}
	return nil
}

func validateCostEstimateRefinement(raw any) error {
	branches, ok := raw.([]any)
	if !ok || len(branches) != 2 {
		return errors.New("costEstimate must contain exactly two tagged oneOf branches")
	}
	known, ok := branches[0].(map[string]any)
	if !ok || !mapKeySetEquals(known, []string{"required", "properties"}) ||
		!stringSetEquals(known["required"], []string{"amount"}) {
		return errors.New("costEstimate known-state refinement drifted")
	}
	knownProperties, err := mapField(known, "properties")
	if err != nil || !mapKeySetEquals(knownProperties, []string{"state", "confidence"}) {
		return errors.New("costEstimate known-state properties drifted")
	}
	knownState, err := mapField(knownProperties, "state")
	if err != nil || !mapKeySetEquals(knownState, []string{"const"}) || knownState["const"] != "Known" {
		return errors.New("costEstimate known-state tag drifted")
	}
	knownConfidence, err := mapField(knownProperties, "confidence")
	if err != nil || !mapKeySetEquals(knownConfidence, []string{"enum"}) ||
		!stringSetEquals(knownConfidence["enum"], []string{"Low", "Medium", "High"}) {
		return errors.New("costEstimate known confidence contract drifted")
	}
	unknown, ok := branches[1].(map[string]any)
	if !ok || !mapKeySetEquals(unknown, []string{"properties", "not"}) {
		return errors.New("costEstimate unknown-state refinement drifted")
	}
	unknownProperties, err := mapField(unknown, "properties")
	if err != nil || !mapKeySetEquals(unknownProperties, []string{"state", "confidence"}) {
		return errors.New("costEstimate unknown-state properties drifted")
	}
	for name, want := range map[string]string{"state": "Unknown", "confidence": "Unknown"} {
		property, err := mapField(unknownProperties, name)
		if err != nil || !mapKeySetEquals(property, []string{"const"}) || property["const"] != want {
			return fmt.Errorf("costEstimate unknown %s contract drifted", name)
		}
	}
	not, err := mapField(unknown, "not")
	if err != nil || !mapKeySetEquals(not, []string{"type", "additionalProperties", "required"}) ||
		not["type"] != "object" || not["additionalProperties"] != true ||
		!stringSetEquals(not["required"], []string{"amount"}) {
		return errors.New("costEstimate unknown amount exclusion drifted")
	}
	return nil
}

func requiredBranchSetEquals(raw any, want [][]string) bool {
	branches, ok := raw.([]any)
	if !ok || len(branches) != len(want) {
		return false
	}
	for index, rawBranch := range branches {
		branch, ok := rawBranch.(map[string]any)
		if !ok || !mapKeySetEquals(branch, []string{"required"}) ||
			!stringSetEquals(branch["required"], want[index]) {
			return false
		}
	}
	return true
}

func validatePolicySpecValue(raw any) error {
	var value policySpecWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("PolicySpec strict decode: %w", err)
	}
	if value.Bindings == nil || len(value.Bindings) > 128 {
		return errors.New("PolicySpec.bindings must be present and contain at most 128 entries")
	}
	var previous policyBindingWire
	for index, binding := range value.Bindings {
		if !opaqueIDValuePattern.MatchString(binding.MemberID) {
			return fmt.Errorf("PolicySpec.bindings[%d].memberId is not an opaque ID", index)
		}
		switch binding.Role {
		case "Viewer", "Developer", "Operator", "WorkspaceAdministrator":
		default:
			return fmt.Errorf("PolicySpec.bindings[%d].role is invalid", index)
		}
		switch binding.Scope.Kind {
		case "Workspace":
			if binding.Scope.EnvironmentID != nil {
				return fmt.Errorf("PolicySpec.bindings[%d] Workspace scope carries environmentId", index)
			}
		case "Environment":
			if binding.Scope.EnvironmentID == nil ||
				!opaqueIDValuePattern.MatchString(*binding.Scope.EnvironmentID) {
				return fmt.Errorf("PolicySpec.bindings[%d] Environment scope requires an opaque environmentId", index)
			}
			if binding.Role == "WorkspaceAdministrator" {
				return fmt.Errorf("PolicySpec.bindings[%d] WorkspaceAdministrator requires Workspace scope", index)
			}
		default:
			return fmt.Errorf("PolicySpec.bindings[%d].scope.kind is invalid", index)
		}
		if index > 0 {
			comparison := comparePolicyBindings(previous, binding)
			if comparison == 0 {
				return fmt.Errorf("PolicySpec.bindings[%d] duplicates the previous canonical binding", index)
			}
			if comparison > 0 {
				return fmt.Errorf("PolicySpec.bindings[%d] is outside canonical order", index)
			}
		}
		previous = binding
	}
	return nil
}

func comparePolicyBindings(left, right policyBindingWire) int {
	for _, values := range [][2]string{
		{left.MemberID, right.MemberID},
		{left.Scope.Kind, right.Scope.Kind},
		{policyEnvironmentID(left.Scope), policyEnvironmentID(right.Scope)},
		{left.Role, right.Role},
	} {
		if comparison := strings.Compare(values[0], values[1]); comparison != 0 {
			return comparison
		}
	}
	return 0
}

func policyEnvironmentID(scope policyScopeWire) string {
	if scope.EnvironmentID == nil {
		return ""
	}
	return *scope.EnvironmentID
}

func validateCredentialReferenceValue(raw any) error {
	var value credentialReferenceWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("credentialReference strict decode: %w", err)
	}
	if !opaqueIDValuePattern.MatchString(value.ReferenceID) {
		return errors.New("credentialReference.referenceId is not an opaque ID")
	}
	if len(value.Version) < 1 || len(value.Version) > 128 ||
		!opaqueVersionValuePattern.MatchString(value.Version) {
		return errors.New("credentialReference.version is invalid")
	}
	return nil
}

func validateProviderConnectionSpecValue(raw any) error {
	var value providerConnectionSpecWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("providerConnectionSpec strict decode: %w", err)
	}
	if !validProviderToken(value.Provider, 64) {
		return errors.New("providerConnectionSpec.provider is invalid")
	}
	return validateCredentialReferenceValue(value.CredentialRef)
}

func validateProviderCapabilityValue(raw any) error {
	var value providerCapabilityWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("providerCapability strict decode: %w", err)
	}
	if err := validateObservationValue(value.Name, value.Source, value.ObservedAt, value.Reason); err != nil {
		return err
	}
	switch value.State {
	case "Supported", "Unsupported", "Unknown":
		return nil
	default:
		return fmt.Errorf("providerCapability.state %q is invalid", value.State)
	}
}

func validateQuotaCheckValue(raw any) error {
	var value quotaCheckWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("quotaCheck strict decode: %w", err)
	}
	if err := validateObservationValue(value.Name, value.Source, value.ObservedAt, value.Reason); err != nil {
		return err
	}
	if value.State == "Unknown" {
		if value.Requested != nil || value.Available != nil {
			return errors.New("unknown quota must omit requested and available")
		}
		return nil
	}
	if value.State != "WithinLimit" && value.State != "Exceeded" {
		return fmt.Errorf("quotaCheck.state %q is invalid", value.State)
	}
	if value.Requested == nil || value.Available == nil ||
		!validCanonicalDecimal(*value.Requested) || !validCanonicalDecimal(*value.Available) {
		return errors.New("known quota requires canonical requested and available decimals")
	}
	requested, requestedOK := new(big.Rat).SetString(*value.Requested)
	available, availableOK := new(big.Rat).SetString(*value.Available)
	if !requestedOK || !availableOK {
		return errors.New("quota decimal parse failed")
	}
	comparison := requested.Cmp(available)
	if value.State == "WithinLimit" && comparison > 0 {
		return errors.New("withinLimit quota requires requested <= available")
	}
	if value.State == "Exceeded" && comparison <= 0 {
		return errors.New("exceeded quota requires requested > available")
	}
	return nil
}

func validateCostEstimateValue(raw any) error {
	var value costEstimateWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("costEstimate strict decode: %w", err)
	}
	if !currencyValuePattern.MatchString(value.Currency) || !regionValuePattern.MatchString(value.Region) ||
		!validProviderToken(value.Source, 64) || !validTimestamp(value.ObservedAt) ||
		!validConditionReason(value.Reason) {
		return errors.New("costEstimate common observation fields are invalid")
	}
	if value.State == "Unknown" {
		if value.Amount != nil || value.Confidence != "Unknown" {
			return errors.New("unknown cost must omit amount and use Unknown confidence")
		}
		return nil
	}
	if value.State != "Known" || value.Amount == nil || !validCanonicalDecimal(*value.Amount) {
		return errors.New("known cost requires a canonical nonnegative amount")
	}
	switch value.Confidence {
	case "Low", "Medium", "High":
		return nil
	default:
		return errors.New("known cost requires non-Unknown confidence")
	}
}

func validateProviderConnectionStatusValue(raw any, resourceGeneration int64) error {
	var value providerConnectionStatusWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return fmt.Errorf("providerConnectionStatus strict decode: %w", err)
	}
	if value.ObservedGeneration < 0 || value.ObservedGeneration > resourceGeneration {
		return errors.New("providerConnectionStatus observedGeneration is outside the resource generation")
	}
	if len(value.Conditions) > 32 || len(value.Capabilities) > 128 || len(value.QuotaChecks) > 128 {
		return errors.New("providerConnectionStatus contains an oversized bounded list")
	}
	previousCondition := ""
	for index, rawCondition := range value.Conditions {
		condition, err := validateConditionValue(rawCondition, resourceGeneration)
		if err != nil {
			return fmt.Errorf("condition %d: %w", index, err)
		}
		if previousCondition != "" && condition.Type <= previousCondition {
			return errors.New("conditions must be strictly ascending and unique by type")
		}
		previousCondition = condition.Type
	}
	previousName := ""
	for index, capability := range value.Capabilities {
		if err := validateProviderCapabilityValue(capability); err != nil {
			return fmt.Errorf("capability %d: %w", index, err)
		}
		if previousName != "" && capability.Name <= previousName {
			return errors.New("capabilities must be strictly ascending and unique by name")
		}
		previousName = capability.Name
	}
	previousName = ""
	for index, quota := range value.QuotaChecks {
		if err := validateQuotaCheckValue(quota); err != nil {
			return fmt.Errorf("quota check %d: %w", index, err)
		}
		if previousName != "" && quota.Name <= previousName {
			return errors.New("quota checks must be strictly ascending and unique by name")
		}
		previousName = quota.Name
	}
	return nil
}

func validateObservationValue(name, source, observedAt, reason string) error {
	if !validProviderToken(name, 128) || !validProviderToken(source, 64) ||
		!validTimestamp(observedAt) || !validConditionReason(reason) {
		return errors.New("provider observation fields are invalid")
	}
	return nil
}

func validProviderToken(value string, maximum int) bool {
	return len(value) >= 1 && len(value) <= maximum && providerTokenValuePattern.MatchString(value)
}

func validConditionReason(value string) bool {
	return len(value) >= 1 && len(value) <= 64 && conditionReasonValuePattern.MatchString(value)
}

func validCanonicalDecimal(value string) bool {
	return len(value) >= 1 && len(value) <= 64 && canonicalDecimalValuePattern.MatchString(value)
}

func validateConditionValue(raw any, resourceGeneration int64) (conditionWire, error) {
	var value conditionWire
	if err := decodeStrictValue(raw, &value); err != nil {
		return value, fmt.Errorf("condition strict decode: %w", err)
	}
	if !validConditionReason(value.Type) || !validConditionReason(value.Reason) ||
		!utf8.ValidString(value.Message) || utf8.RuneCountInString(value.Message) > 512 ||
		!validTimestamp(value.LastTransitionAt) ||
		value.ObservedGeneration < 0 || value.ObservedGeneration > resourceGeneration {
		return value, errors.New("condition fields are invalid")
	}
	switch value.Status {
	case "True", "False", "Unknown":
		return value, nil
	default:
		return value, fmt.Errorf("condition.status %q is invalid", value.Status)
	}
}

func validateOperationValue(raw any) (operationWire, error) {
	var value operationWire
	encoded, err := json.Marshal(raw)
	if err != nil {
		return value, fmt.Errorf("encode operation: %w", err)
	}
	if len(encoded) > 4096 {
		return value, errors.New("operation exceeds 4096 canonical JSON bytes")
	}
	if err := decodeStrictValue(raw, &value); err != nil {
		return value, fmt.Errorf("operation strict decode: %w", err)
	}
	for name, identifier := range map[string]string{
		"id": value.ID, "workspaceId": value.WorkspaceID, "resourceId": value.ResourceID,
	} {
		if !opaqueIDValuePattern.MatchString(identifier) {
			return value, fmt.Errorf("operation.%s is not an opaque ID", name)
		}
	}
	if (value.EnvironmentID == nil) != (value.ProviderConnectionID == nil) {
		return value, errors.New("operation environmentId and providerConnectionId must both be present or absent")
	}
	for name, identifier := range map[string]*string{
		"environmentId": value.EnvironmentID, "providerConnectionId": value.ProviderConnectionID,
	} {
		if identifier != nil && !opaqueIDValuePattern.MatchString(*identifier) {
			return value, fmt.Errorf("operation.%s is not an opaque ID", name)
		}
	}
	if value.Generation < 1 || len(value.ResourceVersion) < 1 || len(value.ResourceVersion) > 128 ||
		!opaqueVersionValuePattern.MatchString(value.ResourceVersion) ||
		!validTimestamp(value.CreatedAt) || !validTimestamp(value.UpdatedAt) {
		return value, errors.New("operation revision or timestamp fields are invalid")
	}
	createdAt, _ := time.Parse("2006-01-02T15:04:05.000Z", value.CreatedAt)
	updatedAt, _ := time.Parse("2006-01-02T15:04:05.000Z", value.UpdatedAt)
	if updatedAt.Before(createdAt) {
		return value, errors.New("operation.updatedAt cannot precede createdAt")
	}
	switch value.Phase {
	case "Pending", "Waiting", "Running", "Succeeded", "Failed", "Canceled":
	default:
		return value, fmt.Errorf("operation.phase %q is invalid", value.Phase)
	}
	if value.Reason != nil && !validConditionReason(*value.Reason) {
		return value, errors.New("operation.reason is invalid")
	}
	if value.Message != nil && (!utf8.ValidString(*value.Message) || utf8.RuneCountInString(*value.Message) > 512) {
		return value, errors.New("operation.message exceeds 512 characters")
	}
	if value.CostEstimate != nil {
		if err := validateCostEstimateValue(*value.CostEstimate); err != nil {
			return value, fmt.Errorf("operation.costEstimate: %w", err)
		}
	}
	return value, nil
}

func validateOperationTransition(beforeRaw, afterRaw any) error {
	before, err := validateOperationValue(beforeRaw)
	if err != nil {
		return fmt.Errorf("before: %w", err)
	}
	after, err := validateOperationValue(afterRaw)
	if err != nil {
		return fmt.Errorf("after: %w", err)
	}
	if before.Phase == "Succeeded" || before.Phase == "Failed" || before.Phase == "Canceled" {
		if !reflect.DeepEqual(before, after) {
			return errors.New("terminal operation permits exact replay only")
		}
		return nil
	}
	if before.ID != after.ID || before.WorkspaceID != after.WorkspaceID ||
		before.ResourceID != after.ResourceID || before.Generation != after.Generation ||
		before.CreatedAt != after.CreatedAt || !reflect.DeepEqual(before.EnvironmentID, after.EnvironmentID) ||
		!reflect.DeepEqual(before.ProviderConnectionID, after.ProviderConnectionID) {
		return errors.New("operation identity, ownership, binding, generation, and creation time are immutable")
	}
	if reflect.DeepEqual(before, after) {
		return nil
	}
	allowed := map[string]map[string]bool{
		"Pending": {"Waiting": true, "Running": true, "Succeeded": true, "Failed": true, "Canceled": true},
		"Waiting": {"Pending": true, "Running": true, "Succeeded": true, "Failed": true, "Canceled": true},
		"Running": {"Waiting": true, "Succeeded": true, "Failed": true, "Canceled": true},
	}
	phaseChanged := before.Phase != after.Phase
	if phaseChanged && !allowed[before.Phase][after.Phase] {
		return fmt.Errorf("operation transition %s -> %s is not allowed", before.Phase, after.Phase)
	}
	materialChanged := phaseChanged || !reflect.DeepEqual(before.Reason, after.Reason) ||
		!reflect.DeepEqual(before.Message, after.Message) ||
		!reflect.DeepEqual(before.CostEstimate, after.CostEstimate)
	if !materialChanged {
		return errors.New("operation revision fields cannot advance without material evidence")
	}
	if before.ResourceVersion == after.ResourceVersion {
		return errors.New("material operation transition must advance resourceVersion")
	}
	beforeUpdated, _ := time.Parse("2006-01-02T15:04:05.000Z", before.UpdatedAt)
	afterUpdated, _ := time.Parse("2006-01-02T15:04:05.000Z", after.UpdatedAt)
	if afterUpdated.Before(beforeUpdated) {
		return errors.New("material operation transition cannot regress updatedAt")
	}
	return nil
}

func validateConditionTransition(beforeRaw, afterRaw any, resourceGeneration int64) error {
	before, err := validateConditionValue(beforeRaw, resourceGeneration)
	if err != nil {
		return fmt.Errorf("before: %w", err)
	}
	after, err := validateConditionValue(afterRaw, resourceGeneration)
	if err != nil {
		return fmt.Errorf("after: %w", err)
	}
	if before.Type != after.Type {
		return errors.New("condition.type is immutable across a transition")
	}
	if after.ObservedGeneration < before.ObservedGeneration {
		return errors.New("condition.observedGeneration must be nondecreasing")
	}
	if before.Status == after.Status {
		if before.LastTransitionAt != after.LastTransitionAt {
			return errors.New("same-status condition transition must preserve lastTransitionAt")
		}
		return nil
	}
	beforeTime, _ := time.Parse("2006-01-02T15:04:05.000Z", before.LastTransitionAt)
	afterTime, _ := time.Parse("2006-01-02T15:04:05.000Z", after.LastTransitionAt)
	if !afterTime.After(beforeTime) {
		return errors.New("changed-status condition transition must advance lastTransitionAt")
	}
	return nil
}

func validateResourceReadSchema(schemas map[string]any, contract resourceSchemaContract) error {
	schema, err := mapField(schemas, contract.kind)
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(schema["required"], []string{"apiVersion", "kind", "metadata", "spec", "status"}) ||
		len(properties) != 5 || !numberEquals(schema["x-veer-maximum-json-bytes"], "262144") {
		return fmt.Errorf("%s read shape or encoded-size contract drifted", contract.kind)
	}
	if !validObservedGenerationUpperBound(schema["x-veer-observed-generation-upper-bound"]) {
		return fmt.Errorf("%s observed-generation upper bound drifted", contract.kind)
	}
	if err := validateResourceIdentity(properties, contract.kind, contract.kind); err != nil {
		return err
	}
	for property, target := range map[string]string{
		"metadata": contract.metadataSchema,
		"spec":     contract.schema("Spec"),
		"status":   contract.schema("Status"),
	} {
		if err := requireReference(properties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("%s: %w", contract.kind, err)
		}
	}
	return nil
}

func validateResourceWriteSchema(
	schemas map[string]any,
	contract resourceSchemaContract,
	suffix string,
) error {
	name := contract.schema(suffix)
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
	if err := validateResourceIdentity(properties, name, contract.kind); err != nil {
		return err
	}
	for property, target := range map[string]string{
		"metadata": "WritableMetadata",
		"spec":     contract.schema("Spec"),
	} {
		if err := requireReference(properties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func validateResourceStatusWriteSchema(schemas map[string]any, contract resourceSchemaContract) error {
	name := contract.schema("StatusWrite")
	schema, err := mapField(schemas, name)
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(schema["required"], []string{"apiVersion", "kind", "status"}) ||
		len(properties) != 3 {
		return fmt.Errorf("%s shape drifted", name)
	}
	if err := validateResourceIdentity(properties, name, contract.kind); err != nil {
		return err
	}
	if err := requireReference(properties, "status", "#/components/schemas/"+contract.schema("Status")); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func validateResourceListSchema(schemas map[string]any, contract resourceSchemaContract) error {
	name := contract.schema("List")
	schema, err := mapField(schemas, name)
	if err != nil {
		return err
	}
	properties, err := mapField(schema, "properties")
	if err != nil {
		return err
	}
	if !stringSetEquals(schema["required"], []string{"items"}) || len(properties) != 2 ||
		!numberEquals(schema["x-veer-maximum-json-bytes"], "262144") ||
		schema["x-veer-page-byte-policy"] != "stop-before-limit" {
		return fmt.Errorf("%s shape or encoded-size contract drifted", name)
	}
	items, err := mapField(properties, "items")
	if err != nil {
		return err
	}
	if items["type"] != "array" || !numberEquals(items["maxItems"], "100") {
		return fmt.Errorf("%s item bound drifted", name)
	}
	if err := requireReference(items, "items", "#/components/schemas/"+contract.kind); err != nil {
		return fmt.Errorf("%s.items: %w", name, err)
	}
	nextPageToken, err := mapField(properties, "nextPageToken")
	if err != nil {
		return err
	}
	if nextPageToken["type"] != "string" || !numberEquals(nextPageToken["minLength"], "16") ||
		!numberEquals(nextPageToken["maxLength"], "1024") || nextPageToken["pattern"] != "^[A-Za-z0-9_-]+$" {
		return fmt.Errorf("%s nextPageToken contract drifted", name)
	}
	return nil
}

func validateResourceIdentity(properties map[string]any, context, kindName string) error {
	apiVersion, err := mapField(properties, "apiVersion")
	if err != nil {
		return err
	}
	kind, err := mapField(properties, "kind")
	if err != nil {
		return err
	}
	if apiVersion["type"] != "string" || apiVersion["const"] != "v1alpha1" ||
		kind["type"] != "string" || kind["const"] != kindName {
		return fmt.Errorf("%s identity contract drifted", context)
	}
	return nil
}

func validateResourceExamples(schemas map[string]any) error {
	type exampleNode struct {
		kind        string
		workspaceID string
	}
	seen := make(map[string]exampleNode, len(resourceSchemaContracts))
	for _, contract := range resourceSchemaContracts {
		schema, err := mapField(schemas, contract.kind)
		if err != nil {
			return err
		}
		example, err := mapField(schema, "example")
		if err != nil {
			return fmt.Errorf("%s example: %w", contract.kind, err)
		}
		if !mapKeySetEquals(example, []string{"apiVersion", "kind", "metadata", "spec", "status"}) ||
			example["apiVersion"] != "v1alpha1" || example["kind"] != contract.kind {
			return fmt.Errorf("%s example envelope drifted", contract.kind)
		}
		metadata, err := mapField(example, "metadata")
		if err != nil {
			return fmt.Errorf("%s example metadata: %w", contract.kind, err)
		}
		metadataKeys := []string{
			"id", "workspaceId", "displayName", "labels", "generation", "resourceVersion", "createdAt", "updatedAt",
		}
		if contract.parentKind != "" {
			metadataKeys = append(metadataKeys, "parent")
		}
		if !mapKeySetEquals(metadata, metadataKeys) || !numberEquals(metadata["generation"], "1") {
			return fmt.Errorf("%s example metadata shape drifted", contract.kind)
		}
		id, idOK := metadata["id"].(string)
		workspaceID, workspaceOK := metadata["workspaceId"].(string)
		displayName, displayNameOK := metadata["displayName"].(string)
		resourceVersion, versionOK := metadata["resourceVersion"].(string)
		createdAt, createdOK := metadata["createdAt"].(string)
		updatedAt, updatedOK := metadata["updatedAt"].(string)
		if !idOK || id == "" || !workspaceOK || workspaceID == "" ||
			!displayNameOK || displayName == "" || !versionOK || resourceVersion == "" ||
			!createdOK || !updatedOK || !validTimestamp(createdAt) || !validTimestamp(updatedAt) {
			return fmt.Errorf("%s example metadata values drifted", contract.kind)
		}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("%s example duplicates resource ID %s", contract.kind, id)
		}
		if contract.parentKind == "" {
			if id != workspaceID {
				return errors.New("workspace example workspaceId must equal its id")
			}
		} else {
			parentID, ok := metadata["parent"].(string)
			if !ok || parentID == "" {
				return fmt.Errorf("%s example parent is missing", contract.kind)
			}
			parent, exists := seen[parentID]
			if !exists {
				return fmt.Errorf("%s example parent is orphaned or cyclic", contract.kind)
			}
			if parent.kind != contract.parentKind {
				return fmt.Errorf("%s example parent kind must be %s", contract.kind, contract.parentKind)
			}
			if parent.workspaceID != workspaceID {
				return fmt.Errorf("%s example crosses workspace ownership", contract.kind)
			}
		}
		spec, err := mapField(example, "spec")
		if err != nil {
			return err
		}
		switch contract.specShape {
		case resourceSpecEmpty:
			if len(spec) != 0 {
				return fmt.Errorf("%s example spec must be empty", contract.kind)
			}
		case resourceSpecWorkspace:
			if len(spec) != 1 || spec["suspendReconciliation"] != false {
				return errors.New("workspace example spec drifted")
			}
		case resourceSpecPolicy:
			if err := validatePolicySpecValue(spec); err != nil {
				return fmt.Errorf("policy example spec: %w", err)
			}
		case resourceSpecProviderConnection:
			if err := validateProviderConnectionSpecValue(spec); err != nil {
				return fmt.Errorf("providerConnection example spec: %w", err)
			}
		default:
			return fmt.Errorf("%s example has an unsupported spec shape", contract.kind)
		}
		status, err := mapField(example, "status")
		if err != nil {
			return err
		}
		if contract.statusShape == resourceStatusProviderConnection {
			if err := validateProviderConnectionStatusValue(status, 1); err != nil {
				return fmt.Errorf("providerConnection example status: %w", err)
			}
		} else {
			conditions, conditionsOK := status["conditions"].([]any)
			if !mapKeySetEquals(status, []string{"observedGeneration", "conditions"}) ||
				!numberEquals(status["observedGeneration"], "0") || !conditionsOK || len(conditions) != 0 {
				return fmt.Errorf("%s example status drifted", contract.kind)
			}
		}
		seen[id] = exampleNode{kind: contract.kind, workspaceID: workspaceID}
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
	encoded, err := json.Marshal(condition)
	if err != nil {
		return fmt.Errorf("encode condition schema: %w", err)
	}
	fingerprint := sha256.Sum256(encoded)
	if fmt.Sprintf("%x", fingerprint) != conditionSchemaSHA256 {
		return errors.New("condition schema changed outside the accepted transition-manifest boundary")
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
	if operation["type"] != "object" || operation["additionalProperties"] != false ||
		!stringSetEquals(operation["required"], []string{
			"id", "workspaceId", "resourceId", "generation", "resourceVersion", "phase", "createdAt", "updatedAt",
		}) || len(properties) != 13 || !numberEquals(operation["x-veer-maximum-json-bytes"], "4096") {
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
			property: "workspaceId",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "wsp_01J00000000000000000000000"},
		},
		{
			property: "environmentId",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "env_01J00000000000000000000000"},
		},
		{
			property: "providerConnectionId",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "pvc_01J00000000000000000000000"},
		},
		{
			property: "resourceId",
			target:   "OpaqueId",
			siblings: map[string]any{"type": "string", "example": "cmp_01J00000000000000000000000"},
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
		[]string{"Pending", "Waiting", "Running", "Succeeded", "Failed", "Canceled"},
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
	if err := requireReference(properties, "costEstimate", "#/components/schemas/CostEstimate"); err != nil {
		return fmt.Errorf("operation: %w", err)
	}
	if err := validateOperationBindingRefinement(operation["oneOf"]); err != nil {
		return err
	}
	example, err := mapField(operation, "example")
	if err != nil {
		return err
	}
	if _, err := validateOperationValue(example); err != nil {
		return fmt.Errorf("operation example: %w", err)
	}
	return nil
}

func validateOperationBindingRefinement(raw any) error {
	branches, ok := raw.([]any)
	if !ok || len(branches) != 2 {
		return errors.New("operation binding must contain exactly two oneOf branches")
	}
	bound, ok := branches[0].(map[string]any)
	if !ok || !mapKeySetEquals(bound, []string{"required"}) ||
		!stringSetEquals(bound["required"], []string{"environmentId", "providerConnectionId"}) {
		return errors.New("operation provider-bound refinement drifted")
	}
	unbound, ok := branches[1].(map[string]any)
	if !ok || !mapKeySetEquals(unbound, []string{"not"}) {
		return errors.New("operation unbound refinement drifted")
	}
	not, err := mapField(unbound, "not")
	if err != nil || !mapKeySetEquals(not, []string{"anyOf"}) ||
		!requiredBranchSetEquals(not["anyOf"], [][]string{{"environmentId"}, {"providerConnectionId"}}) {
		return errors.New("operation partial provider binding exclusion drifted")
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
		"spec":     "WorkspaceSpecWrite",
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
	if !validObservedGenerationUpperBound(schema["x-veer-observed-generation-upper-bound"]) {
		return errors.New("workspace observed-generation upper bound drifted")
	}
	if !reflect.DeepEqual(schema["example"], workspaceExampleContract()) {
		return errors.New("workspace canonical example drifted")
	}
	if err := validateWorkspaceIdentity(properties, "Workspace"); err != nil {
		return err
	}
	for property, target := range map[string]string{
		"metadata": "RootResourceMetadata",
		"spec":     "WorkspaceSpec",
		"status":   "WorkspaceStatus",
	} {
		if err := requireReference(properties, property, "#/components/schemas/"+target); err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
	}
	return nil
}

func workspaceExampleContract() map[string]any {
	return map[string]any{
		"apiVersion": "v1alpha1",
		"kind":       "Workspace",
		"metadata": map[string]any{
			"id":          "wsp_01J00000000000000000000000",
			"workspaceId": "wsp_01J00000000000000000000000",
			"displayName": "payments",
			"labels": map[string]any{
				"environment": "production",
				"team":        "platform",
			},
			"generation":      json.Number("1"),
			"resourceVersion": "rv_01J00000000000000000000000",
			"createdAt":       "2026-09-02T17:30:00.000Z",
			"updatedAt":       "2026-09-02T17:30:00.000Z",
		},
		"spec": map[string]any{
			"suspendReconciliation": false,
		},
		"status": map[string]any{
			"conditions":         []any{},
			"observedGeneration": json.Number("0"),
		},
	}
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
	for _, contract := range []struct {
		name     string
		property map[string]any
	}{
		{name: "type", property: problemType},
		{name: "title", property: title},
		{name: "status", property: status},
		{name: "code", property: code},
	} {
		if !mapKeySetEquals(contract.property, []string{"const"}) {
			return fmt.Errorf("%s.%s refinement has unreviewed keywords", variant.schema, contract.name)
		}
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
	schemas, err := mapField(components, "schemas")
	if err != nil {
		return err
	}
	operationSchema, err := mapField(schemas, "Operation")
	if err != nil {
		return err
	}
	operationExample, err := mapField(operationSchema, "example")
	if err != nil {
		return err
	}
	operationResponse, err := mapField(responses, "Operation")
	if err != nil {
		return err
	}
	operationContent, err := mapField(operationResponse, "content")
	if err != nil {
		return err
	}
	operationMedia, err := mapField(operationContent, "application/json")
	if err != nil {
		return err
	}
	responseExample, err := mapField(operationMedia, "example")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(operationExample, responseExample) {
		return errors.New("operation schema and response examples drifted")
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
