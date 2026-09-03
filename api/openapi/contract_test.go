package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/admission"
	"github.com/ArdurAI/veer/internal/core/domain/audit"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/ports"
)

type schemaExampleWire struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   schemaExampleMetadata      `json:"metadata"`
	Spec       map[string]json.RawMessage `json:"spec"`
	Status     schemaExampleStatus        `json:"status"`
}

type schemaExampleMetadata struct {
	ID              string            `json:"id"`
	WorkspaceID     string            `json:"workspaceId"`
	DisplayName     string            `json:"displayName"`
	Parent          *string           `json:"parent,omitempty"`
	Labels          map[string]string `json:"labels"`
	Generation      int64             `json:"generation"`
	ResourceVersion string            `json:"resourceVersion"`
	CreatedAt       string            `json:"createdAt"`
	UpdatedAt       string            `json:"updatedAt"`
}

type schemaExampleStatus struct {
	ObservedGeneration int64             `json:"observedGeneration"`
	Conditions         []json.RawMessage `json:"conditions"`
}

type controlSchemaInstanceFixture struct {
	Name          string         `json:"name"`
	Schema        string         `json:"schema"`
	SchemaValid   bool           `json:"schemaValid"`
	SemanticValid bool           `json:"semanticValid"`
	Instance      map[string]any `json:"instance"`
}

type admissionSchemaFixtureSet struct {
	Compatibility []admissionSchemaInstanceFixture `json:"compatibility"`
	Defaulting    []admissionDefaultFixture        `json:"defaulting"`
	Negative      []admissionSchemaInstanceFixture `json:"negative"`
}

type admissionSchemaInstanceFixture struct {
	Name     string         `json:"name"`
	Kind     string         `json:"kind,omitempty"`
	Role     string         `json:"role,omitempty"`
	Schema   string         `json:"schema"`
	Instance map[string]any `json:"instance"`
}

type admissionDefaultFixture struct {
	Name      string         `json:"name"`
	Schema    string         `json:"schema"`
	Instance  map[string]any `json:"instance"`
	Canonical map[string]any `json:"canonical"`
}

type controlTransitionFixture struct {
	Operations []operationTransitionFixture `json:"operations"`
	Conditions []conditionTransitionFixture `json:"conditions"`
}

type operationTransitionFixture struct {
	Name   string         `json:"name"`
	Valid  bool           `json:"valid"`
	Before map[string]any `json:"before"`
	After  map[string]any `json:"after"`
}

type conditionTransitionFixture struct {
	Name               string         `json:"name"`
	ResourceGeneration int64          `json:"resourceGeneration"`
	Valid              bool           `json:"valid"`
	Before             map[string]any `json:"before"`
	After              map[string]any `json:"after"`
}

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

func TestAdmissionManifestMatchesRuntimeTokens(t *testing.T) {
	t.Parallel()

	data, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, data)
	manifestStages, ok := nestedMap(t, root, "x-veer-admission")["stages"].([]any)
	if !ok {
		t.Fatal("x-veer-admission.stages is not an array")
	}

	want := []struct {
		stage admission.Stage
		codes []admission.Code
	}{
		{stage: admission.StageSchema, codes: []admission.Code{
			admission.CodeRequestTooLarge,
			admission.CodeInvalidJSON,
			admission.CodeJSONTooDeep,
			admission.CodeTooManyJSONNodes,
			admission.CodeDuplicateField,
			admission.CodeUnknownField,
			admission.CodeMissingField,
			admission.CodeInvalidType,
			admission.CodeInvalidValue,
			admission.CodeUnsupportedVersion,
			admission.CodeUnsupportedKind,
		}},
		{stage: admission.StageSemantic, codes: []admission.Code{
			admission.CodeInvalidSpec,
			admission.CodeInvalidStatus,
			admission.CodeInvalidOrder,
			admission.CodeDuplicateItem,
			admission.CodeFutureObservation,
		}},
		{stage: admission.StageImmutable, codes: []admission.Code{
			admission.CodeImmutableField,
		}},
		{stage: admission.StageReference, codes: []admission.Code{
			admission.CodeInvalidPlacement,
			admission.CodeParentNotFound,
			admission.CodeParentKindMismatch,
			admission.CodeReferenceNotFound,
			admission.CodeReferenceKindMismatch,
			admission.CodeWorkspaceMismatch,
		}},
		{stage: admission.StageDefault, codes: []admission.Code{
			admission.CodeDefaultFailed,
		}},
		{stage: admission.StageConversion, codes: []admission.Code{
			admission.CodeConversionFailed,
		}},
	}
	if len(manifestStages) != len(want) {
		t.Fatalf("x-veer-admission.stages length = %d, want %d", len(manifestStages), len(want))
	}
	for index, expected := range want {
		stage, ok := manifestStages[index].(map[string]any)
		if !ok {
			t.Fatalf("x-veer-admission.stages[%d] is not an object", index)
		}
		if stage["name"] != string(expected.stage) {
			t.Fatalf("x-veer-admission.stages[%d].name = %v, want %q", index, stage["name"], expected.stage)
		}
		codes, ok := stage["codes"].([]any)
		if !ok {
			t.Fatalf("x-veer-admission.stages[%d].codes is not an array", index)
		}
		if len(codes) != len(expected.codes) {
			t.Fatalf("x-veer-admission.stages[%d].codes length = %d, want %d", index, len(codes), len(expected.codes))
		}
		for codeIndex, expectedCode := range expected.codes {
			if codes[codeIndex] != string(expectedCode) {
				t.Fatalf(
					"x-veer-admission.stages[%d].codes[%d] = %v, want %q",
					index,
					codeIndex,
					codes[codeIndex],
					expectedCode,
				)
			}
		}
	}
}

func TestAuthorizationManifestMatchesRuntimeTokens(t *testing.T) {
	t.Parallel()

	data, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, data)
	var manifest authorizationContract
	if err := decodeStrictValue(root["x-veer-authorization"], &manifest); err != nil {
		t.Fatalf("decode authorization manifest: %v", err)
	}

	if manifest.ContractVersion != authorization.ContractVersion {
		t.Fatalf("contractVersion = %q, want %q", manifest.ContractVersion, authorization.ContractVersion)
	}
	if manifest.MaxDecisionBytes != authorization.MaxDecisionBytes {
		t.Fatalf("maxDecisionBytes = %d, want %d", manifest.MaxDecisionBytes, authorization.MaxDecisionBytes)
	}
	if manifest.ListEvaluation != authorization.ListEvaluationMode {
		t.Fatalf("listEvaluation = %q, want %q", manifest.ListEvaluation, authorization.ListEvaluationMode)
	}
	if manifest.PolicyVersionPrefix != authorization.PolicyVersionPrefix ||
		manifest.InputDigestPrefix != authorization.InputDigestPrefix {
		t.Fatalf("digest prefixes = %q/%q, want %q/%q",
			manifest.PolicyVersionPrefix, manifest.InputDigestPrefix,
			authorization.PolicyVersionPrefix, authorization.InputDigestPrefix)
	}
	effects := authorization.Effects()
	wantEffects := make([]string, len(effects))
	for index, effect := range effects {
		wantEffects[index] = effect.String()
	}
	if manifest.DefaultEffect != authorization.DefaultEffect.String() ||
		!reflect.DeepEqual(manifest.Effects, wantEffects) {
		t.Fatalf("effect vocabulary drifted: default %q, effects %#v", manifest.DefaultEffect, manifest.Effects)
	}

	actions := authorization.Actions()
	wantActions := make([]string, len(actions))
	for index, action := range actions {
		wantActions[index] = action.String()
	}
	if !reflect.DeepEqual(manifest.Actions, wantActions) {
		t.Fatalf("action registry drifted:\n manifest %#v\n runtime  %#v", manifest.Actions, wantActions)
	}
	runtimeReserved := authorization.ReservedActions()
	wantReserved := make([]string, len(runtimeReserved))
	for index, action := range runtimeReserved {
		wantReserved[index] = action.String()
	}
	if !reflect.DeepEqual(manifest.ReservedActions, wantReserved) {
		t.Fatalf("reserved actions drifted:\n manifest %#v\n runtime  %#v", manifest.ReservedActions, wantReserved)
	}
	runtimeReservedResources := authorization.ReservedResourceActions()
	wantReservedResources := make([]authorizationResourceAction, len(runtimeReservedResources))
	for index, action := range runtimeReservedResources {
		wantReservedResources[index] = authorizationResourceAction{
			Action: action.Action.String(), ResourceKind: action.ResourceKind.String(),
		}
	}
	if !reflect.DeepEqual(manifest.ReservedResourceActions, wantReservedResources) {
		t.Fatalf("reserved resource actions drifted:\n manifest %#v\n runtime  %#v",
			manifest.ReservedResourceActions, wantReservedResources)
	}

	roles := authorization.Roles()
	if len(manifest.Roles) != len(roles) {
		t.Fatalf("role count = %d, want %d", len(manifest.Roles), len(roles))
	}
	for index, role := range roles {
		manifestRole := manifest.Roles[index]
		if manifestRole.Name != role.String() {
			t.Fatalf("roles[%d].name = %q, want %q", index, manifestRole.Name, role)
		}
		inherited := authorization.InheritedRoles(role)
		wantInherited := make([]string, 0, len(inherited))
		for _, inheritedRole := range inherited {
			if inheritedRole != role {
				wantInherited = append(wantInherited, inheritedRole.String())
			}
		}
		if !reflect.DeepEqual(manifestRole.Inherits, wantInherited) {
			t.Fatalf("role %s inheritance = %#v, want %#v", role, manifestRole.Inherits, wantInherited)
		}
		runtimeGrants := authorization.RoleGrants(role)
		wantGrants := make([]authorizationGrantContract, len(runtimeGrants))
		for grantIndex, grant := range runtimeGrants {
			resourceKinds := make([]string, len(grant.ResourceKinds))
			for resourceIndex, kind := range grant.ResourceKinds {
				resourceKinds[resourceIndex] = kind.String()
			}
			if !sort.StringsAreSorted(resourceKinds) {
				t.Fatalf("runtime role %s grant resource kinds are not canonical: %#v", role, resourceKinds)
			}
			wantGrants[grantIndex] = authorizationGrantContract{
				Action: grant.Action.String(), ObjectKind: grant.ObjectKind.String(), ResourceKinds: resourceKinds,
			}
		}
		if !reflect.DeepEqual(manifestRole.Grants, wantGrants) {
			t.Fatalf("role %s grants drifted:\n manifest %#v\n runtime  %#v", role, manifestRole.Grants, wantGrants)
		}
	}
	scopeKinds := authorization.ScopeKinds()
	if len(manifest.Scopes) != len(scopeKinds) {
		t.Fatalf("scope count = %d, want %d", len(manifest.Scopes), len(scopeKinds))
	}
	for index, scope := range manifest.Scopes {
		if scope.Kind != scopeKinds[index].String() {
			t.Fatalf("scopes[%d].kind = %q, want %q", index, scope.Kind, scopeKinds[index])
		}
		runtimeDescendants := authorization.ScopeDescendants(scopeKinds[index])
		wantDescendants := make([]string, len(runtimeDescendants))
		for descendantIndex, descendant := range runtimeDescendants {
			wantDescendants[descendantIndex] = descendant.String()
		}
		if !reflect.DeepEqual(scope.DescendsTo, wantDescendants) {
			t.Fatalf("scope %s descendants = %#v, want %#v",
				scope.Kind, scope.DescendsTo, wantDescendants)
		}
	}
	objectKinds := authorization.ObjectKinds()
	wantObjects := make([]string, len(objectKinds))
	for index, object := range objectKinds {
		wantObjects[index] = object.String()
	}
	if !reflect.DeepEqual(manifest.Objects, wantObjects) {
		t.Fatalf("object registry drifted:\n manifest %#v\n runtime  %#v", manifest.Objects, wantObjects)
	}
	reasons := authorization.Reasons()
	wantReasons := make([]string, len(reasons))
	for index, reason := range reasons {
		wantReasons[index] = reason.String()
	}
	if !reflect.DeepEqual(manifest.Reasons, wantReasons) {
		t.Fatalf("decision reasons = %#v, want %#v", manifest.Reasons, wantReasons)
	}
}

func TestAuditManifestMatchesRuntimeTokens(t *testing.T) {
	t.Parallel()

	data, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, data)
	var manifest auditContract
	if err := decodeStrictValue(root["x-veer-audit"], &manifest); err != nil {
		t.Fatalf("decode audit manifest: %v", err)
	}

	want := auditManifestRuntimeContract(t)
	if !reflect.DeepEqual(manifest, want) {
		t.Fatalf("x-veer-audit runtime projection drifted:\n manifest %#v\n runtime  %#v", manifest, want)
	}
	if static := auditManifestContract(); !reflect.DeepEqual(static, want) {
		t.Fatalf("contract.go audit projection drifted:\n static  %#v\n runtime %#v", static, want)
	}
}

func auditManifestRuntimeContract(t *testing.T) auditContract {
	t.Helper()

	return auditContract{
		ContractVersion: audit.ContractVersion,
		TimestampFormat: "RFC3339-UTC-milliseconds",
		Ordering:        "stream-sequence",
		Limits: auditLimitsContract{
			MaxCanonicalEventBytes:    audit.MaxCanonicalEventBytes,
			MaxSegmentEvents:          audit.MaxSegmentEvents,
			MaxCanonicalSegmentBytes:  audit.MaxCanonicalSegmentBytes,
			MaxCanonicalManifestBytes: audit.MaxCanonicalManifestBytes,
			MaxSignatureBytes:         audit.MaxSignatureBytes,
			MaxKeyIDBytes:             audit.MaxKeyIDBytes,
			MaxHolds:                  audit.MaxHolds,
		},
		Integrity: auditIntegrityContract{
			Digest:            "SHA-256-domain-separated-uint64-length-frames",
			ChainDigestPrefix: audit.ChainDigestPrefix,
			TailCompleteness:  "trusted-terminal-checkpoint-required",
		},
		Export: auditExportContract{
			BodyDigestPrefix:          audit.ExportBodyDigestPrefix,
			SignatureAlgorithms:       auditStrings(audit.SignatureAlgorithms()),
			SignatureProduction:       "external-not-implemented",
			SignatureVerification:     "caller-supplied-interface",
			TrustedTerminalCheckpoint: true,
		},
		Retention: auditRetentionContract{
			OnlineDays:          exactDurationUnits(t, "audit.OnlineRetention", audit.OnlineRetention, 24*time.Hour),
			ArchiveDays:         exactDurationUnits(t, "audit.ArchiveRetention", audit.ArchiveRetention, 24*time.Hour),
			HoldKinds:           auditStrings(audit.HoldKinds()),
			Dispositions:        auditStrings(audit.RetentionDispositions()),
			DeletionEligibility: "expire-only",
		},
		Vocabulary: auditVocabularyContract{
			StreamKinds:           auditStrings(audit.StreamKinds()),
			ActorKinds:            auditStrings(audit.ActorKinds()),
			AuthenticationMethods: auditStrings(audit.AuthenticationMethods()),
			EventKinds:            auditStrings(audit.EventKinds()),
			Sources:               auditStrings(audit.Sources()),
			Outcomes:              auditStrings(audit.Outcomes()),
			ClockStates:           auditStrings(audit.ClockStates()),
			ElevationStates:       auditStrings(audit.ElevationStates()),
		},
		PrivilegedAdmin: privilegedAdminContract{
			ContractVersion:              administration.ContractVersion,
			Ledger:                       "process-local-reference",
			StrongAuthentication:         "verifier-port-no-adapter",
			StrongAuthenticationFailures: []string{ports.ErrStrongAuthenticationInvalid.Error(), ports.ErrStrongAuthenticationUnavailable.Error()},
			MaxAdministrators:            administration.MaxAdministrators,
			MaxTrackedElevations:         administration.MaxTrackedElevations,
			MaxReasonRunes:               administration.MaxReasonRunes,
			MaxCaseReferenceRunes:        administration.MaxCaseReferenceRunes,
			MaxStrongAuthProofAgeSeconds: exactDurationUnits(t, "administration.MaxStrongAuthProofAge", administration.MaxStrongAuthProofAge, time.Second),
			MaxElevationDurationSeconds:  exactDurationUnits(t, "administration.MaxElevationDuration", administration.MaxElevationDuration, time.Second),
			EligibleActions:              authorizationActions(administration.EligibleActions()),
			TargetKinds: auditStrings([]administration.TargetKind{
				administration.TargetKindPlatformAudit,
				administration.TargetKindWorkspaceAudit,
				administration.TargetKindOperation,
			}),
			GrantStates: auditStrings([]administration.GrantState{
				administration.GrantStateActive,
				administration.GrantStateConsumed,
				administration.GrantStateRevoked,
				administration.GrantStateExpired,
			}),
			Renewal:            "unsupported",
			ExpirationBoundary: "expired-at-equality",
		},
	}
}

func auditStrings[T interface{ String() string }](values []T) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func authorizationActions(actions []authorization.Action) []string {
	result := make([]string, len(actions))
	for index, action := range actions {
		result[index] = action.String()
	}
	return result
}

func exactDurationUnits(t *testing.T, name string, duration, unit time.Duration) int {
	t.Helper()
	if duration <= 0 || duration%unit != 0 {
		t.Fatalf("%s = %s, want a positive exact multiple of %s", name, duration, unit)
	}
	return int(duration / unit)
}

func TestWorkspaceGoldenMatchesContractExample(t *testing.T) {
	t.Parallel()

	contractData, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, contractData)
	example := nestedMap(t, root, "components", "schemas", "Workspace", "example")

	fixtureData, err := os.ReadFile("../../internal/core/domain/resource/testdata/root.golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(fixtureData)))
	decoder.UseNumber()
	var fixture map[string]any
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		t.Fatalf("fixture trailing data: %v", err)
	}
	if !reflect.DeepEqual(fixture, example) {
		t.Fatalf("Workspace fixture does not match the schema example:\n fixture %#v\n example %#v", fixture, example)
	}
}

func TestHierarchyGoldensMatchContractExamples(t *testing.T) {
	t.Parallel()

	contractData, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, contractData)
	for _, contract := range []struct {
		kind    string
		fixture string
	}{
		{kind: "Workspace", fixture: "workspace.golden.json"},
		{kind: "Environment", fixture: "environment.golden.json"},
		{kind: "Application", fixture: "application.golden.json"},
		{kind: "Component", fixture: "component.golden.json"},
	} {
		contract := contract
		t.Run(contract.kind, func(t *testing.T) {
			example := nestedMap(t, root, "components", "schemas", contract.kind, "example")
			fixtureData, err := os.ReadFile(filepath.Join(
				"..", "..", "internal", "core", "domain", "hierarchy", "testdata", contract.fixture,
			))
			if err != nil {
				t.Fatalf("os.ReadFile() error = %v", err)
			}
			fixture := decodeForMutation(t, fixtureData)
			if !reflect.DeepEqual(fixture, example) {
				t.Fatalf("%s fixture does not match the schema example:\n fixture %#v\n example %#v", contract.kind, fixture, example)
			}
		})
	}
}

func TestControlGoldensMatchContractExamples(t *testing.T) {
	t.Parallel()
	contractData, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, contractData)
	for _, contract := range []struct {
		schema  string
		fixture string
	}{
		{schema: "Policy", fixture: "../../internal/core/domain/control/testdata/policy.golden.json"},
		{
			schema:  "ProviderConnection",
			fixture: "../../internal/core/domain/control/testdata/provider-connection.golden.json",
		},
		{schema: "Operation", fixture: "../../internal/core/domain/operation/testdata/provider-bound.golden.json"},
	} {
		contract := contract
		t.Run(contract.schema, func(t *testing.T) {
			t.Parallel()
			fixtureData, err := os.ReadFile(contract.fixture)
			if err != nil {
				t.Fatalf("os.ReadFile() error = %v", err)
			}
			fixture := decodeForMutation(t, fixtureData)
			example := nestedMap(t, root, "components", "schemas", contract.schema, "example")
			if !reflect.DeepEqual(fixture, example) {
				t.Fatalf("%s golden does not match the OpenAPI example:\n fixture %#v\n example %#v", contract.schema, fixture, example)
			}
		})
	}
}

func TestControlSchemaSemanticFixtureMatrix(t *testing.T) {
	t.Parallel()
	var fixtures []controlSchemaInstanceFixture
	decodeStrictFixture(t, "testdata/control-schema-instances.json", &fixtures)
	want := map[string]struct {
		schema        string
		schemaValid   bool
		semanticValid bool
	}{
		"credential reference":               {"CredentialReference", true, true},
		"provider spec":                      {"ProviderConnectionSpec", true, true},
		"embedded credential secret":         {"ProviderConnectionSpec", false, false},
		"raw provider credential":            {"ProviderConnectionSpec", false, false},
		"explicit unknown capability":        {"ProviderCapability", true, true},
		"year zero observation timestamp":    {"ProviderCapability", true, true},
		"capability state omitted":           {"ProviderCapability", false, false},
		"unsorted capability observations":   {"ProviderConnectionStatus", true, false},
		"explicit unknown quota":             {"QuotaCheck", true, true},
		"known quota":                        {"QuotaCheck", true, true},
		"known zero quota":                   {"QuotaCheck", true, true},
		"unknown quota carries operands":     {"QuotaCheck", false, false},
		"quota comparator mismatch":          {"QuotaCheck", true, false},
		"explicit unknown cost":              {"CostEstimate", true, true},
		"known cost":                         {"CostEstimate", true, true},
		"known zero cost":                    {"CostEstimate", true, true},
		"unknown cost carries amount":        {"CostEstimate", false, false},
		"unknown cost uses known confidence": {"CostEstimate", false, false},
		"operation update precedes creation": {"Operation", true, false},
	}
	if len(fixtures) != len(want) {
		t.Fatalf("fixture count = %d, want exactly %d", len(fixtures), len(want))
	}
	seen := make(map[string]struct{}, len(fixtures))
	for _, fixture := range fixtures {
		fixture := fixture
		expected, exists := want[fixture.Name]
		if !exists {
			t.Fatalf("unexpected fixture %q", fixture.Name)
		}
		if _, duplicate := seen[fixture.Name]; duplicate {
			t.Fatalf("duplicate fixture %q", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		if fixture.Schema != expected.schema || fixture.SchemaValid != expected.schemaValid ||
			fixture.SemanticValid != expected.semanticValid {
			t.Fatalf("fixture %q contract = (%s,%t,%t), want (%s,%t,%t)",
				fixture.Name, fixture.Schema, fixture.SchemaValid, fixture.SemanticValid,
				expected.schema, expected.schemaValid, expected.semanticValid)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			err := validateControlFixtureSemantic(fixture.Schema, fixture.Instance)
			if (err == nil) != fixture.SemanticValid {
				t.Fatalf("semantic validity = %t, want %t (error %v)", err == nil, fixture.SemanticValid, err)
			}
		})
	}
}

func TestAuthorizationSchemaSemanticFixtureMatrix(t *testing.T) {
	t.Parallel()
	var fixtures []controlSchemaInstanceFixture
	decodeStrictFixture(t, "testdata/authorization-schema-instances.json", &fixtures)
	want := map[string]struct {
		schemaValid   bool
		semanticValid bool
	}{
		"canonical workspace binding":                    {true, true},
		"canonical environment binding":                  {true, true},
		"empty default-deny policy":                      {true, true},
		"workspace scope carries environment":            {false, false},
		"environment scope omits environment":            {false, false},
		"workspace administrator environment escalation": {true, false},
		"unknown role":                                   {false, false},
		"unsorted binding list":                          {true, false},
		"duplicate binding":                              {false, false},
		"binding gains identity claims":                  {false, false},
		"bindings omitted":                               {false, false},
	}
	if len(fixtures) != len(want) {
		t.Fatalf("fixture count = %d, want exactly %d", len(fixtures), len(want))
	}
	seen := make(map[string]struct{}, len(fixtures))
	for _, fixture := range fixtures {
		fixture := fixture
		expected, exists := want[fixture.Name]
		if !exists {
			t.Fatalf("unexpected fixture %q", fixture.Name)
		}
		if _, duplicate := seen[fixture.Name]; duplicate {
			t.Fatalf("duplicate fixture %q", fixture.Name)
		}
		seen[fixture.Name] = struct{}{}
		if fixture.Schema != "PolicySpec" || fixture.SchemaValid != expected.schemaValid ||
			fixture.SemanticValid != expected.semanticValid {
			t.Fatalf("fixture %q contract = (%s,%t,%t), want (PolicySpec,%t,%t)",
				fixture.Name, fixture.Schema, fixture.SchemaValid, fixture.SemanticValid,
				expected.schemaValid, expected.semanticValid)
		}
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			openAPIErr := validatePolicySpecValue(fixture.Instance)

			encoded, err := json.Marshal(fixture.Instance)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.DisallowUnknownFields()
			var runtimeSpec authorization.PolicySpec
			runtimeErr := decoder.Decode(&runtimeSpec)
			if runtimeErr == nil {
				runtimeErr = requireJSONEOF(decoder)
			}
			if runtimeErr == nil {
				runtimeErr = authorization.ValidatePolicySpec(runtimeSpec)
			}

			if (openAPIErr == nil) != fixture.SemanticValid {
				t.Fatalf("OpenAPI semantic validity = %t, want %t (error %v)",
					openAPIErr == nil, fixture.SemanticValid, openAPIErr)
			}
			if (runtimeErr == nil) != fixture.SemanticValid {
				t.Fatalf("runtime semantic validity = %t, want %t (error %v)",
					runtimeErr == nil, fixture.SemanticValid, runtimeErr)
			}
		})
	}
}

func TestAdmissionSchemaFixtureMatrix(t *testing.T) {
	t.Parallel()
	var fixtures admissionSchemaFixtureSet
	decodeStrictFixture(t, "testdata/admission-schema-instances.json", &fixtures)

	wantCells := make(map[string]string, len(resourceSchemaContracts)*3)
	for _, contract := range resourceSchemaContracts {
		for _, role := range []struct {
			name   string
			suffix string
		}{
			{name: "create", suffix: "Create"},
			{name: "replace", suffix: "Replace"},
			{name: "status", suffix: "StatusWrite"},
		} {
			wantCells[contract.kind+"/"+role.name] = contract.schema(role.suffix)
		}
	}
	if len(fixtures.Compatibility) != len(wantCells) {
		t.Fatalf("compatibility fixture count = %d, want exactly %d", len(fixtures.Compatibility), len(wantCells))
	}
	seenCells := make(map[string]struct{}, len(fixtures.Compatibility))
	seenNames := make(map[string]struct{}, len(fixtures.Compatibility))
	for _, fixture := range fixtures.Compatibility {
		cell := fixture.Kind + "/" + fixture.Role
		wantSchema, exists := wantCells[cell]
		if !exists {
			t.Fatalf("unexpected compatibility cell %q", cell)
		}
		if _, duplicate := seenCells[cell]; duplicate {
			t.Fatalf("duplicate compatibility cell %q", cell)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			t.Fatalf("duplicate admission fixture name %q", fixture.Name)
		}
		seenCells[cell] = struct{}{}
		seenNames[fixture.Name] = struct{}{}
		if fixture.Schema != wantSchema {
			t.Fatalf("compatibility cell %q schema = %q, want %q", cell, fixture.Schema, wantSchema)
		}
		if fixture.Instance["apiVersion"] != "v1alpha1" || fixture.Instance["kind"] != fixture.Kind {
			t.Fatalf("compatibility cell %q identity drifted", cell)
		}
	}

	type defaultFixtureContract struct {
		instance  map[string]any
		canonical map[string]any
	}
	wantDefaults := map[string]defaultFixtureContract{
		"workspace omitted defaults false": {
			instance:  map[string]any{},
			canonical: map[string]any{"suspendReconciliation": false},
		},
		"workspace explicit false remains false": {
			instance:  map[string]any{"suspendReconciliation": false},
			canonical: map[string]any{"suspendReconciliation": false},
		},
		"workspace explicit true remains true": {
			instance:  map[string]any{"suspendReconciliation": true},
			canonical: map[string]any{"suspendReconciliation": true},
		},
	}
	if len(fixtures.Defaulting) != len(wantDefaults) {
		t.Fatalf("default fixture count = %d, want exactly %d", len(fixtures.Defaulting), len(wantDefaults))
	}
	contractData, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, contractData)
	defaulting := nestedMap(t, root, "x-veer-admission", "defaulting")
	rules := defaulting["rules"].([]any)
	rule := rules[0].(map[string]any)
	for _, fixture := range fixtures.Defaulting {
		want, exists := wantDefaults[fixture.Name]
		if !exists {
			t.Fatalf("unexpected default fixture %q", fixture.Name)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			t.Fatalf("duplicate admission fixture name %q", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
		if fixture.Schema != "WorkspaceSpecWrite" ||
			!reflect.DeepEqual(fixture.Instance, want.instance) ||
			!reflect.DeepEqual(fixture.Canonical, want.canonical) {
			t.Fatalf("default fixture %q schema or canonical value drifted", fixture.Name)
		}
		before := cloneFixtureMap(fixture.Instance)
		first := applyWorkspaceDefaultRule(fixture.Instance, rule)
		second := applyWorkspaceDefaultRule(first, rule)
		if !reflect.DeepEqual(fixture.Instance, before) {
			t.Fatalf("default fixture %q input was mutated", fixture.Name)
		}
		if !reflect.DeepEqual(first, fixture.Canonical) || !reflect.DeepEqual(second, first) {
			t.Fatalf("default fixture %q is not deterministic and idempotent: first %#v second %#v want %#v",
				fixture.Name, first, second, fixture.Canonical)
		}
	}

	wantNegative := map[string]string{
		"workspace write rejects null":                                  "WorkspaceSpecWrite",
		"workspace canonical spec requires defaulted member":            "WorkspaceSpec",
		"workspace create requires spec":                                "WorkspaceCreate",
		"workspace status rejects desired state":                        "WorkspaceStatusWrite",
		"workspace create rejects server metadata":                      "WorkspaceCreate",
		"workspace write rejects unknown spec member":                   "WorkspaceSpecWrite",
		"provider connection rejects malformed credential reference id": "ProviderConnectionCreate",
		"workspace create rejects unsupported version":                  "WorkspaceCreate",
		"workspace create rejects unsupported kind":                     "WorkspaceCreate",
	}
	if len(fixtures.Negative) != len(wantNegative) {
		t.Fatalf("negative fixture count = %d, want exactly %d", len(fixtures.Negative), len(wantNegative))
	}
	for _, fixture := range fixtures.Negative {
		wantSchema, exists := wantNegative[fixture.Name]
		if !exists || fixture.Schema != wantSchema {
			t.Fatalf("negative fixture %q schema = %q, want %q", fixture.Name, fixture.Schema, wantSchema)
		}
		if _, duplicate := seenNames[fixture.Name]; duplicate {
			t.Fatalf("duplicate admission fixture name %q", fixture.Name)
		}
		seenNames[fixture.Name] = struct{}{}
	}
}

func cloneFixtureMap(input map[string]any) map[string]any {
	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func applyWorkspaceDefaultRule(input map[string]any, rule map[string]any) map[string]any {
	result := cloneFixtureMap(input)
	if _, exists := result["suspendReconciliation"]; !exists {
		result["suspendReconciliation"] = rule["value"]
	}
	return result
}

func TestSemanticMessageRuneBounds(t *testing.T) {
	t.Parallel()
	contractData, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for _, test := range []struct {
		name  string
		runes int
		valid bool
	}{
		{name: "512 multibyte code points", runes: 512, valid: true},
		{name: "513 multibyte code points", runes: 513, valid: false},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			message := strings.Repeat("界", test.runes)
			condition := map[string]any{
				"type":               "Ready",
				"status":             "Unknown",
				"reason":             "ObservationPending",
				"message":            message,
				"observedGeneration": json.Number("1"),
				"lastTransitionAt":   "2026-09-03T01:02:03.000Z",
			}
			_, conditionErr := validateConditionValue(condition, 1)
			if (conditionErr == nil) != test.valid {
				t.Fatalf("Condition validity = %t, want %t (error %v)", conditionErr == nil, test.valid, conditionErr)
			}

			root := decodeForMutation(t, contractData)
			operation := nestedMap(t, root, "components", "schemas", "Operation", "example")
			operation["message"] = message
			_, operationErr := validateOperationValue(operation)
			if (operationErr == nil) != test.valid {
				t.Fatalf("Operation validity = %t, want %t (error %v)", operationErr == nil, test.valid, operationErr)
			}
		})
	}
}

func TestControlTransitionFixtureMatrix(t *testing.T) {
	t.Parallel()
	var fixtures controlTransitionFixture
	decodeStrictFixture(t, "testdata/control-transitions.json", &fixtures)
	wantOperations := map[string]bool{
		"pending to waiting":                    true,
		"waiting evidence refresh":              true,
		"running cannot return to pending":      false,
		"material change requires new revision": false,
		"terminal mutation rejected":            false,
	}
	wantConditions := map[string]bool{
		"same status preserves timestamp":       true,
		"changed status advances timestamp":     true,
		"same status cannot advance timestamp":  false,
		"changed status must advance timestamp": false,
		"observed generation cannot regress":    false,
	}
	if len(fixtures.Operations) != len(wantOperations) || len(fixtures.Conditions) != len(wantConditions) {
		t.Fatalf("transition fixture counts = %d/%d, want %d/%d",
			len(fixtures.Operations), len(fixtures.Conditions), len(wantOperations), len(wantConditions))
	}
	seenOperations := make(map[string]struct{}, len(fixtures.Operations))
	for _, fixture := range fixtures.Operations {
		fixture := fixture
		wantValid, exists := wantOperations[fixture.Name]
		if !exists || fixture.Valid != wantValid {
			t.Fatalf("operation fixture %q validity = %t, want registered value", fixture.Name, fixture.Valid)
		}
		if _, duplicate := seenOperations[fixture.Name]; duplicate {
			t.Fatalf("duplicate operation fixture %q", fixture.Name)
		}
		seenOperations[fixture.Name] = struct{}{}
		t.Run("Operation/"+fixture.Name, func(t *testing.T) {
			t.Parallel()
			err := validateOperationTransition(fixture.Before, fixture.After)
			if (err == nil) != fixture.Valid {
				t.Fatalf("transition validity = %t, want %t (error %v)", err == nil, fixture.Valid, err)
			}
		})
	}
	seenConditions := make(map[string]struct{}, len(fixtures.Conditions))
	for _, fixture := range fixtures.Conditions {
		fixture := fixture
		wantValid, exists := wantConditions[fixture.Name]
		if !exists || fixture.Valid != wantValid {
			t.Fatalf("condition fixture %q validity = %t, want registered value", fixture.Name, fixture.Valid)
		}
		if _, duplicate := seenConditions[fixture.Name]; duplicate {
			t.Fatalf("duplicate condition fixture %q", fixture.Name)
		}
		seenConditions[fixture.Name] = struct{}{}
		t.Run("Condition/"+fixture.Name, func(t *testing.T) {
			t.Parallel()
			err := validateConditionTransition(fixture.Before, fixture.After, fixture.ResourceGeneration)
			if (err == nil) != fixture.Valid {
				t.Fatalf("transition validity = %t, want %t (error %v)", err == nil, fixture.Valid, err)
			}
		})
	}
}

func validateControlFixtureSemantic(schema string, instance map[string]any) error {
	switch schema {
	case "CredentialReference":
		return validateCredentialReferenceValue(instance)
	case "ProviderConnectionSpec":
		return validateProviderConnectionSpecValue(instance)
	case "ProviderCapability":
		return validateProviderCapabilityValue(instance)
	case "QuotaCheck":
		return validateQuotaCheckValue(instance)
	case "CostEstimate":
		return validateCostEstimateValue(instance)
	case "ProviderConnectionStatus":
		return validateProviderConnectionStatusValue(instance, 1)
	case "Operation":
		_, err := validateOperationValue(instance)
		return err
	default:
		return errors.New("unsupported fixture schema " + schema)
	}
}

func TestHierarchySchemaExampleMatrix(t *testing.T) {
	t.Parallel()

	data, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	root := decodeForMutation(t, data)
	schemas := nestedMap(t, root, "components", "schemas")

	contracts := []struct {
		kind           string
		parentKind     string
		parentID       string
		metadataSchema string
		emptySpec      bool
	}{
		{kind: "Workspace", metadataSchema: "RootResourceMetadata"},
		{
			kind: "Environment", parentKind: "Workspace",
			parentID: "wsp_01J00000000000000000000000", metadataSchema: "ChildResourceMetadata", emptySpec: true,
		},
		{
			kind: "Application", parentKind: "Environment",
			parentID: "env_01J00000000000000000000000", metadataSchema: "ChildResourceMetadata", emptySpec: true,
		},
		{
			kind: "Component", parentKind: "Application",
			parentID: "app_01J00000000000000000000000", metadataSchema: "ChildResourceMetadata", emptySpec: true,
		},
	}
	type seenResource struct {
		kind        string
		workspaceID string
	}
	seen := make(map[string]seenResource, len(contracts))
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.kind, func(t *testing.T) {
			schema := nestedMap(t, schemas, contract.kind)
			example := nestedMap(t, schema, "example")
			exampleJSON, err := json.Marshal(example)
			if err != nil {
				t.Fatalf("json.Marshal(example) error = %v", err)
			}

			decoder := json.NewDecoder(bytes.NewReader(exampleJSON))
			decoder.DisallowUnknownFields()
			var wire schemaExampleWire
			if err := decoder.Decode(&wire); err != nil {
				t.Fatalf("strict decode example: %v", err)
			}
			if err := requireJSONEOF(decoder); err != nil {
				t.Fatalf("strict decode trailing data: %v", err)
			}
			if wire.APIVersion != "v1alpha1" || wire.Kind != contract.kind {
				t.Fatalf("identity = %s/%s, want v1alpha1/%s", wire.APIVersion, wire.Kind, contract.kind)
			}
			if contract.emptySpec && len(wire.Spec) != 0 {
				t.Fatalf("spec = %#v, want closed empty object", wire.Spec)
			}
			if !contract.emptySpec {
				value, exists := wire.Spec["suspendReconciliation"]
				if !exists || string(value) != "false" || len(wire.Spec) != 1 {
					t.Fatalf("Workspace spec = %#v, want suspendReconciliation=false", wire.Spec)
				}
			}
			if wire.Status.ObservedGeneration != 0 || len(wire.Status.Conditions) != 0 {
				t.Fatalf("status = %#v, want observedGeneration=0 and no conditions", wire.Status)
			}
			if contract.parentKind == "" {
				if wire.Metadata.Parent != nil || wire.Metadata.ID != wire.Metadata.WorkspaceID {
					t.Fatalf("root metadata = %#v, want no parent and workspaceId=id", wire.Metadata)
				}
			} else {
				if wire.Metadata.Parent == nil || *wire.Metadata.Parent != contract.parentID {
					t.Fatalf("parent = %v, want %s", wire.Metadata.Parent, contract.parentID)
				}
				parent, exists := seen[*wire.Metadata.Parent]
				if !exists || parent.kind != contract.parentKind {
					t.Fatalf("parent %s is missing or has wrong kind", *wire.Metadata.Parent)
				}
				if parent.workspaceID != wire.Metadata.WorkspaceID {
					t.Fatalf("workspaceId = %s, parent workspaceId = %s", wire.Metadata.WorkspaceID, parent.workspaceID)
				}
			}

			properties := nestedMap(t, schema, "properties")
			if got := nestedMap(t, properties, "metadata")["$ref"]; got != "#/components/schemas/"+contract.metadataSchema {
				t.Fatalf("metadata ref = %v, want %s", got, contract.metadataSchema)
			}
			if got := nestedMap(t, properties, "spec")["$ref"]; got != "#/components/schemas/"+contract.kind+"Spec" {
				t.Fatalf("spec ref = %v", got)
			}
			if got := nestedMap(t, properties, "status")["$ref"]; got != "#/components/schemas/"+contract.kind+"Status" {
				t.Fatalf("status ref = %v", got)
			}

			roundTripJSON, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("json.Marshal(round trip) error = %v", err)
			}
			roundTrip := decodeForMutation(t, roundTripJSON)
			if !reflect.DeepEqual(roundTrip, example) {
				t.Fatalf("v1alpha1 example round trip drifted:\n got %#v\nwant %#v", roundTrip, example)
			}
			seen[wire.Metadata.ID] = seenResource{kind: wire.Kind, workspaceID: wire.Metadata.WorkspaceID}
		})
	}
}

func TestVacuumHierarchySchemaInstanceMatrix(t *testing.T) {
	vacuumPath := os.Getenv("VEER_TEST_VACUUM_BIN")
	if vacuumPath == "" {
		t.Skip("schema-instance matrix runs through ./hack/dev api")
	}
	expectedVacuumPath, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bin", "vacuum"))
	if err != nil {
		t.Fatalf("resolve repository Vacuum path: %v", err)
	}
	if filepath.Clean(vacuumPath) != expectedVacuumPath {
		t.Fatalf("Vacuum path = %q, want repository-pinned %q", vacuumPath, expectedVacuumPath)
	}
	info, err := os.Lstat(vacuumPath)
	if err != nil {
		t.Fatalf("inspect repository Vacuum: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("Vacuum must be a regular non-symlink executable: mode %s", info.Mode())
	}

	baseline, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	configPath, err := filepath.Abs("vacuum.conf.yaml")
	if err != nil {
		t.Fatalf("resolve Vacuum config: %v", err)
	}
	if output, err := runVacuumSchemaExamples(t, vacuumPath, configPath, "veer-v1alpha1.json"); err != nil {
		t.Fatalf("Vacuum rejected positive schema examples: %v\n%s", err, output)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "Workspace forbids parent",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Workspace", "example", "metadata")["parent"] =
					"wsp_01J11111111111111111111111"
			},
		},
		{
			name: "Environment requires parent",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "Environment", "example", "metadata"), "parent")
			},
		},
		{
			name: "Application spec is closed",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Application", "example", "spec")["provider"] = "aws"
			},
		},
		{
			name: "Component requires workspace ownership",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "Component", "example", "metadata"), "workspaceId")
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			contractPath := filepath.Join(t.TempDir(), "invalid-openapi.json")
			if err := os.WriteFile(contractPath, mutated, 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			output, err := runVacuumSchemaExamples(t, vacuumPath, configPath, contractPath)
			if err == nil || !bytes.Contains(output, []byte("oas3-valid-schema-example")) {
				t.Fatalf("Vacuum did not reject invalid schema instance: %v\n%s", err, output)
			}
		})
	}
}

func runVacuumSchemaExamples(
	t *testing.T,
	vacuumPath, configPath, contractPath string,
) ([]byte, error) {
	t.Helper()
	command := exec.Command(
		vacuumPath,
		"lint",
		"--config", configPath,
		"--no-update-check",
		"--ext-refs",
		"--remote=false",
		"--allow-private-networks=false",
		"--allow-http=false",
		"--insecure=false",
		"--min-score", "100",
		"--fail-severity", "warn",
		"--errors",
		"--details",
		"--no-style",
		"--no-banner",
		contractPath,
	)
	command.Env = []string{"NO_COLOR=1", "TMPDIR=" + t.TempDir()}
	return command.CombinedOutput()
}

func TestVacuumControlSchemaInstanceMatrix(t *testing.T) {
	vacuumPath := os.Getenv("VEER_TEST_VACUUM_BIN")
	if vacuumPath == "" {
		t.Skip("schema-instance matrix runs through ./hack/dev api")
	}
	expectedVacuumPath, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bin", "vacuum"))
	if err != nil {
		t.Fatalf("resolve repository Vacuum path: %v", err)
	}
	if filepath.Clean(vacuumPath) != expectedVacuumPath {
		t.Fatalf("Vacuum path = %q, want repository-pinned %q", vacuumPath, expectedVacuumPath)
	}
	info, err := os.Lstat(vacuumPath)
	if err != nil {
		t.Fatalf("inspect repository Vacuum: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("Vacuum must be a regular non-symlink executable: mode %s", info.Mode())
	}
	baseline, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	configPath, err := filepath.Abs("vacuum.conf.yaml")
	if err != nil {
		t.Fatalf("resolve Vacuum config: %v", err)
	}

	var fixtures []controlSchemaInstanceFixture
	decodeStrictFixture(t, "testdata/control-schema-instances.json", &fixtures)
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, fixture.Schema, fixture.Instance)
			if fixture.SchemaValid {
				if bytes.Contains(output, []byte("oas3-valid-schema-example")) ||
					(err != nil && !bytes.Contains(output, []byte("oas3-missing-example"))) {
					t.Fatalf("Vacuum rejected valid %s instance: %v\n%s", fixture.Schema, err, output)
				}
				return
			}
			if err == nil || !bytes.Contains(output, []byte("oas3-valid-schema-example")) {
				t.Fatalf("Vacuum accepted invalid %s instance: %v\n%s", fixture.Schema, err, output)
			}
		})
	}

	var transitions controlTransitionFixture
	decodeStrictFixture(t, "testdata/control-transitions.json", &transitions)
	for _, fixture := range transitions.Operations {
		for label, instance := range map[string]map[string]any{"before": fixture.Before, "after": fixture.After} {
			output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, "Operation", instance)
			if bytes.Contains(output, []byte("oas3-valid-schema-example")) ||
				(err != nil && !bytes.Contains(output, []byte("oas3-missing-example"))) {
				t.Fatalf("Vacuum rejected structurally valid Operation transition %s %s: %v\n%s", fixture.Name, label, err, output)
			}
		}
	}
	for _, fixture := range transitions.Conditions {
		for label, instance := range map[string]map[string]any{"before": fixture.Before, "after": fixture.After} {
			output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, "Condition", instance)
			if bytes.Contains(output, []byte("oas3-valid-schema-example")) ||
				(err != nil && !bytes.Contains(output, []byte("oas3-missing-example"))) {
				t.Fatalf("Vacuum rejected structurally valid Condition transition %s %s: %v\n%s", fixture.Name, label, err, output)
			}
		}
	}
}

func TestVacuumAuthorizationSchemaInstanceMatrix(t *testing.T) {
	vacuumPath := os.Getenv("VEER_TEST_VACUUM_BIN")
	if vacuumPath == "" {
		t.Skip("schema-instance matrix runs through ./hack/dev api")
	}
	expectedVacuumPath, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bin", "vacuum"))
	if err != nil {
		t.Fatalf("resolve repository Vacuum path: %v", err)
	}
	if filepath.Clean(vacuumPath) != expectedVacuumPath {
		t.Fatalf("Vacuum path = %q, want repository-pinned %q", vacuumPath, expectedVacuumPath)
	}
	info, err := os.Lstat(vacuumPath)
	if err != nil {
		t.Fatalf("inspect repository Vacuum: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("Vacuum must be a regular non-symlink executable: mode %s", info.Mode())
	}
	baseline, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	configPath, err := filepath.Abs("vacuum.conf.yaml")
	if err != nil {
		t.Fatalf("resolve Vacuum config: %v", err)
	}

	var fixtures []controlSchemaInstanceFixture
	decodeStrictFixture(t, "testdata/authorization-schema-instances.json", &fixtures)
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, fixture.Schema, fixture.Instance)
			if fixture.SchemaValid {
				if bytes.Contains(output, []byte("oas3-valid-schema-example")) ||
					(err != nil && !bytes.Contains(output, []byte("oas3-missing-example"))) {
					t.Fatalf("Vacuum rejected valid %s instance: %v\n%s", fixture.Schema, err, output)
				}
				return
			}
			if err == nil || !bytes.Contains(output, []byte("oas3-valid-schema-example")) {
				t.Fatalf("Vacuum accepted invalid %s instance: %v\n%s", fixture.Schema, err, output)
			}
		})
	}
}

func TestVacuumAdmissionSchemaInstanceMatrix(t *testing.T) {
	vacuumPath := os.Getenv("VEER_TEST_VACUUM_BIN")
	if vacuumPath == "" {
		t.Skip("schema-instance matrix runs through ./hack/dev api")
	}
	expectedVacuumPath, err := filepath.Abs(filepath.Join("..", "..", ".tools", "bin", "vacuum"))
	if err != nil {
		t.Fatalf("resolve repository Vacuum path: %v", err)
	}
	if filepath.Clean(vacuumPath) != expectedVacuumPath {
		t.Fatalf("Vacuum path = %q, want repository-pinned %q", vacuumPath, expectedVacuumPath)
	}
	info, err := os.Lstat(vacuumPath)
	if err != nil {
		t.Fatalf("inspect repository Vacuum: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("Vacuum must be a regular non-symlink executable: mode %s", info.Mode())
	}
	baseline, err := Load("veer-v1alpha1.json")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	configPath, err := filepath.Abs("vacuum.conf.yaml")
	if err != nil {
		t.Fatalf("resolve Vacuum config: %v", err)
	}

	var fixtures admissionSchemaFixtureSet
	decodeStrictFixture(t, "testdata/admission-schema-instances.json", &fixtures)
	for _, fixture := range fixtures.Compatibility {
		fixture := fixture
		t.Run("compatibility/"+fixture.Name, func(t *testing.T) {
			assertVacuumAcceptsInstance(t, vacuumPath, configPath, baseline, fixture.Schema, fixture.Instance)
		})
	}
	for _, fixture := range fixtures.Defaulting {
		fixture := fixture
		t.Run("defaulting/"+fixture.Name, func(t *testing.T) {
			assertVacuumAcceptsInstance(t, vacuumPath, configPath, baseline, fixture.Schema, fixture.Instance)
			assertVacuumAcceptsInstance(t, vacuumPath, configPath, baseline, "WorkspaceSpec", fixture.Canonical)
		})
	}
	for _, fixture := range fixtures.Negative {
		fixture := fixture
		t.Run("negative/"+fixture.Name, func(t *testing.T) {
			output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, fixture.Schema, fixture.Instance)
			if err == nil || !bytes.Contains(output, []byte("oas3-valid-schema-example")) {
				t.Fatalf("Vacuum accepted invalid %s instance: %v\n%s", fixture.Schema, err, output)
			}
		})
	}
}

func assertVacuumAcceptsInstance(
	t *testing.T,
	vacuumPath, configPath string,
	baseline []byte,
	schema string,
	instance map[string]any,
) {
	t.Helper()
	output, err := runVacuumInstance(t, vacuumPath, configPath, baseline, schema, instance)
	if bytes.Contains(output, []byte("oas3-valid-schema-example")) ||
		(err != nil && !bytes.Contains(output, []byte("oas3-missing-example"))) {
		t.Fatalf("Vacuum rejected valid %s instance: %v\n%s", schema, err, output)
	}
}

func runVacuumInstance(
	t *testing.T,
	vacuumPath, configPath string,
	baseline []byte,
	schemaName string,
	instance map[string]any,
) ([]byte, error) {
	t.Helper()
	root := decodeForMutation(t, baseline)
	nestedMap(t, root, "components", "schemas", schemaName)["example"] = instance
	mutated, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("json.Marshal(%s fixture) error = %v", schemaName, err)
	}
	contractPath := filepath.Join(t.TempDir(), "schema-instance.json")
	if err := os.WriteFile(contractPath, mutated, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return runVacuumSchemaExamples(t, vacuumPath, configPath, contractPath)
}

func TestAdmissionContractRejectsSemanticDrift(t *testing.T) {
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
			name: "manifest removed",
			mutate: func(root map[string]any) {
				delete(root, "x-veer-admission")
			},
			message: "x-veer-admission is missing",
		},
		{
			name: "manifest moved below info",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "info")["x-veer-admission"] = root["x-veer-admission"]
				delete(root, "x-veer-admission")
			},
			message: `uses unreviewed extension "x-veer-admission"`,
		},
		{
			name: "unknown manifest field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission")["unreviewed"] = true
			},
			message: "x-veer-admission field set drifted",
		},
		{
			name: "stage removed",
			mutate: func(root map[string]any) {
				manifest := nestedMap(t, root, "x-veer-admission")
				manifest["stages"] = manifest["stages"].([]any)[:5]
			},
			message: "must contain exactly six entries",
		},
		{
			name: "stage order changed",
			mutate: func(root map[string]any) {
				stages := nestedMap(t, root, "x-veer-admission")["stages"].([]any)
				stages[1], stages[2] = stages[2], stages[1]
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "stage renamed",
			mutate: func(root map[string]any) {
				admissionStageForMutation(t, root, 4)["name"] = "defaults"
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "code moved to another stage",
			mutate: func(root map[string]any) {
				schema := admissionStageForMutation(t, root, 0)
				semantic := admissionStageForMutation(t, root, 1)
				schemaCodes := schema["codes"].([]any)
				schema["codes"] = schemaCodes[:len(schemaCodes)-1]
				semantic["codes"] = append(semantic["codes"].([]any), "unsupported-kind")
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "code duplicated",
			mutate: func(root map[string]any) {
				stage := admissionStageForMutation(t, root, 3)
				stage["codes"] = append(stage["codes"].([]any), "parent-not-found")
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "client failure response remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, admissionStageForMutation(t, root, 2), "defaultResponse")["$ref"] =
					"#/components/responses/InternalFailure"
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "request too large response remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, admissionStageForMutation(t, root, 0), "responseOverrides", "request-too-large")["$ref"] =
					"#/components/responses/ValidationFailure"
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "internal failure response remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, admissionStageForMutation(t, root, 5), "defaultResponse")["$ref"] =
					"#/components/responses/ValidationFailure"
			},
			message: "stage order, codes, or response mapping drifted",
		},
		{
			name: "multiple terminal errors allowed",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "errorSelection")["maximum"] = json.Number("2")
			},
			message: "error selection policy drifted",
		},
		{
			name: "error precedence changed",
			mutate: func(root map[string]any) {
				selection := nestedMap(t, root, "x-veer-admission", "errorSelection")
				selection["precedence"] = []any{
					"lexicographic-code", "stage-order", "lexicographic-bounded-rfc6901-pointer-or-empty",
				}
			},
			message: "error selection policy drifted",
		},
		{
			name: "terminal work ceiling order changed",
			mutate: func(root map[string]any) {
				selection := nestedMap(t, root, "x-veer-admission", "errorSelection")
				selection["terminalWorkCeilings"] = []any{
					"request-too-large", "too-many-json-nodes", "json-too-deep",
				}
			},
			message: "error selection policy drifted",
		},
		{
			name: "terminal syntax error removed",
			mutate: func(root map[string]any) {
				selection := nestedMap(t, root, "x-veer-admission", "errorSelection")
				selection["terminalSyntaxErrors"] = []any{}
			},
			message: "error selection policy drifted",
		},
		{
			name: "field path becomes dot notation",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "fieldPath")["syntax"] = "dot-notation"
			},
			message: "field path policy drifted",
		},
		{
			name: "whole document gains sentinel path",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "fieldPath")["wholeDocument"] = "/"
			},
			message: "field path policy drifted",
		},
		{
			name: "field path truncation allowed",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "fieldPath")["truncation"] = "allowed"
			},
			message: "field path policy drifted",
		},
		{
			name: "unrepresentable path leaks partial field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "fieldPath")["unrepresentable"] = "truncate"
			},
			message: "field path policy drifted",
		},
		{
			name: "field violation schema remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "fieldPath", "fieldViolationSchema")["$ref"] =
					"#/components/schemas/Problem"
			},
			message: "field path policy drifted",
		},
		{
			name: "failure can mutate state",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "failureEffects")["stateMutation"] = "allowed"
			},
			message: "failure effects drifted",
		},
		{
			name: "failure can enqueue work",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "failureEffects")["queueMutation"] = "allowed"
			},
			message: "failure effects drifted",
		},
		{
			name: "failure can invoke callbacks",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "failureEffects")["callbackInvocation"] = "allowed"
			},
			message: "failure effects drifted",
		},
		{
			name: "default mutates input",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "defaulting")["mode"] = "in-place"
			},
			message: "defaulting policy drifted",
		},
		{
			name: "default becomes nondeterministic",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "defaulting")["deterministic"] = false
			},
			message: "defaulting policy drifted",
		},
		{
			name: "default becomes non-idempotent",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "defaulting")["idempotent"] = false
			},
			message: "defaulting policy drifted",
		},
		{
			name: "default pointer changed",
			mutate: func(root map[string]any) {
				admissionDefaultRuleForMutation(t, root)["requestPointer"] = "/spec/reconcile"
			},
			message: "defaulting policy drifted",
		},
		{
			name: "default value changed",
			mutate: func(root map[string]any) {
				admissionDefaultRuleForMutation(t, root)["value"] = true
			},
			message: "defaulting policy drifted",
		},
		{
			name: "write default schema remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, admissionDefaultRuleForMutation(t, root), "writeSpecSchema")["$ref"] =
					"#/components/schemas/WorkspaceSpec"
			},
			message: "defaulting policy drifted",
		},
		{
			name: "canonical default schema remapped",
			mutate: func(root map[string]any) {
				nestedMap(t, admissionDefaultRuleForMutation(t, root), "canonicalSpecSchema")["$ref"] =
					"#/components/schemas/WorkspaceSpecWrite"
			},
			message: "defaulting policy drifted",
		},
		{
			name: "hub exposed as transport version",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "versionHub")["hub"] = "v1alpha1"
			},
			message: "version hub policy drifted",
		},
		{
			name: "served version added without conversion",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "versionHub")["servedVersions"] =
					[]any{"v1alpha1", "v1beta1"}
			},
			message: "version hub policy drifted",
		},
		{
			name: "kind order changed",
			mutate: func(root map[string]any) {
				hub := nestedMap(t, root, "x-veer-admission", "versionHub")
				kinds := hub["kinds"].([]any)
				kinds[0], kinds[1] = kinds[1], kinds[0]
			},
			message: "version hub policy drifted",
		},
		{
			name: "round trip requires representation equality",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-admission", "versionHub")["roundTrip"] = "source-presence-equality"
			},
			message: "version hub policy drifted",
		},
		{
			name: "canonical spec becomes sparse",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "WorkspaceSpec"), "required")
			},
			message: "WorkspaceSpec contract drifted",
		},
		{
			name: "canonical spec regains default annotation",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "WorkspaceSpec", "properties", "suspendReconciliation")["default"] = false
			},
			message: "WorkspaceSpec.suspendReconciliation has unreviewed keywords",
		},
		{
			name: "write spec requires defaulted member",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "WorkspaceSpecWrite")["required"] =
					[]any{"suspendReconciliation"}
			},
			message: "WorkspaceSpecWrite contract drifted",
		},
		{
			name: "write spec loses default",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "WorkspaceSpecWrite", "properties", "suspendReconciliation"), "default")
			},
			message: "WorkspaceSpecWrite contract drifted",
		},
		{
			name: "create uses canonical spec",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "WorkspaceCreate", "properties", "spec")["$ref"] =
					"#/components/schemas/WorkspaceSpec"
			},
			message: "spec must reference #/components/schemas/WorkspaceSpecWrite",
		},
		{
			name: "replace uses canonical spec",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "WorkspaceReplace", "properties", "spec")["$ref"] =
					"#/components/schemas/WorkspaceSpec"
			},
			message: "spec must reference #/components/schemas/WorkspaceSpecWrite",
		},
		{
			name: "read uses sparse spec",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Workspace", "properties", "spec")["$ref"] =
					"#/components/schemas/WorkspaceSpecWrite"
			},
			message: "spec must reference #/components/schemas/WorkspaceSpec",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			err = Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want message containing %q", err, test.message)
			}
		})
	}
}

func TestAuthorizationContractRejectsSemanticDrift(t *testing.T) {
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
			name: "manifest removed",
			mutate: func(root map[string]any) {
				delete(root, "x-veer-authorization")
			},
			message: "x-veer-authorization is missing",
		},
		{
			name: "default deny relaxes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-authorization")["defaultEffect"] = "Allow"
			},
			message: "x-veer-authorization contract drifted",
		},
		{
			name: "list evaluation uses parent target",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-authorization")["listEvaluation"] = "parent-target"
			},
			message: "x-veer-authorization contract drifted",
		},
		{
			name: "viewer gains mutation",
			mutate: func(root map[string]any) {
				roles := nestedMap(t, root, "x-veer-authorization")["roles"].([]any)
				viewer := roles[0].(map[string]any)
				viewer["grants"] = append(viewer["grants"].([]any), map[string]any{
					"action": "resource.delete", "objectKind": "Resource", "resourceKinds": []any{"Workspace"},
				})
			},
			message: "x-veer-authorization contract drifted",
		},
		{
			name: "workspace bootstrap reservation disappears",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-authorization")["reservedResourceActions"] = []any{}
			},
			message: "x-veer-authorization contract drifted",
		},
		{
			name: "reserved worker action becomes tenant grant",
			mutate: func(root map[string]any) {
				manifest := nestedMap(t, root, "x-veer-authorization")
				reserved := manifest["reservedActions"].([]any)
				manifest["reservedActions"] = reserved[1:]
			},
			message: "x-veer-authorization contract drifted",
		},
		{
			name: "operation action annotation disappears",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "get"),
					"x-veer-authorization-action")
			},
			message: `operationId "listWorkspaces" authorization action must be "resource.list"`,
		},
		{
			name: "status operation becomes tenant resource write",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put")["x-veer-authorization-action"] = "resource.replace"
			},
			message: `operationId "replaceWorkspaceStatus" authorization action must be "resource.status.replace"`,
		},
		{
			name: "policy binding bound relaxes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "PolicySpec", "properties", "bindings")["maxItems"] =
					json.Number("129")
			},
			message: "PolicySpec.bindings list contract drifted",
		},
		{
			name: "workspace scope accepts environment identifier",
			mutate: func(root map[string]any) {
				branches := nestedMap(t, root, "components", "schemas", "PolicyScope")["oneOf"].([]any)
				delete(branches[0].(map[string]any), "not")
			},
			message: "PolicyScope Workspace refinement drifted",
		},
		{
			name: "policy example binding order drifts",
			mutate: func(root map[string]any) {
				spec := nestedMap(t, root, "components", "schemas", "Policy", "example", "spec")
				bindings := spec["bindings"].([]any)
				first := bindings[0].(map[string]any)
				spec["bindings"] = []any{
					map[string]any{
						"memberId": "mem_01J00000000000000000000001",
						"role":     first["role"],
						"scope":    first["scope"],
					},
					first,
				}
			},
			message: "outside canonical order",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			err = Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestAuditContractRejectsSemanticDrift(t *testing.T) {
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
			name: "manifest removed",
			mutate: func(root map[string]any) {
				delete(root, "x-veer-audit")
			},
			message: "x-veer-audit is missing",
		},
		{
			name: "canonical event ceiling changes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "limits")["maxCanonicalEventBytes"] = json.Number("16385")
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "tail completeness loses trusted checkpoint",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "integrity")["tailCompleteness"] = "hash-chain-only"
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "export no longer requires trusted terminal checkpoint",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "export")["trustedTerminalCheckpoint"] = false
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "online retention changes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "retention")["onlineDays"] = json.Number("91")
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "hold vocabulary reorders",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "retention")["holdKinds"] = []any{"Incident", "Legal", "Security"}
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "eligible actions reorder",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "privilegedAdministration")["eligibleActions"] =
					[]any{"operation.quarantine", "audit.export", "work.redrive"}
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "ledger claims durability",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "privilegedAdministration")["ledger"] = "durable-cross-node"
			},
			message: "x-veer-audit contract drifted",
		},
		{
			name: "strong authentication claims an adapter",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-audit", "privilegedAdministration")["strongAuthentication"] = "adapter-implemented"
			},
			message: "x-veer-audit contract drifted",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			err = Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func admissionStageForMutation(t *testing.T, root map[string]any, index int) map[string]any {
	t.Helper()
	stages := nestedMap(t, root, "x-veer-admission")["stages"].([]any)
	stage, ok := stages[index].(map[string]any)
	if !ok {
		t.Fatalf("admission stage %d is not an object", index)
	}
	return stage
}

func admissionDefaultRuleForMutation(t *testing.T, root map[string]any) map[string]any {
	t.Helper()
	rules := nestedMap(t, root, "x-veer-admission", "defaulting")["rules"].([]any)
	rule, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatal("admission default rule is not an object")
	}
	return rule
}

func TestHierarchyContractRejectsInvalidPolicyAndExamples(t *testing.T) {
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
			name: "unknown hierarchy field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy")["unreviewed"] = true
			},
			message: "unknown field",
		},
		{
			name: "display name becomes authorization key",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership")["workspaceIdPointer"] =
					"/metadata/displayName"
			},
			message: "workspace ownership policy drifted",
		},
		{
			name: "ownership becomes client writable",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership")["clientWritable"] = true
			},
			message: "workspace ownership policy drifted",
		},
		{
			name: "root ownership derivation drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership")["rootDerivation"] = "caller-value"
			},
			message: "workspace ownership policy drifted",
		},
		{
			name: "child ownership derivation drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership")["childDerivation"] = "request-value"
			},
			message: "workspace ownership policy drifted",
		},
		{
			name: "false ownership field omitted",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership"), "mutable")
			},
			message: "workspaceOwnership field set drifted",
		},
		{
			name: "ownership becomes mutable",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "workspaceOwnership")["mutable"] = true
			},
			message: "workspace ownership policy drifted",
		},
		{
			name: "parent pointer drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "parentReference")["pointer"] = "/metadata/displayName"
			},
			message: "parent reference policy drifted",
		},
		{
			name: "orphan reference accepted",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "referenceValidation")["orphan"] = "allow"
			},
			message: "hierarchy reference validation policy drifted",
		},
		{
			name: "cross-workspace reference accepted",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "referenceValidation")["crossWorkspace"] = "allow"
			},
			message: "hierarchy reference validation policy drifted",
		},
		{
			name: "cycle accepted",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "referenceValidation")["cycle"] = "allow"
			},
			message: "hierarchy reference validation policy drifted",
		},
		{
			name: "cascade deletion",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "deletion")["policy"] = "CASCADE"
			},
			message: "hierarchy deletion policy drifted",
		},
		{
			name: "deletion blocker drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-hierarchy", "deletion")["blockedBy"] = "any-descendant"
			},
			message: "hierarchy deletion policy drifted",
		},
		{
			name: "wrong parent kind",
			mutate: func(root map[string]any) {
				resources := nestedMap(t, root, "x-veer-hierarchy")["resources"].([]any)
				resources[4].(map[string]any)["parentKind"] = "Workspace"
			},
			message: "Application parent kind must be Environment",
		},
		{
			name: "wrong schema reference",
			mutate: func(root map[string]any) {
				resources := nestedMap(t, root, "x-veer-hierarchy")["resources"].([]any)
				nestedMap(t, resources[5].(map[string]any), "schema")["$ref"] = "#/components/schemas/Application"
			},
			message: "Component schema reference drifted",
		},
		{
			name: "wrong status write schema reference",
			mutate: func(root map[string]any) {
				resources := nestedMap(t, root, "x-veer-hierarchy")["resources"].([]any)
				nestedMap(t, resources[2].(map[string]any), "statusWriteSchema")["$ref"] =
					"#/components/schemas/WorkspaceStatusWrite"
			},
			message: "Environment status write schema reference drifted",
		},
		{
			name: "root gains parent",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Workspace", "example", "metadata")["parent"] =
					"wsp_01J99999999999999999999999"
			},
			message: "workspace canonical example drifted",
		},
		{
			name: "orphan example",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Application", "example", "metadata")["parent"] =
					"env_01J99999999999999999999999"
			},
			message: "Application example parent is orphaned or cyclic",
		},
		{
			name: "cross-workspace example",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Component", "example", "metadata")["workspaceId"] =
					"wsp_01J99999999999999999999999"
			},
			message: "Component example crosses workspace ownership",
		},
		{
			name: "cyclic example",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Environment", "example", "metadata")["parent"] =
					"cmp_01J00000000000000000000000"
			},
			message: "Environment example parent is orphaned or cyclic",
		},
		{
			name: "provider field enters empty spec",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "EnvironmentSpec", "properties")["provider"] =
					map[string]any{"type": "string"}
			},
			message: "EnvironmentSpec must remain a closed empty provider-neutral object",
		},
		{
			name: "schema removed",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas"), "ComponentList")
			},
			message: "expected exactly 81 schemas, got 80",
		},
		{
			name: "schema added",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas")["ProviderResource"] = map[string]any{
					"type": "object", "additionalProperties": false, "properties": map[string]any{},
				}
			},
			message: "expected exactly 81 schemas, got 82",
		},
		{
			name: "workspace ownership no longer required",
			mutate: func(root map[string]any) {
				metadata := nestedMap(t, root, "components", "schemas", "ResourceMetadata")
				metadata["required"] = []any{"id", "displayName", "generation", "resourceVersion", "createdAt", "updatedAt"}
			},
			message: "ResourceMetadata shape drifted",
		},
		{
			name: "workspace ownership becomes writable in read schema",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "workspaceId")["readOnly"] = false
			},
			message: "ResourceMetadata.workspaceId must be readOnly",
		},
		{
			name: "root metadata allows parent",
			mutate: func(root map[string]any) {
				rootMetadata := nestedMap(t, root, "components", "schemas", "RootResourceMetadata")
				allOf := rootMetadata["allOf"].([]any)
				nestedMap(t, allOf[1].(map[string]any), "not")["required"] = []any{"workspaceId"}
			},
			message: "permits unconstrained additional properties",
		},
		{
			name: "child metadata makes parent optional",
			mutate: func(root map[string]any) {
				childMetadata := nestedMap(t, root, "components", "schemas", "ChildResourceMetadata")
				allOf := childMetadata["allOf"].([]any)
				allOf[1].(map[string]any)["required"] = []any{"workspaceId"}
			},
			message: "ChildResourceMetadata must require parent",
		},
		{
			name: "environment uses root metadata",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Environment", "properties", "metadata")["$ref"] =
					"#/components/schemas/RootResourceMetadata"
			},
			message: "metadata must reference #/components/schemas/ChildResourceMetadata",
		},
		{
			name: "application kind drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Application", "properties", "kind")["const"] = "Workspace"
			},
			message: "Application identity contract drifted",
		},
		{
			name: "component status conditions become unbounded",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "ComponentStatus", "properties", "conditions"), "maxItems")
			},
			message: "ComponentStatus conditions contract drifted",
		},
		{
			name: "application status example drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "ApplicationStatus", "example")["observedGeneration"] =
					json.Number("1")
			},
			message: "ApplicationStatus canonical example drifted",
		},
		{
			name: "environment list grows beyond page bound",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "EnvironmentList", "properties", "items")["maxItems"] =
					json.Number("101")
			},
			message: "EnvironmentList item bound drifted",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			err = Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestControlContractRejectsSemanticDrift(t *testing.T) {
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
			name: "operation transition manifest gains field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-operation-transitions")["retry"] = true
			},
			message: "operation transition manifest field set drifted",
		},
		{
			name: "operation transition edge disappears",
			mutate: func(root map[string]any) {
				transitions := nestedMap(t, root, "x-veer-operation-transitions", "transitions")
				transitions["Pending"] = []any{"Waiting", "Running", "Failed", "Canceled"}
			},
			message: "operation transition graph drifted",
		},
		{
			name: "terminal replay relaxes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-operation-transitions")["terminalReplay"] = "phase-only"
			},
			message: "operation terminal transition policy drifted",
		},
		{
			name: "unknown phase behavior authorizes side effects",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-operation-transitions")["unknownPhase"] = "execute"
			},
			message: "operation terminal transition policy drifted",
		},
		{
			name: "condition transition pointer drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-condition-transitions")["transitionTimePointer"] = "/updatedAt"
			},
			message: "condition transition policy drifted",
		},
		{
			name: "condition set ordering relaxes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "x-veer-condition-transitions")["setOrder"] = "caller-order"
			},
			message: "condition transition policy drifted",
		},
		{
			name: "condition schema changes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Condition")["description"] = "Changed"
			},
			message: "condition schema changed outside the accepted transition-manifest boundary",
		},
		{
			name: "policy spec gains field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "PolicySpec", "properties")["provider"] =
					map[string]any{"type": "string"}
			},
			message: "PolicySpec shape drifted",
		},
		{
			name: "provider spec accepts raw field",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "ProviderConnectionSpec", "properties")["accessKey"] =
					map[string]any{"type": "string"}
			},
			message: "providerConnectionSpec shape drifted",
		},
		{
			name: "credential reference accepts secret",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "CredentialReference", "properties")["secret"] =
					map[string]any{"type": "string"}
			},
			message: "credentialReference shape drifted",
		},
		{
			name: "capability unknown state disappears",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "ProviderCapability", "properties", "state")["enum"] =
					[]any{"Supported", "Unsupported"}
			},
			message: "ProviderCapability.state contract drifted",
		},
		{
			name: "observation list loses bound",
			mutate: func(root map[string]any) {
				delete(nestedMap(t, root, "components", "schemas", "ProviderConnectionStatus", "properties", "capabilities"), "maxItems")
			},
			message: "providerConnectionStatus.capabilities list contract drifted",
		},
		{
			name: "observation ordering relaxes",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "ProviderConnectionStatus", "properties", "quotaChecks")["x-veer-list-order"] = "none"
			},
			message: "providerConnectionStatus.quotaChecks list contract drifted",
		},
		{
			name: "quota comparator drifts",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "QuotaCheck", "x-veer-quota-comparison")["Exceeded"] =
					"requested>=available"
			},
			message: "quotaCheck comparison manifest drifted",
		},
		{
			name: "unknown quota admits operand",
			mutate: func(root map[string]any) {
				branches := nestedMap(t, root, "components", "schemas", "QuotaCheck")["oneOf"].([]any)
				delete(branches[1].(map[string]any), "not")
			},
			message: "quotaCheck unknown-state refinement drifted",
		},
		{
			name: "unknown cost admits amount",
			mutate: func(root map[string]any) {
				branches := nestedMap(t, root, "components", "schemas", "CostEstimate")["oneOf"].([]any)
				delete(branches[1].(map[string]any), "not")
			},
			message: "costEstimate unknown-state refinement drifted",
		},
		{
			name: "operation workspace binding becomes optional",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "components", "schemas", "Operation")
				operation["required"] = []any{"id", "resourceId", "generation", "resourceVersion", "phase", "createdAt", "updatedAt"}
			},
			message: "operation shape drifted",
		},
		{
			name: "operation provider binding becomes partial",
			mutate: func(root map[string]any) {
				branches := nestedMap(t, root, "components", "schemas", "Operation")["oneOf"].([]any)
				branches[0].(map[string]any)["required"] = []any{"providerConnectionId"}
			},
			message: "operation provider-bound refinement drifted",
		},
		{
			name: "operation byte bound grows",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas", "Operation")["x-veer-maximum-json-bytes"] = json.Number("8192")
			},
			message: "operation shape drifted",
		},
		{
			name: "operation response example drifts",
			mutate: func(root map[string]any) {
				nestedMap(
					t, root, "components", "responses", "Operation", "content", "application/json", "example",
				)["phase"] = "Succeeded"
			},
			message: "operation schema and response examples drifted",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := decodeForMutation(t, baseline)
			test.mutate(root)
			mutated, err := json.Marshal(root)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			err = Validate(mutated)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
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
				post := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post")
				delete(post, "x-veer-response-generation-constant")
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
			name: "route success response reference gains sibling",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get", "responses", "200")
				response["summary"] = "Unreviewed reference annotation"
			},
			message: "200 reference has unreviewed keywords",
		},
		{
			name: "creation response generation constant removed",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post")
				delete(operation, "x-veer-response-generation-constant")
			},
			message: `operationId "createWorkspace" response generation constant drifted`,
		},
		{
			name: "creation response generation constant changes",
			mutate: func(root map[string]any) {
				contract := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces", "post", "x-veer-response-generation-constant")
				contract["value"] = json.Number("2")
			},
			message: `operationId "createWorkspace" response generation constant drifted`,
		},
		{
			name: "workspace point read identity binding removed",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "get")
				delete(operation, "x-veer-path-response-id-binding")
			},
			message: `operationId "getWorkspace" path-response identity binding drifted`,
		},
		{
			name: "operation point read identity pointer drifts",
			mutate: func(root map[string]any) {
				binding := nestedMap(t, root, "paths", "/api/v1alpha1/operations/{operationId}", "get", "x-veer-path-response-id-binding")
				binding["bodyPointer"] = "/resourceId"
			},
			message: `operationId "getOperation" path-response identity binding drifted`,
		},
		{
			name: "delete response identity binding removed",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "delete")
				delete(operation, "x-veer-path-response-id-binding")
			},
			message: `operationId "deleteWorkspace" path-response identity binding drifted`,
		},
		{
			name: "status response identity pointer drifts",
			mutate: func(root map[string]any) {
				binding := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "x-veer-path-response-id-binding")
				binding["bodyPointer"] = "/operationId"
			},
			message: `operationId "replaceWorkspaceStatus" path-response identity binding drifted`,
		},
		{
			name: "replacement response identity parameter drifts",
			mutate: func(root map[string]any) {
				binding := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}", "put", "x-veer-path-response-id-binding")
				binding["pathParameter"] = "operationId"
			},
			message: `operationId "replaceWorkspace" path-response identity binding drifted`,
		},
		{
			name: "status request-response generation binding removed",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put")
				delete(operation, "x-veer-request-response-body-binding")
			},
			message: `operationId "replaceWorkspaceStatus" request-response generation binding drifted`,
		},
		{
			name: "status response generation pointer drifts",
			mutate: func(root map[string]any) {
				binding := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "x-veer-request-response-body-binding")
				binding["responseBodyPointer"] = "/generation"
			},
			message: `operationId "replaceWorkspaceStatus" request-response generation binding drifted`,
		},
		{
			name: "status observed-generation upper bound removed",
			mutate: func(root map[string]any) {
				operation := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put")
				delete(operation, "x-veer-observed-generation-upper-bound")
			},
			message: `operationId "replaceWorkspaceStatus" observed-generation upper bound drifted`,
		},
		{
			name: "status current resource generation pointer drifts",
			mutate: func(root map[string]any) {
				upperBound := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "x-veer-observed-generation-upper-bound")
				upperBound["resourceGenerationPointer"] = "/status/observedGeneration"
			},
			message: `operationId "replaceWorkspaceStatus" observed-generation upper bound drifted`,
		},
		{
			name: "status condition generation pointer template drifts",
			mutate: func(root map[string]any) {
				upperBound := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces/{workspaceId}/status", "put", "x-veer-observed-generation-upper-bound")
				upperBound["conditionObservedGenerationPointerTemplate"] = "/status/conditions/0/observedGeneration"
			},
			message: `operationId "replaceWorkspaceStatus" observed-generation upper bound drifted`,
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
			name: "path parameter reference gains sibling",
			mutate: func(root map[string]any) {
				item := nestedMap(t, root, "paths", "/api/v1alpha1/workspaces")
				parameters := item["parameters"].([]any)
				parameters[0].(map[string]any)["description"] = "Unreviewed reference annotation"
			},
			message: "parameter reference has unreviewed keywords",
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
			name: "request body reference gains assertion sibling",
			mutate: func(root map[string]any) {
				schema := nestedMap(
					t,
					root,
					"paths",
					"/api/v1alpha1/workspaces",
					"post",
					"requestBody",
					"content",
					"application/json",
					"schema",
				)
				schema["not"] = map[string]any{}
			},
			message: "schema reference has unreviewed keywords",
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
			name: "generation omits lifecycle and deletion writes",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "x-veer-evolution", "generation")
				generation["unchanged"] = []any{"metadata-only-write", "status-only-write", "idempotent-replay"}
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
			name: "page size format removed",
			mutate: func(root map[string]any) {
				pageSize := nestedMap(t, root, "components", "parameters", "PageSize", "schema")
				delete(pageSize, "format")
			},
			message: "PageSize parameter contract drifted",
		},
		{
			name: "page size gains narrowing const",
			mutate: func(root map[string]any) {
				pageSize := nestedMap(t, root, "components", "parameters", "PageSize", "schema")
				pageSize["const"] = json.Number("50")
			},
			message: "PageSize schema has unreviewed keywords",
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
			name: "page token gains narrowing const",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "parameters", "PageToken", "schema")
				schema["const"] = "opaque-token"
			},
			message: "PageToken schema has unreviewed keywords",
		},
		{
			name: "page token enables empty values",
			mutate: func(root map[string]any) {
				parameter := nestedMap(t, root, "components", "parameters", "PageToken")
				parameter["allowEmptyValue"] = true
			},
			message: "PageToken parameter has unreviewed keywords",
		},
		{
			name: "idempotency parameter marked deprecated",
			mutate: func(root map[string]any) {
				parameter := nestedMap(t, root, "components", "parameters", "IdempotencyKey")
				parameter["deprecated"] = true
			},
			message: "IdempotencyKey parameter has unreviewed keywords",
		},
		{
			name: "request ID reference gains narrowing sibling",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "parameters", "VeerRequestId", "schema")
				schema["const"] = "fixed-request-id"
			},
			message: "schema has unreviewed keywords",
		},
		{
			name: "operation ID wire name drifts",
			mutate: func(root map[string]any) {
				parameter := nestedMap(t, root, "components", "parameters", "OperationId")
				parameter["name"] = "workspaceId"
			},
			message: "OperationId path parameter contract drifted",
		},
		{
			name: "operation ID path serialization drifts",
			mutate: func(root map[string]any) {
				parameter := nestedMap(t, root, "components", "parameters", "OperationId")
				parameter["style"] = "matrix"
				parameter["explode"] = true
			},
			message: "OperationId path parameter contract drifted",
		},
		{
			name: "success response reference gains const sibling",
			mutate: func(root map[string]any) {
				schema := nestedMap(
					t,
					root,
					"components",
					"responses",
					"Workspace",
					"content",
					"application/json",
					"schema",
				)
				schema["const"] = map[string]any{}
			},
			message: "schema reference has unreviewed keywords",
		},
		{
			name: "error response reference gains enum sibling",
			mutate: func(root map[string]any) {
				schema := nestedMap(
					t,
					root,
					"components",
					"responses",
					"ValidationFailure",
					"content",
					"application/problem+json",
					"schema",
				)
				schema["enum"] = []any{}
			},
			message: "schema reference has unreviewed keywords",
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
			name: "response deprecation notice binding shortened",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Workspace")
				response["x-veer-deprecation-sunset-minimum-notice-days"] = json.Number("30")
			},
			message: "success response Workspace deprecation notice binding drifted",
		},
		{
			name: "sunset example violates deprecation notice window",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Deprecation", "schema")
				schema["example"] = "@1780520401"
			},
			message: "deprecation/sunset example notice window drifted",
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
			name: "response request ID request binding removed",
			mutate: func(root map[string]any) {
				header := nestedMap(t, root, "components", "headers", "VeerRequestId")
				delete(header, "x-veer-request-id-binding")
			},
			message: "VeerRequestId header request binding drifted",
		},
		{
			name: "ETag response header marked deprecated",
			mutate: func(root map[string]any) {
				header := nestedMap(t, root, "components", "headers", "ETag")
				header["deprecated"] = true
			},
			message: "ETag header has unreviewed keywords",
		},
		{
			name: "request ID response header marked deprecated",
			mutate: func(root map[string]any) {
				header := nestedMap(t, root, "components", "headers", "VeerRequestId")
				header["deprecated"] = true
			},
			message: "VeerRequestId header has unreviewed keywords",
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
			name: "retry after header gains narrowing enum",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "RetryAfter", "schema")
				schema["enum"] = []any{"1"}
			},
			message: "RetryAfter header schema has unreviewed keywords",
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
			name: "operation Location header gains narrowing const",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "Location", "schema")
				schema["const"] = "/api/v1alpha1/operations/op_01J000000000000000000000000"
			},
			message: "Location header schema has unreviewed keywords",
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
			name: "deprecation link with invalid URI-reference",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "headers", "DeprecationLink", "schema")
				schema["example"] = `<not a URI>; rel="deprecation"`
			},
			message: "DeprecationLink header URI-reference contract drifted",
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
			name: "throttling example omits retry delay",
			mutate: func(root map[string]any) {
				value := nestedMap(t, root, "components", "examples", "Throttled", "value")
				delete(value, "retryAfterSeconds")
			},
			message: "example Throttled retryAfterSeconds drifted",
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
			name: "opaque ID gains additive narrowing assertion",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "OpaqueId")
				schema["const"] = "wsp_01J00000000000000000000000"
			},
			message: "OpaqueId schema has unreviewed keywords",
		},
		{
			name: "opaque ID gains enum narrowing assertion",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "OpaqueId")
				schema["enum"] = []any{"wsp_01J00000000000000000000000"}
			},
			message: "OpaqueId schema has unreviewed keywords",
		},
		{
			name: "opaque ID gains negated assertion",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "OpaqueId")
				schema["not"] = map[string]any{"pattern": "^reserved"}
			},
			message: "OpaqueId schema has unreviewed keywords",
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
			name: "workspace schema fixture gains undeclared spec field",
			mutate: func(root map[string]any) {
				spec := nestedMap(t, root, "components", "schemas", "Workspace", "example", "spec")
				spec["region"] = "us-east-1"
			},
			message: "workspace canonical example drifted",
		},
		{
			name: "workspace observed-generation upper bound removed",
			mutate: func(root map[string]any) {
				workspace := nestedMap(t, root, "components", "schemas", "Workspace")
				delete(workspace, "x-veer-observed-generation-upper-bound")
			},
			message: "workspace observed-generation upper bound drifted",
		},
		{
			name: "workspace observed-generation pointer drifts",
			mutate: func(root map[string]any) {
				upperBound := nestedMap(t, root, "components", "schemas", "Workspace", "x-veer-observed-generation-upper-bound")
				upperBound["observedGenerationPointer"] = "/metadata/generation"
			},
			message: "workspace observed-generation upper bound drifted",
		},
		{
			name: "workspace spec gains top level narrowing assertion",
			mutate: func(root map[string]any) {
				spec := nestedMap(t, root, "components", "schemas", "WorkspaceSpec")
				spec["not"] = map[string]any{}
			},
			message: "WorkspaceSpec schema has unreviewed keywords",
		},
		{
			name: "workspace spec field gains narrowing assertion",
			mutate: func(root map[string]any) {
				suspend := nestedMap(t, root, "components", "schemas", "WorkspaceSpec", "properties", "suspendReconciliation")
				suspend["const"] = false
			},
			message: "WorkspaceSpec.suspendReconciliation has unreviewed keywords",
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
			name: "resource metadata parent is removed",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties")
				delete(properties, "parent")
			},
			message: "ResourceMetadata shape drifted",
		},
		{
			name: "resource metadata parent becomes required",
			mutate: func(root map[string]any) {
				metadata := nestedMap(t, root, "components", "schemas", "ResourceMetadata")
				metadata["required"] = append(metadata["required"].([]any), "parent")
			},
			message: "ResourceMetadata shape drifted",
		},
		{
			name: "resource metadata parent becomes writable",
			mutate: func(root map[string]any) {
				parent := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "parent")
				delete(parent, "readOnly")
			},
			message: "ResourceMetadata.parent must be readOnly",
		},
		{
			name: "resource metadata parent reference drifts",
			mutate: func(root map[string]any) {
				parent := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "parent")
				parent["$ref"] = "#/components/schemas/RequestId"
			},
			message: "parent must reference #/components/schemas/OpaqueId",
		},
		{
			name: "resource metadata parent gains narrowing assertion",
			mutate: func(root map[string]any) {
				parent := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "parent")
				parent["const"] = "wsp_01J00000000000000000000000"
			},
			message: "parent reference has unreviewed keywords",
		},
		{
			name: "writable metadata exposes parent",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "WritableMetadata", "properties")
				properties["parent"] = map[string]any{"$ref": "#/components/schemas/OpaqueId"}
			},
			message: "WritableMetadata exposes server-owned field parent",
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
			name: "condition message gains narrowing const",
			mutate: func(root map[string]any) {
				message := nestedMap(t, root, "components", "schemas", "Condition", "properties", "message")
				message["const"] = "Only this message"
			},
			message: "condition schema changed outside the accepted transition-manifest boundary",
		},
		{
			name: "workspace status conditions gains minimum",
			mutate: func(root map[string]any) {
				conditions := nestedMap(t, root, "components", "schemas", "WorkspaceStatus", "properties", "conditions")
				conditions["minItems"] = json.Number("1")
			},
			message: "WorkspaceStatus.conditions schema has unreviewed keywords",
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
			name: "resource generation gains narrowing const",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "generation")
				generation["const"] = json.Number("1")
			},
			message: "ResourceMetadata.generation has unreviewed keywords",
		},
		{
			name: "mutation receipt generation gains narrowing enum",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "MutationReceipt", "properties", "generation")
				generation["enum"] = []any{json.Number("1")}
			},
			message: "MutationReceipt.generation has unreviewed keywords",
		},
		{
			name: "status observed generation gains narrowing not",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "WorkspaceStatus", "properties", "observedGeneration")
				generation["not"] = map[string]any{"const": json.Number("0")}
			},
			message: "WorkspaceStatus.observedGeneration has unreviewed keywords",
		},
		{
			name: "status receipt observed generation gains narrowing const",
			mutate: func(root map[string]any) {
				generation := nestedMap(t, root, "components", "schemas", "StatusReceipt", "properties", "observedGeneration")
				generation["const"] = json.Number("0")
			},
			message: "StatusReceipt observedGeneration has unreviewed keywords",
		},
		{
			name: "resource version gains narrowing enum",
			mutate: func(root map[string]any) {
				version := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "resourceVersion")
				version["enum"] = []any{"rv_fixed"}
			},
			message: "ResourceMetadata resourceVersion has unreviewed keywords",
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
			name: "annotated property reference gains assertion sibling",
			mutate: func(root map[string]any) {
				id := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "id")
				id["not"] = map[string]any{}
			},
			message: "id reference has unreviewed keywords",
		},
		{
			name: "annotated property reference type drifts",
			mutate: func(root map[string]any) {
				id := nestedMap(t, root, "components", "schemas", "ResourceMetadata", "properties", "id")
				id["type"] = "integer"
			},
			message: "id reference type drifted",
		},
		{
			name: "pure property reference gains dynamic sibling",
			mutate: func(root map[string]any) {
				spec := nestedMap(t, root, "components", "schemas", "WorkspaceCreate", "properties", "spec")
				spec["$dynamicRef"] = "#/components/schemas/WorkspaceSpec"
			},
			message: "spec reference has unreviewed keywords",
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
			name: "next page token gains narrowing enum",
			mutate: func(root map[string]any) {
				token := nestedMap(t, root, "components", "schemas", "WorkspaceList", "properties", "nextPageToken")
				token["enum"] = []any{"opaque-token"}
			},
			message: "WorkspaceList nextPageToken has unreviewed keywords",
		},
		{
			name: "workspace list items gains minimum",
			mutate: func(root map[string]any) {
				items := nestedMap(t, root, "components", "schemas", "WorkspaceList", "properties", "items")
				items["minItems"] = json.Number("1")
			},
			message: "WorkspaceList.items schema has unreviewed keywords",
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
			name: "operation phase gains narrowing const",
			mutate: func(root map[string]any) {
				phase := nestedMap(t, root, "components", "schemas", "Operation", "properties", "phase")
				phase["const"] = "Pending"
			},
			message: "Operation.phase schema has unreviewed keywords",
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
			name: "problem detail gains narrowing const",
			mutate: func(root map[string]any) {
				detail := nestedMap(t, root, "components", "schemas", "Problem", "properties", "detail")
				detail["const"] = "Only this detail"
			},
			message: "Problem.detail schema has unreviewed keywords",
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
			name: "field pointer encoded byte ceiling removed",
			mutate: func(root map[string]any) {
				field := nestedMap(t, root, "components", "schemas", "FieldViolation", "properties", "field")
				delete(field, "x-veer-maximum-encoded-json-bytes")
			},
			message: "FieldViolation primitive contract drifted",
		},
		{
			name: "field pointer grammar excludes unknown member names",
			mutate: func(root map[string]any) {
				field := nestedMap(t, root, "components", "schemas", "FieldViolation", "properties", "field")
				field["pattern"] = "^(/([A-Za-z0-9._:-]|~0|~1)*)+$"
			},
			message: "FieldViolation primitive contract drifted",
		},
		{
			name: "field violation code gains narrowing enum",
			mutate: func(root map[string]any) {
				code := nestedMap(t, root, "components", "schemas", "FieldViolation", "properties", "code")
				code["enum"] = []any{"invalid"}
			},
			message: "FieldViolation.code schema has unreviewed keywords",
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
			name: "problem retry bound removed",
			mutate: func(root map[string]any) {
				retry := nestedMap(t, root, "components", "schemas", "Problem", "properties", "retryAfterSeconds")
				delete(retry, "maximum")
			},
			message: "problem.retryAfterSeconds contract drifted",
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
			name: "timestamp gains narrowing const",
			mutate: func(root map[string]any) {
				timestamp := nestedMap(t, root, "components", "schemas", "Timestamp")
				timestamp["const"] = "2026-09-01T21:00:00.000Z"
			},
			message: "timestamp schema has unreviewed keywords",
		},
		{
			name: "timestamp gains narrowing enum",
			mutate: func(root map[string]any) {
				timestamp := nestedMap(t, root, "components", "schemas", "Timestamp")
				timestamp["enum"] = []any{"2026-09-01T21:00:00.000Z"}
			},
			message: "timestamp schema has unreviewed keywords",
		},
		{
			name: "timestamp gains narrowing not",
			mutate: func(root map[string]any) {
				timestamp := nestedMap(t, root, "components", "schemas", "Timestamp")
				timestamp["not"] = map[string]any{"const": "2026-09-01T21:00:00.000Z"}
			},
			message: "timestamp schema has unreviewed keywords",
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
			name: "problem gains optional declared member",
			mutate: func(root map[string]any) {
				properties := nestedMap(t, root, "components", "schemas", "Problem", "properties")
				properties["debugInfo"] = map[string]any{"type": "string"}
			},
			message: "problem property set drifted",
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
			message: "is not the reviewed free-form Labels map",
		},
		{
			name: "request schema opts into free-form fields",
			mutate: func(root map[string]any) {
				create := nestedMap(t, root, "components", "schemas", "WorkspaceCreate")
				create["x-veer-free-form-map"] = true
				create["additionalProperties"] = map[string]any{"type": "string", "maxLength": json.Number("64")}
			},
			message: "is not the reviewed free-form Labels map",
		},
		{
			name: "closed request schema gains pattern properties",
			mutate: func(root map[string]any) {
				create := nestedMap(t, root, "components", "schemas", "WorkspaceCreate")
				create["patternProperties"] = map[string]any{".*": map[string]any{}}
			},
			message: "uses unreviewed patternProperties",
		},
		{
			name: "generator extensions are rejected",
			mutate: func(root map[string]any) {
				spec := nestedMap(t, root, "components", "schemas", "WorkspaceSpec")
				spec["x-go-type"] = "marker.Type"
				spec["x-go-type-import"] = map[string]any{
					"name": "marker\nbenign",
					"path": "example.invalid/marker",
				}
			},
			message: "uses unreviewed extension",
		},
		{
			name: "problem composition reference gains sibling",
			mutate: func(root map[string]any) {
				variant := nestedMap(t, root, "components", "schemas", "ValidationProblem")
				allOf := variant["allOf"].([]any)
				allOf[0].(map[string]any)["not"] = map[string]any{}
			},
			message: "ValidationProblem does not refine Problem",
		},
		{
			name: "unknown Veer extension is rejected",
			mutate: func(root map[string]any) {
				root["x-veer-unknown"] = true
			},
			message: `uses unreviewed extension "x-veer-unknown"`,
		},
		{
			name: "reviewed extension at unreviewed location is rejected",
			mutate: func(root map[string]any) {
				root["x-veer-write-class"] = "delete"
			},
			message: `uses unreviewed extension "x-veer-write-class"`,
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
			name: "labels key schema gains narrowing const",
			mutate: func(root map[string]any) {
				propertyNames := nestedMap(t, root, "components", "schemas", "Labels", "propertyNames")
				propertyNames["const"] = "team"
			},
			message: "labels propertyNames schema has unreviewed keywords",
		},
		{
			name: "labels value schema gains narrowing const",
			mutate: func(root map[string]any) {
				values := nestedMap(t, root, "components", "schemas", "Labels", "additionalProperties")
				values["const"] = "platform"
			},
			message: "labels value schema has unreviewed keywords",
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
			name: "conflict response title schema mismatched",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "IdempotencyConflictProblem")
				allOf := schema["allOf"].([]any)
				refinement := allOf[1].(map[string]any)
				title := nestedMap(t, refinement, "properties", "title")
				title["const"] = "Internal failure"
			},
			message: "IdempotencyConflictProblem constants drifted for response Conflict",
		},
		{
			name: "problem refinement constant gains annotation",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "IdempotencyConflictProblem")
				allOf := schema["allOf"].([]any)
				refinement := allOf[1].(map[string]any)
				code := nestedMap(t, refinement, "properties", "code")
				code["description"] = "Unreviewed refinement annotation"
			},
			message: "IdempotencyConflictProblem.code refinement has unreviewed keywords",
		},
		{
			name: "problem refinement reports first field deterministically",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "IdempotencyConflictProblem")
				allOf := schema["allOf"].([]any)
				refinement := allOf[1].(map[string]any)
				typeProperty := nestedMap(t, refinement, "properties", "type")
				code := nestedMap(t, refinement, "properties", "code")
				typeProperty["description"] = "Unreviewed type annotation"
				code["description"] = "Unreviewed code annotation"
			},
			message: "IdempotencyConflictProblem.type refinement has unreviewed keywords",
		},
		{
			name: "throttled response makes retry delay optional",
			mutate: func(root map[string]any) {
				schema := nestedMap(t, root, "components", "schemas", "ThrottledProblem")
				allOf := schema["allOf"].([]any)
				refinement := allOf[1].(map[string]any)
				delete(refinement, "required")
			},
			message: "ThrottledProblem does not refine Problem",
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
			name: "accepted mutation creation example generation drifts",
			mutate: func(root map[string]any) {
				example := nestedMap(t, root, "components", "responses", "MutationAccepted", "content", "application/json", "example")
				example["generation"] = json.Number("3")
			},
			message: "success response MutationAccepted generation example drifted",
		},
		{
			name: "error request ID body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Conflict")
				delete(response, "x-veer-request-id-body-pointer")
			},
			message: "error response Conflict request-ID body binding drifted",
		},
		{
			name: "retry header body binding removed",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Throttled")
				delete(response, "x-veer-retry-after-body-pointer")
			},
			message: "error response Throttled Retry-After body binding drifted",
		},
		{
			name: "success response declares retry body binding",
			mutate: func(root map[string]any) {
				response := nestedMap(t, root, "components", "responses", "Workspace")
				response["x-veer-retry-after-body-pointer"] = "/retryAfterSeconds"
			},
			message: `uses unreviewed extension "x-veer-retry-after-body-pointer"`,
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

func TestFieldPointerValues(t *testing.T) {
	t.Parallel()
	pointer := regexp.MustCompile(fieldPointerPattern)
	tests := []struct {
		value string
		valid bool
	}{
		{value: "/bad key", valid: true},
		{value: "/☃", valid: true},
		{value: "/a~1b", valid: true},
		{value: "/~0", valid: true},
		{value: "/", valid: true},
		{value: "", valid: false},
		{value: "bad", valid: false},
		{value: "/bad~2escape", valid: false},
		{value: "/bad~", valid: false},
	}
	for _, test := range tests {
		if got := pointer.MatchString(test.value); got != test.valid {
			t.Errorf("field pointer %q validity = %t, want %t", test.value, got, test.valid)
		}
	}

	withinBudget, err := json.Marshal("/" + strings.Repeat("☃", 31))
	if err != nil {
		t.Fatalf("json.Marshal(withinBudget) error = %v", err)
	}
	overBudget, err := json.Marshal("/" + strings.Repeat("☃", 32))
	if err != nil {
		t.Fatalf("json.Marshal(overBudget) error = %v", err)
	}
	if len(withinBudget) > 98 || len(overBudget) <= 98 {
		t.Fatalf("encoded pointer sizes = %d and %d, want <= 98 then > 98", len(withinBudget), len(overBudget))
	}
}

func TestRetryAfterValues(t *testing.T) {
	t.Parallel()
	retryAfter := regexp.MustCompile(retryAfterPattern)
	tests := []struct {
		value string
		valid bool
	}{
		{value: "1", valid: true},
		{value: "9", valid: true},
		{value: "10", valid: true},
		{value: "9999", valid: true},
		{value: "10000", valid: true},
		{value: "79999", valid: true},
		{value: "80000", valid: true},
		{value: "85999", valid: true},
		{value: "86000", valid: true},
		{value: "86399", valid: true},
		{value: "86400", valid: true},
		{value: "", valid: false},
		{value: "0", valid: false},
		{value: "01", valid: false},
		{value: "86401", valid: false},
		{value: "99999", valid: false},
		{value: "100000", valid: false},
	}
	for _, test := range tests {
		if got := retryAfter.MatchString(test.value); got != test.valid {
			t.Errorf("Retry-After %q validity = %t, want %t", test.value, got, test.valid)
		}
	}
}

func TestDeprecationWindowValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		deprecation string
		sunset      string
		valid       bool
	}{
		{
			name: "exact ninety day window", deprecation: "@1780520400",
			sunset: "Tue, 01 Sep 2026 21:00:00 GMT", valid: true,
		},
		{
			name: "one second short", deprecation: "@1780520401",
			sunset: "Tue, 01 Sep 2026 21:00:00 GMT", valid: false,
		},
		{
			name: "sunset precedes deprecation", deprecation: "@1788296401",
			sunset: "Tue, 01 Sep 2026 21:00:00 GMT", valid: false,
		},
		{
			name: "invalid structured date", deprecation: "1780520400",
			sunset: "Tue, 01 Sep 2026 21:00:00 GMT", valid: false,
		},
		{
			name: "invalid HTTP date", deprecation: "@1780520400",
			sunset: "Mon, 01 Sep 2026 21:00:00 GMT", valid: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validDeprecationWindow(test.deprecation, test.sunset, 90); got != test.valid {
				t.Fatalf("validDeprecationWindow(%q, %q, 90) = %t, want %t", test.deprecation, test.sunset, got, test.valid)
			}
		})
	}
}

func TestDeprecationLinkValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value string
		valid bool
	}{
		{value: `</docs/migrations/v1alpha1>; rel="deprecation"`, valid: true},
		{value: `</docs/migrations/v1alpha1%2Fguide>; rel="deprecation"`, valid: true},
		{value: `</docs/migrations?next=%2Fdocs%2Fv2>; rel="deprecation"`, valid: true},
		{value: `<https://docs.example.invalid/migrations?v=v1#steps>; rel="deprecation"`, valid: true},
		{
			value: `</docs/migrations/v1alpha1>; rel="deprecation", </docs/sunset/v1alpha1>; rel="sunset"`,
			valid: true,
		},
		{value: `<not a URI>; rel="deprecation"`, valid: false},
		{value: `</docs/"quoted">; rel="deprecation"`, valid: false},
		{value: `</docs/☃>; rel="deprecation"`, valid: false},
		{value: `</docs/%zz>; rel="deprecation"`, valid: false},
		{value: `</docs/migrations?next=%zz>; rel="deprecation"`, valid: false},
		{value: `<http://docs.example.invalid/migrations>; rel="deprecation"`, valid: false},
		{value: `<//docs.example.invalid/migrations>; rel="deprecation"`, valid: false},
		{value: `<https://user@example.invalid/migrations>; rel="deprecation"`, valid: false},
		{value: `</docs/migrations>; rel="sunset"`, valid: false},
		{value: `<` + strings.Repeat("a", 901) + `>; rel="deprecation"`, valid: false},
	}
	for _, test := range tests {
		if got := validDeprecationLink(test.value); got != test.valid {
			t.Errorf("deprecation Link %q validity = %t, want %t", test.value, got, test.valid)
		}
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

func decodeStrictFixture(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v", path, err)
	}
	if len(data) > maxContractBytes {
		t.Fatalf("fixture %s is %d bytes, maximum %d", path, len(data), maxContractBytes)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		t.Fatalf("fixture %s contains duplicate keys: %v", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("strict decode %s: %v", path, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		t.Fatalf("fixture %s trailing data: %v", path, err)
	}
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
