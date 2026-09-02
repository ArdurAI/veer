package openapi

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
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
				resources[2].(map[string]any)["parentKind"] = "Workspace"
			},
			message: "Application parent kind must be Environment",
		},
		{
			name: "wrong schema reference",
			mutate: func(root map[string]any) {
				resources := nestedMap(t, root, "x-veer-hierarchy")["resources"].([]any)
				nestedMap(t, resources[3].(map[string]any), "schema")["$ref"] = "#/components/schemas/Application"
			},
			message: "Component schema reference drifted",
		},
		{
			name: "wrong status write schema reference",
			mutate: func(root map[string]any) {
				resources := nestedMap(t, root, "x-veer-hierarchy")["resources"].([]any)
				nestedMap(t, resources[1].(map[string]any), "statusWriteSchema")["$ref"] =
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
			message: "expected exactly 60 schemas, got 59",
		},
		{
			name: "schema added",
			mutate: func(root map[string]any) {
				nestedMap(t, root, "components", "schemas")["ProviderResource"] = map[string]any{
					"type": "object", "additionalProperties": false, "properties": map[string]any{},
				}
			},
			message: "expected exactly 60 schemas, got 61",
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
			message: "Condition.message schema has unreviewed keywords",
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
