package identity

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	testIssuer          = "https://issuer.example/tenant"
	testSubject         = "subject-123"
	testWorkload        = "service-account:reconciler"
	issuerCanary        = "issuer-canary.invalid"
	subjectCanary       = "subject-canary-private"
	audienceCanary      = "audience-canary-private"
	groupCanary         = "group-canary-private"
	workloadCanary      = "workload-canary-private"
	expectedFingerprint = "prn1_Bkz778twUPb04kMwSx5YTwV_1vAgibNkkGEhXtBChxQ"
)

func TestNewPrincipalNormalizesAndOwnsClaims(t *testing.T) {
	t.Parallel()

	audiences := []string{"z-api", "a-api", "z-api"}
	groups := []string{"operators", "developers", "operators"}
	workload := mustWorkloadIdentity(t, testWorkload)
	principal, err := NewPrincipal(PrincipalInput{
		Kind:             KindWorkload,
		Issuer:           testIssuer,
		Subject:          testSubject,
		Audiences:        audiences,
		Groups:           groups,
		WorkloadIdentity: &workload,
	})
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	if err := ValidatePrincipal(principal); err != nil {
		t.Fatalf("ValidatePrincipal() error = %v", err)
	}
	if got, want := principal.Audiences(), []string{"a-api", "z-api"}; !slices.Equal(got, want) {
		t.Fatalf("Audiences() = %#v, want %#v", got, want)
	}
	if got, want := principal.Groups(), []string{"developers", "operators"}; !slices.Equal(got, want) {
		t.Fatalf("Groups() = %#v, want %#v", got, want)
	}
	if got, present := principal.WorkloadIdentity(); !present || got.Value() != testWorkload {
		t.Fatalf("WorkloadIdentity() = %v, %t", got, present)
	}

	// Mutating every caller-owned container after construction must not change
	// the principal.
	audiences[0] = "mutated-audience"
	groups[0] = "mutated-group"
	workload.value = "mutated-workload"
	if got := principal.Audiences(); !slices.Equal(got, []string{"a-api", "z-api"}) {
		t.Fatalf("principal retained audience input alias: %#v", got)
	}
	if got := principal.Groups(); !slices.Equal(got, []string{"developers", "operators"}) {
		t.Fatalf("principal retained group input alias: %#v", got)
	}
	if got, _ := principal.WorkloadIdentity(); got.Value() != testWorkload {
		t.Fatalf("principal retained workload input alias: %q", got.Value())
	}

	returnedAudiences := principal.Audiences()
	returnedGroups := principal.Groups()
	returnedAudiences[0] = "mutated-return"
	returnedGroups[0] = "mutated-return"
	if slices.Equal(returnedAudiences, principal.Audiences()) ||
		slices.Equal(returnedGroups, principal.Groups()) {
		t.Fatal("principal accessor returned an internal slice alias")
	}

	clone := ClonePrincipal(principal)
	if !EqualPrincipal(principal, clone) {
		t.Fatal("ClonePrincipal changed the semantic value")
	}
	clone.audiences[0] = "clone-mutated-audience"
	clone.groups[0] = "clone-mutated-group"
	clone.workloadIdentity.value = "clone-mutated-workload"
	if principal.Audiences()[0] != "a-api" ||
		principal.Groups()[0] != "developers" {
		t.Fatal("ClonePrincipal retained a slice alias")
	}
	if got, _ := principal.WorkloadIdentity(); got.Value() != testWorkload {
		t.Fatal("ClonePrincipal retained a workload pointer alias")
	}
}

func TestPrincipalHumanAndWorkloadKindsAreExplicit(t *testing.T) {
	t.Parallel()

	human := mustPrincipal(t, PrincipalInput{
		Kind:      KindHuman,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"veer-api"},
	})
	if human.Kind() != KindHuman {
		t.Fatalf("Kind() = %v, want human", human.Kind())
	}
	if workload, present := human.WorkloadIdentity(); present || workload.Value() != "" {
		t.Fatalf("human WorkloadIdentity() = %v, %t", workload, present)
	}

	workloadIdentity := mustWorkloadIdentity(t, testWorkload)
	workload := mustPrincipal(t, PrincipalInput{
		Kind:             KindWorkload,
		Issuer:           testIssuer,
		Subject:          testSubject,
		Audiences:        []string{"veer-api"},
		WorkloadIdentity: &workloadIdentity,
	})
	if workload.Kind() != KindWorkload {
		t.Fatalf("Kind() = %v, want workload", workload.Kind())
	}
	if EqualPrincipal(human, workload) {
		t.Fatal("human and workload principals compared equal")
	}
	if !SameLogicalIdentity(human, workload) {
		t.Fatal("kind changed exact issuer-and-subject logical identity")
	}

	_, err := NewPrincipal(PrincipalInput{
		Kind:             KindHuman,
		Issuer:           testIssuer,
		Subject:          testSubject,
		Audiences:        []string{"veer-api"},
		WorkloadIdentity: &workloadIdentity,
	})
	if !errors.Is(err, ErrWorkloadIdentityForbidden) {
		t.Fatalf("NewPrincipal(human with workload) error = %v", err)
	}
	_, err = NewPrincipal(PrincipalInput{
		Kind:      KindWorkload,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"veer-api"},
	})
	if !errors.Is(err, ErrWorkloadIdentityRequired) {
		t.Fatalf("NewPrincipal(workload without identity) error = %v", err)
	}
	_, err = NewPrincipal(PrincipalInput{
		Kind:      Kind(255),
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"veer-api"},
	})
	if !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("NewPrincipal(unknown kind) error = %v", err)
	}
}

func TestLogicalIdentityIsExactAndFingerprintIsStable(t *testing.T) {
	t.Parallel()

	base := mustPrincipal(t, PrincipalInput{
		Kind:      KindHuman,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"api-a"},
		Groups:    []string{"group-a"},
	})
	if got := base.Fingerprint().String(); got != expectedFingerprint {
		t.Fatalf("Fingerprint() = %q, want %q", got, expectedFingerprint)
	}

	changedClaims := mustPrincipal(t, PrincipalInput{
		Kind:      KindHuman,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"api-b"},
		Groups:    []string{"group-b"},
	})
	if !SameLogicalIdentity(base, changedClaims) {
		t.Fatal("audience or group changes altered logical identity")
	}
	if !base.Fingerprint().Equal(changedClaims.Fingerprint()) {
		t.Fatal("audience or group changes altered fingerprint")
	}
	if EqualPrincipal(base, changedClaims) {
		t.Fatal("different normalized claims compared fully equal")
	}

	for _, test := range []struct {
		name    string
		issuer  string
		subject string
	}{
		{"issuer path slash", testIssuer + "/", testSubject},
		{"issuer host case", "https://ISSUER.example/tenant", testSubject},
		{"subject case", testIssuer, "Subject-123"},
	} {
		t.Run(test.name, func(t *testing.T) {
			other := mustPrincipal(t, PrincipalInput{
				Kind:      KindHuman,
				Issuer:    test.issuer,
				Subject:   test.subject,
				Audiences: []string{"api-a"},
			})
			if SameLogicalIdentity(base, other) {
				t.Fatal("distinct exact issuer/subject values compared equal")
			}
			if base.Fingerprint().Equal(other.Fingerprint()) {
				t.Fatal("distinct exact issuer/subject values produced equal test fingerprints")
			}
		})
	}

	unicodeGroups := mustPrincipal(t, PrincipalInput{
		Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
		Audiences: []string{"api"}, Groups: []string{"group-\u00e9", "group-e\u0301"},
	})
	if len(unicodeGroups.Groups()) != 2 {
		t.Fatal("exact Unicode group values were normalized into one alias")
	}

	// Length framing prevents concatenation aliases.
	left, err := NewLogicalIdentity("https://issuer.example/a", "bc")
	if err != nil {
		t.Fatalf("NewLogicalIdentity(left) error = %v", err)
	}
	right, err := NewLogicalIdentity("https://issuer.example/ab", "c")
	if err != nil {
		t.Fatalf("NewLogicalIdentity(right) error = %v", err)
	}
	if left.Fingerprint().Equal(right.Fingerprint()) {
		t.Fatal("length-ambiguous logical identities produced equal fingerprints")
	}
}

func TestPrincipalValidationBoundsAndClassifications(t *testing.T) {
	t.Parallel()

	validIssuerAtLimit := "https://issuer.example/" + strings.Repeat("a", MaxIssuerBytes-len("https://issuer.example/"))
	tests := []struct {
		name  string
		input PrincipalInput
		want  error
	}{
		{
			name: "issuer at limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: validIssuerAtLimit,
				Subject: testSubject, Audiences: []string{"api"}},
		},
		{
			name: "issuer over limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: validIssuerAtLimit + "a",
				Subject: testSubject, Audiences: []string{"api"}},
			want: ErrInvalidIssuer,
		},
		{
			name: "issuer not https",
			input: PrincipalInput{Kind: KindHuman, Issuer: "http://issuer.example",
				Subject: testSubject, Audiences: []string{"api"}},
			want: ErrInvalidIssuer,
		},
		{
			name: "issuer query",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer + "?tenant=private",
				Subject: testSubject, Audiences: []string{"api"}},
			want: ErrInvalidIssuer,
		},
		{
			name: "subject at limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: strings.Repeat("s", MaxSubjectBytes), Audiences: []string{"api"}},
		},
		{
			name: "subject over limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: strings.Repeat("s", MaxSubjectBytes+1), Audiences: []string{"api"}},
			want: ErrInvalidSubject,
		},
		{
			name: "subject must be ASCII",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: "subject-\u00e9", Audiences: []string{"api"}},
			want: ErrInvalidSubject,
		},
		{
			name: "audience required",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject},
			want: ErrAudienceRequired,
		},
		{
			name: "too many audiences",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: repeatedClaims("aud", MaxAudiences+1)},
			want: ErrTooManyAudiences,
		},
		{
			name: "audience over limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: []string{strings.Repeat("a", MaxAudienceBytes+1)}},
			want: ErrInvalidAudiences,
		},
		{
			name: "too many groups",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: []string{"api"}, Groups: repeatedClaims("group", MaxGroups+1)},
			want: ErrTooManyGroups,
		},
		{
			name: "group over limit",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: []string{"api"}, Groups: []string{strings.Repeat("g", MaxGroupBytes+1)}},
			want: ErrInvalidGroups,
		},
		{
			name: "surrounding whitespace is rejected not normalized",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: []string{" api"}},
			want: ErrInvalidAudiences,
		},
		{
			name: "control character",
			input: PrincipalInput{Kind: KindHuman, Issuer: testIssuer,
				Subject: testSubject, Audiences: []string{"api"}, Groups: []string{"admin\nprivate"}},
			want: ErrInvalidGroups,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal, err := NewPrincipal(test.input)
			if test.want == nil {
				if err != nil {
					t.Fatalf("NewPrincipal() error = %v", err)
				}
				if err := ValidatePrincipal(principal); err != nil {
					t.Fatalf("ValidatePrincipal() error = %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPrincipal) || !errors.Is(err, test.want) {
				t.Fatalf("NewPrincipal() error = %v, want ErrInvalidPrincipal and %v", err, test.want)
			}
			assertNoIdentityCanary(t, err.Error())
		})
	}

	if _, err := NewWorkloadIdentity(strings.Repeat("w", MaxWorkloadIdentityBytes)); err != nil {
		t.Fatalf("NewWorkloadIdentity(at limit) error = %v", err)
	}
	if _, err := NewWorkloadIdentity(strings.Repeat("w", MaxWorkloadIdentityBytes+1)); !errors.Is(err, ErrInvalidWorkloadIdentity) {
		t.Fatalf("NewWorkloadIdentity(over limit) error = %v", err)
	}
}

func TestValidatePrincipalRejectsNonCanonicalAndForgedValues(t *testing.T) {
	t.Parallel()

	principal := mustPrincipal(t, PrincipalInput{
		Kind:      KindHuman,
		Issuer:    testIssuer,
		Subject:   testSubject,
		Audiences: []string{"api-a", "api-b"},
		Groups:    []string{"group-a", "group-b"},
	})
	tests := []struct {
		name   string
		mutate func(*Principal)
		want   error
	}{
		{"zero kind", func(value *Principal) { value.kind = 0 }, ErrInvalidKind},
		{"changed issuer", func(value *Principal) { value.logicalIdentity.issuer += "/changed" }, ErrInvalidFingerprint},
		{"changed subject", func(value *Principal) { value.logicalIdentity.subject += "-changed" }, ErrInvalidFingerprint},
		{"zero fingerprint", func(value *Principal) { value.logicalIdentity.fingerprint = Fingerprint{} }, ErrInvalidFingerprint},
		{"unsorted audiences", func(value *Principal) {
			value.audiences[0], value.audiences[1] = value.audiences[1], value.audiences[0]
		}, ErrInvalidAudiences},
		{"duplicate audiences", func(value *Principal) { value.audiences[1] = value.audiences[0] }, ErrInvalidAudiences},
		{"unsorted groups", func(value *Principal) { value.groups[0], value.groups[1] = value.groups[1], value.groups[0] }, ErrInvalidGroups},
		{"human workload", func(value *Principal) { value.workloadIdentity = &WorkloadIdentity{value: testWorkload} }, ErrWorkloadIdentityForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := ClonePrincipal(principal)
			test.mutate(&candidate)
			err := ValidatePrincipal(candidate)
			if !errors.Is(err, ErrInvalidPrincipal) || !errors.Is(err, test.want) {
				t.Fatalf("ValidatePrincipal() error = %v, want ErrInvalidPrincipal and %v", err, test.want)
			}
		})
	}
	if err := ValidatePrincipal(Principal{}); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("ValidatePrincipal(zero) error = %v", err)
	}
}

func TestIdentityValidationErrorsNeverExposeClaims(t *testing.T) {
	t.Parallel()

	invalidWorkload := WorkloadIdentity{value: " " + workloadCanary}
	tests := []struct {
		name string
		run  func() error
	}{
		{
			"issuer",
			func() error {
				_, err := NewLogicalIdentity("https://"+issuerCanary+"?private", testSubject)
				return err
			},
		},
		{
			"subject",
			func() error {
				_, err := NewLogicalIdentity(testIssuer, subjectCanary+"\n")
				return err
			},
		},
		{
			"audience",
			func() error {
				_, err := NewPrincipal(PrincipalInput{
					Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
					Audiences: []string{" " + audienceCanary},
				})
				return err
			},
		},
		{
			"group",
			func() error {
				_, err := NewPrincipal(PrincipalInput{
					Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
					Audiences: []string{"api"}, Groups: []string{groupCanary + "\n"},
				})
				return err
			},
		},
		{
			"workload",
			func() error {
				_, err := NewWorkloadIdentity(" " + workloadCanary)
				return err
			},
		},
		{
			"principal workload",
			func() error {
				_, err := NewPrincipal(PrincipalInput{
					Kind: KindWorkload, Issuer: testIssuer, Subject: testSubject,
					Audiences: []string{"api"}, WorkloadIdentity: &invalidWorkload,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil {
				t.Fatal("invalid identity claim was accepted")
			}
			assertNoIdentityCanary(t, err.Error())
		})
	}
}

func TestIdentityDiagnosticsAndSerializationNeverExposeClaims(t *testing.T) {
	t.Parallel()

	workload := mustWorkloadIdentity(t, workloadCanary)
	input := PrincipalInput{
		Kind:             KindWorkload,
		Issuer:           "https://" + issuerCanary,
		Subject:          subjectCanary,
		Audiences:        []string{audienceCanary},
		Groups:           []string{groupCanary},
		WorkloadIdentity: &workload,
	}
	principal := mustPrincipal(t, input)
	logical := principal.LogicalIdentity()

	for name, value := range map[string]any{
		"principal":         principal,
		"principal pointer": &principal,
		"principal input":   input,
		"logical identity":  logical,
		"workload identity": workload,
		"nested principal":  struct{ Principal Principal }{Principal: principal},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{
				"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%o", "%f",
			} {
				assertNoIdentityCanary(t, fmt.Sprintf(format, value))
			}
			encoded, err := json.Marshal(value)
			if err == nil {
				t.Fatalf("json.Marshal(%s) = %s, want error", name, encoded)
			}
			assertNoIdentityCanary(t, string(encoded))
			assertNoIdentityCanary(t, err.Error())
		})
	}

	for name, value := range map[string]any{
		"principal input":         input,
		"principal input pointer": &input,
		"nested principal input":  struct{ Input PrincipalInput }{Input: input},
	} {
		t.Run("gob "+name, func(t *testing.T) {
			var output bytes.Buffer
			err := gob.NewEncoder(&output).Encode(value)
			if !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("gob.Encode(%s) error = %v, want %v", name, err, ErrSerializationForbidden)
			}
			assertNoIdentityCanary(t, output.String())
			assertNoIdentityCanary(t, err.Error())
		})
	}

	if got := principal.String(); !strings.Contains(got, principal.Fingerprint().String()) ||
		!strings.Contains(got, "kind=workload") {
		t.Fatalf("Principal.String() = %q", got)
	}
	if got := fmt.Sprintf("%#v", principal); got != principal.String() {
		t.Fatalf("Principal GoString formatting = %q, want %q", got, principal.String())
	}

	var typedNil *Principal
	for _, formatted := range []string{
		fmt.Sprintf("%v", typedNil),
		fmt.Sprintf("%+v", typedNil),
		fmt.Sprintf("%#v", typedNil),
	} {
		assertNoIdentityCanary(t, formatted)
	}
	if encoded, err := json.Marshal(typedNil); err != nil || string(encoded) != "null" {
		t.Fatalf("json.Marshal(typed nil) = %q, %v", encoded, err)
	}
	if (Principal{}).String() != "principal(invalid)" {
		t.Fatalf("zero Principal.String() = %q", (Principal{}).String())
	}
	if (Fingerprint{}).String() != "prn1_invalid" ||
		(Fingerprint{}).Equal(Fingerprint{}) {
		t.Fatal("zero Fingerprint was represented as a valid correlation identity")
	}
	if EqualLogicalIdentity(LogicalIdentity{}, LogicalIdentity{}) ||
		EqualPrincipal(Principal{}, Principal{}) ||
		SameLogicalIdentity(Principal{}, Principal{}) {
		t.Fatal("zero identity values compared as authenticated identities")
	}
}

func TestPrincipalCannotEnterResourceSerialization(t *testing.T) {
	t.Parallel()

	workload := mustWorkloadIdentity(t, workloadCanary)
	principal := mustPrincipal(t, PrincipalInput{
		Kind:             KindWorkload,
		Issuer:           "https://" + issuerCanary,
		Subject:          subjectCanary,
		Audiences:        []string{audienceCanary},
		Groups:           []string{groupCanary},
		WorkloadIdentity: &workload,
	})
	_, err := resource.New(resource.CreateInput[principalResourceSpec, emptyResourceStatus]{
		APIVersion:      "v1alpha1",
		Kind:            "IdentitySerializationProbe",
		ID:              "probe_01J00000000000000000000",
		WorkspaceID:     "wsp_01J00000000000000000000000",
		DisplayName:     "serialization probe",
		ResourceVersion: "rv_01J00000000000000000000000",
		CreatedAt:       time.Date(2026, 9, 3, 1, 2, 3, 0, time.UTC),
		Spec:            principalResourceSpec{Principal: principal},
		Status:          emptyResourceStatus{},
	})
	if err == nil {
		t.Fatal("resource.New accepted a Principal in resource spec")
	}
	assertNoIdentityCanary(t, err.Error())
}

type principalResourceSpec struct {
	Principal Principal `json:"principal"`
}

type emptyResourceStatus struct{}

func (emptyResourceStatus) ObservedGenerations() []int64 { return nil }

func mustPrincipal(t *testing.T, input PrincipalInput) Principal {
	t.Helper()
	principal, err := NewPrincipal(input)
	if err != nil {
		t.Fatalf("NewPrincipal() error = %v", err)
	}
	return principal
}

func mustWorkloadIdentity(t *testing.T, value string) WorkloadIdentity {
	t.Helper()
	workload, err := NewWorkloadIdentity(value)
	if err != nil {
		t.Fatalf("NewWorkloadIdentity() error = %v", err)
	}
	return workload
}

func repeatedClaims(prefix string, count int) []string {
	result := make([]string, count)
	for index := range result {
		result[index] = fmt.Sprintf("%s-%04d", prefix, index)
	}
	return result
}

func assertNoIdentityCanary(t *testing.T, value string) {
	t.Helper()
	for _, canary := range []string{
		issuerCanary,
		subjectCanary,
		audienceCanary,
		groupCanary,
		workloadCanary,
	} {
		if strings.Contains(value, canary) {
			t.Fatalf("diagnostic or serialization leaked canary %q: %q", canary, value)
		}
	}
}
