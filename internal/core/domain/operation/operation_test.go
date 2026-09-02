package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	operationID   resource.ID = "op_01J000000000000000000000000"
	workspaceID   resource.ID = "wsp_01J00000000000000000000000"
	resourceID    resource.ID = "cmp_01J00000000000000000000000"
	environmentID resource.ID = "env_01J00000000000000000000000"
	connectionID  resource.ID = "pvc_01J00000000000000000000000"
)

var operationFixtureTime = time.Date(2026, 9, 3, 1, 3, 0, 0, time.UTC)

func TestNewControlAndProviderBoundOperations(t *testing.T) {
	t.Parallel()

	controlOperation, err := New(Input{
		ID: operationID, WorkspaceID: workspaceID, ResourceID: workspaceID,
		Generation: 1, ResourceVersion: "rv_control", Reason: "Accepted",
		CreatedAt: operationFixtureTime,
	})
	if err != nil {
		t.Fatalf("New(control) error = %v", err)
	}
	if controlOperation.EnvironmentID != nil || controlOperation.ProviderConnectionID != nil ||
		controlOperation.Phase != PhasePending || controlOperation.CreatedAt != controlOperation.UpdatedAt {
		t.Fatalf("control operation = %#v", controlOperation)
	}

	providerOperation := newProviderOperation(t)
	if providerOperation.EnvironmentID == nil || *providerOperation.EnvironmentID != environmentID ||
		providerOperation.ProviderConnectionID == nil || *providerOperation.ProviderConnectionID != connectionID {
		t.Fatalf("provider binding = %#v", providerOperation)
	}
	if err := Validate(providerOperation); err != nil {
		t.Fatalf("Validate(provider operation) error = %v", err)
	}
}

func TestYearZeroTimestampCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	value, err := New(Input{
		ID: operationID, WorkspaceID: workspaceID, ResourceID: resourceID,
		Generation: 1, ResourceVersion: "rv_year_zero",
		CreatedAt: time.Date(0, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("New(year zero) error = %v", err)
	}
	if value.CreatedAt != "0000-01-01T00:00:00.000Z" || value.UpdatedAt != value.CreatedAt {
		t.Fatalf("year-zero timestamps = %q / %q", value.CreatedAt, value.UpdatedAt)
	}
	encoded, err := MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical(year zero) error = %v", err)
	}
	decoded, err := UnmarshalCanonical(encoded)
	if err != nil {
		t.Fatalf("UnmarshalCanonical(year zero) error = %v", err)
	}
	if !equal(decoded, value) {
		t.Fatalf("year-zero round trip differs: %#v / %#v", decoded, value)
	}
	goZero, err := New(Input{
		ID: operationID, WorkspaceID: workspaceID, ResourceID: resourceID,
		Generation: 1, ResourceVersion: "rv_go_zero", CreatedAt: time.Time{},
	})
	if err != nil {
		t.Fatalf("New(Go zero) error = %v", err)
	}
	if goZero.CreatedAt != "0001-01-01T00:00:00.000Z" || goZero.UpdatedAt != goZero.CreatedAt {
		t.Fatalf("Go-zero timestamps = %q / %q", goZero.CreatedAt, goZero.UpdatedAt)
	}

	for _, createdAt := range []time.Time{
		time.Date(0, time.January, 1, 0, 0, 0, 0, time.FixedZone("east", 60*60)),
		time.Date(9999, time.December, 31, 23, 59, 59, 0, time.FixedZone("west", -60*60)),
	} {
		_, err := New(Input{
			ID: operationID, WorkspaceID: workspaceID, ResourceID: resourceID,
			Generation: 1, ResourceVersion: "rv_boundary", CreatedAt: createdAt,
		})
		if !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatalf("New(UTC year rollover %v) error = %v", createdAt, err)
		}
	}
}

func TestCanonicalSizeAppliesToValidationAndTransitions(t *testing.T) {
	t.Parallel()

	maxID := resource.ID(strings.Repeat("a", 128))
	environment := resource.ID(strings.Repeat("e", 128))
	connection := resource.ID(strings.Repeat("p", 128))
	before, err := New(Input{
		ID: maxID, WorkspaceID: maxID, ResourceID: maxID,
		EnvironmentID: &environment, ProviderConnectionID: &connection,
		Generation: 1, ResourceVersion: "rv_initial", CreatedAt: operationFixtureTime,
	})
	if err != nil {
		t.Fatalf("New(size baseline) error = %v", err)
	}

	oversized := clone(before)
	oversized.ResourceVersion = strings.Repeat("v", 128)
	oversized.Phase = PhaseRunning
	oversized.Reason = "R" + strings.Repeat("a", 63)
	oversized.Message = strings.Repeat("\x00", maxMessageRunes)
	amount := strings.Repeat("9", 64)
	oversized.CostEstimate = costPointer(control.CostEstimate{
		State: control.CostKnown, Amount: &amount,
		Currency: "USD", Region: strings.Repeat("a", 63), Source: strings.Repeat("a", 64),
		ObservedAt: "2026-09-03T01:03:00.000Z", Confidence: control.ConfidenceHigh,
		Reason: "R" + strings.Repeat("a", 63),
	})
	oversized.UpdatedAt = "2026-09-03T01:04:00.000Z"
	raw, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("json.Marshal(oversized) error = %v", err)
	}
	if len(raw) <= MaxCanonicalBytes {
		t.Fatalf("oversized fixture = %d bytes, want > %d", len(raw), MaxCanonicalBytes)
	}
	if err := Validate(oversized); !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("Validate(oversized) error = %v", err)
	}
	if _, err := MarshalCanonical(oversized); !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("MarshalCanonical(oversized) error = %v", err)
	}

	_, err = New(Input{
		ID: maxID, WorkspaceID: maxID, ResourceID: maxID,
		EnvironmentID: &environment, ProviderConnectionID: &connection,
		Generation: 1, ResourceVersion: oversized.ResourceVersion,
		Reason: oversized.Reason, Message: oversized.Message,
		CostEstimate: oversized.CostEstimate, CreatedAt: operationFixtureTime,
	})
	if !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("New(oversized) error = %v", err)
	}

	after, err := Transition(before, TransitionInput{
		Phase: oversized.Phase, Reason: oversized.Reason, Message: oversized.Message,
		CostEstimate: oversized.CostEstimate, ResourceVersion: oversized.ResourceVersion,
		UpdatedAt: operationFixtureTime.Add(time.Minute),
	})
	if !errors.Is(err, ErrCanonicalTooLarge) || !equal(after, before) {
		t.Fatalf("Transition(oversized) = %#v, %v", after, err)
	}

	bounded := clone(oversized)
	for len(bounded.Message) > 0 {
		encoded, marshalErr := json.Marshal(bounded)
		if marshalErr != nil {
			t.Fatalf("json.Marshal(boundary) error = %v", marshalErr)
		}
		if len(encoded) <= MaxCanonicalBytes {
			break
		}
		bounded.Message = bounded.Message[:len(bounded.Message)-1]
	}
	if err := Validate(bounded); err != nil {
		t.Fatalf("Validate(boundary) error = %v", err)
	}
}

func TestCanonicalEncodingMatchesPinnedV1Profile(t *testing.T) {
	t.Parallel()

	value := newProviderOperation(t)
	value.Message = "<>&\u2028\u2029"
	want, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	got, err := MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical profile drifted:\n got %s\nwant %s", got, want)
	}
	for _, escaped := range [][]byte{
		[]byte(`\u003c`), []byte(`\u003e`), []byte(`\u0026`), []byte(`\u2028`), []byte(`\u2029`),
	} {
		if !bytes.Contains(got, escaped) {
			t.Fatalf("canonical output %s is missing %s", got, escaped)
		}
	}
}

func TestPhaseTransitionMatrix(t *testing.T) {
	t.Parallel()

	phases := []Phase{PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled}
	allowed := map[Phase]map[Phase]bool{
		PhasePending: {
			PhaseWaiting: true, PhaseRunning: true, PhaseSucceeded: true,
			PhaseFailed: true, PhaseCanceled: true,
		},
		PhaseWaiting: {
			PhasePending: true, PhaseRunning: true, PhaseSucceeded: true,
			PhaseFailed: true, PhaseCanceled: true,
		},
		PhaseRunning: {
			PhaseWaiting: true, PhaseSucceeded: true, PhaseFailed: true, PhaseCanceled: true,
		},
	}
	for _, beforePhase := range phases {
		beforePhase := beforePhase
		for _, afterPhase := range phases {
			afterPhase := afterPhase
			t.Run(string(beforePhase)+"_to_"+string(afterPhase), func(t *testing.T) {
				t.Parallel()
				before := newProviderOperation(t)
				before.Phase = beforePhase
				input := TransitionInput{
					Phase: afterPhase, Reason: "PhaseChanged", Message: "A bounded safe summary.",
					ResourceVersion: "rv_phase_changed", UpdatedAt: operationFixtureTime.Add(time.Minute),
				}
				if beforePhase == afterPhase {
					input.Reason = before.Reason
					input.Message = before.Message
					input.CostEstimate = cloneCost(before.CostEstimate)
				}
				after, err := Transition(before, input)
				wantSuccess := beforePhase == afterPhase || allowed[beforePhase][afterPhase]
				if wantSuccess {
					if err != nil {
						t.Fatalf("Transition() error = %v", err)
					}
					if after.Phase != afterPhase {
						t.Fatalf("phase = %q, want %q", after.Phase, afterPhase)
					}
					if beforePhase == afterPhase && !equal(after, before) {
						t.Fatal("exact replay changed operation")
					}
					return
				}
				if !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, ErrPhaseTransition) {
					t.Fatalf("Transition() error = %v, want phase-transition rejection", err)
				}
				if !equal(after, before) {
					t.Fatal("rejected transition changed operation")
				}
			})
		}
	}
}

func TestSamePhaseEvidenceRefresh(t *testing.T) {
	t.Parallel()

	for _, phase := range []Phase{PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled} {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			before := newProviderOperation(t)
			before.Phase = phase
			after, err := Transition(before, TransitionInput{
				Phase: phase, Reason: "Changed", Message: before.Message,
				CostEstimate: cloneCost(before.CostEstimate), ResourceVersion: "rv_evidence_refresh",
				UpdatedAt: operationFixtureTime.Add(time.Minute),
			})
			if terminal(phase) {
				if !errors.Is(err, ErrPhaseTransition) || !equal(after, before) {
					t.Fatalf("terminal refresh = %#v, %v", after, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Transition(nonterminal refresh) error = %v", err)
			}
			if after.Phase != before.Phase || after.Reason != "Changed" ||
				after.ResourceVersion != "rv_evidence_refresh" {
				t.Fatalf("refreshed operation = %#v", after)
			}
		})
	}
}

func TestExactReplayIgnoresUnusedVersionAndTime(t *testing.T) {
	t.Parallel()

	for _, phase := range []Phase{PhasePending, PhaseWaiting, PhaseRunning, PhaseSucceeded, PhaseFailed, PhaseCanceled} {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			before := newProviderOperation(t)
			before.Phase = phase
			after, err := Transition(before, TransitionInput{
				Phase: phase, Reason: before.Reason, Message: before.Message,
				CostEstimate:    cloneCost(before.CostEstimate),
				ResourceVersion: "invalid version is intentionally unused",
				UpdatedAt:       time.Time{},
			})
			if err != nil {
				t.Fatalf("Transition(exact replay) error = %v", err)
			}
			if !equal(after, before) {
				t.Fatal("exact replay changed operation")
			}
		})
	}
}

func TestProviderBindingMatrix(t *testing.T) {
	t.Parallel()

	valid := newProviderOperation(t)
	tests := []struct {
		name   string
		mutate func(*Operation)
	}{
		{name: "environment only", mutate: func(value *Operation) { value.ProviderConnectionID = nil }},
		{name: "connection only", mutate: func(value *Operation) { value.EnvironmentID = nil }},
		{name: "bad environment", mutate: func(value *Operation) { value.EnvironmentID = idPointer("short") }},
		{name: "bad connection", mutate: func(value *Operation) { value.ProviderConnectionID = idPointer("short") }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			test.mutate(&candidate)
			err := Validate(candidate)
			if !errors.Is(err, ErrInvalidOperation) || !errors.Is(err, ErrInvalidProviderBinding) {
				t.Fatalf("Validate() error = %v, want binding rejection", err)
			}
		})
	}
}

func TestImmutableTransitionMatrix(t *testing.T) {
	t.Parallel()

	before := newProviderOperation(t)
	validAfter := clone(before)
	validAfter.Phase = PhaseRunning
	validAfter.Reason = "Reconciling"
	validAfter.ResourceVersion = "rv_transition"
	validAfter.UpdatedAt = "2026-09-03T01:04:00.000Z"
	tests := []struct {
		name   string
		mutate func(*Operation)
		want   error
	}{
		{name: "operation ID", mutate: func(value *Operation) { value.ID = "op_01J111111111111111111111111" }, want: ErrImmutableOperationID},
		{name: "workspace ID", mutate: func(value *Operation) { value.WorkspaceID = "wsp_01J11111111111111111111111" }, want: ErrImmutableWorkspaceID},
		{name: "resource ID", mutate: func(value *Operation) { value.ResourceID = "cmp_01J11111111111111111111111" }, want: ErrImmutableResourceID},
		{name: "environment ID", mutate: func(value *Operation) { value.EnvironmentID = idPointer("env_01J11111111111111111111111") }, want: ErrImmutableProviderBinding},
		{name: "connection ID", mutate: func(value *Operation) { value.ProviderConnectionID = idPointer("pvc_01J11111111111111111111111") }, want: ErrImmutableProviderBinding},
		{name: "generation", mutate: func(value *Operation) { value.Generation++ }, want: ErrImmutableGeneration},
		{name: "created timestamp", mutate: func(value *Operation) { value.CreatedAt = "2026-09-03T01:02:00.000Z" }, want: ErrImmutableCreatedAt},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(validAfter)
			test.mutate(&candidate)
			err := CheckTransition(before, candidate)
			if !errors.Is(err, ErrInvalidTransition) || !errors.Is(err, test.want) {
				t.Fatalf("CheckTransition() error = %v, want transition and %v", err, test.want)
			}
		})
	}

	regressed := clone(validAfter)
	regressed.UpdatedAt = "2026-09-03T01:02:59.999Z"
	if err := CheckTransition(before, regressed); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatalf("CheckTransition(regressed time) error = %v", err)
	}
}

func TestTransitionRequiresNewResourceVersionForMaterialChange(t *testing.T) {
	t.Parallel()

	before := newProviderOperation(t)
	for _, version := range []string{"", before.ResourceVersion} {
		after, err := Transition(before, TransitionInput{
			Phase: PhaseRunning, Reason: "Reconciling", Message: before.Message,
			ResourceVersion: version, UpdatedAt: operationFixtureTime.Add(time.Minute),
		})
		if !errors.Is(err, ErrInvalidTransition) || !equal(after, before) {
			t.Fatalf("Transition(version %q) = %#v, %v", version, after, err)
		}
		if version == before.ResourceVersion && !errors.Is(err, ErrResourceVersionUnchanged) {
			t.Fatalf("Transition(unchanged version) error = %v", err)
		}
	}

	versionOnly := clone(before)
	versionOnly.ResourceVersion = "rv_version_only"
	versionOnly.UpdatedAt = "2026-09-03T01:04:00.000Z"
	if err := CheckTransition(before, versionOnly); !errors.Is(err, ErrNoMaterialChange) {
		t.Fatalf("CheckTransition(version only) error = %v", err)
	}
}

func TestOperationValidationMatrix(t *testing.T) {
	t.Parallel()

	valid := newProviderOperation(t)
	tests := []struct {
		name   string
		mutate func(*Operation)
		want   error
	}{
		{name: "ID", mutate: func(value *Operation) { value.ID = "short" }, want: ErrInvalidOperationID},
		{name: "workspace", mutate: func(value *Operation) { value.WorkspaceID = "short" }, want: ErrInvalidWorkspaceID},
		{name: "resource", mutate: func(value *Operation) { value.ResourceID = "short" }, want: ErrInvalidResourceID},
		{name: "generation", mutate: func(value *Operation) { value.Generation = 0 }, want: ErrInvalidGeneration},
		{name: "version", mutate: func(value *Operation) { value.ResourceVersion = "bad version" }, want: ErrInvalidResourceVersion},
		{name: "phase", mutate: func(value *Operation) { value.Phase = "Cancelled" }, want: ErrInvalidPhase},
		{name: "reason", mutate: func(value *Operation) { value.Reason = "provider.error" }, want: ErrInvalidReason},
		{name: "message utf8", mutate: func(value *Operation) { value.Message = string([]byte{0xff}) }, want: ErrInvalidMessage},
		{name: "message bound", mutate: func(value *Operation) { value.Message = strings.Repeat("界", maxMessageRunes+1) }, want: ErrInvalidMessage},
		{name: "message byte preflight", mutate: func(value *Operation) { value.Message = strings.Repeat("x", 1<<20) }, want: ErrInvalidMessage},
		{name: "cost", mutate: func(value *Operation) { value.CostEstimate = costPointer(invalidCost()) }, want: control.ErrInvalidCostEstimate},
		{name: "created timestamp", mutate: func(value *Operation) { value.CreatedAt = "2026-09-03T01:03:00Z" }, want: ErrInvalidTimestamp},
		{name: "timestamp byte preflight", mutate: func(value *Operation) { value.CreatedAt = strings.Repeat("0", 1<<20) }, want: ErrInvalidTimestamp},
		{name: "updated before created", mutate: func(value *Operation) { value.UpdatedAt = "2026-09-03T01:02:59.999Z" }, want: ErrInvalidTimestamp},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := clone(valid)
			test.mutate(&candidate)
			err := Validate(candidate)
			if !errors.Is(err, ErrInvalidOperation) || !errors.Is(err, test.want) {
				t.Fatalf("Validate() error = %v, want operation and %v", err, test.want)
			}
		})
	}
}

func TestProviderBoundGoldenAndStrictCanonicalDecode(t *testing.T) {
	t.Parallel()

	value := runningProviderOperation(t)
	want, err := os.ReadFile("testdata/provider-bound.golden.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	want = bytes.TrimSpace(want)
	got, err := MarshalCanonical(value)
	if err != nil {
		t.Fatalf("MarshalCanonical() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes:\n got %s\nwant %s", got, want)
	}
	restored, err := UnmarshalCanonical(want)
	if err != nil {
		t.Fatalf("UnmarshalCanonical() error = %v", err)
	}
	if !equal(restored, value) {
		t.Fatalf("round trip differs: %#v / %#v", restored, value)
	}

	withUnknown := bytes.Replace(want, []byte(`"phase":"Running"`), []byte(`"phase":"Running","secret":"CustomerSecretValue"`), 1)
	if _, err := UnmarshalCanonical(withUnknown); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("UnmarshalCanonical(unknown member) error = %v", err)
	}
	withWhitespace := append(bytes.Clone(want), '\n')
	if _, err := UnmarshalCanonical(withWhitespace); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("UnmarshalCanonical(whitespace) error = %v", err)
	}
	duplicate := bytes.Replace(want, []byte(`"id":"`), []byte(`"id":"op_01J111111111111111111111111","id":"`), 1)
	if _, err := UnmarshalCanonical(duplicate); !errors.Is(err, ErrNonCanonical) {
		t.Fatalf("UnmarshalCanonical(duplicate member) error = %v", err)
	}
	if _, err := UnmarshalCanonical(make([]byte, MaxCanonicalBytes+1)); !errors.Is(err, ErrCanonicalTooLarge) {
		t.Fatalf("UnmarshalCanonical(over limit) error = %v", err)
	}
}

func TestOperationClonesOptionalValues(t *testing.T) {
	t.Parallel()

	environment := environmentID
	connection := connectionID
	estimate := knownCost()
	value, err := New(Input{
		ID: operationID, WorkspaceID: workspaceID, ResourceID: resourceID,
		EnvironmentID: &environment, ProviderConnectionID: &connection,
		Generation: 3, ResourceVersion: "rv_target", CostEstimate: &estimate,
		CreatedAt: operationFixtureTime,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	environment = "env_01J11111111111111111111111"
	connection = "pvc_01J11111111111111111111111"
	*estimate.Amount = "99"
	if *value.EnvironmentID != environmentID || *value.ProviderConnectionID != connectionID || *value.CostEstimate.Amount != "12.34" {
		t.Fatal("New() retained caller pointer aliases")
	}
}

func TestOperationErrorsDoNotContainValues(t *testing.T) {
	t.Parallel()

	sensitive := "customer-secret-operation-value"
	value := newProviderOperation(t)
	value.Message = sensitive + strings.Repeat("x", maxMessageRunes)
	err := Validate(value)
	if err == nil {
		t.Fatal("Validate() unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), sensitive) {
		t.Fatalf("error contains operation value: %q", err)
	}
}

func newProviderOperation(t *testing.T) Operation {
	t.Helper()
	value, err := New(Input{
		ID: operationID, WorkspaceID: workspaceID, ResourceID: resourceID,
		EnvironmentID: idPointer(environmentID), ProviderConnectionID: idPointer(connectionID),
		Generation: 3, ResourceVersion: "rv_01J00000000000000000000030",
		Reason: "Accepted", Message: "The desired state was accepted.", CreatedAt: operationFixtureTime,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return value
}

func runningProviderOperation(t *testing.T) Operation {
	t.Helper()
	value, err := Transition(newProviderOperation(t), TransitionInput{
		Phase: PhaseRunning, Reason: "Reconciling",
		Message:      "The current generation is being reconciled.",
		CostEstimate: costPointer(knownCost()), ResourceVersion: "rv_01J00000000000000000000031",
		UpdatedAt: operationFixtureTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Transition(Running) error = %v", err)
	}
	return value
}

func knownCost() control.CostEstimate {
	amount := "12.34"
	return control.CostEstimate{
		State: control.CostKnown, Amount: &amount, Currency: "USD", Region: "us-east-1",
		Source: "provider-observation", ObservedAt: "2026-09-03T01:02:03.000Z",
		Confidence: control.ConfidenceHigh, Reason: "ProviderCatalog",
	}
}

func invalidCost() control.CostEstimate {
	value := knownCost()
	value.Currency = "usd"
	return value
}

func costPointer(value control.CostEstimate) *control.CostEstimate {
	return &value
}

func idPointer(value resource.ID) *resource.ID {
	return &value
}
