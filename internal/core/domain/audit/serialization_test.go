package audit

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestOpaqueRuntimeValuesForbidLossyGenericSerialization(t *testing.T) {
	t.Parallel()

	requestEvent := mustRequestEvent(t, 1)
	request, _ := requestEvent.Request()
	providerEvent := mustProviderAttemptEvent(t, 1)
	operationReference, _ := providerEvent.Operation()
	attempt, _ := providerEvent.Attempt()
	grant, _ := mustAdministrationGrant(t, "Emergency audit export", "CASE-417")
	elevation, err := ElevationRefFromGrant(grant, ElevationStateIssued)
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	segment, terminal, err := NewSegment(genesis, []Event{requestEvent})
	if err != nil {
		t.Fatal(err)
	}
	rangeValue, _ := segment.Range()
	hold, err := NewHold(testHoldID, HoldKindSecurity)
	if err != nil {
		t.Fatal(err)
	}
	retention, err := EvaluateRetention(RetentionInput{
		RecordedAt:          testTime,
		EvaluatedAt:         testTime.Add(ArchiveRetention),
		PreviousEvaluatedAt: testTime,
		ClockState:          ClockStateSynchronized,
	})
	if err != nil {
		t.Fatal(err)
	}
	actorPseudonym, _ := requestEvent.Actor().Pseudonym()
	serializationCanaries := []string{
		testWorkspaceID.String(),
		testOperationID.String(),
		testAttemptID.String(),
		testAdministratorID.String(),
		actorPseudonym,
		"Emergency audit export",
		"CASE-417",
	}
	values := map[string]any{
		"stream":             requestEvent.Stream(),
		"actor":              requestEvent.Actor(),
		"request":            request,
		"target":             TargetRef{},
		"decision":           DecisionRef{},
		"operation":          operationReference,
		"attempt":            attempt,
		"elevation":          elevation,
		"checkpoint":         terminal,
		"record":             segment.Records()[0],
		"range":              rangeValue,
		"hold":               hold,
		"retention decision": retention,
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			if encoded, err := json.Marshal(value); !errors.Is(err, ErrSerializationForbidden) || len(encoded) != 0 {
				t.Fatalf("json.Marshal = %q, %v", encoded, err)
			}
			textValue, ok := value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("value does not implement encoding.TextMarshaler")
			}
			if encoded, err := textValue.MarshalText(); !errors.Is(err, ErrSerializationForbidden) || len(encoded) != 0 {
				t.Fatalf("MarshalText = %q, %v", encoded, err)
			}
			binaryValue, ok := value.(encoding.BinaryMarshaler)
			if !ok {
				t.Fatal("value does not implement encoding.BinaryMarshaler")
			}
			if encoded, err := binaryValue.MarshalBinary(); !errors.Is(err, ErrSerializationForbidden) || len(encoded) != 0 {
				t.Fatalf("MarshalBinary = %q, %v", encoded, err)
			}
			var encoded bytes.Buffer
			gobErr := gob.NewEncoder(&encoded).Encode(value)
			if !errors.Is(gobErr, ErrSerializationForbidden) {
				t.Fatalf("gob Encode = %v", gobErr)
			}
			for _, canary := range serializationCanaries {
				if strings.Contains(encoded.String(), canary) || strings.Contains(gobErr.Error(), canary) {
					t.Fatalf("gob Encode(%T) exposed %q", value, canary)
				}
			}
		})
	}

	containers := []any{
		struct{ Checkpoint Checkpoint }{Checkpoint: terminal},
		[]Record{segment.Records()[0]},
		struct{ Actor ActorRef }{Actor: requestEvent.Actor()},
	}
	for _, container := range containers {
		if encoded, err := json.Marshal(container); !errors.Is(err, ErrSerializationForbidden) || len(encoded) != 0 {
			t.Fatalf("nested json.Marshal(%T) = %q, %v", container, encoded, err)
		}
	}

	// Digest text values are intentionally typed, lossless wire scalars rather
	// than runtime-only containers.
	if encoded, err := json.Marshal(genesis.Digest()); err != nil || !bytes.Contains(encoded, []byte(ChainDigestPrefix)) {
		t.Fatalf("chain digest JSON = %q, %v", encoded, err)
	}

	diagnosticValues := append([]any{}, requestEvent.Stream(), requestEvent.Actor(), request, operationReference, attempt,
		elevation, terminal, segment.Records()[0], rangeValue, segment, hold, retention)
	for _, value := range diagnosticValues {
		for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%o", "%f"} {
			output := fmt.Sprintf(format, value)
			for _, canary := range serializationCanaries {
				if strings.Contains(output, canary) {
					t.Fatalf("format %q of %T exposed %q: %s", format, value, canary, output)
				}
			}
		}
		var logOutput bytes.Buffer
		slog.New(slog.NewTextHandler(&logOutput, nil)).Info("audit diagnostic", "value", value)
		for _, canary := range serializationCanaries {
			if strings.Contains(logOutput.String(), canary) {
				t.Fatalf("slog of %T exposed %q: %s", value, canary, logOutput.String())
			}
		}
	}
}
