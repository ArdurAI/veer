package audit

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestClosedVocabularyOrderAndParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		got    any
		want   any
		parse  func(string) error
		values []string
	}{
		{"streams", StreamKinds(), []StreamKind{StreamKindWorkspace, StreamKindPlatform}, func(value string) error { _, err := ParseStreamKind(value); return err }, []string{"Workspace", "Platform"}},
		{"actors", ActorKinds(), []ActorKind{ActorKindAnonymous, ActorKindHuman, ActorKindWorkload, ActorKindAdministrator}, func(value string) error { _, err := ParseActorKind(value); return err }, []string{"Anonymous", "Human", "Workload", "Administrator"}},
		{"authentication", AuthenticationMethods(), []AuthenticationMethod{AuthenticationMethodNone, AuthenticationMethodOIDC, AuthenticationMethodWorkloadOIDC, AuthenticationMethodStrongOIDC, AuthenticationMethodInternal}, func(value string) error { _, err := ParseAuthenticationMethod(value); return err }, []string{"None", "OIDC", "WorkloadOIDC", "StrongOIDC", "Internal"}},
		{"events", EventKinds(), []EventKind{EventKindRequest, EventKindAuthorization, EventKindOperation, EventKindProviderAttempt, EventKindElevation, EventKindExport, EventKindRetention, EventKindIntegrity}, func(value string) error { _, err := ParseEventKind(value); return err }, []string{"Request", "Authorization", "Operation", "ProviderAttempt", "Elevation", "Export", "Retention", "Integrity"}},
		{"sources", Sources(), []Source{SourceAPI, SourceWorker, SourceController, SourceProviderAdapter, SourceAdministration, SourceSystem}, func(value string) error { _, err := ParseSource(value); return err }, []string{"API", "Worker", "Controller", "ProviderAdapter", "Administration", "System"}},
		{"outcomes", Outcomes(), []Outcome{OutcomeAccepted, OutcomeSucceeded, OutcomeDenied, OutcomeFailed, OutcomeCanceled, OutcomeIndeterminate}, func(value string) error { _, err := ParseOutcome(value); return err }, []string{"Accepted", "Succeeded", "Denied", "Failed", "Canceled", "Indeterminate"}},
		{"clocks", ClockStates(), []ClockState{ClockStateSynchronized, ClockStateUncertain, ClockStateRegressed}, func(value string) error { _, err := ParseClockState(value); return err }, []string{"Synchronized", "Uncertain", "Regressed"}},
		{"elevations", ElevationStates(), []ElevationState{ElevationStateIssued, ElevationStateConsumed, ElevationStateRevoked, ElevationStateExpired}, func(value string) error { _, err := ParseElevationState(value); return err }, []string{"Issued", "Consumed", "Revoked", "Expired"}},
		{"algorithms", SignatureAlgorithms(), []SignatureAlgorithm{SignatureAlgorithmEd25519}, func(value string) error { _, err := ParseSignatureAlgorithm(value); return err }, []string{"Ed25519"}},
		{"holds", HoldKinds(), []HoldKind{HoldKindLegal, HoldKindIncident, HoldKindSecurity}, func(value string) error { _, err := ParseHoldKind(value); return err }, []string{"Legal", "Incident", "Security"}},
		{"retention", RetentionDispositions(), []RetentionDisposition{RetentionDispositionOnline, RetentionDispositionArchive, RetentionDispositionHeld, RetentionDispositionExpire}, func(value string) error { _, err := ParseRetentionDisposition(value); return err }, []string{"Online", "Archive", "Held", "Expire"}},
	}
	for _, test := range tests {
		if !reflect.DeepEqual(test.got, test.want) {
			t.Fatalf("%s registry = %#v, want %#v", test.name, test.got, test.want)
		}
		for _, value := range test.values {
			if err := test.parse(value); err != nil {
				t.Fatalf("%s parser rejected %q: %v", test.name, value, err)
			}
		}
		if err := test.parse("OpenEndedValue"); err == nil {
			t.Fatalf("%s parser accepted an open value", test.name)
		}
	}

	copy := EventKinds()
	copy[0] = EventKind("Mutated")
	if slices.Equal(copy, EventKinds()) {
		t.Fatal("EventKinds returned shared storage")
	}
}

func TestCanonicalEventGoldenAndStrictDecode(t *testing.T) {
	t.Parallel()

	event := mustRequestEvent(t, 1)
	got, err := MarshalCanonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/request-event.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v; got=%s", err, got)
	}
	want = bytes.TrimSpace(want)
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical event mismatch\ngot:  %s\nwant: %s", got, want)
	}
	parsed, err := UnmarshalCanonicalEvent(got)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := MarshalCanonicalEvent(parsed)
	if err != nil || !bytes.Equal(reencoded, got) {
		t.Fatalf("round trip = %s, %v", reencoded, err)
	}
	if len(got) > MaxCanonicalEventBytes {
		t.Fatalf("event bytes = %d", len(got))
	}
	generic, err := json.Marshal(event)
	if err != nil || !bytes.Equal(generic, got) {
		t.Fatalf("generic event JSON = %s, %v", generic, err)
	}
	var genericEvent Event
	if err := json.Unmarshal(got, &genericEvent); err != nil {
		t.Fatalf("generic event decode = %v", err)
	}
	var nilEvent *Event
	if err := nilEvent.UnmarshalJSON(got); err == nil {
		t.Fatal("nil event receiver accepted canonical input")
	}

	for _, invalid := range [][]byte{
		bytes.Replace(got, []byte(`"outcome":"Accepted"`), []byte(`"unknown":true,"outcome":"Accepted"`), 1),
		bytes.Replace(got, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1),
		bytes.Replace(got, []byte(`"recordedAt":"2026-`), []byte(`"recordedAt":"0000-`), 1),
		append(slices.Clone(got), ' '),
		bytes.Repeat([]byte{'x'}, MaxCanonicalEventBytes+1),
	} {
		if _, err := UnmarshalCanonicalEvent(invalid); err == nil {
			t.Fatalf("accepted non-canonical event: %.120q", invalid)
		}
		if len(invalid) <= MaxCanonicalEventBytes && invalid[len(invalid)-1] != ' ' {
			var decoded Event
			if err := json.Unmarshal(invalid, &decoded); err == nil {
				t.Fatalf("generic JSON accepted invalid event: %.120q", invalid)
			}
		}
	}
}

func TestActorAuthenticationPairingAndRequiredReferences(t *testing.T) {
	t.Parallel()

	valid := mustRequestEvent(t, 1)
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{"missing request", func(event *Event) { event.request = nil }},
		{"empty action", func(event *Event) { event.action = "" }},
		{"human none", func(event *Event) { event.authenticationMethod = AuthenticationMethodNone }},
		{"anonymous oidc", func(event *Event) { event.actor = AnonymousActor() }},
		{"zero sequence", func(event *Event) { event.sequence = 0 }},
		{"open kind", func(event *Event) { event.kind = "Other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := cloneEvent(valid)
			test.mutate(&event)
			if err := ValidateEvent(event); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("ValidateEvent() = %v", err)
			}
		})
	}
}

func TestOperationReferenceRetainsSafeTimelineAndProviderBinding(t *testing.T) {
	t.Parallel()

	event := mustProviderAttemptEvent(t, 1)
	reference, present := event.Operation()
	if !present {
		t.Fatal("operation reference missing")
	}
	environmentID, environmentPresent := reference.EnvironmentID()
	providerID, providerPresent := reference.ProviderConnectionID()
	if !environmentPresent || !providerPresent || environmentID != testEnvironmentID || providerID != testConnectionID {
		t.Fatalf("provider binding = %s/%t %s/%t", environmentID, environmentPresent, providerID, providerPresent)
	}
	if reference.ID() != testOperationID || reference.ResourceID() != testResourceID ||
		reference.Generation() != 7 || reference.ResourceVersion() != "rv_audit_operation_1" ||
		reference.Reason() != "ProviderExecution" || !reference.UpdatedAt().Equal(testTime) {
		t.Fatalf("operation reference drifted: %#v", reference)
	}
	data, err := MarshalCanonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("excluded-message-canary")) || bytes.Contains(data, []byte("costEstimate")) {
		t.Fatalf("operation projection leaked excluded data: %s", data)
	}
	if _, err := UnmarshalCanonicalEvent(data); err != nil {
		t.Fatal(err)
	}
	wire := eventToWire(event)
	wire.Operation.UpdatedAt = "0000-09-03T12:34:56.789Z"
	invalidTime, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCanonicalEvent(invalidTime); err == nil {
		t.Fatal("canonical operation reference accepted year zero")
	}

	broken := cloneEvent(event)
	broken.operation.providerConnectionID = nil
	if err := ValidateEvent(broken); err == nil {
		t.Fatal("accepted one-sided provider binding")
	}
}

func TestProviderAttemptRequiresMatchingWorkspaceStream(t *testing.T) {
	t.Parallel()

	valid := mustProviderAttemptEvent(t, 1)
	operationReference, operationPresent := valid.Operation()
	attemptReference, attemptPresent := valid.Attempt()
	if !operationPresent || !attemptPresent {
		t.Fatal("provider-attempt fixture omitted required references")
	}
	otherWorkspaceID := resource.ID("wsp_01JAUDIT00000000000000001")
	otherWorkspace, err := NewWorkspaceStream(otherWorkspaceID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		stream Stream
	}{
		{name: "platform stream", stream: NewPlatformStream()},
		{name: "different workspace stream", stream: otherWorkspace},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewEvent(EventInput{
				ID:                   eventID(2),
				Stream:               test.stream,
				Sequence:             2,
				RecordedAt:           testTime.Add(time.Millisecond),
				ClockState:           valid.ClockState(),
				Kind:                 valid.Kind(),
				Source:               valid.Source(),
				Actor:                valid.Actor(),
				AuthenticationMethod: valid.AuthenticationMethod(),
				Action:               valid.Action(),
				Operation:            &operationReference,
				Attempt:              &attemptReference,
				Outcome:              valid.Outcome(),
			})
			if !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("NewEvent() = %v, want %v", err, ErrWorkspaceMismatch)
			}

			wire := eventToWire(valid)
			wire.Stream = streamToWire(test.stream)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("UnmarshalCanonicalEvent() = %v, want %v; event=%s", err, ErrWorkspaceMismatch, data)
			}
		})
	}
}

func TestOperationRequiresMatchingWorkspaceStream(t *testing.T) {
	t.Parallel()

	valid := mustOperationEvent(t, 1)
	operationReference, present := valid.Operation()
	if !present {
		t.Fatal("operation event fixture omitted operation reference")
	}
	otherWorkspace, err := NewWorkspaceStream(resource.ID("wsp_01JAUDIT00000000000000001"))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		stream Stream
	}{
		{name: "platform stream", stream: NewPlatformStream()},
		{name: "different workspace stream", stream: otherWorkspace},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewEvent(EventInput{
				ID:                   eventID(2),
				Stream:               test.stream,
				Sequence:             2,
				RecordedAt:           testTime.Add(time.Millisecond),
				ClockState:           valid.ClockState(),
				Kind:                 valid.Kind(),
				Source:               valid.Source(),
				Actor:                valid.Actor(),
				AuthenticationMethod: valid.AuthenticationMethod(),
				Action:               valid.Action(),
				Operation:            &operationReference,
				Outcome:              valid.Outcome(),
			})
			if !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("NewEvent() = %v, want %v", err, ErrWorkspaceMismatch)
			}

			wire := eventToWire(valid)
			wire.Stream = streamToWire(test.stream)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("UnmarshalCanonicalEvent() = %v, want %v; event=%s", err, ErrWorkspaceMismatch, data)
			}
		})
	}
}

func TestUnboundOperationAcceptsHierarchyDerivedTarget(t *testing.T) {
	t.Parallel()

	snapshot := mustHierarchySnapshot(t)
	actor, err := ActorFromPrincipal(mustWorkloadPrincipal(t))
	if err != nil {
		t.Fatal(err)
	}
	for index, test := range []struct {
		name       string
		resourceID resource.ID
	}{
		{name: "environment", resourceID: testEnvironmentID},
		{name: "application", resourceID: testApplicationID},
		{name: "component", resourceID: testResourceID},
		{name: "provider connection", resourceID: testConnectionID},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := operation.New(operation.Input{
				ID:              resource.ID(fmt.Sprintf("op_01JAUDIT%016d", index+10)),
				WorkspaceID:     testWorkspaceID,
				ResourceID:      test.resourceID,
				Generation:      1,
				ResourceVersion: fmt.Sprintf("rv_audit_unbound_%d", index),
				CreatedAt:       testTime,
			})
			if err != nil {
				t.Fatal(err)
			}
			operationReference, err := OperationRefFromOperation(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := operationReference.EnvironmentID(); present {
				t.Fatal("unbound operation gained an environment reference")
			}
			if _, present := operationReference.ProviderConnectionID(); present {
				t.Fatal("unbound operation gained a provider reference")
			}

			target, err := authorization.ResolveResourceTarget(snapshot, test.resourceID)
			if err != nil {
				t.Fatal(err)
			}
			targetReference, err := TargetRefFromAuthorization(target)
			if err != nil {
				t.Fatal(err)
			}
			if environmentID, present := targetReference.EnvironmentID(); !present || environmentID != testEnvironmentID {
				t.Fatalf("hierarchy-derived environment = %q, %t", environmentID, present)
			}

			event, err := NewEvent(EventInput{
				ID:                   eventID(uint64(index + 10)),
				Stream:               mustWorkspaceStream(t),
				Sequence:             uint64(index + 10),
				RecordedAt:           testTime.Add(time.Duration(index) * time.Millisecond),
				ClockState:           ClockStateSynchronized,
				Kind:                 EventKindOperation,
				Source:               SourceController,
				Actor:                actor,
				AuthenticationMethod: AuthenticationMethodWorkloadOIDC,
				Action:               authorization.ActionResourceReplace,
				Target:               &targetReference,
				Operation:            &operationReference,
				Outcome:              OutcomeSucceeded,
			})
			if err != nil {
				t.Fatalf("NewEvent(unbound %s operation) = %v", test.name, err)
			}
			canonical, err := MarshalCanonicalEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(canonical); err != nil {
				t.Fatalf("UnmarshalCanonicalEvent(unbound %s operation) = %v", test.name, err)
			}
		})
	}
}

func TestBoundOperationRequiresExactTargetProviderScope(t *testing.T) {
	t.Parallel()

	elevationEvent := mustOperationElevationEvent(t)
	operationReference, operationPresent := elevationEvent.Operation()
	targetReference, targetPresent := elevationEvent.Target()
	if !operationPresent || !targetPresent {
		t.Fatal("bound elevation fixture omitted operation or target reference")
	}
	actor, err := ActorFromPrincipal(mustWorkloadPrincipal(t))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := NewEvent(EventInput{
		ID:                   eventID(1),
		Stream:               mustWorkspaceStream(t),
		Sequence:             1,
		RecordedAt:           testTime,
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindOperation,
		Source:               SourceController,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodWorkloadOIDC,
		Action:               authorization.ActionOperationGet,
		Target:               &targetReference,
		Operation:            &operationReference,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherID := resource.ID("ref_01JAUDIT00000000000000001")
	for _, test := range []struct {
		name       string
		mutateRef  func(*TargetRef)
		mutateWire func(*eventWire)
	}{
		{
			name:       "environment",
			mutateRef:  func(reference *TargetRef) { reference.environmentID = idPointer(otherID) },
			mutateWire: func(wire *eventWire) { wire.Target.EnvironmentID = otherID.String() },
		},
		{
			name:       "provider connection",
			mutateRef:  func(reference *TargetRef) { reference.providerConnectionID = idPointer(otherID) },
			mutateWire: func(wire *eventWire) { wire.Target.ProviderConnectionID = otherID.String() },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := eventInputFromEvent(valid)
			test.mutateRef(input.Target)
			if _, err := NewEvent(input); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("NewEvent() = %v, want %v", err, ErrWorkspaceMismatch)
			}

			wire := eventToWire(valid)
			test.mutateWire(&wire)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("UnmarshalCanonicalEvent() = %v, want %v; event=%s", err, ErrWorkspaceMismatch, data)
			}
		})
	}
}

func TestReferenceStreamScopeIsExact(t *testing.T) {
	t.Parallel()

	snapshot := mustHierarchySnapshot(t)
	target, err := authorization.ResolveResourceTarget(snapshot, testResourceID)
	if err != nil {
		t.Fatal(err)
	}
	targetReference, err := TargetRefFromAuthorization(target)
	if err != nil {
		t.Fatal(err)
	}
	targetEvent := mustRequestEvent(t, 1)
	targetEvent.target = &targetReference
	workspaceElevation := mustOperationElevationEvent(t)
	workspaceElevation.target = nil
	workspaceElevation.operation = nil
	otherWorkspace, err := NewWorkspaceStream(resource.ID("wsp_01JAUDIT00000000000000001"))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name          string
		valid         Event
		invalidStream Stream
	}{
		{name: "target on platform", valid: targetEvent, invalidStream: NewPlatformStream()},
		{name: "target on different workspace", valid: targetEvent, invalidStream: otherWorkspace},
		{name: "workspace elevation on platform", valid: workspaceElevation, invalidStream: NewPlatformStream()},
		{name: "workspace elevation on different workspace", valid: workspaceElevation, invalidStream: otherWorkspace},
		{name: "platform elevation on workspace", valid: mustPlatformAuditElevationEvent(t), invalidStream: mustWorkspaceStream(t)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateEvent(test.valid); err != nil {
				t.Fatalf("valid control = %v", err)
			}
			input := eventInputFromEvent(test.valid)
			input.Stream = test.invalidStream
			if _, err := NewEvent(input); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("NewEvent() = %v, want %v", err, ErrWorkspaceMismatch)
			}

			wire := eventToWire(test.valid)
			wire.Stream = streamToWire(test.invalidStream)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("UnmarshalCanonicalEvent() = %v, want %v; event=%s", err, ErrWorkspaceMismatch, data)
			}
		})
	}
}

func TestCanonicalDecodeRejectsImpossibleAuthorizationTargetRelabels(t *testing.T) {
	t.Parallel()

	environmentID := testEnvironmentID
	target := TargetRef{
		initialized:   true,
		objectKind:    authorization.ObjectKindResource,
		objectID:      testEnvironmentID,
		resourceKind:  "Environment",
		resourceID:    testEnvironmentID,
		workspaceID:   testWorkspaceID,
		environmentID: &environmentID,
	}
	base := mustRequestEvent(t, 1)
	base.target = &target
	if err := ValidateEvent(base); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*eventWire)
	}{
		{"resource object mismatch", func(wire *eventWire) { wire.Target.ObjectID = testResourceID.String() }},
		{"workspace with environment", func(wire *eventWire) { wire.Target.ResourceKind = "Workspace" }},
		{"membership on environment", func(wire *eventWire) { wire.Target.ObjectKind = authorization.ObjectKindMembership }},
		{"audit on environment", func(wire *eventWire) { wire.Target.ObjectKind = authorization.ObjectKindAudit }},
		{"audit with provider", func(wire *eventWire) {
			wire.Target.ObjectKind = authorization.ObjectKindAudit
			wire.Target.ProviderConnectionID = testConnectionID.String()
		}},
		{"operation provider without environment", func(wire *eventWire) {
			wire.Target.ObjectKind = authorization.ObjectKindOperation
			wire.Target.ProviderConnectionID = testConnectionID.String()
			wire.Target.EnvironmentID = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := eventToWire(base)
			test.mutate(&wire)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); err == nil {
				t.Fatalf("accepted impossible target: %s", data)
			}
		})
	}
}

func TestElevationProjectionReconstructsAndRedactsTimeline(t *testing.T) {
	const (
		reasonCanary = "Emergency export for incident response"
		caseCanary   = "INCIDENT-PRIVATE-417"
	)
	grant, ledger := mustAdministrationGrant(t, reasonCanary, caseCanary)

	issued, err := ElevationRefFromGrant(grant, ElevationStateIssued)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := ElevationRefFromGrant(grant, ElevationStateExpired)
	if err != nil {
		t.Fatal(err)
	}
	if issued.RecordedAt() != grant.IssuedAt() || expired.RecordedAt() != grant.ExpiresAt() {
		t.Fatal("grant lifecycle projection lost its boundary time")
	}
	if _, err := ElevationRefFromGrant(grant, ElevationStateConsumed); err == nil {
		t.Fatal("grant projected consumption without a receipt")
	}

	consumption, err := ledger.Consume(
		testTime.Add(time.Minute),
		grant,
		authorization.ActionAuditExport,
		administration.ResolvePlatformAuditExportTarget(),
	)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := ElevationRefFromConsumption(consumption)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.State() != ElevationStateConsumed || consumed.Reason() != reasonCanary ||
		consumed.IssuedAt() != grant.IssuedAt() || consumed.ExpiresAt() != grant.ExpiresAt() {
		t.Fatal("consumption projection lost required evidence")
	}
	if got, present := consumed.CaseReference(); !present || got != caseCanary {
		t.Fatalf("case reference = %q, %t", got, present)
	}

	actor, err := AdministratorActor(testAdministratorID)
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(1),
		Stream:               NewPlatformStream(),
		Sequence:             1,
		RecordedAt:           consumed.RecordedAt(),
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindElevation,
		Source:               SourceAdministration,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodStrongOIDC,
		Action:               consumed.Action(),
		Elevation:            &consumed,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := MarshalCanonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canonical, []byte(reasonCanary)) || !bytes.Contains(canonical, []byte(caseCanary)) {
		t.Fatalf("canonical elevation omitted required reason/case: %s", canonical)
	}
	if _, err := UnmarshalCanonicalEvent(canonical); err != nil {
		t.Fatal(err)
	}

	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	logger.Info("elevation", "reference", consumed)
	for name, output := range map[string]string{
		"String":   consumed.String(),
		"GoString": fmt.Sprintf("%#v", consumed),
		"format":   fmt.Sprintf("%+v", consumed),
		"slog":     logOutput.String(),
	} {
		for _, canary := range []string{reasonCanary, caseCanary, testAdministratorID.String()} {
			if strings.Contains(output, canary) {
				t.Fatalf("%s exposed elevation canary %q: %s", name, canary, output)
			}
		}
	}
}

func TestCanonicalDecodeRejectsImpossibleElevationTargetAndActionRelabels(t *testing.T) {
	t.Parallel()

	grant, _ := mustAdministrationGrant(t, "Emergency audit export", "CASE-417")
	elevation, err := ElevationRefFromGrant(grant, ElevationStateIssued)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := AdministratorActor(elevation.AdministratorID())
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(EventInput{
		ID:                   eventID(1),
		Stream:               NewPlatformStream(),
		Sequence:             1,
		RecordedAt:           elevation.RecordedAt(),
		ClockState:           ClockStateSynchronized,
		Kind:                 EventKindElevation,
		Source:               SourceAdministration,
		Actor:                actor,
		AuthenticationMethod: AuthenticationMethodStrongOIDC,
		Action:               elevation.Action(),
		Elevation:            &elevation,
		Outcome:              OutcomeSucceeded,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*eventWire)
	}{
		{"platform target with workspace", func(wire *eventWire) {
			wire.Elevation.WorkspaceID = testWorkspaceID.String()
		}},
		{"workspace target missing IDs", func(wire *eventWire) {
			wire.Elevation.TargetKind = "WorkspaceAudit"
		}},
		{"workspace target unequal IDs", func(wire *eventWire) {
			wire.Elevation.TargetKind = "WorkspaceAudit"
			wire.Elevation.WorkspaceID = testWorkspaceID.String()
			wire.Elevation.ObjectID = testResourceID.String()
			wire.Elevation.ResourceID = testWorkspaceID.String()
		}},
		{"workspace target with environment", func(wire *eventWire) {
			wire.Elevation.TargetKind = "WorkspaceAudit"
			wire.Elevation.WorkspaceID = testWorkspaceID.String()
			wire.Elevation.ObjectID = testWorkspaceID.String()
			wire.Elevation.ResourceID = testWorkspaceID.String()
			wire.Elevation.EnvironmentID = testEnvironmentID.String()
		}},
		{"operation target missing scope", func(wire *eventWire) {
			wire.Action = authorization.ActionOperationQuarantine
			wire.Elevation.Action = authorization.ActionOperationQuarantine
			wire.Elevation.TargetKind = "Operation"
		}},
		{"operation provider without environment", func(wire *eventWire) {
			wire.Action = authorization.ActionOperationQuarantine
			wire.Elevation.Action = authorization.ActionOperationQuarantine
			wire.Elevation.TargetKind = "Operation"
			wire.Elevation.ObjectID = testOperationID.String()
			wire.Elevation.WorkspaceID = testWorkspaceID.String()
			wire.Elevation.ResourceID = testResourceID.String()
			wire.Elevation.ProviderConnectionID = testConnectionID.String()
		}},
		{"audit action on operation", func(wire *eventWire) {
			wire.Elevation.TargetKind = "Operation"
			wire.Elevation.ObjectID = testOperationID.String()
			wire.Elevation.WorkspaceID = testWorkspaceID.String()
			wire.Elevation.ResourceID = testResourceID.String()
		}},
		{"operation action on platform audit", func(wire *eventWire) {
			wire.Action = authorization.ActionOperationQuarantine
			wire.Elevation.Action = authorization.ActionOperationQuarantine
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := eventToWire(event)
			test.mutate(&wire)
			data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := UnmarshalCanonicalEvent(data); err == nil {
				t.Fatalf("accepted impossible elevation: %s", data)
			}
		})
	}

	operationEvent := mustOperationElevationEvent(t)
	operationWire := eventToWire(operationEvent)
	operationWire.Elevation.ProviderConnectionID = ""
	data, err := jsonv2.Marshal(operationWire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCanonicalEvent(data); err == nil {
		t.Fatal("canonical elevation accepted environment without provider")
	}

	operationWire = eventToWire(operationEvent)
	operationWire.Elevation.IssuedAt = "0000-09-03T12:34:56.789Z"
	data, err = jsonv2.Marshal(operationWire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCanonicalEvent(data); err == nil {
		t.Fatal("canonical elevation accepted year zero")
	}
}

func TestElevationCoReferencesMustMatchEverySharedScopeID(t *testing.T) {
	t.Parallel()

	valid := mustOperationElevationEvent(t)
	if err := ValidateEvent(valid); err != nil {
		t.Fatal(err)
	}
	otherID := resource.ID("ref_01JAUDIT00000000000000001")
	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{"operation object", func(event *Event) {
			event.target = nil
			event.operation.id = otherID
		}},
		{"operation workspace", func(event *Event) {
			event.target = nil
			event.operation.workspaceID = otherID
		}},
		{"operation resource", func(event *Event) {
			event.target = nil
			event.operation.resourceID = otherID
		}},
		{"operation environment", func(event *Event) {
			event.target = nil
			event.operation.environmentID = idPointer(otherID)
		}},
		{"operation provider", func(event *Event) {
			event.target = nil
			event.operation.providerConnectionID = idPointer(otherID)
		}},
		{"target object", func(event *Event) {
			event.operation = nil
			event.target.objectID = otherID
		}},
		{"target workspace", func(event *Event) {
			event.operation = nil
			event.target.workspaceID = otherID
		}},
		{"target resource", func(event *Event) {
			event.operation = nil
			event.target.resourceID = otherID
		}},
		{"target environment", func(event *Event) {
			event.operation = nil
			event.target.environmentID = idPointer(otherID)
		}},
		{"target provider", func(event *Event) {
			event.operation = nil
			event.target.providerConnectionID = idPointer(otherID)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := cloneEvent(valid)
			test.mutate(&event)
			if err := ValidateEvent(event); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("ValidateEvent() = %v", err)
			}
		})
	}

	platformGrant, _ := mustAdministrationGrant(t, "Emergency audit export", "CASE-417")
	platformElevation, err := ElevationRefFromGrant(platformGrant, ElevationStateIssued)
	if err != nil {
		t.Fatal(err)
	}
	platform := cloneEvent(valid)
	platform.action = authorization.ActionAuditExport
	platform.elevation = &platformElevation
	platform.recordedAt = platformElevation.recordedAt
	if err := ValidateEvent(platform); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("platform elevation accepted unrelated co-references: %v", err)
	}
}

func TestEventContainsOnlyPseudonymousPrincipalAttribution(t *testing.T) {
	t.Parallel()

	event := mustRequestEvent(t, 1)
	data, err := MarshalCanonicalEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{testIssuerCanary, testSubjectCanary, testGroupCanary} {
		if bytes.Contains(data, []byte(canary)) || strings.Contains(fmt.Sprintf("%#v", event), canary) {
			t.Fatalf("personal identity claim leaked: %q", canary)
		}
	}
	actor := event.Actor()
	pseudonym, present := actor.Pseudonym()
	if !present || !strings.HasPrefix(pseudonym, "prn1_") {
		t.Fatalf("actor pseudonym = %q, %t", pseudonym, present)
	}
}
