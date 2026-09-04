package reconciliation

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
	"time"
)

func TestOpaqueValuesRejectGenericSerializationAndRedactDiagnostics(t *testing.T) {
	fixture := newPlanFixture(t, 1, 71, true)
	effect := mustEffect(t, fixture.plan, "secret-effect-canary")
	table, token := mustLease(t, fixture, fixtureTime.Add(time.Second))
	prepared := mustPreparedAttempt(
		t,
		fixture,
		effect,
		AttemptPurposeForward,
		901,
		token,
		fixtureTime.Add(time.Second),
	)
	authority, permit := mustPermit(
		t, fixture, fixture.op, fixtureTime.Add(time.Second), table, token, prepared, 5*time.Second,
	)
	attempt := mustAttempt(t, fixture, effect, AttemptStateIndeterminate, 1)
	projection, err := EffectProjectionFromAttempt(attempt)
	requireSafetyNoError(t, err)
	retryProof, err := NewRetryProof(
		effect, attempt.requestFingerprint, "secret-adapter-version", fixtureTime.Add(time.Hour), []byte("secret-proof-canary"),
	)
	requireSafetyNoError(t, err)
	next := nextGenerationFixture(t, fixture, 2, 72)
	nextEffect := mustEffect(t, next.plan, "secret-effect-canary")
	supersession, err := NewSafeSupersessionProof(
		effect,
		nextEffect,
		"secret-adapter-version",
		[]byte("secret-proof-canary"),
	)
	requireSafetyNoError(t, err)
	compensation := fixture.candidate(
		t, 2, PlanKindCompensation,
		mustEvidence(t, EvidenceObservedSnapshot, "observation-2", []byte("changed")),
		[]EffectKey{effect}, []EffectKey{effect},
	)
	inverse := mustEffect(t, compensation, "inverse")
	appliedProjection, err := EffectProjectionFromAttempt(
		mustAttempt(t, fixture, effect, AttemptStateApplied, 2),
	)
	requireSafetyNoError(t, err)
	compensationProof, err := NewCompensationProof(
		appliedProjection, inverse, 1, "secret-adapter-version", []byte("secret-proof-canary"),
	)
	requireSafetyNoError(t, err)
	compensationStep, err := NextCompensationStep(
		compensation,
		[]CompensationProof{compensationProof},
		nil,
	)
	requireSafetyNoError(t, err)
	bundle, err := NewTransitionBundle(TransitionBundleInput{AttemptWrite: true})
	requireSafetyNoError(t, err)
	budget, err := NewObservationBudget(effect, 2, fixtureTime.Add(time.Hour))
	requireSafetyNoError(t, err)
	budget, observationPermit, err := ReserveObservation(budget, fixtureTime)
	requireSafetyNoError(t, err)
	attemptAdmission, err := NewAttemptAdmission(AttemptAdmissionInput{
		DatabaseTime: fixtureTime, Plan: fixture.plan, Effect: effect,
		Purpose: AttemptPurposeForward, RequestFingerprint: mustRequestFingerprint(t, "secret-admission-canary"),
	})
	requireSafetyNoError(t, err)
	replacementAuthority, _, err := AuthorizeGenerationReplacement(
		fixture.plan,
		next.plan,
		generationReplacementInput(t, next.plan, 72),
	)
	requireSafetyNoError(t, err)
	scope, err := NewIdempotencyScope(fixture.actor, "PUT", []byte("/secret-target-canary"))
	requireSafetyNoError(t, err)
	idempotencyLedger, err := NewIdempotencyLedger(2)
	requireSafetyNoError(t, err)
	reservation, disposition, err := idempotencyLedger.Reserve(
		fixtureTime, scope, fixtureIdempotencyKey, mustRequestFingerprint(t, "secret-request-canary"),
	)
	if err != nil || disposition != IdempotencyReserved {
		t.Fatalf("idempotency reservation = %s, %v", disposition, err)
	}
	deliveryLedger, err := NewDeliveryLedger(2)
	requireSafetyNoError(t, err)
	queueBudget, err := NewQueueBudget(10, 2)
	requireSafetyNoError(t, err)
	work, err := NewWorkKey(fixture.plan, []byte("queue-work"))
	requireSafetyNoError(t, err)
	queueReservation, err := queueBudget.Reserve(work, 2)
	requireSafetyNoError(t, err)
	leaseTable, err := NewLeaseTable(2)
	requireSafetyNoError(t, err)
	binding, err := LeaseBindingFromPlan(fixture.plan)
	requireSafetyNoError(t, err)

	values := []any{
		fixture.desired,
		*fixture.provider,
		fixture.plan,
		effect,
		scope,
		reservation,
		binding,
		token,
		authority,
		permit,
		replacementAuthority,
		attemptAdmission,
		attempt,
		projection,
		retryProof,
		supersession,
		compensationProof,
		compensationStep,
		bundle,
		budget,
		observationPermit,
		idempotencyLedger,
		deliveryLedger,
		queueReservation,
		queueBudget,
		leaseTable,
	}
	invalidPermit := permit
	invalidPermit.authorizedAt = time.Time{}
	if got := invalidPermit.String(); got != "reconciliation-dispatch-permit(invalid)" {
		t.Fatalf("invalid dispatch permit diagnostic = %q", got)
	}
	canaries := []string{
		fixture.op.ID.String(), fixture.op.WorkspaceID.String(), fixture.op.ResourceID.String(),
		fixture.actor.Issuer(), fixture.actor.Subject(), "secret-adapter-version", "secret-proof-canary",
		"secret-request-canary", "secret-target-canary", "secret-effect-canary",
		"secret-admission-canary",
	}
	for _, value := range values {
		value := value
		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			if _, err := json.Marshal(value); !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("json error = %v", err)
			}
			text, ok := value.(encoding.TextMarshaler)
			if !ok {
				t.Fatalf("%T lacks TextMarshaler rejection", value)
			}
			if _, err := text.MarshalText(); !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("text error = %v", err)
			}
			binary, ok := value.(encoding.BinaryMarshaler)
			if !ok {
				t.Fatalf("%T lacks BinaryMarshaler rejection", value)
			}
			if _, err := binary.MarshalBinary(); !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("binary error = %v", err)
			}
			var gobbed bytes.Buffer
			if err := gob.NewEncoder(&gobbed).Encode(value); !errors.Is(err, ErrSerializationForbidden) {
				t.Fatalf("gob error = %v", err)
			}
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
				assertNoCanary(t, fmt.Sprintf(format, value), canaries)
			}
			var logged bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logged, nil))
			logger.Info("value", "item", value)
			assertNoCanary(t, logged.String(), canaries)
		})
	}
}

func requireSafetyNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTypedPersistentDigestsRoundTripWithoutCrossTypeParsing(t *testing.T) {
	t.Parallel()
	fixture := newPlanFixture(t, 1, 73, false)
	work, err := NewWorkKey(fixture.plan, []byte("work"))
	requireSafetyNoError(t, err)
	fingerprint := mustRequestFingerprint(t, "request")
	result := mustResultDigest(t, "result")
	tests := []struct {
		name  string
		value string
		parse func(string) error
	}{
		{name: "evidence", value: fixture.desired.digest.String(), parse: func(raw string) error {
			parsed, err := ParseEvidenceDigest(raw)
			if err == nil && !parsed.Equal(fixture.desired.digest) {
				return ErrInvalidDigest
			}
			return err
		}},
		{name: "plan", value: fixture.plan.digest.String(), parse: func(raw string) error {
			parsed, err := ParsePlanDigest(raw)
			if err == nil && !parsed.Equal(fixture.plan.digest) {
				return ErrInvalidDigest
			}
			return err
		}},
		{name: "request", value: fingerprint.String(), parse: func(raw string) error {
			parsed, err := ParseRequestFingerprint(raw)
			if err == nil && !parsed.Equal(fingerprint) {
				return ErrInvalidDigest
			}
			return err
		}},
		{name: "result", value: result.String(), parse: func(raw string) error {
			parsed, err := ParseResultDigest(raw)
			if err == nil && !parsed.Equal(result) {
				return ErrInvalidDigest
			}
			return err
		}},
		{name: "work", value: work.String(), parse: func(raw string) error {
			parsed, err := ParseWorkKey(raw)
			if err == nil && !parsed.Equal(work) {
				return ErrInvalidDigest
			}
			return err
		}},
	}
	for _, test := range tests {
		if err := test.parse(test.value); err != nil {
			t.Fatalf("%s round trip: %v", test.name, err)
		}
		if _, err := ParsePlanDigest(test.value); test.name != "plan" && !errors.Is(err, ErrInvalidDigest) {
			t.Fatalf("%s parsed as PlanDigest: %v", test.name, err)
		}
	}
	for _, malformed := range []string{
		workKeyPrefix + strings.TrimPrefix(work.PlanDigest().String(), planDigestPrefix),
		work.String() + ".extra",
		strings.Replace(work.String(), ".", "", 1),
	} {
		if _, err := ParseWorkKey(malformed); !errors.Is(err, ErrInvalidDigest) {
			t.Fatalf("malformed work key %q error = %v", malformed, err)
		}
	}
}

func assertNoCanary(t testing.TB, output string, canaries []string) {
	t.Helper()
	for _, canary := range canaries {
		if canary != "" && strings.Contains(output, canary) {
			t.Fatalf("diagnostic leaked canary %q in %q", canary, output)
		}
	}
}
