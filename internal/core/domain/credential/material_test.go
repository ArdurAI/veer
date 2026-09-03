package credential

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

func TestMaterialBoundsCopyAndDestroy(t *testing.T) {
	t.Parallel()
	if _, err := NewSourceMaterial(nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("NewSourceMaterial(empty) error = %v", err)
	}
	if _, err := NewSourceMaterial(make([]byte, MaxSourceMaterialBytes+1)); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("NewSourceMaterial(over limit) error = %v", err)
	}
	if _, err := NewSessionMaterial(make([]byte, MaxSessionMaterialBytes+1)); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("NewSessionMaterial(over limit) error = %v", err)
	}

	input := credentialBytes(64)
	want := bytes.Clone(input)
	material, err := NewSourceMaterial(input)
	if err != nil {
		t.Fatal(err)
	}
	clear(input)
	if material.Len() != len(want) || !material.Valid() {
		t.Fatal("valid source material did not retain an owned bounded copy")
	}
	var borrowed []byte
	if err := material.WithBytes(func(value []byte) error {
		borrowed = value
		if !bytes.Equal(value, want) {
			t.Fatal("callback did not receive the owned value")
		}
		clear(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !allZero(borrowed) {
		t.Fatal("callback scratch copy was not cleared after return")
	}
	if err := material.WithBytes(func(value []byte) error {
		if !bytes.Equal(value, want) {
			t.Fatal("callback mutation changed the master material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	alias := *material
	material.Destroy()
	material.Destroy()
	if material.Valid() || alias.Valid() || material.Len() != 0 || alias.Len() != 0 {
		t.Fatal("Destroy did not invalidate all wrapper aliases")
	}
	if err := alias.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrMaterialDestroyed) {
		t.Fatalf("WithBytes(after Destroy) error = %v", err)
	}
}

func TestMaterialCallbackMayDestroyWithoutDeadlock(t *testing.T) {
	t.Parallel()
	material, err := NewSourceMaterial(credentialBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	var borrowed []byte
	if err := material.WithBytes(func(value []byte) error {
		borrowed = value
		material.Destroy()
		if material.Valid() {
			t.Fatal("Destroy from callback did not invalidate the master cell")
		}
		if allZero(value) {
			t.Fatal("Destroy unexpectedly cleared the active scratch copy")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !allZero(borrowed) {
		t.Fatal("reentrant callback scratch copy was not cleared after return")
	}
}

func TestMaterialConcurrentUseAndDestroy(t *testing.T) {
	t.Parallel()
	material, err := NewSessionMaterial(credentialBytes(128))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			err := material.WithBytes(func(value []byte) error {
				if len(value) != 128 {
					t.Errorf("callback length = %d", len(value))
				}
				return nil
			})
			if err != nil && !errors.Is(err, ErrMaterialDestroyed) {
				t.Errorf("WithBytes() error = %v", err)
			}
		}()
	}
	material.Destroy()
	wait.Wait()
	if material.Valid() {
		t.Fatal("concurrently destroyed material remains valid")
	}
}

func TestIssuedSessionLifetimeAndOwnership(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	input, err := NewSessionMaterial(credentialBytes(96))
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewIssuedSession(
		fixture.request,
		input,
		testNow.Add(750*time.Millisecond),
		testNow.Add(RequestedSessionTTL+750*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	if input.Valid() {
		t.Fatal("NewIssuedSession did not consume input material")
	}
	if !session.Valid() || !session.BindingDigest().Equal(fixture.request.BindingDigest()) {
		t.Fatal("issued session lost its exact request binding")
	}
	if !session.IssuedAt().Equal(testNow) ||
		!session.ExpiresAt().Equal(testNow.Add(RequestedSessionTTL)) {
		t.Fatalf("session times = %s..%s", session.IssuedAt(), session.ExpiresAt())
	}
	if !session.RefreshAt().Equal(session.ExpiresAt().Add(-SessionRefreshAhead)) {
		t.Fatal("RefreshAt does not use the frozen cutoff")
	}
	if session.RefreshDueAt(session.RefreshAt().Add(-time.Nanosecond)) ||
		!session.RefreshDueAt(session.RefreshAt()) {
		t.Fatal("refresh cutoff is not exact")
	}
	newUseCutoff := session.ExpiresAt().Add(-SessionExpirySkew - MinNewUseLifetime)
	if !session.CanStartUse(newUseCutoff) ||
		session.CanStartUse(newUseCutoff.Add(time.Nanosecond)) {
		t.Fatal("minimum new-use cutoff is not exact")
	}
	expiryCutoff := session.ExpiresAt().Add(-SessionExpirySkew)
	if session.ExpiredAt(expiryCutoff.Add(-time.Nanosecond)) ||
		!session.ExpiredAt(expiryCutoff) {
		t.Fatal("skew-adjusted expiry cutoff is not exact")
	}
	if err := session.WithBytes(func(value []byte) error {
		if len(value) != 96 {
			t.Fatalf("session callback length = %d", len(value))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIssuedSessionRejectsLifetimeOutsideBoundsAndDestroysInput(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	tests := []struct {
		name     string
		duration time.Duration
		valid    bool
	}{
		{name: "below minimum", duration: MinIssuedSessionTTL - time.Second},
		{name: "minimum", duration: MinIssuedSessionTTL, valid: true},
		{name: "maximum", duration: MaxIssuedSessionTTL, valid: true},
		{name: "above maximum", duration: MaxIssuedSessionTTL + time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material, err := NewSessionMaterial(credentialBytes(32))
			if err != nil {
				t.Fatal(err)
			}
			session, err := NewIssuedSession(
				fixture.request,
				material,
				testNow,
				testNow.Add(test.duration),
			)
			if material.Valid() {
				t.Fatal("constructor did not consume input material")
			}
			if test.valid {
				if err != nil || session == nil || !session.Valid() {
					t.Fatalf("NewIssuedSession() = %v, %v", session, err)
				}
				session.Destroy()
				return
			}
			if !errors.Is(err, ErrInvalidSessionLifetime) || session != nil {
				t.Fatalf("NewIssuedSession() = %v, %v, want lifetime error", session, err)
			}
		})
	}
}

func TestIssuedSessionRejectsUTCYearRollover(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	tests := []struct {
		name     string
		issuedAt time.Time
	}{
		{
			name: "below year one after UTC normalization",
			issuedAt: time.Date(
				1, time.January, 1, 0, 0, 0, 0,
				time.FixedZone("east", int(time.Hour/time.Second)),
			),
		},
		{
			name: "above year 9999 after UTC normalization",
			issuedAt: time.Date(
				9999, time.December, 31, 23, 59, 59, 0,
				time.FixedZone("west", -int(time.Hour/time.Second)),
			),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material, err := NewSessionMaterial(credentialBytes(32))
			if err != nil {
				t.Fatal(err)
			}
			session, err := NewIssuedSession(
				fixture.request,
				material,
				test.issuedAt,
				test.issuedAt.Add(MinIssuedSessionTTL),
			)
			if session != nil || !errors.Is(err, ErrInvalidSessionLifetime) {
				t.Fatalf("NewIssuedSession(UTC rollover) = %v, %v", session, err)
			}
			if material.Valid() {
				t.Fatal("invalid rollover did not consume material")
			}
		})
	}
}

func TestCredentialValuesRedactAndRejectSerialization(t *testing.T) {
	t.Parallel()
	fixture := newCredentialFixture(t)
	sourceMaterial, err := NewSourceMaterial(credentialBytes(48))
	if err != nil {
		t.Fatal(err)
	}
	defer sourceMaterial.Destroy()
	sessionInput, err := NewSessionMaterial(credentialBytes(49))
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewIssuedSession(
		fixture.request,
		sessionInput,
		testNow,
		testNow.Add(RequestedSessionTTL),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()

	values := []any{
		fixture.recipient,
		fixture.target,
		fixture.request.SourceLookup(),
		fixture.request.SourceLookup().Digest(),
		fixture.request,
		fixture.request.BindingDigest(),
		*sourceMaterial,
		*session.material,
		*session,
	}
	for _, value := range values {
		assertSafeValue(t, value)
	}
}

func TestTypedNilCredentialPointersAreSafeThroughGenericBoundaries(t *testing.T) {
	t.Parallel()
	values := []any{
		(*SourceMaterial)(nil),
		(*SessionMaterial)(nil),
		(*IssuedSession)(nil),
	}
	for _, value := range values {
		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
				assertDoesNotPanic(t, "fmt", func() {
					_ = fmt.Sprintf(format, value)
				})
			}
			assertDoesNotPanic(t, "slog", func() {
				_ = slog.AnyValue(value).Resolve().String()
			})
			assertDoesNotPanic(t, "json", func() {
				data, err := json.Marshal(value)
				if err != nil || !bytes.Equal(data, []byte("null")) {
					t.Fatalf("json.Marshal(typed nil %T) = %q, %v", value, data, err)
				}
			})
		})
	}
}

func assertSafeValue(t testing.TB, value any) {
	t.Helper()
	forbiddenValues := []string{
		testWorkspaceID.String(),
		testEnvironmentA.String(),
		testConnectionA.String(),
		testComponentA.String(),
		testOperationA.String(),
		testReferenceA.String(),
		"provider-adapter",
		"version_1",
		string(credentialBytes(48)),
		string(credentialBytes(49)),
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		formatted := fmt.Sprintf(format, value)
		for forbiddenIndex, forbidden := range forbiddenValues {
			if bytes.Contains([]byte(formatted), []byte(forbidden)) {
				t.Fatalf("format %q for %T leaked protected field %d", format, value, forbiddenIndex)
			}
		}
	}
	logValue := slog.AnyValue(value).Resolve().String()
	for forbiddenIndex, forbidden := range forbiddenValues {
		if bytes.Contains([]byte(logValue), []byte(forbidden)) {
			t.Fatalf("slog value for %T leaked protected field %d", value, forbiddenIndex)
		}
	}
	if data, err := json.Marshal(value); !errors.Is(err, ErrSerializationForbidden) || len(data) != 0 {
		t.Fatalf("json.Marshal() = %q, %v", data, err)
	}
	textMarshaler, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%T does not implement encoding.TextMarshaler", value)
	}
	if data, err := textMarshaler.MarshalText(); !errors.Is(err, ErrSerializationForbidden) || len(data) != 0 {
		t.Fatalf("MarshalText() = %q, %v", data, err)
	}
	binaryMarshaler, ok := value.(encoding.BinaryMarshaler)
	if !ok {
		t.Fatalf("%T does not implement encoding.BinaryMarshaler", value)
	}
	if data, err := binaryMarshaler.MarshalBinary(); !errors.Is(err, ErrSerializationForbidden) || len(data) != 0 {
		t.Fatalf("MarshalBinary() = %q, %v", data, err)
	}
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(value); err == nil {
		t.Fatalf("gob.Encode(%T) unexpectedly succeeded", value)
	}
	for _, forbidden := range [][]byte{
		[]byte(testReferenceA.String()),
		credentialBytes(48),
		credentialBytes(49),
	} {
		if bytes.Contains(buffer.Bytes(), forbidden) {
			t.Fatalf("gob.Encode(%T) retained protected material", value)
		}
	}
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func assertDoesNotPanic(t testing.TB, boundary string, callback func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s boundary panicked for typed nil", boundary)
		}
	}()
	callback()
}
