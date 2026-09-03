package credential

import (
	"bytes"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

// SourceMaterial is bounded, in-memory source credential material. Copies of
// this wrapper share one destruction state rather than copying the raw bytes.
// Public constructors return a non-nil pointer. Call diagnostic or encoding
// methods directly only on constructed non-nil pointers; their value receivers
// deliberately preserve redaction and serialization denial for copied values.
type SourceMaterial struct {
	state *materialState
}

// NewSourceMaterial copies one non-empty bounded source value into broker-owned
// memory. The caller remains responsible for clearing its input buffer.
func NewSourceMaterial(value []byte) (*SourceMaterial, error) {
	state, err := newMaterialState(value, MaxSourceMaterialBytes)
	if err != nil {
		return nil, err
	}
	return &SourceMaterial{state: state}, nil
}

// WithBytes gives the callback an ephemeral copy and clears that copy before
// returning. Destroy can clear the master cell while a callback is active, but
// code retaining another copy inside the callback remains outside Go's
// enforceable boundary.
func (material *SourceMaterial) WithBytes(callback func([]byte) error) error {
	if material == nil {
		return ErrMaterialDestroyed
	}
	return material.state.withBytes(callback)
}

// Destroy immediately clears the owned master buffer. It is idempotent and
// affects every copy of this wrapper; an already-issued callback scratch copy
// remains usable only until that callback returns.
func (material *SourceMaterial) Destroy() {
	if material != nil {
		material.state.destroy()
	}
}

// Valid reports whether material is currently non-empty, bounded, and usable.
func (material *SourceMaterial) Valid() bool {
	return material != nil && material.state.valid()
}

// Len returns the current bounded byte count, or zero after destruction.
func (material *SourceMaterial) Len() int {
	if material == nil {
		return 0
	}
	return material.state.length()
}

func (material SourceMaterial) String() string {
	if !material.Valid() {
		return "credential-source-material(invalid)"
	}
	return "credential-source-material(redacted)"
}

func (material SourceMaterial) GoString() string { return material.String() }

func (material SourceMaterial) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, material.String())
}

func (material SourceMaterial) LogValue() slog.Value { return redactedLogValue(material.String()) }

func (SourceMaterial) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceMaterial) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceMaterial) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (SourceMaterial) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// SessionMaterial is bounded, short-lived provider credential material. It is
// structurally distinct from SourceMaterial so source credentials cannot be
// returned to a provider-operation adapter by type confusion. Public
// constructors return a non-nil pointer; direct diagnostic or encoding method
// calls require that constructed non-nil pointer so copied values retain the
// same redaction and serialization-denial method set.
type SessionMaterial struct {
	state *materialState
}

// NewSessionMaterial copies one non-empty bounded provider session value.
// The caller remains responsible for clearing its input buffer.
func NewSessionMaterial(value []byte) (*SessionMaterial, error) {
	state, err := newMaterialState(value, MaxSessionMaterialBytes)
	if err != nil {
		return nil, err
	}
	return &SessionMaterial{state: state}, nil
}

// WithBytes gives the callback an ephemeral copy and clears it before return.
func (material *SessionMaterial) WithBytes(callback func([]byte) error) error {
	if material == nil {
		return ErrMaterialDestroyed
	}
	return material.state.withBytes(callback)
}

// Destroy immediately clears the owned master session buffer. An active
// callback keeps only its independent scratch copy until callback return.
func (material *SessionMaterial) Destroy() {
	if material != nil {
		material.state.destroy()
	}
}

// Valid reports whether material is currently non-empty, bounded, and usable.
func (material *SessionMaterial) Valid() bool {
	return material != nil && material.state.valid()
}

// Len returns the current bounded byte count, or zero after destruction.
func (material *SessionMaterial) Len() int {
	if material == nil {
		return 0
	}
	return material.state.length()
}

func (material SessionMaterial) String() string {
	if !material.Valid() {
		return "credential-session-material(invalid)"
	}
	return "credential-session-material(redacted)"
}

func (material SessionMaterial) GoString() string { return material.String() }

func (material SessionMaterial) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, material.String())
}

func (material SessionMaterial) LogValue() slog.Value { return redactedLogValue(material.String()) }

func (SessionMaterial) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SessionMaterial) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SessionMaterial) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (SessionMaterial) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// IssuedSession owns one provider-issued session bound to exactly one Request.
// The supplied SessionMaterial is consumed and destroyed on every constructor
// path so the resulting session has one independently owned material cell.
// NewIssuedSession returns a non-nil pointer on success; direct diagnostic or
// encoding method calls require that constructed non-nil pointer so copied
// values remain redacted and non-serializable.
type IssuedSession struct {
	binding   BindingDigest
	issuedAt  time.Time
	expiresAt time.Time
	material  *SessionMaterial
}

// NewIssuedSession consumes material and validates the provider-reported
// issuance interval against the exact alpha bounds.
func NewIssuedSession(
	request Request,
	material *SessionMaterial,
	issuedAt time.Time,
	expiresAt time.Time,
) (*IssuedSession, error) {
	if material == nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIssuedSession, ErrInvalidMaterial)
	}
	defer material.Destroy()
	if err := ValidateRequest(request); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIssuedSession, ErrInvalidRequest)
	}
	normalizedIssued, ok := normalizeSessionTime(issuedAt)
	if !ok {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIssuedSession, ErrInvalidSessionLifetime)
	}
	normalizedExpires, ok := normalizeSessionTime(expiresAt)
	if !ok || !validSessionDuration(issuedAt, expiresAt) ||
		!validSessionDuration(normalizedIssued, normalizedExpires) {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIssuedSession, ErrInvalidSessionLifetime)
	}

	var owned *SessionMaterial
	if err := material.WithBytes(func(value []byte) error {
		var copyErr error
		owned, copyErr = NewSessionMaterial(value)
		return copyErr
	}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidIssuedSession, ErrInvalidMaterial)
	}
	session := &IssuedSession{
		binding:   request.binding,
		issuedAt:  normalizedIssued,
		expiresAt: normalizedExpires,
		material:  owned,
	}
	if !session.Valid() {
		session.Destroy()
		return nil, ErrInvalidIssuedSession
	}
	return session, nil
}

// BindingDigest returns the exact opaque Request binding echoed by the session.
func (session *IssuedSession) BindingDigest() BindingDigest {
	if session == nil {
		return BindingDigest{}
	}
	return session.binding
}

// IssuedAt returns the normalized whole-second UTC issuance instant.
func (session *IssuedSession) IssuedAt() time.Time {
	if session == nil {
		return time.Time{}
	}
	return session.issuedAt
}

// ExpiresAt returns the normalized whole-second UTC provider expiration.
func (session *IssuedSession) ExpiresAt() time.Time {
	if session == nil {
		return time.Time{}
	}
	return session.expiresAt
}

// RefreshAt is the exact instant at which broker renewal becomes due.
func (session *IssuedSession) RefreshAt() time.Time {
	if session == nil || session.expiresAt.IsZero() {
		return time.Time{}
	}
	return session.expiresAt.Add(-SessionRefreshAhead)
}

// RefreshDueAt reports whether renewal is due at or after the exact cutoff.
func (session *IssuedSession) RefreshDueAt(now time.Time) bool {
	return session != nil && session.Valid() && !now.IsZero() &&
		!now.UTC().Before(session.RefreshAt())
}

// ExpiredAt treats the skew-adjusted expiration instant as closed.
func (session *IssuedSession) ExpiredAt(now time.Time) bool {
	return session == nil || !session.Valid() || now.IsZero() ||
		!now.UTC().Before(session.expiresAt.Add(-SessionExpirySkew))
}

// CanStartUse requires at least MinNewUseLifetime before the skew-adjusted
// expiration. Equality at the cutoff preserves the stated minimum exactly.
func (session *IssuedSession) CanStartUse(now time.Time) bool {
	return session != nil && session.Valid() && !now.IsZero() &&
		!now.UTC().After(
			session.expiresAt.Add(-SessionExpirySkew-MinNewUseLifetime),
		)
}

// WithBytes gives the callback an ephemeral session-material copy. The broker
// remains responsible for checking CanStartUse with its injected clock first.
func (session *IssuedSession) WithBytes(callback func([]byte) error) error {
	if session == nil || session.material == nil {
		return ErrMaterialDestroyed
	}
	return session.material.WithBytes(callback)
}

// Destroy clears the owned session material. It is safe to call repeatedly.
func (session *IssuedSession) Destroy() {
	if session != nil && session.material != nil {
		session.material.Destroy()
	}
}

// Valid verifies immutable binding, lifetime, and current material ownership.
func (session *IssuedSession) Valid() bool {
	return session != nil && session.binding.Valid() &&
		canonicalSessionTime(session.issuedAt) && canonicalSessionTime(session.expiresAt) &&
		validSessionDuration(session.issuedAt, session.expiresAt) &&
		session.material != nil && session.material.Valid()
}

func (session IssuedSession) String() string {
	if !session.Valid() {
		return "credential-issued-session(invalid)"
	}
	return "credential-issued-session(redacted)"
}

func (session IssuedSession) GoString() string { return session.String() }

func (session IssuedSession) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, session.String())
}

func (session IssuedSession) LogValue() slog.Value { return redactedLogValue(session.String()) }

func (IssuedSession) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (IssuedSession) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (IssuedSession) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (IssuedSession) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

type materialState struct {
	mu        sync.RWMutex
	value     []byte
	limit     int
	destroyed bool
}

func newMaterialState(value []byte, limit int) (*materialState, error) {
	if len(value) == 0 || len(value) > limit {
		return nil, ErrInvalidMaterial
	}
	return &materialState{value: bytes.Clone(value), limit: limit}, nil
}

func (state *materialState) withBytes(callback func([]byte) error) error {
	if callback == nil {
		return ErrInvalidMaterialCallback
	}
	if state == nil {
		return ErrMaterialDestroyed
	}
	state.mu.RLock()
	if state.destroyed || len(state.value) == 0 || len(state.value) > state.limit {
		state.mu.RUnlock()
		return ErrMaterialDestroyed
	}
	value := bytes.Clone(state.value)
	state.mu.RUnlock()
	defer func() {
		clear(value)
		runtime.KeepAlive(value)
	}()
	return callback(value)
}

func (state *materialState) destroy() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.destroyed {
		return
	}
	clear(state.value)
	runtime.KeepAlive(state.value)
	state.value = nil
	state.destroyed = true
}

func (state *materialState) valid() bool {
	if state == nil {
		return false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return !state.destroyed && len(state.value) > 0 && len(state.value) <= state.limit
}

func (state *materialState) length() int {
	if state == nil {
		return 0
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.destroyed {
		return 0
	}
	return len(state.value)
}

func normalizeSessionTime(value time.Time) (time.Time, bool) {
	if value.IsZero() {
		return time.Time{}, false
	}
	normalized := value.UTC().Truncate(time.Second)
	if normalized.Year() < 1 || normalized.Year() > 9999 {
		return time.Time{}, false
	}
	return normalized, true
}

func canonicalSessionTime(value time.Time) bool {
	normalized, ok := normalizeSessionTime(value)
	return ok && value.Location() == time.UTC && value.Nanosecond() == 0 && value.Equal(normalized)
}

func validSessionDuration(issuedAt, expiresAt time.Time) bool {
	duration := expiresAt.Sub(issuedAt)
	return duration >= MinIssuedSessionTTL && duration <= MaxIssuedSessionTTL
}
