// Package audit defines Veer's transport-independent, append-only audit
// reference contract. It performs no persistence, network, key-management, or
// signing I/O.
package audit

import (
	"slices"
	"time"
)

const (
	// ContractVersion binds the canonical event, chain, export, and retention
	// vocabulary implemented by this package.
	ContractVersion = "veer.audit.v1alpha1"

	// MaxCanonicalEventBytes is the alpha pre-compression event ceiling.
	MaxCanonicalEventBytes = 16_384
	// MaxSegmentEvents bounds one in-memory or exported verification segment.
	MaxSegmentEvents = 1_000
	// MaxCanonicalSegmentBytes bounds the worst-case canonical event payloads
	// plus their record framing without integer multiplication at runtime.
	MaxCanonicalSegmentBytes = 16_640_512
	// MaxCanonicalManifestBytes bounds one signed export manifest.
	MaxCanonicalManifestBytes = 4_096
	// MaxSignatureBytes bounds an externally produced signature envelope.
	MaxSignatureBytes = 512
	// MaxKeyIDBytes bounds the non-secret verifier key selector.
	MaxKeyIDBytes = 128
	// MaxHolds bounds one retention evaluation.
	MaxHolds = 32

	// OnlineRetention is the fixed queryable audit interval.
	OnlineRetention = 90 * 24 * time.Hour
	// ArchiveRetention is the fixed immutable archive interval.
	ArchiveRetention = 365 * 24 * time.Hour

	// ChainDigestPrefix identifies the current audit-chain digest framing.
	ChainDigestPrefix = "ach1_"
	// ExportBodyDigestPrefix identifies the current export-body digest framing.
	ExportBodyDigestPrefix = "aeb1_"

	timestampLayout = "2006-01-02T15:04:05.000Z"
)

// StreamKind separates tenant-visible Workspace history from privileged
// platform history.
type StreamKind string

const (
	StreamKindWorkspace StreamKind = "Workspace"
	StreamKindPlatform  StreamKind = "Platform"
)

var streamKinds = []StreamKind{StreamKindWorkspace, StreamKindPlatform}

func (value StreamKind) String() string { return string(value) }
func ParseStreamKind(value string) (StreamKind, error) {
	return parseClosed(StreamKind(value), streamKinds, ErrInvalidStream)
}
func StreamKinds() []StreamKind { return slices.Clone(streamKinds) }

// ActorKind describes only a pseudonymous attribution class. It never carries
// an issuer, subject, email, group, token, or source-network claim.
type ActorKind string

const (
	ActorKindAnonymous     ActorKind = "Anonymous"
	ActorKindHuman         ActorKind = "Human"
	ActorKindWorkload      ActorKind = "Workload"
	ActorKindAdministrator ActorKind = "Administrator"
)

var actorKinds = []ActorKind{
	ActorKindAnonymous,
	ActorKindHuman,
	ActorKindWorkload,
	ActorKindAdministrator,
}

func (value ActorKind) String() string { return string(value) }
func ParseActorKind(value string) (ActorKind, error) {
	return parseClosed(ActorKind(value), actorKinds, ErrInvalidActor)
}
func ActorKinds() []ActorKind { return slices.Clone(actorKinds) }

// AuthenticationMethod is the closed method recorded independently from the
// actor pseudonym.
type AuthenticationMethod string

const (
	AuthenticationMethodNone         AuthenticationMethod = "None"
	AuthenticationMethodOIDC         AuthenticationMethod = "OIDC"
	AuthenticationMethodWorkloadOIDC AuthenticationMethod = "WorkloadOIDC"
	AuthenticationMethodStrongOIDC   AuthenticationMethod = "StrongOIDC"
	AuthenticationMethodInternal     AuthenticationMethod = "Internal"
)

var authenticationMethods = []AuthenticationMethod{
	AuthenticationMethodNone,
	AuthenticationMethodOIDC,
	AuthenticationMethodWorkloadOIDC,
	AuthenticationMethodStrongOIDC,
	AuthenticationMethodInternal,
}

func (value AuthenticationMethod) String() string { return string(value) }
func ParseAuthenticationMethod(value string) (AuthenticationMethod, error) {
	return parseClosed(AuthenticationMethod(value), authenticationMethods, ErrInvalidAuthentication)
}
func AuthenticationMethods() []AuthenticationMethod { return slices.Clone(authenticationMethods) }

// EventKind is the closed semantic family of an audit event.
type EventKind string

const (
	EventKindRequest         EventKind = "Request"
	EventKindAuthorization   EventKind = "Authorization"
	EventKindOperation       EventKind = "Operation"
	EventKindProviderAttempt EventKind = "ProviderAttempt"
	EventKindElevation       EventKind = "Elevation"
	EventKindExport          EventKind = "Export"
	EventKindRetention       EventKind = "Retention"
	EventKindIntegrity       EventKind = "Integrity"
)

var eventKinds = []EventKind{
	EventKindRequest,
	EventKindAuthorization,
	EventKindOperation,
	EventKindProviderAttempt,
	EventKindElevation,
	EventKindExport,
	EventKindRetention,
	EventKindIntegrity,
}

func (value EventKind) String() string { return string(value) }
func ParseEventKind(value string) (EventKind, error) {
	return parseClosed(EventKind(value), eventKinds, ErrInvalidEventKind)
}
func EventKinds() []EventKind { return slices.Clone(eventKinds) }

// Source is the bounded component class that observed the event.
type Source string

const (
	SourceAPI             Source = "API"
	SourceWorker          Source = "Worker"
	SourceController      Source = "Controller"
	SourceProviderAdapter Source = "ProviderAdapter"
	SourceAdministration  Source = "Administration"
	SourceSystem          Source = "System"
)

var sources = []Source{
	SourceAPI,
	SourceWorker,
	SourceController,
	SourceProviderAdapter,
	SourceAdministration,
	SourceSystem,
}

func (value Source) String() string { return string(value) }
func ParseSource(value string) (Source, error) {
	return parseClosed(Source(value), sources, ErrInvalidSource)
}
func Sources() []Source { return slices.Clone(sources) }

// Outcome is the closed result vocabulary. Indeterminate preserves unknown
// provider outcomes without asserting success or retry safety.
type Outcome string

const (
	OutcomeAccepted      Outcome = "Accepted"
	OutcomeSucceeded     Outcome = "Succeeded"
	OutcomeDenied        Outcome = "Denied"
	OutcomeFailed        Outcome = "Failed"
	OutcomeCanceled      Outcome = "Canceled"
	OutcomeIndeterminate Outcome = "Indeterminate"
)

var outcomes = []Outcome{
	OutcomeAccepted,
	OutcomeSucceeded,
	OutcomeDenied,
	OutcomeFailed,
	OutcomeCanceled,
	OutcomeIndeterminate,
}

func (value Outcome) String() string { return string(value) }
func ParseOutcome(value string) (Outcome, error) {
	return parseClosed(Outcome(value), outcomes, ErrInvalidOutcome)
}
func Outcomes() []Outcome { return slices.Clone(outcomes) }

// ClockState records wall-clock quality; sequence remains authoritative order.
type ClockState string

const (
	ClockStateSynchronized ClockState = "Synchronized"
	ClockStateUncertain    ClockState = "Uncertain"
	ClockStateRegressed    ClockState = "Regressed"
)

var clockStates = []ClockState{
	ClockStateSynchronized,
	ClockStateUncertain,
	ClockStateRegressed,
}

func (value ClockState) String() string { return string(value) }
func ParseClockState(value string) (ClockState, error) {
	return parseClosed(ClockState(value), clockStates, ErrInvalidClockState)
}
func ClockStates() []ClockState { return slices.Clone(clockStates) }

// ElevationState is the closed lifecycle projection for a privileged grant.
type ElevationState string

const (
	ElevationStateIssued   ElevationState = "Issued"
	ElevationStateConsumed ElevationState = "Consumed"
	ElevationStateRevoked  ElevationState = "Revoked"
	ElevationStateExpired  ElevationState = "Expired"
)

var elevationStates = []ElevationState{
	ElevationStateIssued,
	ElevationStateConsumed,
	ElevationStateRevoked,
	ElevationStateExpired,
}

func (value ElevationState) String() string { return string(value) }
func ParseElevationState(value string) (ElevationState, error) {
	return parseClosed(ElevationState(value), elevationStates, ErrInvalidReference)
}
func ElevationStates() []ElevationState { return slices.Clone(elevationStates) }

// SignatureAlgorithm identifies the external verifier contract. The audit
// package intentionally implements neither signing nor public-key parsing.
type SignatureAlgorithm string

const SignatureAlgorithmEd25519 SignatureAlgorithm = "Ed25519"

var signatureAlgorithms = []SignatureAlgorithm{SignatureAlgorithmEd25519}

func (value SignatureAlgorithm) String() string { return string(value) }
func ParseSignatureAlgorithm(value string) (SignatureAlgorithm, error) {
	return parseClosed(SignatureAlgorithm(value), signatureAlgorithms, ErrInvalidExport)
}
func SignatureAlgorithms() []SignatureAlgorithm { return slices.Clone(signatureAlgorithms) }

// HoldKind is one reviewed reason an otherwise expired event must remain.
type HoldKind string

const (
	HoldKindLegal    HoldKind = "Legal"
	HoldKindIncident HoldKind = "Incident"
	HoldKindSecurity HoldKind = "Security"
)

var holdKinds = []HoldKind{HoldKindLegal, HoldKindIncident, HoldKindSecurity}

func (value HoldKind) String() string { return string(value) }
func ParseHoldKind(value string) (HoldKind, error) {
	return parseClosed(HoldKind(value), holdKinds, ErrInvalidHold)
}
func HoldKinds() []HoldKind { return slices.Clone(holdKinds) }

// RetentionDisposition is a pure decision, not a deletion instruction.
type RetentionDisposition string

const (
	RetentionDispositionOnline  RetentionDisposition = "Online"
	RetentionDispositionArchive RetentionDisposition = "Archive"
	RetentionDispositionHeld    RetentionDisposition = "Held"
	RetentionDispositionExpire  RetentionDisposition = "Expire"
)

var retentionDispositions = []RetentionDisposition{
	RetentionDispositionOnline,
	RetentionDispositionArchive,
	RetentionDispositionHeld,
	RetentionDispositionExpire,
}

func (value RetentionDisposition) String() string { return string(value) }
func ParseRetentionDisposition(value string) (RetentionDisposition, error) {
	return parseClosed(RetentionDisposition(value), retentionDispositions, ErrInvalidRetention)
}
func RetentionDispositions() []RetentionDisposition { return slices.Clone(retentionDispositions) }

func parseClosed[T comparable](value T, candidates []T, invalid error) (T, error) {
	for _, candidate := range candidates {
		if value == candidate {
			return value, nil
		}
	}
	var zero T
	return zero, invalid
}
