package audit

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

var (
	opaqueVersionPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	operationReasonPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
)

// Stream is an immutable chain identity. Workspace streams carry exactly one
// stable Workspace ID; the platform stream carries none.
type Stream struct {
	initialized bool
	kind        StreamKind
	workspaceID resource.ID
}

func NewWorkspaceStream(workspaceID resource.ID) (Stream, error) {
	if _, err := resource.ParseID(workspaceID.String()); err != nil {
		return Stream{}, fmt.Errorf("%w: workspace ID", ErrInvalidStream)
	}
	return Stream{initialized: true, kind: StreamKindWorkspace, workspaceID: workspaceID}, nil
}

func NewPlatformStream() Stream {
	return Stream{initialized: true, kind: StreamKindPlatform}
}

func ValidateStream(stream Stream) error {
	if !stream.initialized {
		return ErrInvalidStream
	}
	if _, err := ParseStreamKind(stream.kind.String()); err != nil {
		return ErrInvalidStream
	}
	switch stream.kind {
	case StreamKindWorkspace:
		if _, err := resource.ParseID(stream.workspaceID.String()); err != nil {
			return ErrInvalidStream
		}
	case StreamKindPlatform:
		if stream.workspaceID != "" {
			return ErrInvalidStream
		}
	default:
		return ErrInvalidStream
	}
	return nil
}

func (stream Stream) Kind() StreamKind { return stream.kind }
func (stream Stream) WorkspaceID() (resource.ID, bool) {
	if ValidateStream(stream) != nil || stream.kind != StreamKindWorkspace {
		return "", false
	}
	return stream.workspaceID, true
}
func (stream Stream) Equal(other Stream) bool {
	return ValidateStream(stream) == nil && ValidateStream(other) == nil &&
		stream.kind == other.kind && stream.workspaceID == other.workspaceID
}
func (stream Stream) String() string {
	if ValidateStream(stream) != nil {
		return "audit-stream(invalid)"
	}
	return "audit-stream(kind=" + stream.kind.String() + ")"
}
func (stream Stream) GoString() string { return stream.String() }
func (stream Stream) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, stream.String())
}

// ActorRef is a pseudonymous audit attribution. Human and Workload values use
// identity.Fingerprint; Administrator values use a separate opaque server ID.
// Anonymous carries no identifier.
type ActorRef struct {
	initialized bool
	kind        ActorKind
	pseudonym   string
}

func ActorFromPrincipal(principal identity.Principal) (ActorRef, error) {
	if err := identity.ValidatePrincipal(principal); err != nil {
		return ActorRef{}, fmt.Errorf("%w: principal", ErrInvalidActor)
	}
	kind := ActorKindHuman
	if principal.Kind() == identity.KindWorkload {
		kind = ActorKindWorkload
	}
	actor := ActorRef{
		initialized: true,
		kind:        kind,
		pseudonym:   principal.Fingerprint().String(),
	}
	if err := ValidateActorRef(actor); err != nil {
		return ActorRef{}, err
	}
	return actor, nil
}

func AnonymousActor() ActorRef {
	return ActorRef{initialized: true, kind: ActorKindAnonymous}
}

func AdministratorActor(administratorID resource.ID) (ActorRef, error) {
	if _, err := resource.ParseID(administratorID.String()); err != nil {
		return ActorRef{}, fmt.Errorf("%w: administrator ID", ErrInvalidActor)
	}
	return ActorRef{
		initialized: true,
		kind:        ActorKindAdministrator,
		pseudonym:   administratorID.String(),
	}, nil
}

func ValidateActorRef(actor ActorRef) error {
	if !actor.initialized {
		return ErrInvalidActor
	}
	if _, err := ParseActorKind(actor.kind.String()); err != nil {
		return ErrInvalidActor
	}
	switch actor.kind {
	case ActorKindAnonymous:
		if actor.pseudonym != "" {
			return ErrInvalidActor
		}
	case ActorKindHuman, ActorKindWorkload:
		if !validPrincipalFingerprint(actor.pseudonym) {
			return ErrInvalidActor
		}
	case ActorKindAdministrator:
		if _, err := resource.ParseID(actor.pseudonym); err != nil {
			return ErrInvalidActor
		}
	default:
		return ErrInvalidActor
	}
	return nil
}

func (actor ActorRef) Kind() ActorKind { return actor.kind }
func (actor ActorRef) Pseudonym() (string, bool) {
	if ValidateActorRef(actor) != nil || actor.kind == ActorKindAnonymous {
		return "", false
	}
	return actor.pseudonym, true
}
func (actor ActorRef) Equal(other ActorRef) bool {
	return ValidateActorRef(actor) == nil && ValidateActorRef(other) == nil &&
		actor.kind == other.kind && actor.pseudonym == other.pseudonym
}
func (actor ActorRef) String() string {
	if ValidateActorRef(actor) != nil {
		return "audit-actor(invalid)"
	}
	return "audit-actor(kind=" + actor.kind.String() + ",pseudonym=redacted)"
}
func (actor ActorRef) GoString() string { return actor.String() }
func (actor ActorRef) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, actor.String())
}

// RequestRef correlates an event with one server-issued request identity.
type RequestRef struct {
	initialized bool
	id          resource.ID
}

func NewRequestRef(id resource.ID) (RequestRef, error) {
	if _, err := resource.ParseID(id.String()); err != nil {
		return RequestRef{}, fmt.Errorf("%w: request ID", ErrInvalidReference)
	}
	return RequestRef{initialized: true, id: id}, nil
}

func (reference RequestRef) ID() resource.ID { return reference.id }

// TargetRef is the non-assertable projection of an authorization.Target.
type TargetRef struct {
	initialized          bool
	objectKind           authorization.ObjectKind
	objectID             resource.ID
	resourceKind         string
	resourceID           resource.ID
	workspaceID          resource.ID
	environmentID        *resource.ID
	providerConnectionID *resource.ID
}

func TargetRefFromAuthorization(target authorization.Target) (TargetRef, error) {
	if err := authorization.ValidateTarget(target); err != nil {
		return TargetRef{}, fmt.Errorf("%w: authorization target", ErrInvalidReference)
	}
	reference := TargetRef{
		initialized:  true,
		objectKind:   target.ObjectKind(),
		objectID:     target.ObjectID(),
		resourceKind: target.ResourceKind().String(),
		resourceID:   target.ResourceID(),
		workspaceID:  target.WorkspaceID(),
	}
	if id, present := target.EnvironmentID(); present {
		reference.environmentID = idPointer(id)
	}
	if id, present := target.ProviderConnectionID(); present {
		reference.providerConnectionID = idPointer(id)
	}
	if err := validateTargetRef(reference); err != nil {
		return TargetRef{}, err
	}
	return reference, nil
}

func (reference TargetRef) ObjectKind() authorization.ObjectKind { return reference.objectKind }
func (reference TargetRef) ObjectID() resource.ID                { return reference.objectID }
func (reference TargetRef) ResourceKind() string                 { return reference.resourceKind }
func (reference TargetRef) ResourceID() resource.ID              { return reference.resourceID }
func (reference TargetRef) WorkspaceID() resource.ID             { return reference.workspaceID }
func (reference TargetRef) EnvironmentID() (resource.ID, bool) {
	return optionalID(reference.environmentID)
}
func (reference TargetRef) ProviderConnectionID() (resource.ID, bool) {
	return optionalID(reference.providerConnectionID)
}

// DecisionRef is a bounded non-personal projection of an authorization receipt.
type DecisionRef struct {
	initialized   bool
	policyVersion string
	inputDigest   string
	effect        authorization.Effect
	reason        authorization.Reason
}

func DecisionRefFromAuthorization(decision authorization.Decision) (DecisionRef, error) {
	if err := authorization.ValidateDecision(decision); err != nil {
		return DecisionRef{}, fmt.Errorf("%w: authorization decision", ErrInvalidReference)
	}
	reference := DecisionRef{
		initialized:   true,
		policyVersion: decision.PolicyVersion().String(),
		inputDigest:   decision.InputDigest().String(),
		effect:        decision.Effect(),
		reason:        decision.Reason(),
	}
	if err := validateDecisionRef(reference); err != nil {
		return DecisionRef{}, err
	}
	return reference, nil
}

func (reference DecisionRef) PolicyVersion() string        { return reference.policyVersion }
func (reference DecisionRef) InputDigest() string          { return reference.inputDigest }
func (reference DecisionRef) Effect() authorization.Effect { return reference.effect }
func (reference DecisionRef) Reason() authorization.Reason { return reference.reason }

// OperationRef retains only safe state needed to reconstruct an operation
// timeline. Message and cost estimate are deliberately excluded.
type OperationRef struct {
	initialized          bool
	id                   resource.ID
	workspaceID          resource.ID
	resourceID           resource.ID
	environmentID        *resource.ID
	providerConnectionID *resource.ID
	generation           int64
	resourceVersion      string
	phase                operation.Phase
	reason               string
	updatedAt            string
}

func OperationRefFromOperation(value operation.Operation) (OperationRef, error) {
	if err := operation.Validate(value); err != nil {
		return OperationRef{}, fmt.Errorf("%w: operation", ErrInvalidReference)
	}
	reference := OperationRef{
		initialized:          true,
		id:                   value.ID,
		workspaceID:          value.WorkspaceID,
		resourceID:           value.ResourceID,
		environmentID:        cloneIDPointer(value.EnvironmentID),
		providerConnectionID: cloneIDPointer(value.ProviderConnectionID),
		generation:           value.Generation,
		resourceVersion:      value.ResourceVersion,
		phase:                value.Phase,
		reason:               value.Reason,
		updatedAt:            value.UpdatedAt,
	}
	if err := validateOperationRef(reference); err != nil {
		return OperationRef{}, err
	}
	return reference, nil
}

func (reference OperationRef) ID() resource.ID          { return reference.id }
func (reference OperationRef) WorkspaceID() resource.ID { return reference.workspaceID }
func (reference OperationRef) ResourceID() resource.ID  { return reference.resourceID }
func (reference OperationRef) EnvironmentID() (resource.ID, bool) {
	return optionalID(reference.environmentID)
}
func (reference OperationRef) ProviderConnectionID() (resource.ID, bool) {
	return optionalID(reference.providerConnectionID)
}
func (reference OperationRef) Generation() int64       { return reference.generation }
func (reference OperationRef) ResourceVersion() string { return reference.resourceVersion }
func (reference OperationRef) Phase() operation.Phase  { return reference.phase }
func (reference OperationRef) Reason() string          { return reference.reason }
func (reference OperationRef) UpdatedAt() time.Time {
	parsed, _ := parseTimestamp(reference.updatedAt)
	return parsed
}

// AttemptRef distinguishes every externally attempted provider mutation,
// including retries.
type AttemptRef struct {
	initialized bool
	id          resource.ID
	ordinal     uint32
}

func NewAttemptRef(id resource.ID, ordinal uint32) (AttemptRef, error) {
	if _, err := resource.ParseID(id.String()); err != nil || ordinal == 0 {
		return AttemptRef{}, fmt.Errorf("%w: provider attempt", ErrInvalidReference)
	}
	return AttemptRef{initialized: true, id: id, ordinal: ordinal}, nil
}

func (reference AttemptRef) ID() resource.ID { return reference.id }
func (reference AttemptRef) Ordinal() uint32 { return reference.ordinal }

// ElevationRef is a canonical projection of a privileged administration
// lifecycle transition. Its construction from administration types is kept in
// administration_projection.go to preserve the one-way import.
type ElevationRef struct {
	initialized          bool
	grantID              resource.ID
	administratorID      resource.ID
	action               authorization.Action
	targetKind           string
	workspaceID          *resource.ID
	objectID             *resource.ID
	resourceID           *resource.ID
	environmentID        *resource.ID
	providerConnectionID *resource.ID
	reason               string
	caseReference        string
	issuedAt             string
	expiresAt            string
	state                ElevationState
	recordedAt           string
}

func (reference ElevationRef) GrantID() resource.ID         { return reference.grantID }
func (reference ElevationRef) AdministratorID() resource.ID { return reference.administratorID }
func (reference ElevationRef) Action() authorization.Action { return reference.action }
func (reference ElevationRef) TargetKind() string           { return reference.targetKind }
func (reference ElevationRef) WorkspaceID() (resource.ID, bool) {
	return optionalID(reference.workspaceID)
}
func (reference ElevationRef) ObjectID() (resource.ID, bool) {
	return optionalID(reference.objectID)
}
func (reference ElevationRef) ResourceID() (resource.ID, bool) {
	return optionalID(reference.resourceID)
}
func (reference ElevationRef) EnvironmentID() (resource.ID, bool) {
	return optionalID(reference.environmentID)
}
func (reference ElevationRef) ProviderConnectionID() (resource.ID, bool) {
	return optionalID(reference.providerConnectionID)
}
func (reference ElevationRef) Reason() string { return reference.reason }
func (reference ElevationRef) CaseReference() (string, bool) {
	return reference.caseReference, reference.caseReference != ""
}
func (reference ElevationRef) IssuedAt() time.Time {
	parsed, _ := parseTimestamp(reference.issuedAt)
	return parsed
}
func (reference ElevationRef) ExpiresAt() time.Time {
	parsed, _ := parseTimestamp(reference.expiresAt)
	return parsed
}
func (reference ElevationRef) State() ElevationState { return reference.state }
func (reference ElevationRef) RecordedAt() time.Time {
	parsed, _ := parseTimestamp(reference.recordedAt)
	return parsed
}

func validPrincipalFingerprint(value string) bool {
	if !strings.HasPrefix(value, "prn1_") {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "prn1_"))
	return err == nil && len(decoded) == 32 &&
		"prn1_"+base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validateRequestRef(reference RequestRef) error {
	if !reference.initialized {
		return ErrInvalidReference
	}
	if _, err := resource.ParseID(reference.id.String()); err != nil {
		return ErrInvalidReference
	}
	return nil
}

func validateTargetRef(reference TargetRef) error {
	if !reference.initialized {
		return ErrInvalidReference
	}
	if _, err := authorization.ParseObjectKind(reference.objectKind.String()); err != nil ||
		!validResourceKind(reference.resourceKind) {
		return ErrInvalidReference
	}
	for _, id := range []resource.ID{reference.objectID, reference.resourceID, reference.workspaceID} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidReference
		}
	}
	for _, id := range []*resource.ID{reference.environmentID, reference.providerConnectionID} {
		if id != nil {
			if _, err := resource.ParseID(id.String()); err != nil {
				return ErrInvalidReference
			}
		}
	}
	if reference.providerConnectionID != nil && reference.environmentID == nil {
		return ErrInvalidReference
	}
	if reference.resourceKind == "Workspace" && reference.resourceID != reference.workspaceID {
		return ErrInvalidReference
	}
	wantsEnvironment := reference.resourceKind == "Environment" ||
		reference.resourceKind == "Application" ||
		reference.resourceKind == "Component" ||
		reference.resourceKind == "ProviderConnection"
	if wantsEnvironment != (reference.environmentID != nil) {
		return ErrInvalidReference
	}
	switch reference.objectKind {
	case authorization.ObjectKindResource:
		if reference.objectID != reference.resourceID || reference.providerConnectionID != nil {
			return ErrInvalidReference
		}
	case authorization.ObjectKindMembership:
		if reference.resourceKind != "Workspace" || reference.resourceID != reference.workspaceID ||
			reference.providerConnectionID != nil {
			return ErrInvalidReference
		}
	case authorization.ObjectKindAudit:
		if reference.resourceKind != "Workspace" || reference.resourceID != reference.workspaceID ||
			reference.environmentID != nil || reference.providerConnectionID != nil {
			return ErrInvalidReference
		}
	case authorization.ObjectKindOperation, authorization.ObjectKindPlan:
	default:
		return ErrInvalidReference
	}
	return nil
}

func validateDecisionRef(reference DecisionRef) error {
	if !reference.initialized {
		return ErrInvalidReference
	}
	if _, err := authorization.ParsePolicyVersion(reference.policyVersion); err != nil {
		return ErrInvalidReference
	}
	if _, err := authorization.ParseInputDigest(reference.inputDigest); err != nil {
		return ErrInvalidReference
	}
	validEffect := false
	for _, candidate := range authorization.Effects() {
		validEffect = validEffect || reference.effect == candidate
	}
	validReason := false
	for _, candidate := range authorization.Reasons() {
		validReason = validReason || reference.reason == candidate
	}
	if !validEffect || !validReason ||
		(reference.effect == authorization.EffectAllow) !=
			(reference.reason == authorization.ReasonRoleGranted) {
		return ErrInvalidReference
	}
	return nil
}

func validateOperationRef(reference OperationRef) error {
	if !reference.initialized {
		return ErrInvalidReference
	}
	for _, id := range []resource.ID{reference.id, reference.workspaceID, reference.resourceID} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidReference
		}
	}
	if (reference.environmentID == nil) != (reference.providerConnectionID == nil) {
		return ErrInvalidReference
	}
	for _, id := range []*resource.ID{reference.environmentID, reference.providerConnectionID} {
		if id != nil {
			if _, err := resource.ParseID(id.String()); err != nil {
				return ErrInvalidReference
			}
		}
	}
	if reference.generation < 1 || !opaqueVersionPattern.MatchString(reference.resourceVersion) ||
		!validOperationPhase(reference.phase) ||
		(reference.reason != "" && !operationReasonPattern.MatchString(reference.reason)) {
		return ErrInvalidReference
	}
	if _, err := parseTimestamp(reference.updatedAt); err != nil {
		return ErrInvalidReference
	}
	return nil
}

func validateAttemptRef(reference AttemptRef) error {
	if !reference.initialized || reference.ordinal == 0 {
		return ErrInvalidReference
	}
	if _, err := resource.ParseID(reference.id.String()); err != nil {
		return ErrInvalidReference
	}
	return nil
}

func validateElevationRef(reference ElevationRef) error {
	if !reference.initialized {
		return ErrInvalidReference
	}
	for _, id := range []resource.ID{reference.grantID, reference.administratorID} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidReference
		}
	}
	if _, err := authorization.ParseAction(reference.action.String()); err != nil {
		return ErrInvalidReference
	}
	if !validElevationTargetShape(reference) || !validElevationActionReference(reference) {
		return ErrInvalidReference
	}
	for _, id := range []*resource.ID{
		reference.workspaceID,
		reference.objectID,
		reference.resourceID,
		reference.environmentID,
		reference.providerConnectionID,
	} {
		if id != nil {
			if _, err := resource.ParseID(id.String()); err != nil {
				return ErrInvalidReference
			}
		}
	}
	if _, err := ParseElevationState(reference.state.String()); err != nil {
		return ErrInvalidReference
	}
	issuedAt, issuedErr := parseTimestamp(reference.issuedAt)
	expiresAt, expiresErr := parseTimestamp(reference.expiresAt)
	recordedAt, recordedErr := parseTimestamp(reference.recordedAt)
	if issuedErr != nil || expiresErr != nil || recordedErr != nil ||
		!validElevationPeriod(issuedAt, expiresAt) {
		return ErrInvalidReference
	}
	if !validElevationReason(reference.reason) ||
		(reference.caseReference != "" && !validElevationCaseReference(reference.caseReference)) {
		return ErrInvalidReference
	}
	switch reference.state {
	case ElevationStateIssued:
		if !recordedAt.Equal(issuedAt) {
			return ErrInvalidReference
		}
	case ElevationStateConsumed, ElevationStateRevoked:
		if recordedAt.Before(issuedAt) || !recordedAt.Before(expiresAt) {
			return ErrInvalidReference
		}
	case ElevationStateExpired:
		if !recordedAt.Equal(expiresAt) {
			return ErrInvalidReference
		}
	}
	return nil
}

func validResourceKind(value string) bool {
	switch value {
	case "Workspace", "Policy", "Environment", "Application", "Component", "ProviderConnection":
		return true
	default:
		return false
	}
}

func validOperationPhase(value operation.Phase) bool {
	switch value {
	case operation.PhasePending, operation.PhaseWaiting, operation.PhaseRunning,
		operation.PhaseSucceeded, operation.PhaseFailed, operation.PhaseCanceled:
		return true
	default:
		return false
	}
}

func validateKeyID(value string) bool {
	if value == "" || len(value) > MaxKeyIDBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, current := range value {
		if current < 0x21 || current > 0x7e {
			return false
		}
	}
	return true
}

func idPointer(id resource.ID) *resource.ID {
	copy := id
	return &copy
}

func cloneIDPointer(id *resource.ID) *resource.ID {
	if id == nil {
		return nil
	}
	return idPointer(*id)
}

func optionalID(id *resource.ID) (resource.ID, bool) {
	if id == nil {
		return "", false
	}
	return *id, true
}

func equalIDPointers(left, right *resource.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func parseTimestamp(value string) (time.Time, error) {
	if len(value) != len(timestampLayout) {
		return time.Time{}, ErrInvalidClockState
	}
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.Year() < 1 || parsed.Year() > 9999 || parsed.Format(timestampLayout) != value {
		return time.Time{}, ErrInvalidClockState
	}
	return parsed, nil
}

func normalizeTimestamp(value time.Time) (string, error) {
	if value.IsZero() {
		return "", ErrInvalidClockState
	}
	value = value.UTC().Truncate(time.Millisecond)
	if value.Year() < 1 || value.Year() > 9999 {
		return "", ErrInvalidClockState
	}
	return value.Format(timestampLayout), nil
}

func writeSafeFormat(state fmt.State, _ rune, safe string) {
	_, _ = state.Write([]byte(safe))
}
