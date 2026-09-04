package audit

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/administration"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// EventInput contains only bounded references and closed vocabulary. It has no
// arbitrary payload, request body, response body, error text, or identity claim.
type EventInput struct {
	ID                   resource.ID
	Stream               Stream
	Sequence             uint64
	RecordedAt           time.Time
	ClockState           ClockState
	Kind                 EventKind
	Source               Source
	Actor                ActorRef
	AuthenticationMethod AuthenticationMethod
	Action               authorization.Action
	Request              *RequestRef
	Target               *TargetRef
	Decision             *DecisionRef
	Operation            *OperationRef
	Attempt              *AttemptRef
	Elevation            *ElevationRef
	Outcome              Outcome
}

// Event is one immutable canonical audit fact. Sequence, not wall-clock time,
// defines stream order.
type Event struct {
	initialized          bool
	id                   resource.ID
	stream               Stream
	sequence             uint64
	recordedAt           string
	clockState           ClockState
	kind                 EventKind
	source               Source
	actor                ActorRef
	authenticationMethod AuthenticationMethod
	action               authorization.Action
	request              *RequestRef
	target               *TargetRef
	decision             *DecisionRef
	operation            *OperationRef
	attempt              *AttemptRef
	elevation            *ElevationRef
	outcome              Outcome
}

// NewEvent validates and takes ownership-independent copies of every reference.
func NewEvent(input EventInput) (Event, error) {
	recordedAt, err := normalizeTimestamp(input.RecordedAt)
	if err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidClockState)
	}
	event := Event{
		initialized:          true,
		id:                   input.ID,
		stream:               input.Stream,
		sequence:             input.Sequence,
		recordedAt:           recordedAt,
		clockState:           input.ClockState,
		kind:                 input.Kind,
		source:               input.Source,
		actor:                input.Actor,
		authenticationMethod: input.AuthenticationMethod,
		action:               input.Action,
		request:              cloneRequestRef(input.Request),
		target:               cloneTargetRef(input.Target),
		decision:             cloneDecisionRef(input.Decision),
		operation:            cloneOperationRef(input.Operation),
		attempt:              cloneAttemptRef(input.Attempt),
		elevation:            cloneElevationRef(input.Elevation),
		outcome:              input.Outcome,
	}
	if err := ValidateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

// ValidateEvent checks the complete semantic and encoded-size contract.
func ValidateEvent(event Event) error {
	if err := validateEventFields(event); err != nil {
		return err
	}
	data, err := encodeEvent(event)
	if err != nil {
		return fmt.Errorf("%w: encode", ErrInvalidEvent)
	}
	if len(data) > MaxCanonicalEventBytes {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrCanonicalTooLarge)
	}
	return nil
}

// MarshalCanonicalEvent emits the only accepted compact event representation.
func MarshalCanonicalEvent(event Event) ([]byte, error) {
	if err := validateEventFields(event); err != nil {
		return nil, err
	}
	data, err := encodeEvent(event)
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrInvalidEvent)
	}
	if len(data) > MaxCanonicalEventBytes {
		return nil, ErrCanonicalTooLarge
	}
	return data, nil
}

// UnmarshalCanonicalEvent rejects unknown fields, duplicate names, alternate
// encodings, and values over the event ceiling.
func UnmarshalCanonicalEvent(data []byte) (Event, error) {
	if len(data) == 0 {
		return Event{}, ErrNonCanonical
	}
	if len(data) > MaxCanonicalEventBytes {
		return Event{}, ErrCanonicalTooLarge
	}
	var wire eventWire
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Event{}, ErrNonCanonical
	}
	event, err := eventFromWire(wire)
	if err != nil {
		return Event{}, err
	}
	canonical, err := MarshalCanonicalEvent(event)
	if err != nil {
		return Event{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Event{}, ErrNonCanonical
	}
	return event, nil
}

func (event Event) MarshalJSON() ([]byte, error) { return MarshalCanonicalEvent(event) }

func (event *Event) UnmarshalJSON(data []byte) error {
	if event == nil {
		return ErrInvalidEvent
	}
	parsed, err := UnmarshalCanonicalEvent(data)
	if err != nil {
		return err
	}
	*event = parsed
	return nil
}

func (event Event) ID() resource.ID        { return event.id }
func (event Event) Stream() Stream         { return event.stream }
func (event Event) Sequence() uint64       { return event.sequence }
func (event Event) ClockState() ClockState { return event.clockState }
func (event Event) Kind() EventKind        { return event.kind }
func (event Event) Source() Source         { return event.source }
func (event Event) Actor() ActorRef        { return event.actor }
func (event Event) AuthenticationMethod() AuthenticationMethod {
	return event.authenticationMethod
}
func (event Event) Action() authorization.Action { return event.action }
func (event Event) Outcome() Outcome             { return event.outcome }
func (event Event) RecordedAt() time.Time {
	parsed, _ := parseTimestamp(event.recordedAt)
	return parsed
}
func (event Event) Request() (RequestRef, bool) {
	if event.request == nil {
		return RequestRef{}, false
	}
	return *cloneRequestRef(event.request), true
}
func (event Event) Target() (TargetRef, bool) {
	if event.target == nil {
		return TargetRef{}, false
	}
	return *cloneTargetRef(event.target), true
}
func (event Event) Decision() (DecisionRef, bool) {
	if event.decision == nil {
		return DecisionRef{}, false
	}
	return *cloneDecisionRef(event.decision), true
}
func (event Event) Operation() (OperationRef, bool) {
	if event.operation == nil {
		return OperationRef{}, false
	}
	return *cloneOperationRef(event.operation), true
}
func (event Event) Attempt() (AttemptRef, bool) {
	if event.attempt == nil {
		return AttemptRef{}, false
	}
	return *cloneAttemptRef(event.attempt), true
}
func (event Event) Elevation() (ElevationRef, bool) {
	if event.elevation == nil {
		return ElevationRef{}, false
	}
	return *cloneElevationRef(event.elevation), true
}

func (event Event) String() string {
	if ValidateEvent(event) != nil {
		return "audit-event(invalid)"
	}
	return fmt.Sprintf(
		"audit-event(kind=%s,source=%s,sequence=%d,outcome=%s)",
		event.kind,
		event.source,
		event.sequence,
		event.outcome,
	)
}
func (event Event) GoString() string { return event.String() }
func (event Event) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, event.String())
}

type streamWire struct {
	Kind        StreamKind `json:"kind"`
	WorkspaceID string     `json:"workspaceId,omitempty"`
}

type actorWire struct {
	Kind      ActorKind `json:"kind"`
	Pseudonym string    `json:"pseudonym,omitempty"`
}

type requestRefWire struct {
	ID string `json:"id"`
}

type targetRefWire struct {
	ObjectKind           authorization.ObjectKind `json:"objectKind"`
	ObjectID             string                   `json:"objectId"`
	ResourceKind         string                   `json:"resourceKind"`
	ResourceID           string                   `json:"resourceId"`
	WorkspaceID          string                   `json:"workspaceId"`
	EnvironmentID        string                   `json:"environmentId,omitempty"`
	ProviderConnectionID string                   `json:"providerConnectionId,omitempty"`
}

type decisionRefWire struct {
	PolicyVersion string               `json:"policyVersion"`
	InputDigest   string               `json:"inputDigest"`
	Effect        authorization.Effect `json:"effect"`
	Reason        authorization.Reason `json:"reason"`
}

type operationRefWire struct {
	ID                   string          `json:"id"`
	WorkspaceID          string          `json:"workspaceId"`
	ResourceID           string          `json:"resourceId"`
	EnvironmentID        string          `json:"environmentId,omitempty"`
	ProviderConnectionID string          `json:"providerConnectionId,omitempty"`
	Generation           int64           `json:"generation"`
	ResourceVersion      string          `json:"resourceVersion"`
	Phase                operation.Phase `json:"phase"`
	Reason               string          `json:"reason,omitempty"`
	UpdatedAt            string          `json:"updatedAt"`
}

type attemptRefWire struct {
	ID      string `json:"id"`
	Ordinal uint32 `json:"ordinal"`
}

type elevationRefWire struct {
	GrantID              string               `json:"grantId"`
	AdministratorID      string               `json:"administratorId"`
	Action               authorization.Action `json:"action"`
	TargetKind           string               `json:"targetKind"`
	WorkspaceID          string               `json:"workspaceId,omitempty"`
	ObjectID             string               `json:"objectId,omitempty"`
	ResourceID           string               `json:"resourceId,omitempty"`
	EnvironmentID        string               `json:"environmentId,omitempty"`
	ProviderConnectionID string               `json:"providerConnectionId,omitempty"`
	Reason               string               `json:"reason"`
	CaseReference        string               `json:"caseReference,omitempty"`
	IssuedAt             string               `json:"issuedAt"`
	ExpiresAt            string               `json:"expiresAt"`
	State                ElevationState       `json:"state"`
	RecordedAt           string               `json:"recordedAt"`
}

type eventWire struct {
	ContractVersion      string               `json:"contractVersion"`
	ID                   string               `json:"id"`
	Stream               streamWire           `json:"stream"`
	Sequence             uint64               `json:"sequence"`
	RecordedAt           string               `json:"recordedAt"`
	ClockState           ClockState           `json:"clockState"`
	Kind                 EventKind            `json:"kind"`
	Source               Source               `json:"source"`
	Actor                actorWire            `json:"actor"`
	AuthenticationMethod AuthenticationMethod `json:"authenticationMethod"`
	Action               authorization.Action `json:"action"`
	Request              *requestRefWire      `json:"request,omitempty"`
	Target               *targetRefWire       `json:"target,omitempty"`
	Decision             *decisionRefWire     `json:"decision,omitempty"`
	Operation            *operationRefWire    `json:"operation,omitempty"`
	Attempt              *attemptRefWire      `json:"attempt,omitempty"`
	Elevation            *elevationRefWire    `json:"elevation,omitempty"`
	Outcome              Outcome              `json:"outcome"`
}

func encodeEvent(event Event) ([]byte, error) {
	return jsonv2.Marshal(
		eventToWire(event),
		json.DefaultOptionsV1(),
		jsontext.AllowInvalidUTF8(false),
	)
}

func eventToWire(event Event) eventWire {
	wire := eventWire{
		ContractVersion:      ContractVersion,
		ID:                   event.id.String(),
		Stream:               streamToWire(event.stream),
		Sequence:             event.sequence,
		RecordedAt:           event.recordedAt,
		ClockState:           event.clockState,
		Kind:                 event.kind,
		Source:               event.source,
		Actor:                actorToWire(event.actor),
		AuthenticationMethod: event.authenticationMethod,
		Action:               event.action,
		Outcome:              event.outcome,
	}
	if event.request != nil {
		wire.Request = &requestRefWire{ID: event.request.id.String()}
	}
	if event.target != nil {
		wire.Target = targetToWire(*event.target)
	}
	if event.decision != nil {
		wire.Decision = &decisionRefWire{
			PolicyVersion: event.decision.policyVersion,
			InputDigest:   event.decision.inputDigest,
			Effect:        event.decision.effect,
			Reason:        event.decision.reason,
		}
	}
	if event.operation != nil {
		wire.Operation = &operationRefWire{
			ID:              event.operation.id.String(),
			WorkspaceID:     event.operation.workspaceID.String(),
			ResourceID:      event.operation.resourceID.String(),
			Generation:      event.operation.generation,
			ResourceVersion: event.operation.resourceVersion,
			Phase:           event.operation.phase,
			Reason:          event.operation.reason,
			UpdatedAt:       event.operation.updatedAt,
		}
		if event.operation.environmentID != nil {
			wire.Operation.EnvironmentID = event.operation.environmentID.String()
		}
		if event.operation.providerConnectionID != nil {
			wire.Operation.ProviderConnectionID = event.operation.providerConnectionID.String()
		}
	}
	if event.attempt != nil {
		wire.Attempt = &attemptRefWire{ID: event.attempt.id.String(), Ordinal: event.attempt.ordinal}
	}
	if event.elevation != nil {
		wire.Elevation = elevationToWire(*event.elevation)
	}
	return wire
}

func eventFromWire(wire eventWire) (Event, error) {
	if wire.ContractVersion != ContractVersion {
		return Event{}, ErrInvalidEvent
	}
	id, err := parseReferenceID(wire.ID)
	if err != nil {
		return Event{}, err
	}
	stream, err := streamFromWire(wire.Stream)
	if err != nil {
		return Event{}, err
	}
	actor := ActorRef{initialized: true, kind: wire.Actor.Kind, pseudonym: wire.Actor.Pseudonym}
	event := Event{
		initialized:          true,
		id:                   id,
		stream:               stream,
		sequence:             wire.Sequence,
		recordedAt:           wire.RecordedAt,
		clockState:           wire.ClockState,
		kind:                 wire.Kind,
		source:               wire.Source,
		actor:                actor,
		authenticationMethod: wire.AuthenticationMethod,
		action:               wire.Action,
		outcome:              wire.Outcome,
	}
	if wire.Request != nil {
		id, parseErr := parseReferenceID(wire.Request.ID)
		if parseErr != nil {
			return Event{}, parseErr
		}
		event.request = &RequestRef{initialized: true, id: id}
	}
	if wire.Target != nil {
		reference, parseErr := targetFromWire(*wire.Target)
		if parseErr != nil {
			return Event{}, parseErr
		}
		event.target = &reference
	}
	if wire.Decision != nil {
		reference := DecisionRef{
			initialized:   true,
			policyVersion: wire.Decision.PolicyVersion,
			inputDigest:   wire.Decision.InputDigest,
			effect:        wire.Decision.Effect,
			reason:        wire.Decision.Reason,
		}
		event.decision = &reference
	}
	if wire.Operation != nil {
		reference, parseErr := operationFromWire(*wire.Operation)
		if parseErr != nil {
			return Event{}, parseErr
		}
		event.operation = &reference
	}
	if wire.Attempt != nil {
		id, parseErr := parseReferenceID(wire.Attempt.ID)
		if parseErr != nil {
			return Event{}, parseErr
		}
		event.attempt = &AttemptRef{initialized: true, id: id, ordinal: wire.Attempt.Ordinal}
	}
	if wire.Elevation != nil {
		reference, parseErr := elevationFromWire(*wire.Elevation)
		if parseErr != nil {
			return Event{}, parseErr
		}
		event.elevation = &reference
	}
	if err := ValidateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

func validateEventFields(event Event) error {
	if !event.initialized {
		return ErrInvalidEvent
	}
	if _, err := resource.ParseID(event.id.String()); err != nil || event.sequence == 0 {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if err := ValidateStream(event.stream); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidStream)
	}
	if _, err := parseTimestamp(event.recordedAt); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidClockState)
	}
	if _, err := ParseClockState(event.clockState.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidClockState)
	}
	if _, err := ParseEventKind(event.kind.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidEventKind)
	}
	if _, err := ParseSource(event.source.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidSource)
	}
	if err := ValidateActorRef(event.actor); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidActor)
	}
	if err := validateActorAuthentication(event.actor, event.authenticationMethod); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, err)
	}
	if _, err := authorization.ParseAction(event.action.String()); err != nil {
		return fmt.Errorf("%w: invalid action", ErrInvalidEvent)
	}
	if _, err := ParseOutcome(event.outcome.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidOutcome)
	}
	if event.request != nil && validateRequestRef(*event.request) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if event.target != nil && validateTargetRef(*event.target) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if event.decision != nil && validateDecisionRef(*event.decision) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if event.operation != nil && validateOperationRef(*event.operation) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if event.attempt != nil && validateAttemptRef(*event.attempt) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if event.elevation != nil && validateElevationRef(*event.elevation) != nil {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrInvalidReference)
	}
	if err := validateEventRelationships(event); err != nil {
		return err
	}
	return nil
}

func validateActorAuthentication(actor ActorRef, method AuthenticationMethod) error {
	if _, err := ParseAuthenticationMethod(method.String()); err != nil {
		return ErrInvalidAuthentication
	}
	valid := false
	switch actor.kind {
	case ActorKindAnonymous:
		valid = method == AuthenticationMethodNone
	case ActorKindHuman:
		valid = method == AuthenticationMethodOIDC || method == AuthenticationMethodStrongOIDC
	case ActorKindWorkload:
		valid = method == AuthenticationMethodWorkloadOIDC || method == AuthenticationMethodInternal
	case ActorKindAdministrator:
		valid = method == AuthenticationMethodStrongOIDC
	}
	if !valid {
		return ErrInvalidAuthentication
	}
	return nil
}

func validateEventRelationships(event Event) error {
	switch event.kind {
	case EventKindRequest:
		if event.request == nil {
			return fmt.Errorf("%w: request reference required", ErrInvalidEvent)
		}
	case EventKindAuthorization:
		if event.decision == nil {
			return fmt.Errorf("%w: decision reference required", ErrInvalidEvent)
		}
	case EventKindOperation:
		if event.operation == nil {
			return fmt.Errorf("%w: operation reference required", ErrInvalidEvent)
		}
	case EventKindProviderAttempt:
		if event.operation == nil || event.attempt == nil || event.source != SourceProviderAdapter {
			return fmt.Errorf("%w: operation and attempt references required", ErrInvalidEvent)
		}
	case EventKindElevation:
		if event.elevation == nil || event.source != SourceAdministration ||
			event.actor.kind != ActorKindAdministrator ||
			event.authenticationMethod != AuthenticationMethodStrongOIDC {
			return fmt.Errorf("%w: elevation attribution", ErrInvalidEvent)
		}
	default:
	}
	if event.attempt != nil && event.kind != EventKindProviderAttempt {
		return fmt.Errorf("%w: attempt reference on non-attempt event", ErrInvalidEvent)
	}
	if event.elevation != nil {
		if event.kind != EventKindElevation || event.elevation.action != event.action ||
			event.elevation.administratorID.String() != event.actor.pseudonym ||
			event.elevation.recordedAt != event.recordedAt {
			return fmt.Errorf("%w: elevation reference mismatch", ErrInvalidEvent)
		}
		if event.operation != nil && !elevationMatchesOperation(*event.elevation, *event.operation) {
			return fmt.Errorf("%w: elevation and operation scope mismatch", ErrInvalidEvent)
		}
		if event.target != nil && !elevationMatchesTarget(*event.elevation, *event.target) {
			return fmt.Errorf("%w: elevation and target scope mismatch", ErrInvalidEvent)
		}
	}
	if event.operation != nil && event.target != nil {
		if event.operation.workspaceID != event.target.workspaceID ||
			event.operation.resourceID != event.target.resourceID ||
			!equalIDPointers(event.operation.environmentID, event.target.environmentID) ||
			!equalIDPointers(event.operation.providerConnectionID, event.target.providerConnectionID) {
			return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrWorkspaceMismatch)
		}
		if event.target.objectKind == authorization.ObjectKindOperation &&
			event.target.objectID != event.operation.id {
			return fmt.Errorf("%w: operation target mismatch", ErrInvalidEvent)
		}
	}
	workspaceID, workspaceStream := event.stream.WorkspaceID()
	if !workspaceStream {
		return nil
	}
	if event.target != nil && event.target.workspaceID != workspaceID {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrWorkspaceMismatch)
	}
	if event.operation != nil && event.operation.workspaceID != workspaceID {
		return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrWorkspaceMismatch)
	}
	if event.elevation != nil {
		elevationWorkspace, present := optionalID(event.elevation.workspaceID)
		if !present || elevationWorkspace != workspaceID {
			return fmt.Errorf("%w: %w", ErrInvalidEvent, ErrWorkspaceMismatch)
		}
	}
	return nil
}

func elevationMatchesOperation(elevation ElevationRef, operationReference OperationRef) bool {
	return elevation.targetKind == administration.TargetKindOperation.String() &&
		elevation.objectID != nil && *elevation.objectID == operationReference.id &&
		elevation.workspaceID != nil && *elevation.workspaceID == operationReference.workspaceID &&
		elevation.resourceID != nil && *elevation.resourceID == operationReference.resourceID &&
		equalIDPointers(elevation.environmentID, operationReference.environmentID) &&
		equalIDPointers(elevation.providerConnectionID, operationReference.providerConnectionID)
}

func elevationMatchesTarget(elevation ElevationRef, target TargetRef) bool {
	switch administration.TargetKind(elevation.targetKind) {
	case administration.TargetKindWorkspaceAudit:
		return target.objectKind == authorization.ObjectKindAudit &&
			elevation.objectID != nil && *elevation.objectID == target.objectID &&
			elevation.workspaceID != nil && *elevation.workspaceID == target.workspaceID &&
			elevation.resourceID != nil && *elevation.resourceID == target.resourceID &&
			equalIDPointers(elevation.environmentID, target.environmentID) &&
			equalIDPointers(elevation.providerConnectionID, target.providerConnectionID)
	case administration.TargetKindOperation:
		return target.objectKind == authorization.ObjectKindOperation &&
			elevation.objectID != nil && *elevation.objectID == target.objectID &&
			elevation.workspaceID != nil && *elevation.workspaceID == target.workspaceID &&
			elevation.resourceID != nil && *elevation.resourceID == target.resourceID &&
			equalIDPointers(elevation.environmentID, target.environmentID) &&
			equalIDPointers(elevation.providerConnectionID, target.providerConnectionID)
	default:
		// PlatformAudit has no authorization.Target representation, and an
		// unrelated co-reference would make the privileged scope ambiguous.
		return false
	}
}

func streamToWire(stream Stream) streamWire {
	wire := streamWire{Kind: stream.kind}
	if stream.kind == StreamKindWorkspace {
		wire.WorkspaceID = stream.workspaceID.String()
	}
	return wire
}

func streamFromWire(wire streamWire) (Stream, error) {
	switch wire.Kind {
	case StreamKindWorkspace:
		id, err := parseReferenceID(wire.WorkspaceID)
		if err != nil {
			return Stream{}, fmt.Errorf("%w: workspace ID", ErrInvalidStream)
		}
		return NewWorkspaceStream(id)
	case StreamKindPlatform:
		if wire.WorkspaceID != "" {
			return Stream{}, ErrInvalidStream
		}
		return NewPlatformStream(), nil
	default:
		return Stream{}, ErrInvalidStream
	}
}

func actorToWire(actor ActorRef) actorWire {
	return actorWire{Kind: actor.kind, Pseudonym: actor.pseudonym}
}

func targetToWire(reference TargetRef) *targetRefWire {
	wire := &targetRefWire{
		ObjectKind:   reference.objectKind,
		ObjectID:     reference.objectID.String(),
		ResourceKind: reference.resourceKind,
		ResourceID:   reference.resourceID.String(),
		WorkspaceID:  reference.workspaceID.String(),
	}
	if reference.environmentID != nil {
		wire.EnvironmentID = reference.environmentID.String()
	}
	if reference.providerConnectionID != nil {
		wire.ProviderConnectionID = reference.providerConnectionID.String()
	}
	return wire
}

func targetFromWire(wire targetRefWire) (TargetRef, error) {
	objectID, err := parseReferenceID(wire.ObjectID)
	if err != nil {
		return TargetRef{}, err
	}
	resourceID, err := parseReferenceID(wire.ResourceID)
	if err != nil {
		return TargetRef{}, err
	}
	workspaceID, err := parseReferenceID(wire.WorkspaceID)
	if err != nil {
		return TargetRef{}, err
	}
	reference := TargetRef{
		initialized:  true,
		objectKind:   wire.ObjectKind,
		objectID:     objectID,
		resourceKind: wire.ResourceKind,
		resourceID:   resourceID,
		workspaceID:  workspaceID,
	}
	if wire.EnvironmentID != "" {
		id, parseErr := parseReferenceID(wire.EnvironmentID)
		if parseErr != nil {
			return TargetRef{}, parseErr
		}
		reference.environmentID = idPointer(id)
	}
	if wire.ProviderConnectionID != "" {
		id, parseErr := parseReferenceID(wire.ProviderConnectionID)
		if parseErr != nil {
			return TargetRef{}, parseErr
		}
		reference.providerConnectionID = idPointer(id)
	}
	if err := validateTargetRef(reference); err != nil {
		return TargetRef{}, err
	}
	return reference, nil
}

func operationFromWire(wire operationRefWire) (OperationRef, error) {
	id, err := parseReferenceID(wire.ID)
	if err != nil {
		return OperationRef{}, err
	}
	workspaceID, err := parseReferenceID(wire.WorkspaceID)
	if err != nil {
		return OperationRef{}, err
	}
	resourceID, err := parseReferenceID(wire.ResourceID)
	if err != nil {
		return OperationRef{}, err
	}
	reference := OperationRef{
		initialized:     true,
		id:              id,
		workspaceID:     workspaceID,
		resourceID:      resourceID,
		generation:      wire.Generation,
		resourceVersion: wire.ResourceVersion,
		phase:           wire.Phase,
		reason:          wire.Reason,
		updatedAt:       wire.UpdatedAt,
	}
	if wire.EnvironmentID != "" {
		environmentID, parseErr := parseReferenceID(wire.EnvironmentID)
		if parseErr != nil {
			return OperationRef{}, parseErr
		}
		reference.environmentID = idPointer(environmentID)
	}
	if wire.ProviderConnectionID != "" {
		providerID, parseErr := parseReferenceID(wire.ProviderConnectionID)
		if parseErr != nil {
			return OperationRef{}, parseErr
		}
		reference.providerConnectionID = idPointer(providerID)
	}
	if err := validateOperationRef(reference); err != nil {
		return OperationRef{}, err
	}
	return reference, nil
}

func elevationToWire(reference ElevationRef) *elevationRefWire {
	wire := &elevationRefWire{
		GrantID:         reference.grantID.String(),
		AdministratorID: reference.administratorID.String(),
		Action:          reference.action,
		TargetKind:      reference.targetKind,
		Reason:          reference.reason,
		CaseReference:   reference.caseReference,
		IssuedAt:        reference.issuedAt,
		ExpiresAt:       reference.expiresAt,
		State:           reference.state,
		RecordedAt:      reference.recordedAt,
	}
	if reference.workspaceID != nil {
		wire.WorkspaceID = reference.workspaceID.String()
	}
	if reference.objectID != nil {
		wire.ObjectID = reference.objectID.String()
	}
	if reference.resourceID != nil {
		wire.ResourceID = reference.resourceID.String()
	}
	if reference.environmentID != nil {
		wire.EnvironmentID = reference.environmentID.String()
	}
	if reference.providerConnectionID != nil {
		wire.ProviderConnectionID = reference.providerConnectionID.String()
	}
	return wire
}

func elevationFromWire(wire elevationRefWire) (ElevationRef, error) {
	grantID, err := parseReferenceID(wire.GrantID)
	if err != nil {
		return ElevationRef{}, err
	}
	administratorID, err := parseReferenceID(wire.AdministratorID)
	if err != nil {
		return ElevationRef{}, err
	}
	reference := ElevationRef{
		initialized:     true,
		grantID:         grantID,
		administratorID: administratorID,
		action:          wire.Action,
		targetKind:      wire.TargetKind,
		reason:          wire.Reason,
		caseReference:   wire.CaseReference,
		issuedAt:        wire.IssuedAt,
		expiresAt:       wire.ExpiresAt,
		state:           wire.State,
		recordedAt:      wire.RecordedAt,
	}
	values := []struct {
		value       string
		destination **resource.ID
	}{
		{wire.WorkspaceID, &reference.workspaceID},
		{wire.ObjectID, &reference.objectID},
		{wire.ResourceID, &reference.resourceID},
		{wire.EnvironmentID, &reference.environmentID},
		{wire.ProviderConnectionID, &reference.providerConnectionID},
	}
	for _, candidate := range values {
		value, destination := candidate.value, candidate.destination
		if value == "" {
			continue
		}
		id, parseErr := parseReferenceID(value)
		if parseErr != nil {
			return ElevationRef{}, parseErr
		}
		*destination = idPointer(id)
	}
	if err := validateElevationRef(reference); err != nil {
		return ElevationRef{}, err
	}
	return reference, nil
}

func parseReferenceID(value string) (resource.ID, error) {
	id, err := resource.ParseID(value)
	if err != nil {
		return "", fmt.Errorf("%w: opaque ID", ErrInvalidReference)
	}
	return id, nil
}

func cloneRequestRef(reference *RequestRef) *RequestRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	return &copy
}

func cloneTargetRef(reference *TargetRef) *TargetRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	copy.environmentID = cloneIDPointer(reference.environmentID)
	copy.providerConnectionID = cloneIDPointer(reference.providerConnectionID)
	return &copy
}

func cloneDecisionRef(reference *DecisionRef) *DecisionRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	return &copy
}

func cloneOperationRef(reference *OperationRef) *OperationRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	copy.environmentID = cloneIDPointer(reference.environmentID)
	copy.providerConnectionID = cloneIDPointer(reference.providerConnectionID)
	return &copy
}

func cloneAttemptRef(reference *AttemptRef) *AttemptRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	return &copy
}

func cloneElevationRef(reference *ElevationRef) *ElevationRef {
	if reference == nil {
		return nil
	}
	copy := *reference
	copy.workspaceID = cloneIDPointer(reference.workspaceID)
	copy.objectID = cloneIDPointer(reference.objectID)
	copy.resourceID = cloneIDPointer(reference.resourceID)
	copy.environmentID = cloneIDPointer(reference.environmentID)
	copy.providerConnectionID = cloneIDPointer(reference.providerConnectionID)
	return &copy
}
