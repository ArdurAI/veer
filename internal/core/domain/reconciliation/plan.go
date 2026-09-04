package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"log/slog"
	"slices"
	"sort"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// PlanInput contains the complete provider-neutral identity basis for one
// immutable plan. Plan ID, revision, and Supersedes are lineage metadata and
// intentionally do not alter the semantic Digest.
type PlanInput struct {
	ID               resource.ID
	Revision         uint32
	Kind             PlanKind
	Operation        operation.Operation
	PlannerVersion   string
	DesiredIntent    Evidence
	ObservedSnapshot Evidence
	Actor            identity.Principal
	Authorization    authorization.Decision
	ProviderBinding  *ProviderBinding
	Capability       Evidence
	Quota            Evidence
	Cost             Evidence
	Supersedes       *PlanDigest
	CompletedEffects []EffectKey
	Compensates      []EffectKey
}

// Plan is one immutable plan identity and its bounded safe basis. It is not a
// provider-native plan body; issue #33 owns executable steps.
type Plan struct {
	initialized        bool
	id                 resource.ID
	revision           uint32
	kind               PlanKind
	operationID        resource.ID
	workspaceID        resource.ID
	resourceID         resource.ID
	environmentID      *resource.ID
	connectionID       *resource.ID
	generation         int64
	plannerVersion     string
	desired            Evidence
	observed           Evidence
	actorKind          identity.Kind
	actorFingerprint   string
	policyVersion      string
	authorizationInput string
	providerBinding    *ProviderBinding
	capability         Evidence
	quota              Evidence
	cost               Evidence
	supersedes         *PlanDigest
	completedEffects   []EffectKey
	compensates        []EffectKey
	digest             PlanDigest
}

// NewPlan validates and hashes one complete plan basis without retaining actor claims.
func NewPlan(input PlanInput) (Plan, error) {
	if !validID(input.ID) || input.Revision == 0 || !validVersion(input.PlannerVersion) ||
		operation.Validate(input.Operation) != nil || terminalOperation(input.Operation.Phase) {
		return Plan{}, ErrInvalidPlan
	}
	if _, err := ParsePlanKind(input.Kind.String()); err != nil {
		return Plan{}, ErrInvalidPlan
	}
	if identity.ValidatePrincipal(input.Actor) != nil ||
		authorization.ValidateDecision(input.Authorization) != nil || !input.Authorization.Allowed() {
		return Plan{}, ErrInvalidPlan
	}
	if !evidenceHasKind(input.DesiredIntent, EvidenceDesiredIntent) ||
		!evidenceHasKind(input.ObservedSnapshot, EvidenceObservedSnapshot) ||
		!evidenceHasKind(input.Capability, EvidenceCapability) ||
		!evidenceHasKind(input.Quota, EvidenceQuota) ||
		!evidenceHasKind(input.Cost, EvidenceCost) {
		return Plan{}, ErrInvalidPlan
	}
	if err := validatePlanProviderBinding(input.Operation, input.ProviderBinding); err != nil {
		return Plan{}, err
	}
	completed, err := canonicalEffectSet(input.CompletedEffects, input.Operation)
	if err != nil {
		return Plan{}, err
	}
	if input.Revision == 1 && len(completed) != 0 {
		return Plan{}, ErrInvalidPlan
	}
	compensates, err := canonicalEffectSet(input.Compensates, input.Operation)
	if err != nil {
		return Plan{}, err
	}
	switch input.Kind {
	case PlanKindForward:
		if len(compensates) != 0 {
			return Plan{}, ErrInvalidPlan
		}
	case PlanKindCompensation:
		if input.Revision == 1 || len(compensates) == 0 || !effectSetContainsAll(completed, compensates) {
			return Plan{}, ErrInvalidPlan
		}
	}
	if (input.Revision == 1) != (input.Supersedes == nil) {
		return Plan{}, ErrInvalidPlan
	}
	if input.Supersedes != nil && !input.Supersedes.initialized {
		return Plan{}, ErrInvalidPlan
	}

	value := Plan{
		initialized:        true,
		id:                 input.ID,
		revision:           input.Revision,
		kind:               input.Kind,
		operationID:        input.Operation.ID,
		workspaceID:        input.Operation.WorkspaceID,
		resourceID:         input.Operation.ResourceID,
		environmentID:      cloneID(input.Operation.EnvironmentID),
		connectionID:       cloneID(input.Operation.ProviderConnectionID),
		generation:         input.Operation.Generation,
		plannerVersion:     input.PlannerVersion,
		desired:            input.DesiredIntent,
		observed:           input.ObservedSnapshot,
		actorKind:          input.Actor.Kind(),
		actorFingerprint:   input.Actor.Fingerprint().String(),
		policyVersion:      input.Authorization.PolicyVersion().String(),
		authorizationInput: input.Authorization.InputDigest().String(),
		providerBinding:    cloneProviderBinding(input.ProviderBinding),
		capability:         input.Capability,
		quota:              input.Quota,
		cost:               input.Cost,
		supersedes:         clonePlanDigest(input.Supersedes),
		completedEffects:   completed,
		compensates:        compensates,
	}
	value.digest = derivePlanDigest(value)
	if err := ValidatePlan(value); err != nil {
		return Plan{}, err
	}
	return value, nil
}

// ValidatePlan checks a complete plan and recomputes its semantic digest.
func ValidatePlan(value Plan) error {
	if !value.initialized || !validID(value.id) || value.revision == 0 ||
		!validID(value.operationID) || !validID(value.workspaceID) || !validID(value.resourceID) ||
		value.generation < 1 || !validVersion(value.plannerVersion) ||
		!validActorProjection(value.actorKind, value.actorFingerprint) ||
		!validVersion(value.policyVersion) || value.authorizationInput == "" || !value.digest.initialized {
		return ErrInvalidPlan
	}
	if _, err := authorization.ParseInputDigest(value.authorizationInput); err != nil {
		return ErrInvalidPlan
	}
	if _, err := authorization.ParsePolicyVersion(value.policyVersion); err != nil {
		return ErrInvalidPlan
	}
	if _, err := ParsePlanKind(value.kind.String()); err != nil {
		return ErrInvalidPlan
	}
	if !evidenceHasKind(value.desired, EvidenceDesiredIntent) ||
		!evidenceHasKind(value.observed, EvidenceObservedSnapshot) ||
		!evidenceHasKind(value.capability, EvidenceCapability) ||
		!evidenceHasKind(value.quota, EvidenceQuota) || !evidenceHasKind(value.cost, EvidenceCost) {
		return ErrInvalidPlan
	}
	if (value.environmentID == nil) != (value.connectionID == nil) {
		return ErrInvalidPlan
	}
	if value.environmentID != nil && (!validID(*value.environmentID) || !validID(*value.connectionID)) {
		return ErrInvalidPlan
	}
	if (value.connectionID == nil) != (value.providerBinding == nil) {
		return ErrInvalidPlan
	}
	if value.providerBinding != nil {
		if ValidateProviderBinding(*value.providerBinding) != nil ||
			value.providerBinding.connectionID != *value.connectionID {
			return ErrInvalidPlan
		}
	}
	if (value.revision == 1) != (value.supersedes == nil) ||
		(value.supersedes != nil && !value.supersedes.initialized) {
		return ErrInvalidPlan
	}
	if value.revision == 1 && len(value.completedEffects) != 0 {
		return ErrInvalidPlan
	}
	if !validCanonicalEffects(value.completedEffects, value) || !validCanonicalEffects(value.compensates, value) {
		return ErrInvalidPlan
	}
	if (value.kind == PlanKindForward && len(value.compensates) != 0) ||
		(value.kind == PlanKindCompensation && (value.revision == 1 || len(value.compensates) == 0 ||
			!effectSetContainsAll(value.completedEffects, value.compensates))) {
		return ErrInvalidPlan
	}
	if !value.digest.Equal(derivePlanDigest(value)) {
		return ErrInvalidPlan
	}
	return nil
}

func (value Plan) ID() resource.ID               { return value.id }
func (value Plan) Revision() uint32              { return value.revision }
func (value Plan) Kind() PlanKind                { return value.kind }
func (value Plan) OperationID() resource.ID      { return value.operationID }
func (value Plan) WorkspaceID() resource.ID      { return value.workspaceID }
func (value Plan) ResourceID() resource.ID       { return value.resourceID }
func (value Plan) Generation() int64             { return value.generation }
func (value Plan) PlannerVersion() string        { return value.plannerVersion }
func (value Plan) DesiredIntent() Evidence       { return value.desired }
func (value Plan) ObservedSnapshot() Evidence    { return value.observed }
func (value Plan) Digest() PlanDigest            { return value.digest }
func (value Plan) CompletedEffects() []EffectKey { return slices.Clone(value.completedEffects) }
func (value Plan) Compensates() []EffectKey      { return slices.Clone(value.compensates) }
func (value Plan) ProviderBinding() (ProviderBinding, bool) {
	if value.providerBinding == nil {
		return ProviderBinding{}, false
	}
	return *value.providerBinding, true
}
func (value Plan) Supersedes() (PlanDigest, bool) {
	if value.supersedes == nil {
		return PlanDigest{}, false
	}
	return *value.supersedes, true
}

// NewWorkKey derives one compact queue identity from an exact plan and
// provider-neutral bounded work description.
func NewWorkKey(plan Plan, canonicalWork []byte) (WorkKey, error) {
	if ValidatePlan(plan) != nil || len(canonicalWork) == 0 || len(canonicalWork) > MaxEvidenceBytes {
		return WorkKey{}, ErrInvalidPlan
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.work.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, plan.operationID.String())
	writeHashBytes(hasher, plan.digest.digest[:])
	writeHashBytes(hasher, canonicalWork)
	return WorkKey{digestValue: digestFromHasher(hasher), planDigest: plan.digest}, nil
}

func (value Plan) String() string {
	if ValidatePlan(value) != nil {
		return "reconciliation-plan(invalid)"
	}
	return fmt.Sprintf("reconciliation-plan(kind=%s,revision=%d,identity=redacted,evidence=redacted)", value.kind, value.revision)
}
func (value Plan) GoString() string                  { return value.String() }
func (value Plan) Format(state fmt.State, verb rune) { writeSafeFormat(state, verb, value.String()) }
func (value Plan) LogValue() slog.Value              { return redactedLogValue(value.String()) }

func (Plan) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Plan) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Plan) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Plan) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

func derivePlanDigest(value Plan) PlanDigest {
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.plan.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, value.kind.String())
	writeHashFrame(hasher, value.operationID.String())
	writeHashFrame(hasher, value.workspaceID.String())
	writeHashFrame(hasher, value.resourceID.String())
	writeOptionalID(hasher, value.environmentID)
	writeOptionalID(hasher, value.connectionID)
	writeHashInt64(hasher, value.generation)
	writeHashFrame(hasher, value.plannerVersion)
	writeEvidence(hasher, value.desired)
	writeEvidence(hasher, value.observed)
	writeHashFrame(hasher, value.actorKind.String())
	writeHashFrame(hasher, value.actorFingerprint)
	writeHashFrame(hasher, authorization.ContractVersion)
	writeHashFrame(hasher, value.policyVersion)
	writeHashFrame(hasher, value.authorizationInput)
	writeProviderBinding(hasher, value.providerBinding)
	writeEvidence(hasher, value.capability)
	writeEvidence(hasher, value.quota)
	writeEvidence(hasher, value.cost)
	writeHashUint64(hasher, uint64(len(value.completedEffects)))
	for _, effect := range value.completedEffects {
		writeHashBytes(hasher, effect.digest.digest[:])
	}
	writeHashUint64(hasher, uint64(len(value.compensates)))
	for _, effect := range value.compensates {
		writeHashBytes(hasher, effect.digest.digest[:])
	}
	return PlanDigest{digestFromHasher(hasher)}
}

func writeEvidence(hasher hash.Hash, value Evidence) {
	writeHashFrame(hasher, value.kind.String())
	writeHashFrame(hasher, value.version)
	writeHashBytes(hasher, value.digest.digest[:])
}

func writeProviderBinding(hasher hash.Hash, value *ProviderBinding) {
	if value == nil {
		writeHashFrame(hasher, "0")
		return
	}
	writeHashFrame(hasher, "1")
	writeHashFrame(hasher, value.connectionID.String())
	writeHashInt64(hasher, value.connectionGeneration)
	writeHashFrame(hasher, value.connectionResourceVersion)
	writeEvidence(hasher, value.connectionEvidence)
	writeHashFrame(hasher, value.credentialReferenceID.String())
	writeHashInt64(hasher, value.credentialGeneration)
	writeHashFrame(hasher, value.credentialResourceVersion)
	writeEvidence(hasher, value.credentialEvidence)
}

func evidenceHasKind(value Evidence, kind EvidenceKind) bool {
	return ValidateEvidence(value) == nil && value.kind == kind
}

func validatePlanProviderBinding(op operation.Operation, binding *ProviderBinding) error {
	if op.ProviderConnectionID == nil {
		if binding != nil {
			return ErrPlanMismatch
		}
		return nil
	}
	if binding == nil || ValidateProviderBinding(*binding) != nil || binding.connectionID != *op.ProviderConnectionID {
		return ErrPlanMismatch
	}
	return nil
}

func canonicalEffectSet(values []EffectKey, op operation.Operation) ([]EffectKey, error) {
	if len(values) > MaxEffectsPerOperation {
		return nil, ErrInvalidPlan
	}
	result := slices.Clone(values)
	for _, value := range result {
		if ValidateEffectKey(value) != nil || value.operationID != op.ID || value.workspaceID != op.WorkspaceID ||
			value.resourceID != op.ResourceID || value.generation != op.Generation {
			return nil, ErrInvalidPlan
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].String() < result[right].String() })
	for index := 1; index < len(result); index++ {
		if result[index-1].Equal(result[index]) {
			return nil, ErrInvalidPlan
		}
	}
	return result, nil
}

func validCanonicalEffects(values []EffectKey, plan Plan) bool {
	for index, value := range values {
		if ValidateEffectKey(value) != nil || value.operationID != plan.operationID ||
			value.workspaceID != plan.workspaceID || value.resourceID != plan.resourceID ||
			value.generation != plan.generation || (index > 0 && values[index-1].String() >= value.String()) {
			return false
		}
	}
	return true
}

func effectSetContainsAll(superset, subset []EffectKey) bool {
	available := make(map[string]struct{}, len(superset))
	for _, effect := range superset {
		available[effect.String()] = struct{}{}
	}
	for _, effect := range subset {
		if _, exists := available[effect.String()]; !exists {
			return false
		}
	}
	return true
}

func effectSetContains(values []EffectKey, candidate EffectKey) bool {
	for _, value := range values {
		if value.Equal(candidate) {
			return true
		}
	}
	return false
}

func validActorProjection(kind identity.Kind, fingerprint string) bool {
	if kind != identity.KindHuman && kind != identity.KindWorkload {
		return false
	}
	return len(fingerprint) > 5 && fingerprint[:5] == "prn1_" && fingerprint != "prn1_invalid"
}

func terminalOperation(phase operation.Phase) bool {
	switch phase {
	case operation.PhaseSucceeded, operation.PhaseFailed, operation.PhaseCanceled:
		return true
	default:
		return false
	}
}

func cloneID(value *resource.ID) *resource.ID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneProviderBinding(value *ProviderBinding) *ProviderBinding {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func clonePlanDigest(value *PlanDigest) *PlanDigest {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
