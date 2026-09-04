package reconciliation

import (
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// EffectKey is a generation- and Operation-bound semantic provider effect.
// Its digest deliberately excludes plan ID/revision and physical attempt ID.
type EffectKey struct {
	initialized bool
	digest      digestValue
	workspaceID resource.ID
	resourceID  resource.ID
	operationID resource.ID
	generation  int64
}

// NewEffectKey derives one stable logical effect from bounded canonical semantics.
func NewEffectKey(plan Plan, canonicalSemanticEffect []byte) (EffectKey, error) {
	if ValidatePlan(plan) != nil || len(canonicalSemanticEffect) == 0 ||
		len(canonicalSemanticEffect) > MaxSemanticEffectBytes {
		return EffectKey{}, ErrInvalidDigest
	}
	hasher := sha256.New()
	writeHashFrame(hasher, "veer.reconciliation.effect.v1")
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, plan.workspaceID.String())
	writeHashFrame(hasher, plan.resourceID.String())
	writeHashInt64(hasher, plan.generation)
	writeHashFrame(hasher, plan.operationID.String())
	writeHashBytes(hasher, canonicalSemanticEffect)
	return EffectKey{
		initialized: true,
		digest:      digestFromHasher(hasher),
		workspaceID: plan.workspaceID,
		resourceID:  plan.resourceID,
		operationID: plan.operationID,
		generation:  plan.generation,
	}, nil
}

// ValidateEffectKey checks a complete logical-effect key.
func ValidateEffectKey(value EffectKey) error {
	if !value.initialized || !value.digest.initialized || !validID(value.workspaceID) ||
		!validID(value.resourceID) || !validID(value.operationID) || value.generation < 1 {
		return ErrInvalidDigest
	}
	return nil
}

func (value EffectKey) String() string   { return formatDigest(effectKeyPrefix, value.digest) }
func (value EffectKey) GoString() string { return value.String() }
func (value EffectKey) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, value.String())
}
func (value EffectKey) LogValue() slog.Value { return redactedLogValue(value.String()) }
func (value EffectKey) Equal(other EffectKey) bool {
	return ValidateEffectKey(value) == nil && ValidateEffectKey(other) == nil &&
		value.workspaceID == other.workspaceID && value.resourceID == other.resourceID &&
		value.operationID == other.operationID && value.generation == other.generation &&
		equalDigest(value.digest, other.digest)
}
func (value EffectKey) WorkspaceID() resource.ID { return value.workspaceID }
func (value EffectKey) ResourceID() resource.ID  { return value.resourceID }
func (value EffectKey) OperationID() resource.ID { return value.operationID }
func (value EffectKey) Generation() int64        { return value.generation }

func (EffectKey) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (EffectKey) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (EffectKey) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (EffectKey) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
