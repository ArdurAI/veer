package authorization

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// InputDigestPrefix identifies the current authorization input framing.
	InputDigestPrefix = "azi1_"
	inputDigestDomain = "veer.authorization.input.v1"
)

// Input is one authenticated actor, closed action, and hierarchy-sealed
// target. Its principal claims cannot be serialized through this value.
type Input struct {
	Principal identity.Principal
	Action    Action
	Target    Target
}

func (input Input) String() string {
	if validateInput(input) != nil {
		return "authorization-input(invalid)"
	}
	return "authorization-input(principal=redacted,action=" + input.Action.String() + ")"
}

func (input Input) GoString() string { return input.String() }

func (input Input) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, input.String())
}

func (Input) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Input) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Input) GobEncode() ([]byte, error)   { return nil, ErrSerializationForbidden }

// InputDigest is the domain-separated digest of every normalized principal
// claim, the action, and every sealed target field. Exact claims are hashed
// but never exposed by this type or the Decision representation.
type InputDigest struct {
	initialized bool
	digest      [sha256.Size]byte
}

func (digest InputDigest) String() string {
	if !digest.initialized {
		return InputDigestPrefix + "invalid"
	}
	return InputDigestPrefix + base64.RawURLEncoding.EncodeToString(digest.digest[:])
}

func (digest InputDigest) Equal(other InputDigest) bool {
	return digest.initialized && other.initialized && digest.digest == other.digest
}

// ParseInputDigest accepts only the canonical current-version string.
func ParseInputDigest(value string) (InputDigest, error) {
	if !strings.HasPrefix(value, InputDigestPrefix) {
		return InputDigest{}, ErrInvalidInputDigest
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, InputDigestPrefix))
	if err != nil || len(decoded) != sha256.Size ||
		InputDigestPrefix+base64.RawURLEncoding.EncodeToString(decoded) != value {
		return InputDigest{}, ErrInvalidInputDigest
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return InputDigest{initialized: true, digest: digest}, nil
}

func (digest InputDigest) MarshalText() ([]byte, error) {
	if !digest.initialized {
		return nil, ErrInvalidInputDigest
	}
	return []byte(digest.String()), nil
}

// Decision is one immutable default-deny result. Its canonical form contains
// only versioned digests and closed outcome vocabulary, never identity claims,
// member IDs, resource IDs, or arbitrary policy text.
type Decision struct {
	initialized   bool
	policyVersion PolicyVersion
	inputDigest   InputDigest
	effect        Effect
	reason        Reason
}

// Evaluate deterministically evaluates a complete valid input against this
// immutable PolicySet. Invalid inputs return an error rather than creating a
// decision receipt for an action that was never in the decision domain.
func (set PolicySet) Evaluate(input Input) (Decision, error) {
	if !set.initialized || !set.version.initialized || !set.directory.initialized ||
		set.directory.workspaceID != set.workspaceID {
		return Decision{}, ErrInvalidPolicySet
	}
	if err := validateInput(input); err != nil {
		return Decision{}, err
	}
	digest := deriveInputDigest(input)
	decision := Decision{
		initialized:   true,
		policyVersion: set.version,
		inputDigest:   digest,
		effect:        EffectDeny,
	}

	if input.Target.workspaceID != set.workspaceID {
		decision.reason = ReasonCrossWorkspace
		return decision, nil
	}
	if actionReserved(input.Action, input.Target) {
		decision.reason = ReasonReservedAction
		return decision, nil
	}

	key := memberKey(input.Principal.Kind(), input.Principal.LogicalIdentity())
	memberID, exists := set.directory.byIdentity[key]
	if !exists {
		decision.reason = ReasonNoMembership
		return decision, nil
	}
	member, exists := set.directory.byID[memberID]
	if !exists || member.kind != input.Principal.Kind() ||
		!identity.EqualLogicalIdentity(member.logicalIdentity, input.Principal.LogicalIdentity()) {
		decision.reason = ReasonNoMembership
		return decision, nil
	}
	if input.Action == ActionMembershipGet && input.Target.objectKind == ObjectKindMembership &&
		input.Target.objectID == member.id {
		decision.effect = EffectAllow
		decision.reason = ReasonRoleGranted
		return decision, nil
	}

	compiled, exists := set.bindings[member.id]
	if !exists || compiled.all == 0 {
		decision.reason = ReasonNoRoleBinding
		return decision, nil
	}

	roles := compiled.workspace
	if input.Target.environmentID != nil {
		roles |= compiled.environments[*input.Target.environmentID]
	}
	if roles == 0 {
		decision.reason = ReasonScopeNotGranted
		return decision, nil
	}
	for _, role := range roles.roles() {
		if roleAllows(role, input.Action, input.Target) {
			decision.effect = EffectAllow
			decision.reason = ReasonRoleGranted
			return decision, nil
		}
	}
	decision.reason = ReasonActionNotGranted
	return decision, nil
}

func (decision Decision) Effect() Effect               { return decision.effect }
func (decision Decision) Reason() Reason               { return decision.reason }
func (decision Decision) PolicyVersion() PolicyVersion { return decision.policyVersion }
func (decision Decision) InputDigest() InputDigest     { return decision.inputDigest }
func (decision Decision) Allowed() bool                { return decision.effect == EffectAllow }

func (decision Decision) String() string {
	if validateDecisionFields(decision) != nil {
		return "authorization-decision(invalid)"
	}
	return "authorization-decision(effect=" + decision.effect.String() +
		",reason=" + decision.reason.String() + ")"
}

func (decision Decision) GoString() string { return decision.String() }

func (decision Decision) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, decision.String())
}

func validateInput(input Input) error {
	if identity.ValidatePrincipal(input.Principal) != nil {
		return fmt.Errorf("%w: invalid principal", ErrInvalidInput)
	}
	if _, err := ParseAction(input.Action.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidAction)
	}
	if err := ValidateTarget(input.Target); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidTarget)
	}
	return nil
}

func deriveInputDigest(input Input) InputDigest {
	hasher := sha256.New()
	writeHashFrame(hasher, inputDigestDomain)
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, input.Principal.Kind().String())
	writeHashFrame(hasher, input.Principal.Issuer())
	writeHashFrame(hasher, input.Principal.Subject())
	audiences := input.Principal.Audiences()
	writeHashUint64(hasher, uint64(len(audiences)))
	for _, audience := range audiences {
		writeHashFrame(hasher, audience)
	}
	groups := input.Principal.Groups()
	writeHashUint64(hasher, uint64(len(groups)))
	for _, group := range groups {
		writeHashFrame(hasher, group)
	}
	workload, present := input.Principal.WorkloadIdentity()
	if present {
		writeHashFrame(hasher, "1")
		writeHashFrame(hasher, workload.Value())
	} else {
		writeHashFrame(hasher, "0")
	}
	writeHashFrame(hasher, input.Action.String())
	writeHashFrame(hasher, input.Target.objectKind.String())
	writeHashFrame(hasher, input.Target.objectID.String())
	writeHashFrame(hasher, input.Target.resourceKind.String())
	writeHashFrame(hasher, input.Target.resourceID.String())
	writeHashFrame(hasher, input.Target.workspaceID.String())
	writeOptionalIDFrame(hasher, input.Target.environmentID)
	writeOptionalIDFrame(hasher, input.Target.providerConnectionID)
	var result [sha256.Size]byte
	copy(result[:], hasher.Sum(nil))
	return InputDigest{initialized: true, digest: result}
}

func writeOptionalIDFrame(hasher hash.Hash, id *resource.ID) {
	if id == nil {
		writeHashFrame(hasher, "0")
		return
	}
	writeHashFrame(hasher, "1")
	writeHashFrame(hasher, id.String())
}
