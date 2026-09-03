package authorization

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
)

type decisionWire struct {
	ContractVersion string `json:"contractVersion"`
	PolicyVersion   string `json:"policyVersion"`
	InputDigest     string `json:"inputDigest"`
	Effect          Effect `json:"effect"`
	Reason          Reason `json:"reason"`
}

// ValidateDecision checks a complete decision and its canonical size.
func ValidateDecision(decision Decision) error {
	if err := validateDecisionFields(decision); err != nil {
		return err
	}
	data, err := encodeDecision(decision)
	if err != nil {
		return fmt.Errorf("%w: encode", ErrInvalidDecision)
	}
	if len(data) > MaxDecisionBytes {
		return fmt.Errorf("%w: %w", ErrInvalidDecision, ErrDecisionTooLarge)
	}
	return nil
}

// MarshalCanonical emits the only accepted compact Decision representation.
func MarshalCanonical(decision Decision) ([]byte, error) {
	if err := validateDecisionFields(decision); err != nil {
		return nil, err
	}
	data, err := encodeDecision(decision)
	if err != nil {
		return nil, fmt.Errorf("%w: encode", ErrInvalidDecision)
	}
	if len(data) > MaxDecisionBytes {
		return nil, ErrDecisionTooLarge
	}
	return data, nil
}

// UnmarshalCanonical decodes a bounded, duplicate-free, unknown-field-free,
// byte-for-byte canonical Decision.
func UnmarshalCanonical(data []byte) (Decision, error) {
	if len(data) == 0 {
		return Decision{}, ErrNonCanonicalDecision
	}
	if len(data) > MaxDecisionBytes {
		return Decision{}, ErrDecisionTooLarge
	}
	var wire decisionWire
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Decision{}, ErrNonCanonicalDecision
	}
	if wire.ContractVersion != ContractVersion {
		return Decision{}, ErrInvalidDecision
	}
	version, err := ParsePolicyVersion(wire.PolicyVersion)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %w", ErrInvalidDecision, ErrInvalidPolicyVersion)
	}
	digest, err := ParseInputDigest(wire.InputDigest)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %w", ErrInvalidDecision, ErrInvalidInputDigest)
	}
	decision := Decision{
		initialized:   true,
		policyVersion: version,
		inputDigest:   digest,
		effect:        wire.Effect,
		reason:        wire.Reason,
	}
	if err := ValidateDecision(decision); err != nil {
		return Decision{}, err
	}
	canonical, err := MarshalCanonical(decision)
	if err != nil {
		return Decision{}, err
	}
	if !bytes.Equal(data, canonical) {
		return Decision{}, ErrNonCanonicalDecision
	}
	return decision, nil
}

// MarshalJSON emits the same canonical representation as MarshalCanonical.
func (decision Decision) MarshalJSON() ([]byte, error) { return MarshalCanonical(decision) }

// UnmarshalJSON accepts only the canonical representation.
func (decision *Decision) UnmarshalJSON(data []byte) error {
	if decision == nil {
		return ErrInvalidDecision
	}
	parsed, err := UnmarshalCanonical(data)
	if err != nil {
		return err
	}
	*decision = parsed
	return nil
}

func validateDecisionFields(decision Decision) error {
	if !decision.initialized {
		return ErrInvalidDecision
	}
	if _, err := ParsePolicyVersion(decision.policyVersion.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDecision, ErrInvalidPolicyVersion)
	}
	if _, err := ParseInputDigest(decision.inputDigest.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidDecision, ErrInvalidInputDigest)
	}
	switch decision.effect {
	case EffectAllow:
		if decision.reason != ReasonRoleGranted {
			return ErrInvalidDecision
		}
	case EffectDeny:
		switch decision.reason {
		case ReasonCrossWorkspace,
			ReasonReservedAction,
			ReasonNoMembership,
			ReasonNoRoleBinding,
			ReasonScopeNotGranted,
			ReasonActionNotGranted:
		default:
			return ErrInvalidDecision
		}
	default:
		return ErrInvalidDecision
	}
	return nil
}

func encodeDecision(decision Decision) ([]byte, error) {
	wire := decisionWire{
		ContractVersion: ContractVersion,
		PolicyVersion:   decision.policyVersion.String(),
		InputDigest:     decision.inputDigest.String(),
		Effect:          decision.effect,
		Reason:          decision.reason,
	}
	return jsonv2.Marshal(
		wire,
		json.DefaultOptionsV1(),
		jsontext.AllowInvalidUTF8(false),
	)
}
