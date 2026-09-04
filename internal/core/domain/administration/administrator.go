package administration

import (
	"fmt"
	"log/slog"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// Administrator privately binds one server-issued opaque administrator ID to
// one exact human issuer-and-subject identity. Fingerprints are deliberately
// absent because they are correlation values, not equality or authority keys.
type Administrator struct {
	initialized     bool
	id              resource.ID
	kind            identity.Kind
	logicalIdentity identity.LogicalIdentity
}

// NewAdministrator validates and captures an exact human identity binding.
func NewAdministrator(id resource.ID, principal identity.Principal) (Administrator, error) {
	if _, err := resource.ParseID(id.String()); err != nil {
		return Administrator{}, fmt.Errorf("%w: invalid administrator ID", ErrInvalidAdministrator)
	}
	if err := identity.ValidatePrincipal(principal); err != nil {
		return Administrator{}, ErrInvalidAdministrator
	}
	if principal.Kind() != identity.KindHuman {
		return Administrator{}, fmt.Errorf("%w: %w", ErrInvalidAdministrator, ErrAdministratorNotHuman)
	}
	return Administrator{
		initialized:     true,
		id:              id,
		kind:            principal.Kind(),
		logicalIdentity: principal.LogicalIdentity(),
	}, nil
}

// ValidateAdministrator checks a complete exact-identity binding.
func ValidateAdministrator(administrator Administrator) error {
	if !administrator.initialized {
		return ErrInvalidAdministrator
	}
	if _, err := resource.ParseID(administrator.id.String()); err != nil {
		return ErrInvalidAdministrator
	}
	if administrator.kind != identity.KindHuman {
		return fmt.Errorf("%w: %w", ErrInvalidAdministrator, ErrAdministratorNotHuman)
	}
	if err := identity.ValidateLogicalIdentity(administrator.logicalIdentity); err != nil {
		return ErrInvalidAdministrator
	}
	return nil
}

// ID returns the stable opaque platform-administrator identifier.
func (administrator Administrator) ID() resource.ID { return administrator.id }

// MatchesPrincipal compares exact kind, issuer, and subject values. It never
// uses Fingerprint, audiences, groups, or a serialized issuer/subject key.
func (administrator Administrator) MatchesPrincipal(principal identity.Principal) bool {
	return ValidateAdministrator(administrator) == nil &&
		identity.ValidatePrincipal(principal) == nil &&
		principal.Kind() == administrator.kind &&
		identity.EqualLogicalIdentity(administrator.logicalIdentity, principal.LogicalIdentity())
}

func equalAdministrator(left, right Administrator) bool {
	return ValidateAdministrator(left) == nil && ValidateAdministrator(right) == nil &&
		left.id == right.id && left.kind == right.kind &&
		identity.EqualLogicalIdentity(left.logicalIdentity, right.logicalIdentity)
}

type administratorIdentityKey struct {
	kind    identity.Kind
	issuer  string
	subject string
}

func administratorKey(value Administrator) administratorIdentityKey {
	return administratorIdentityKey{
		kind:    value.kind,
		issuer:  value.logicalIdentity.Issuer(),
		subject: value.logicalIdentity.Subject(),
	}
}

func (administrator Administrator) String() string {
	if ValidateAdministrator(administrator) != nil {
		return "platform-administrator(invalid)"
	}
	return "platform-administrator(identity=redacted)"
}

func (administrator Administrator) GoString() string { return administrator.String() }
func (administrator Administrator) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, administrator.String())
}
func (administrator Administrator) LogValue() slog.Value {
	return redactedLogValue(administrator.String())
}
func (Administrator) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Administrator) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Administrator) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Administrator) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }
