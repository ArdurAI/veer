package authorization

import (
	"fmt"
	"slices"
	"sort"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

// MemberInput supplies one server-issued opaque member ID and the exact
// authenticated identity to which it is privately bound. It deliberately has
// no JSON representation.
type MemberInput struct {
	ID              resource.ID
	WorkspaceID     resource.ID
	Kind            identity.Kind
	LogicalIdentity identity.LogicalIdentity
}

func (input MemberInput) String() string {
	return "authorization-member-input(identity=redacted)"
}

func (input MemberInput) GoString() string { return input.String() }

func (input MemberInput) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, input.String())
}

func (MemberInput) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (MemberInput) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

// GobEncode rejects generic binary persistence of construction-time exact
// identity data, including when MemberInput is nested in another value.
func (MemberInput) GobEncode() ([]byte, error) { return nil, ErrSerializationForbidden }

// MemberRecord is the non-serializable exact-identity side of an opaque
// PolicySpec memberId. Private fields prevent a public Policy resource from
// becoming a store for OIDC issuer or subject claims.
type MemberRecord struct {
	initialized     bool
	id              resource.ID
	workspaceID     resource.ID
	kind            identity.Kind
	logicalIdentity identity.LogicalIdentity
}

// NewMemberRecord validates and takes an immutable exact-identity binding.
func NewMemberRecord(input MemberInput) (MemberRecord, error) {
	if _, err := resource.ParseID(input.ID.String()); err != nil {
		return MemberRecord{}, fmt.Errorf("%w: invalid member ID", ErrInvalidMember)
	}
	if _, err := resource.ParseID(input.WorkspaceID.String()); err != nil {
		return MemberRecord{}, fmt.Errorf("%w: invalid workspace ID", ErrInvalidMember)
	}
	if input.Kind != identity.KindHuman && input.Kind != identity.KindWorkload {
		return MemberRecord{}, fmt.Errorf("%w: %w", ErrInvalidMember, ErrPrincipalKindNotAllowed)
	}
	if err := identity.ValidateLogicalIdentity(input.LogicalIdentity); err != nil {
		return MemberRecord{}, fmt.Errorf("%w: invalid logical identity", ErrInvalidMember)
	}
	return MemberRecord{
		initialized:     true,
		id:              input.ID,
		workspaceID:     input.WorkspaceID,
		kind:            input.Kind,
		logicalIdentity: input.LogicalIdentity,
	}, nil
}

// ID returns the stable opaque member identifier.
func (member MemberRecord) ID() resource.ID { return member.id }

// WorkspaceID returns the immutable Workspace owner.
func (member MemberRecord) WorkspaceID() resource.ID { return member.workspaceID }

// Kind returns the authenticated Human or Workload class.
func (member MemberRecord) Kind() identity.Kind { return member.kind }

// LogicalIdentity returns the exact private identity. Callers must not log,
// trace, meter, or serialize it.
func (member MemberRecord) LogicalIdentity() identity.LogicalIdentity {
	return member.logicalIdentity
}

func (member MemberRecord) String() string {
	if validateMemberRecord(member) != nil {
		return "authorization-member(invalid)"
	}
	return "authorization-member(identity=redacted)"
}

func (member MemberRecord) GoString() string { return member.String() }

func (member MemberRecord) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, member.String())
}

func (MemberRecord) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (MemberRecord) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

type memberIdentityKey struct {
	kind    identity.Kind
	issuer  string
	subject string
}

// MemberDirectory is one immutable Workspace-scoped exact-identity index.
// Its maps and ordered records are private and never leave this package.
type MemberDirectory struct {
	initialized bool
	workspaceID resource.ID
	byID        map[resource.ID]MemberRecord
	byIdentity  map[memberIdentityKey]resource.ID
	ordered     []MemberRecord
}

// NewMemberDirectory validates a bounded Workspace member set, rejecting both
// duplicate opaque IDs and ambiguous duplicate exact logical identities.
func NewMemberDirectory(workspaceID resource.ID, members []MemberRecord) (MemberDirectory, error) {
	if _, err := resource.ParseID(workspaceID.String()); err != nil {
		return MemberDirectory{}, ErrInvalidMemberDirectory
	}
	if len(members) > MaxMembers {
		return MemberDirectory{}, fmt.Errorf("%w: %w", ErrInvalidMemberDirectory, ErrTooManyMembers)
	}

	byID := make(map[resource.ID]MemberRecord, len(members))
	byIdentity := make(map[memberIdentityKey]resource.ID, len(members))
	ordered := slices.Clone(members)
	for _, member := range ordered {
		if err := validateMemberRecord(member); err != nil {
			return MemberDirectory{}, fmt.Errorf("%w: %w", ErrInvalidMemberDirectory, err)
		}
		if member.workspaceID != workspaceID {
			return MemberDirectory{}, fmt.Errorf("%w: %w", ErrInvalidMemberDirectory, ErrWorkspaceMismatch)
		}
		if _, exists := byID[member.id]; exists {
			return MemberDirectory{}, fmt.Errorf("%w: %w", ErrInvalidMemberDirectory, ErrDuplicateMemberID)
		}
		key := memberKey(member.kind, member.logicalIdentity)
		if _, exists := byIdentity[key]; exists {
			return MemberDirectory{}, fmt.Errorf("%w: %w", ErrInvalidMemberDirectory, ErrDuplicateLogicalIdentity)
		}
		byID[member.id] = member
		byIdentity[key] = member.id
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].id.String() < ordered[right].id.String()
	})

	return MemberDirectory{
		initialized: true,
		workspaceID: workspaceID,
		byID:        byID,
		byIdentity:  byIdentity,
		ordered:     ordered,
	}, nil
}

// ValidateMemberDirectory checks a complete value without exposing claims.
func ValidateMemberDirectory(directory MemberDirectory) error {
	if !directory.initialized {
		return ErrInvalidMemberDirectory
	}
	if _, err := resource.ParseID(directory.workspaceID.String()); err != nil {
		return ErrInvalidMemberDirectory
	}
	if len(directory.byID) != len(directory.byIdentity) || len(directory.byID) != len(directory.ordered) ||
		len(directory.ordered) > MaxMembers {
		return ErrInvalidMemberDirectory
	}
	for index, member := range directory.ordered {
		if err := validateMemberRecord(member); err != nil || member.workspaceID != directory.workspaceID {
			return ErrInvalidMemberDirectory
		}
		if index > 0 && directory.ordered[index-1].id.String() >= member.id.String() {
			return ErrInvalidMemberDirectory
		}
		indexed, exists := directory.byID[member.id]
		if !exists || !equalMemberRecord(indexed, member) {
			return ErrInvalidMemberDirectory
		}
		id, exists := directory.byIdentity[memberKey(member.kind, member.logicalIdentity)]
		if !exists || id != member.id {
			return ErrInvalidMemberDirectory
		}
	}
	return nil
}

// WorkspaceID returns the directory's Workspace or the zero ID for an invalid
// zero value. ValidateMemberDirectory distinguishes those states.
func (directory MemberDirectory) WorkspaceID() resource.ID { return directory.workspaceID }

// Len returns the bounded number of members.
func (directory MemberDirectory) Len() int { return len(directory.ordered) }

// Lookup returns one independent immutable member record.
func (directory MemberDirectory) Lookup(id resource.ID) (MemberRecord, error) {
	if ValidateMemberDirectory(directory) != nil {
		return MemberRecord{}, ErrInvalidMemberDirectory
	}
	if _, err := resource.ParseID(id.String()); err != nil {
		return MemberRecord{}, ErrMemberNotFound
	}
	member, exists := directory.byID[id]
	if !exists {
		return MemberRecord{}, ErrMemberNotFound
	}
	return member, nil
}

// Match uses exact kind, issuer, and subject values. It deliberately does not
// consult the principal fingerprint, audiences, groups, or workload claim.
func (directory MemberDirectory) Match(principal identity.Principal) (MemberRecord, bool) {
	if ValidateMemberDirectory(directory) != nil || identity.ValidatePrincipal(principal) != nil {
		return MemberRecord{}, false
	}
	key := memberKey(principal.Kind(), principal.LogicalIdentity())
	id, exists := directory.byIdentity[key]
	if !exists {
		return MemberRecord{}, false
	}
	member, exists := directory.byID[id]
	if !exists || member.kind != principal.Kind() ||
		!identity.EqualLogicalIdentity(member.logicalIdentity, principal.LogicalIdentity()) {
		return MemberRecord{}, false
	}
	return member, true
}

func (directory MemberDirectory) String() string {
	if ValidateMemberDirectory(directory) != nil {
		return "authorization-member-directory(invalid)"
	}
	return "authorization-member-directory(identity=redacted)"
}

func (directory MemberDirectory) GoString() string { return directory.String() }

func (directory MemberDirectory) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, directory.String())
}

func (MemberDirectory) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (MemberDirectory) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

func validateMemberRecord(member MemberRecord) error {
	if !member.initialized {
		return ErrInvalidMember
	}
	if _, err := resource.ParseID(member.id.String()); err != nil {
		return ErrInvalidMember
	}
	if _, err := resource.ParseID(member.workspaceID.String()); err != nil {
		return ErrInvalidMember
	}
	if member.kind != identity.KindHuman && member.kind != identity.KindWorkload {
		return ErrInvalidMember
	}
	if identity.ValidateLogicalIdentity(member.logicalIdentity) != nil {
		return ErrInvalidMember
	}
	return nil
}

func memberKey(kind identity.Kind, logical identity.LogicalIdentity) memberIdentityKey {
	return memberIdentityKey{kind: kind, issuer: logical.Issuer(), subject: logical.Subject()}
}

func equalMemberRecord(left, right MemberRecord) bool {
	return left.initialized && right.initialized && left.id == right.id &&
		left.workspaceID == right.workspaceID && left.kind == right.kind &&
		identity.EqualLogicalIdentity(left.logicalIdentity, right.logicalIdentity)
}
