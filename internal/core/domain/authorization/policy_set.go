package authorization

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"slices"
	"sort"
	"strings"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// PolicyVersionPrefix identifies the current PolicySet digest framing.
	PolicyVersionPrefix = "azv1_"
	policyVersionDomain = "veer.authorization.policy-set.v1"
)

// PolicyRevision binds the authorization-relevant immutable hierarchy record,
// desired-state generation, and canonical Policy spec. Resource versions,
// display metadata, and status are deliberately excluded.
type PolicyRevision struct {
	Record     hierarchy.Record
	Generation resource.Generation
	Spec       PolicySpec
}

// PolicyVersion is the domain-separated digest of one complete Workspace
// member directory and ordered Policy revision set.
type PolicyVersion struct {
	initialized bool
	digest      [sha256.Size]byte
}

// String returns the exact URL-safe version framing.
func (version PolicyVersion) String() string {
	if !version.initialized {
		return PolicyVersionPrefix + "invalid"
	}
	return PolicyVersionPrefix + base64.RawURLEncoding.EncodeToString(version.digest[:])
}

// Equal compares complete initialized digests.
func (version PolicyVersion) Equal(other PolicyVersion) bool {
	return version.initialized && other.initialized && version.digest == other.digest
}

// ParsePolicyVersion accepts only the canonical current-version string.
func ParsePolicyVersion(value string) (PolicyVersion, error) {
	if !strings.HasPrefix(value, PolicyVersionPrefix) {
		return PolicyVersion{}, ErrInvalidPolicyVersion
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, PolicyVersionPrefix))
	if err != nil || len(decoded) != sha256.Size ||
		PolicyVersionPrefix+base64.RawURLEncoding.EncodeToString(decoded) != value {
		return PolicyVersion{}, ErrInvalidPolicyVersion
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return PolicyVersion{initialized: true, digest: digest}, nil
}

// MarshalText emits the bounded non-sensitive version identifier.
func (version PolicyVersion) MarshalText() ([]byte, error) {
	if !version.initialized {
		return nil, ErrInvalidPolicyVersion
	}
	return []byte(version.String()), nil
}

// PolicySet is an immutable, Workspace-scoped compiled authorization view.
// It owns private copies of the exact member directory and Policy specs.
type PolicySet struct {
	initialized bool
	workspaceID resource.ID
	directory   MemberDirectory
	policies    []PolicyRevision
	bindings    map[resource.ID]compiledMemberBindings
	version     PolicyVersion
}

type roleMask uint8

type compiledMemberBindings struct {
	all          roleMask
	workspace    roleMask
	environments map[resource.ID]roleMask
}

// NewPolicySet validates references against one exact hierarchy snapshot,
// canonicalizes Policy order, compiles member bindings, and derives a version.
// An empty Policy slice is valid and default-denies every valid input except
// an exact self-membership read.
func NewPolicySet(
	snapshot hierarchy.Snapshot,
	directory MemberDirectory,
	policies []PolicyRevision,
) (PolicySet, error) {
	workspace, err := snapshot.Lookup(snapshot.WorkspaceID())
	if err != nil || workspace.Kind() != hierarchy.KindWorkspace {
		return PolicySet{}, ErrInvalidPolicySet
	}
	if err := ValidateMemberDirectory(directory); err != nil {
		return PolicySet{}, fmt.Errorf("%w: %w", ErrInvalidPolicySet, ErrInvalidMemberDirectory)
	}
	if directory.WorkspaceID() != snapshot.WorkspaceID() || workspace.WorkspaceID() != directory.WorkspaceID() {
		return PolicySet{}, fmt.Errorf("%w: %w", ErrInvalidPolicySet, ErrWorkspaceMismatch)
	}
	if len(policies) > MaxPolicies {
		return PolicySet{}, fmt.Errorf("%w: %w", ErrInvalidPolicySet, ErrTooManyPolicies)
	}

	owned := make([]PolicyRevision, len(policies))
	seen := make(map[resource.ID]struct{}, len(policies))
	for index, policy := range policies {
		if err := validatePolicyRevision(policy, snapshot, directory); err != nil {
			return PolicySet{}, fmt.Errorf("%w: policy %d: %w", ErrInvalidPolicySet, index, err)
		}
		if _, exists := seen[policy.Record.ID()]; exists {
			return PolicySet{}, fmt.Errorf("%w: %w", ErrInvalidPolicySet, ErrDuplicatePolicyID)
		}
		seen[policy.Record.ID()] = struct{}{}
		owned[index] = clonePolicyRevision(policy)
	}
	sort.Slice(owned, func(left, right int) bool {
		return owned[left].Record.ID().String() < owned[right].Record.ID().String()
	})

	bindings := compilePolicyBindings(owned)

	ownedDirectory := cloneMemberDirectory(directory)
	version := derivePolicyVersion(directory, owned)
	return PolicySet{
		initialized: true,
		workspaceID: snapshot.WorkspaceID(),
		directory:   ownedDirectory,
		policies:    owned,
		bindings:    bindings,
		version:     version,
	}, nil
}

// ValidatePolicySet checks the complete compiled value without exposing or
// serializing exact personal claims.
func ValidatePolicySet(set PolicySet) error {
	if !set.initialized {
		return ErrInvalidPolicySet
	}
	if _, err := resource.ParseID(set.workspaceID.String()); err != nil {
		return ErrInvalidPolicySet
	}
	if err := ValidateMemberDirectory(set.directory); err != nil || set.directory.WorkspaceID() != set.workspaceID {
		return ErrInvalidPolicySet
	}
	if len(set.policies) > MaxPolicies || len(set.bindings) > MaxMembers {
		return ErrInvalidPolicySet
	}
	if _, err := ParsePolicyVersion(set.version.String()); err != nil {
		return ErrInvalidPolicySet
	}
	if !set.version.Equal(derivePolicyVersion(set.directory, set.policies)) {
		return ErrInvalidPolicySet
	}
	seen := make(map[resource.ID]struct{}, len(set.policies))
	for index, policy := range set.policies {
		if index > 0 && set.policies[index-1].Record.ID().String() >= policy.Record.ID().String() {
			return ErrInvalidPolicySet
		}
		if policy.Record.Kind() != hierarchy.KindPolicy || policy.Record.WorkspaceID() != set.workspaceID ||
			policy.Generation.Int64() < 1 || ValidatePolicySpec(policy.Spec) != nil {
			return ErrInvalidPolicySet
		}
		if _, exists := seen[policy.Record.ID()]; exists {
			return ErrInvalidPolicySet
		}
		seen[policy.Record.ID()] = struct{}{}
		if err := hierarchy.CheckTransition(policy.Record, policy.Record); err != nil {
			return ErrInvalidPolicySet
		}
		for _, binding := range policy.Spec.Bindings {
			member, exists := set.directory.byID[binding.MemberID]
			if !exists || (binding.Role == RoleWorkspaceAdministrator && member.Kind() != identity.KindHuman) {
				return ErrInvalidPolicySet
			}
		}
	}
	if !equalCompiledBindings(set.bindings, compilePolicyBindings(set.policies)) {
		return ErrInvalidPolicySet
	}
	return nil
}

// WorkspaceID returns the PolicySet's exact Workspace owner.
func (set PolicySet) WorkspaceID() resource.ID { return set.workspaceID }

// Version returns the complete member-and-policy version digest.
func (set PolicySet) Version() PolicyVersion { return set.version }

// Len returns the number of retained Policy revisions.
func (set PolicySet) Len() int { return len(set.policies) }

func (set PolicySet) String() string {
	if ValidatePolicySet(set) != nil {
		return "authorization-policy-set(invalid)"
	}
	return "authorization-policy-set(version=" + set.version.String() + ")"
}

func (set PolicySet) GoString() string { return set.String() }

func (set PolicySet) Format(state fmt.State, verb rune) {
	writeSafeFormat(state, verb, set.String())
}

func (PolicySet) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (PolicySet) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }

func validatePolicyRevision(
	policy PolicyRevision,
	snapshot hierarchy.Snapshot,
	directory MemberDirectory,
) error {
	if policy.Record.Kind() != hierarchy.KindPolicy {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyRevision, ErrReferenceKindMismatch)
	}
	if policy.Record.WorkspaceID() != snapshot.WorkspaceID() {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyRevision, ErrWorkspaceMismatch)
	}
	retained, err := snapshot.Lookup(policy.Record.ID())
	if err != nil {
		return fmt.Errorf("%w: policy resource not found", ErrInvalidPolicyRevision)
	}
	if err := hierarchy.CheckTransition(retained, policy.Record); err != nil {
		return fmt.Errorf("%w: policy record does not match snapshot", ErrInvalidPolicyRevision)
	}
	if policy.Generation.Int64() < 1 {
		return ErrInvalidPolicyRevision
	}
	if err := ValidatePolicyReferences(policy.Spec, snapshot, directory); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyRevision, err)
	}
	return nil
}

func clonePolicyRevision(policy PolicyRevision) PolicyRevision {
	policy.Spec = ClonePolicySpec(policy.Spec)
	return policy
}

func compilePolicyBindings(policies []PolicyRevision) map[resource.ID]compiledMemberBindings {
	bindings := make(map[resource.ID]compiledMemberBindings)
	for _, policy := range policies {
		for _, binding := range policy.Spec.Bindings {
			compiled := bindings[binding.MemberID]
			bit := maskForRole(binding.Role)
			compiled.all |= bit
			switch binding.Scope.Kind {
			case ScopeKindWorkspace:
				compiled.workspace |= bit
			case ScopeKindEnvironment:
				if compiled.environments == nil {
					compiled.environments = make(map[resource.ID]roleMask)
				}
				compiled.environments[*binding.Scope.EnvironmentID] |= bit
			}
			bindings[binding.MemberID] = compiled
		}
	}
	return bindings
}

func equalCompiledBindings(
	left map[resource.ID]compiledMemberBindings,
	right map[resource.ID]compiledMemberBindings,
) bool {
	if len(left) != len(right) {
		return false
	}
	for memberID, leftMember := range left {
		rightMember, exists := right[memberID]
		if !exists || leftMember.all != rightMember.all || leftMember.workspace != rightMember.workspace ||
			len(leftMember.environments) != len(rightMember.environments) {
			return false
		}
		for environmentID, roles := range leftMember.environments {
			if rightMember.environments[environmentID] != roles {
				return false
			}
		}
	}
	return true
}

func cloneMemberDirectory(directory MemberDirectory) MemberDirectory {
	result := MemberDirectory{
		initialized: directory.initialized,
		workspaceID: directory.workspaceID,
		byID:        make(map[resource.ID]MemberRecord, len(directory.byID)),
		byIdentity:  make(map[memberIdentityKey]resource.ID, len(directory.byIdentity)),
		ordered:     slices.Clone(directory.ordered),
	}
	for id, member := range directory.byID {
		result.byID[id] = member
	}
	for key, id := range directory.byIdentity {
		result.byIdentity[key] = id
	}
	return result
}

func derivePolicyVersion(directory MemberDirectory, policies []PolicyRevision) PolicyVersion {
	hasher := sha256.New()
	writeHashFrame(hasher, policyVersionDomain)
	writeHashFrame(hasher, ContractVersion)
	writeHashFrame(hasher, directory.workspaceID.String())
	writeHashUint64(hasher, uint64(len(directory.ordered)))
	for _, member := range directory.ordered {
		writeHashFrame(hasher, member.id.String())
		writeHashFrame(hasher, member.kind.String())
		writeHashFrame(hasher, member.logicalIdentity.Issuer())
		writeHashFrame(hasher, member.logicalIdentity.Subject())
	}
	writeHashUint64(hasher, uint64(len(policies)))
	for _, policy := range policies {
		writeHashFrame(hasher, policy.Record.ID().String())
		writeHashUint64(hasher, uint64(policy.Generation.Int64()))
		writeHashUint64(hasher, uint64(len(policy.Spec.Bindings)))
		for _, binding := range policy.Spec.Bindings {
			writeHashFrame(hasher, binding.MemberID.String())
			writeHashFrame(hasher, binding.Role.String())
			writeHashFrame(hasher, binding.Scope.Kind.String())
			writeHashFrame(hasher, scopeEnvironment(binding.Scope))
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return PolicyVersion{initialized: true, digest: digest}
}

func writeHashFrame(hasher hash.Hash, value string) {
	writeHashUint64(hasher, uint64(len(value)))
	_, _ = hasher.Write([]byte(value))
}

func writeHashUint64(hasher hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = hasher.Write(encoded[:])
}

func maskForRole(role Role) roleMask {
	switch role {
	case RoleViewer:
		return 1 << 0
	case RoleDeveloper:
		return 1 << 1
	case RoleOperator:
		return 1 << 2
	case RoleWorkspaceAdministrator:
		return 1 << 3
	default:
		return 0
	}
}

func (mask roleMask) roles() []Role {
	result := make([]Role, 0, len(allRoles))
	for _, role := range allRoles {
		if mask&maskForRole(role) != 0 {
			result = append(result, role)
		}
	}
	return result
}
