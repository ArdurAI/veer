package authorization

import (
	"bytes"
	"errors"
	"testing"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func FuzzUnmarshalCanonicalDecision(f *testing.F) {
	f.Add([]byte(`{"contractVersion":"veer.authorization.v1alpha1","policyVersion":"azv1_bWmTGhAhKgCLxKUvUAnDTpvuq0qXu3-GpU3-lAQtKQk","inputDigest":"azi1_uCRuS5pfpHN3eE_EboEGGjWQj0pBp5NL0kkRHfpWuHY","effect":"Allow","reason":"RoleGranted"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"effect":"Deny","effect":"Allow"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDecisionBytes+1 {
			return
		}
		decision, err := UnmarshalCanonical(data)
		if err != nil {
			return
		}
		if err := ValidateDecision(decision); err != nil {
			t.Fatalf("successful decode produced invalid Decision: %v", err)
		}
		canonical, err := MarshalCanonical(decision)
		if err != nil {
			t.Fatalf("successful decode could not re-encode: %v", err)
		}
		if !bytes.Equal(data, canonical) {
			t.Fatalf("successful decode was not canonical: %q != %q", data, canonical)
		}
	})
}

func FuzzClosedVocabularyParsers(f *testing.F) {
	for _, seed := range []string{
		ActionResourceGet.String(), RoleViewer.String(), ScopeKindWorkspace.String(),
		ObjectKindResource.String(), "", "Owner", "resource.Get",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 256 || !utf8.ValidString(value) {
			return
		}
		if parsed, err := ParseAction(value); err == nil && parsed.String() != value {
			t.Fatalf("ParseAction(%q) changed spelling", value)
		}
		if parsed, err := ParseRole(value); err == nil && parsed.String() != value {
			t.Fatalf("ParseRole(%q) changed spelling", value)
		}
		if parsed, err := ParseScopeKind(value); err == nil && parsed.String() != value {
			t.Fatalf("ParseScopeKind(%q) changed spelling", value)
		}
		if parsed, err := ParseObjectKind(value); err == nil && parsed.String() != value {
			t.Fatalf("ParseObjectKind(%q) changed spelling", value)
		}
	})
}

func FuzzExactLogicalIdentityMembership(f *testing.F) {
	f.Add("subject", "other")
	f.Add("Case", "case")
	f.Add("a", "ab")
	f.Fuzz(func(t *testing.T, subject, other string) {
		if len(subject) == 0 || len(subject) > identity.MaxSubjectBytes ||
			len(other) == 0 || len(other) > identity.MaxSubjectBytes ||
			!utf8.ValidString(subject) || !utf8.ValidString(other) {
			return
		}
		logical, err := identity.NewLogicalIdentity(testIssuer, subject)
		if err != nil {
			return
		}
		member, err := NewMemberRecord(MemberInput{
			ID: testViewerID, WorkspaceID: testWorkspaceAID,
			Kind: identity.KindHuman, LogicalIdentity: logical,
		})
		if err != nil {
			t.Fatal(err)
		}
		directory, err := NewMemberDirectory(testWorkspaceAID, []MemberRecord{member})
		if err != nil {
			t.Fatal(err)
		}
		principal, err := identity.NewPrincipal(identity.PrincipalInput{
			Kind: identity.KindHuman, Issuer: testIssuer, Subject: subject,
			Audiences: []string{"veer-api"}, Groups: []string{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if matched, ok := directory.Match(principal); !ok || matched.ID() != testViewerID {
			t.Fatal("exact logical identity did not match")
		}
		if other == subject {
			return
		}
		otherPrincipal, err := identity.NewPrincipal(identity.PrincipalInput{
			Kind: identity.KindHuman, Issuer: testIssuer, Subject: other,
			Audiences: []string{"veer-api"}, Groups: []string{},
		})
		if err != nil {
			return
		}
		if _, ok := directory.Match(otherPrincipal); ok {
			t.Fatal("distinct exact logical identity matched")
		}
	})
}

func FuzzRoleBindingComparator(f *testing.F) {
	f.Add("mem_01J00000000000000000000001", "Viewer", "Workspace", "")
	f.Add("mem_01J00000000000000000000002", "Developer", "Environment", "env_01J00000000000000000000000")
	f.Fuzz(func(t *testing.T, memberID, role, scopeKind, environmentID string) {
		if len(memberID)+len(role)+len(scopeKind)+len(environmentID) > 1024 {
			return
		}
		var environment *resource.ID
		if environmentID != "" {
			value := resource.ID(environmentID)
			environment = &value
		}
		binding := RoleBinding{
			MemberID: resource.ID(memberID), Role: Role(role),
			Scope: Scope{Kind: ScopeKind(scopeKind), EnvironmentID: environment},
		}
		if CompareRoleBindings(binding, binding) != 0 {
			t.Fatal("binding does not compare equal to itself")
		}
		other := RoleBinding{MemberID: testViewerID, Role: RoleViewer, Scope: Scope{Kind: ScopeKindWorkspace}}
		left := CompareRoleBindings(binding, other)
		right := CompareRoleBindings(other, binding)
		if (left < 0) != (right > 0) || (left > 0) != (right < 0) || (left == 0) != (right == 0) {
			t.Fatalf("comparator is not antisymmetric: %d, %d", left, right)
		}
		if err := ValidatePolicySpec(PolicySpec{Bindings: []RoleBinding{binding}}); err != nil &&
			!errors.Is(err, ErrInvalidPolicySpec) {
			t.Fatalf("PolicySpec error classification = %v", err)
		}
	})
}
