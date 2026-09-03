package authorization

import (
	"sync"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/identity"
)

func TestPolicyVersionCanonicalizesSetAndDirectoryOrder(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	viewer := mustMember(t, testViewerID, testWorkspaceAID, identity.KindHuman, "viewer")
	developer := mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "developer")
	firstSpec := canonicalSpec(workspaceBinding(testViewerID, RoleViewer))
	secondSpec := canonicalSpec(environmentBinding(testDeveloperID, RoleDeveloper, testEnvironmentA))
	firstPolicies := []PolicyRevision{
		policyRevision(fixture.records[testPolicySecond], 3, secondSpec),
		policyRevision(fixture.records[testPolicyAID], 2, firstSpec),
	}
	secondPolicies := []PolicyRevision{
		policyRevision(fixture.records[testPolicyAID], 2, firstSpec),
		policyRevision(fixture.records[testPolicySecond], 3, secondSpec),
	}
	first, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID, developer, viewer),
		firstPolicies,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewPolicySet(
		fixture.snapshot,
		mustDirectory(t, testWorkspaceAID, viewer, developer),
		secondPolicies,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Version().Equal(second.Version()) {
		t.Fatalf("input ordering changed version: %s != %s", first.Version(), second.Version())
	}

	// Mutating every caller-owned slice and EnvironmentID pointer after
	// construction must not alter the compiled set or its version.
	versionBefore := first.Version()
	firstPolicies[0].Spec.Bindings[0].Role = RoleOperator
	*firstPolicies[0].Spec.Bindings[0].Scope.EnvironmentID = testEnvironmentB
	firstPolicies[0], firstPolicies[1] = firstPolicies[1], firstPolicies[0]
	if !first.Version().Equal(versionBefore) || ValidatePolicySet(first) != nil {
		t.Fatal("PolicySet retained caller-owned Policy state")
	}
}

func TestFramingSeparatesAdjacentIdentityComponents(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	leftLogical, err := identity.NewLogicalIdentity("https://issuer.example/a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	rightLogical, err := identity.NewLogicalIdentity("https://issuer.example/ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	leftMember, err := NewMemberRecord(MemberInput{
		ID: testViewerID, WorkspaceID: testWorkspaceAID, Kind: identity.KindHuman, LogicalIdentity: leftLogical,
	})
	if err != nil {
		t.Fatal(err)
	}
	rightMember, err := NewMemberRecord(MemberInput{
		ID: testViewerID, WorkspaceID: testWorkspaceAID, Kind: identity.KindHuman, LogicalIdentity: rightLogical,
	})
	if err != nil {
		t.Fatal(err)
	}
	left, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, leftMember), nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, rightMember), nil)
	if err != nil {
		t.Fatal(err)
	}
	if left.Version().Equal(right.Version()) {
		t.Fatal("distinct length-framed identities produced equal PolicyVersion")
	}
}

func TestConcurrentEvaluationIsImmutableAndDeterministic(t *testing.T) {
	fixture := newHierarchyFixture(t, testWorkspaceAID)
	member := mustMember(t, testDeveloperID, testWorkspaceAID, identity.KindHuman, "developer")
	set, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID, member), []PolicyRevision{
		policyRevision(
			fixture.records[testPolicyAID],
			1,
			canonicalSpec(environmentBinding(testDeveloperID, RoleDeveloper, testEnvironmentA)),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	target, err := ResolveResourceTarget(fixture.snapshot, testComponentA)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{
		Principal: mustPrincipal(t, identity.KindHuman, "developer"),
		Action:    ActionResourceReplace,
		Target:    target,
	}
	want, err := set.Evaluate(input)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 64
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 100 {
				got, evaluateErr := set.Evaluate(input)
				if evaluateErr != nil {
					errorsChannel <- evaluateErr
					return
				}
				if got.Effect() != want.Effect() || got.Reason() != want.Reason() ||
					!got.PolicyVersion().Equal(want.PolicyVersion()) ||
					!got.InputDigest().Equal(want.InputDigest()) {
					errorsChannel <- ErrInvalidDecision
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatalf("concurrent Evaluate(): %v", err)
	}
}

func TestEveryReservedActionPrecedesMembershipAndRoles(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, testWorkspaceAID)
	target, err := ResolveResourceTarget(fixture.snapshot, testApplicationA)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := NewPolicySet(fixture.snapshot, mustDirectory(t, testWorkspaceAID), nil)
	if err != nil {
		t.Fatal(err)
	}
	outsider := mustPrincipal(t, identity.KindHuman, "outsider")
	for _, action := range ReservedActions() {
		decision, evaluateErr := empty.Evaluate(Input{Principal: outsider, Action: action, Target: target})
		if evaluateErr != nil {
			t.Fatalf("Evaluate(%s): %v", action, evaluateErr)
		}
		if decision.Effect() != EffectDeny || decision.Reason() != ReasonReservedAction {
			t.Fatalf("Evaluate(%s) = %s/%s", action, decision.Effect(), decision.Reason())
		}
	}
}
