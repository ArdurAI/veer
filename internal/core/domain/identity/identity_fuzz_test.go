package identity

import (
	"errors"
	"fmt"
	"testing"
)

func FuzzPrincipalConstructionIsDeterministicAndSafe(f *testing.F) {
	f.Add(testIssuer, testSubject, "api-b", "api-a", "group-b", "group-a", uint8(1), testWorkload)
	f.Add("https://issuer.example", "subject", "api", "api", "group", "group", uint8(0), "")
	f.Add("not-an-issuer", "subject\nprivate", " api", "", "group", "", uint8(255), " workload")

	f.Fuzz(func(
		t *testing.T,
		issuer, subject, audienceA, audienceB, groupA, groupB string,
		kindByte uint8,
		workloadValue string,
	) {
		if len(issuer)+len(subject)+len(audienceA)+len(audienceB)+
			len(groupA)+len(groupB)+len(workloadValue) > 16_384 {
			t.Skip()
		}
		kind := KindHuman
		var workload *WorkloadIdentity
		if kindByte&1 != 0 {
			kind = KindWorkload
			candidate, err := NewWorkloadIdentity(workloadValue)
			if err == nil {
				workload = &candidate
			}
		}
		input := PrincipalInput{
			Kind: kind, Issuer: issuer, Subject: subject,
			Audiences:        []string{audienceA, audienceB},
			Groups:           []string{groupA, groupB},
			WorkloadIdentity: workload,
		}
		first, firstErr := NewPrincipal(input)
		second, secondErr := NewPrincipal(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("NewPrincipal success was nondeterministic")
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() || !errors.Is(firstErr, ErrInvalidPrincipal) {
				t.Fatalf("NewPrincipal error classification was unstable: %v / %v", firstErr, secondErr)
			}
			return
		}
		if !EqualPrincipal(first, second) || !SameLogicalIdentity(first, second) {
			t.Fatal("NewPrincipal result was nondeterministic")
		}
		if err := ValidatePrincipal(first); err != nil {
			t.Fatalf("ValidatePrincipal(NewPrincipal()) error = %v", err)
		}
		if fmt.Sprint(first) != first.String() ||
			fmt.Sprintf("%+v", first) != first.String() ||
			fmt.Sprintf("%#v", first) != first.GoString() {
			t.Fatal("Principal diagnostic formatting was not stable")
		}
	})
}

func FuzzExactLogicalIdentityDoesNotCreateConcatenationAliases(f *testing.F) {
	f.Add("tenant", "subject", uint8(3))
	f.Add("a", "bc", uint8(1))
	f.Fuzz(func(t *testing.T, leftPart, rightPart string, split uint8) {
		if leftPart == "" || rightPart == "" ||
			len(leftPart)+len(rightPart) > MaxSubjectBytes-1 {
			t.Skip()
		}
		joined := leftPart + rightPart
		position := int(split)%len(joined) + 1
		if position >= len(joined) {
			position = len(joined) - 1
		}
		if position <= 0 {
			t.Skip()
		}
		leftIssuer := testIssuer + "/" + joined[:position]
		leftSubject := joined[position:]
		rightIssuer := testIssuer + "/" + joined[:position-1]
		rightSubject := joined[position-1:]
		left, leftErr := NewLogicalIdentity(leftIssuer, leftSubject)
		right, rightErr := NewLogicalIdentity(rightIssuer, rightSubject)
		if leftErr != nil || rightErr != nil {
			return
		}
		if EqualLogicalIdentity(left, right) {
			t.Fatal("distinct framed values compared equal")
		}
		if left.Fingerprint().Equal(right.Fingerprint()) {
			t.Fatal("distinct framed values produced equal fuzz fingerprints")
		}
	})
}
