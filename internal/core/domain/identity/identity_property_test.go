package identity

import (
	"math/rand"
	"slices"
	"testing"
	"testing/quick"
)

func TestPropertyClaimPermutationAndDuplicationNormalizeIdentically(t *testing.T) {
	t.Parallel()

	property := func(seed uint64) bool {
		canonicalAudiences := []string{"api-a", "api-b", "api-c", "api-d"}
		canonicalGroups := []string{"group-a", "group-b", "group-c", "group-d"}
		random := rand.New(rand.NewSource(int64(seed)))
		audiences := append(slices.Clone(canonicalAudiences), canonicalAudiences[random.Intn(len(canonicalAudiences))])
		groups := append(slices.Clone(canonicalGroups), canonicalGroups[random.Intn(len(canonicalGroups))])
		random.Shuffle(len(audiences), func(left, right int) {
			audiences[left], audiences[right] = audiences[right], audiences[left]
		})
		random.Shuffle(len(groups), func(left, right int) {
			groups[left], groups[right] = groups[right], groups[left]
		})

		left, err := NewPrincipal(PrincipalInput{
			Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
			Audiences: audiences, Groups: groups,
		})
		if err != nil {
			return false
		}
		right, err := NewPrincipal(PrincipalInput{
			Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
			Audiences: canonicalAudiences, Groups: canonicalGroups,
		})
		return err == nil && EqualPrincipal(left, right) &&
			slices.Equal(left.Audiences(), canonicalAudiences) &&
			slices.Equal(left.Groups(), canonicalGroups)
	}
	checkIdentityProperty(t, property)
}

func TestPropertyExactIdentityAndFingerprintAreDeterministic(t *testing.T) {
	t.Parallel()

	property := func(suffix uint64) bool {
		issuer := testIssuer + "/" + base36(suffix)
		subject := testSubject + "-" + base36(suffix)
		left, err := NewLogicalIdentity(issuer, subject)
		if err != nil {
			return false
		}
		right, err := NewLogicalIdentity(issuer, subject)
		return err == nil && EqualLogicalIdentity(left, right) &&
			left.Fingerprint().Equal(right.Fingerprint()) &&
			left.Fingerprint().String() == right.Fingerprint().String()
	}
	checkIdentityProperty(t, property)
}

func TestPropertyPrincipalEqualityIsReflexiveSymmetricAndCloneStable(t *testing.T) {
	t.Parallel()

	principal := mustPrincipal(t, PrincipalInput{
		Kind: KindHuman, Issuer: testIssuer, Subject: testSubject,
		Audiences: []string{"api-a", "api-b"}, Groups: []string{"group-a", "group-b"},
	})
	property := func(seed uint64) bool {
		left := ClonePrincipal(principal)
		right := ClonePrincipal(principal)
		if seed&1 != 0 {
			right.groups = append(right.groups, "group-c")
		}
		return EqualPrincipal(left, left) &&
			EqualPrincipal(left, right) == EqualPrincipal(right, left) &&
			EqualPrincipal(ClonePrincipal(left), left)
	}
	checkIdentityProperty(t, property)
}

func checkIdentityProperty(t *testing.T, property any) {
	t.Helper()
	configuration := &quick.Config{
		MaxCount: 250,
		Rand:     rand.New(rand.NewSource(22)),
	}
	if err := quick.Check(property, configuration); err != nil {
		t.Fatal(err)
	}
}

func base36(value uint64) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	if value == 0 {
		return "0"
	}
	var buffer [13]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = alphabet[value%36]
		value /= 36
	}
	return string(buffer[index:])
}
