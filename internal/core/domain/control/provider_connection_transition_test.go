package control

import (
	"errors"
	"testing"
)

func TestCheckProviderConnectionSpecTransition(t *testing.T) {
	t.Parallel()
	before := ProviderConnectionSpec{
		Provider: "aws",
		CredentialRef: CredentialReference{
			ReferenceID: "sec_01J00000000000000000000000",
			Version:     "version_1",
		},
	}
	tests := []struct {
		name   string
		mutate func(*ProviderConnectionSpec)
		want   error
	}{
		{name: "exact replay", mutate: func(*ProviderConnectionSpec) {}},
		{name: "version rotation", mutate: func(value *ProviderConnectionSpec) { value.CredentialRef.Version = "version_2" }},
		{name: "provider rebind", mutate: func(value *ProviderConnectionSpec) { value.Provider = "kubernetes" }, want: ErrProviderConnectionRebind},
		{name: "reference rebind", mutate: func(value *ProviderConnectionSpec) {
			value.CredentialRef.ReferenceID = "sec_01J11111111111111111111111"
		}, want: ErrProviderConnectionRebind},
		{name: "invalid next version", mutate: func(value *ProviderConnectionSpec) { value.CredentialRef.Version = "" }, want: ErrInvalidProviderConnectionSpecTransition},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			after := before
			test.mutate(&after)
			err := CheckProviderConnectionSpecTransition(before, after)
			if test.want == nil && err != nil {
				t.Fatalf("CheckProviderConnectionSpecTransition() error = %v", err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("CheckProviderConnectionSpecTransition() error = %v, want %v", err, test.want)
			}
		})
	}
}

func FuzzCheckProviderConnectionSpecTransition(f *testing.F) {
	f.Add("aws", "sec_01J00000000000000000000000", "version_1")
	f.Fuzz(func(t *testing.T, provider, referenceID, version string) {
		before := ProviderConnectionSpec{
			Provider: "aws",
			CredentialRef: CredentialReference{
				ReferenceID: "sec_01J00000000000000000000000",
				Version:     "version_1",
			},
		}
		after := ProviderConnectionSpec{
			Provider: provider,
			CredentialRef: CredentialReference{
				ReferenceID: referenceID,
				Version:     version,
			},
		}
		err := CheckProviderConnectionSpecTransition(before, after)
		if ValidateProviderConnectionSpec(after) != nil {
			if !errors.Is(err, ErrInvalidProviderConnectionSpecTransition) {
				t.Fatalf("invalid after spec returned %v", err)
			}
			return
		}
		if provider != before.Provider || referenceID != before.CredentialRef.ReferenceID {
			if !errors.Is(err, ErrProviderConnectionRebind) {
				t.Fatalf("valid rebind returned %v", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid replay or version rotation returned %v", err)
		}
	})
}
