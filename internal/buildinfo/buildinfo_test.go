package buildinfo

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		version  string
		revision string
		modified bool
		want     Info
	}{
		{
			name:     "release identity",
			version:  " v0.1.0 ",
			revision: " abc123 ",
			modified: false,
			want: Info{
				Version:  "v0.1.0",
				Revision: "abc123",
				Modified: false,
			},
		},
		{
			name:     "development defaults",
			modified: true,
			want: Info{
				Version:  DevelopmentVersion,
				Revision: UnknownRevision,
				Modified: true,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := New(test.version, test.revision, test.modified); got != test.want {
				t.Fatalf("New() = %#v, want %#v", got, test.want)
			}
		})
	}
}
