// Package buildinfo defines the stable build identity shared by Veer binaries.
package buildinfo

import "strings"

const (
	// DevelopmentVersion is used when a build has no injected release version.
	DevelopmentVersion = "dev"
	// UnknownRevision is used when source-control metadata is unavailable.
	UnknownRevision = "unknown"
)

// Info identifies the source used to build a Veer process.
type Info struct {
	Version  string
	Revision string
	Modified bool
}

// New normalizes optional linker-provided values into a complete identity.
func New(version, revision string, modified bool) Info {
	version = strings.TrimSpace(version)
	if version == "" {
		version = DevelopmentVersion
	}

	revision = strings.TrimSpace(revision)
	if revision == "" {
		revision = UnknownRevision
	}

	return Info{
		Version:  version,
		Revision: revision,
		Modified: modified,
	}
}
