package hack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const archiveListingLimit = 8 * 1024 * 1024

func TestArchiveValidationAcceptsBoundedPAXArchive(t *testing.T) {
	archive := writePAXArchive(t, 1, len("tool"), "tool")
	output, err := runArchiveValidation(t, archive)
	if err != nil {
		t.Fatalf("validate bounded archive: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("members=1")) {
		t.Fatalf("validation output does not report the member count: %s", output)
	}
}

func TestArchiveValidationDoesNotMaskTarFailure(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	if err := os.WriteFile(archive, []byte("not a gzip archive"), 0o600); err != nil {
		t.Fatalf("write corrupt archive: %v", err)
	}
	output, err := runArchiveValidation(t, archive)
	if err == nil {
		t.Fatalf("corrupt archive unexpectedly passed: %s", output)
	}
	want := "cannot produce compact archive listing"
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("missing producer-failure diagnostic %q: %s", want, output)
	}
}

func TestArchiveValidationRejectsOversizedCompactPAXListing(t *testing.T) {
	archive := writePAXArchive(t, 48, 190_000, "")
	output, err := runArchiveValidation(t, archive)
	if err == nil {
		t.Fatalf("oversized compact listing unexpectedly passed: %s", output)
	}
	want := fmt.Sprintf("compact archive listing for %s exceeds %d bytes", filepath.Base(archive), archiveListingLimit)
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("missing bounded compact-listing diagnostic %q: %s", want, output)
	}
}

func TestArchiveValidationRejectsOversizedVerbosePAXListing(t *testing.T) {
	archive := writePAXArchive(t, 19_000, 400, "")
	output, err := runArchiveValidation(t, archive)
	if err == nil {
		t.Fatalf("oversized verbose listing unexpectedly passed: %s", output)
	}
	want := fmt.Sprintf("verbose archive listing for %s exceeds %d bytes", filepath.Base(archive), archiveListingLimit)
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("missing bounded verbose-listing diagnostic %q: %s", want, output)
	}
}

func writePAXArchive(t *testing.T, members, nameLength int, exactName string) string {
	t.Helper()

	archive := filepath.Join(t.TempDir(), "fixture.tar.gz")
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)

	for index := 0; index < members; index++ {
		name := exactName
		if name == "" {
			prefix := fmt.Sprintf("%06d-", index)
			if len(prefix) > nameLength {
				t.Fatalf("name length %d is smaller than prefix %q", nameLength, prefix)
			}
			name = prefix + strings.Repeat("a", nameLength-len(prefix))
		}
		header := &tar.Header{
			Name:   name,
			Mode:   0o600,
			Size:   1,
			Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write archive header %d: %v", index, err)
		}
		if _, err := tarWriter.Write([]byte{'x'}); err != nil {
			t.Fatalf("write archive body %d: %v", index, err)
		}
	}

	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close archive: %v", err)
	}
	return archive
}

func runArchiveValidation(t *testing.T, archive string) ([]byte, error) {
	t.Helper()

	packageDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("resolve package working directory: %v", err)
	}
	repositoryRoot := filepath.Dir(packageDirectory)
	temporaryRoot := t.TempDir()
	command := exec.Command("sh", filepath.Join(repositoryRoot, "hack", "dev"), "_validate-archive", archive)
	command.Dir = repositoryRoot
	command.Env = make([]string, 0, len(os.Environ())+1)
	for _, environmentEntry := range os.Environ() {
		if !strings.HasPrefix(environmentEntry, "TMPDIR=") {
			command.Env = append(command.Env, environmentEntry)
		}
	}
	command.Env = append(command.Env, "TMPDIR="+temporaryRoot)
	output, err := command.CombinedOutput()

	entries, readErr := os.ReadDir(temporaryRoot)
	if readErr != nil {
		t.Fatalf("read validator temporary root: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("validator left %d temporary entries after completion", len(entries))
	}
	return output, err
}
