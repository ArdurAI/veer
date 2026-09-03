package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	jsonv2 "encoding/json/v2"
)

type recordingSignatureVerifier struct {
	wantAlgorithm SignatureAlgorithm
	wantKeyID     string
	wantMessage   []byte
	wantSignature []byte
	err           error
	calls         int
}

func (verifier *recordingSignatureVerifier) Verify(
	algorithm SignatureAlgorithm,
	keyID string,
	message []byte,
	signature []byte,
) error {
	verifier.calls++
	if algorithm != verifier.wantAlgorithm || keyID != verifier.wantKeyID ||
		!bytes.Equal(message, verifier.wantMessage) || !bytes.Equal(signature, verifier.wantSignature) {
		return errors.New("unexpected verifier input")
	}
	return verifier.err
}

type exportFixture struct {
	genesis    Checkpoint
	segment    Segment
	terminal   Checkpoint
	body       []byte
	descriptor ExportDescriptor
	manifest   ExportManifest
	signature  []byte
}

func newExportFixture(t testing.TB) exportFixture {
	t.Helper()
	genesis, err := GenesisCheckpoint(mustWorkspaceStream(t))
	if err != nil {
		t.Fatal(err)
	}
	segment, terminal, err := NewSegment(
		genesis,
		[]Event{mustRequestEvent(t, 1), mustProviderAttemptEvent(t, 2)},
	)
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalCanonicalSegment(segment)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := DescribeExport(
		genesis,
		segment,
		testTime.Add(10),
		ClockStateSynchronized,
		SignatureAlgorithmEd25519,
		"audit-verifier-2026-09",
	)
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte("opaque-external-signature")
	manifest, err := BindExportSignature(descriptor, signature)
	if err != nil {
		t.Fatal(err)
	}
	return exportFixture{
		genesis:    genesis,
		segment:    segment,
		terminal:   terminal,
		body:       body,
		descriptor: descriptor,
		manifest:   manifest,
		signature:  signature,
	}
}

func TestVerifyExportRequiresIntegritySignatureAndTrustedTerminal(t *testing.T) {
	t.Parallel()

	fixture := newExportFixture(t)
	message, err := MarshalCanonicalExportDescriptor(fixture.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &recordingSignatureVerifier{
		wantAlgorithm: SignatureAlgorithmEd25519,
		wantKeyID:     fixture.descriptor.KeyID(),
		wantMessage:   message,
		wantSignature: slices.Clone(fixture.signature),
	}
	if err := VerifyExport(fixture.manifest, fixture.body, fixture.terminal, verifier); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 {
		t.Fatalf("verifier calls = %d", verifier.calls)
	}

	tamperedBody := slices.Clone(fixture.body)
	tamperedBody[len(tamperedBody)/2] ^= 1
	if err := VerifyExport(fixture.manifest, tamperedBody, fixture.terminal, verifier); !errors.Is(err, ErrBodyDigestMismatch) {
		t.Fatalf("tampered body = %v", err)
	}
	if verifier.calls != 1 {
		t.Fatal("signature verifier ran before body integrity passed")
	}

	wrongHead, err := NewCheckpoint(
		fixture.terminal.Stream(),
		fixture.terminal.Sequence()-1,
		fixture.terminal.Digest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyExport(fixture.manifest, fixture.body, wrongHead, verifier); !errors.Is(err, ErrExpectedHead) {
		t.Fatalf("untrusted terminal = %v", err)
	}
	if err := VerifyExport(fixture.manifest, fixture.body, fixture.terminal, nil); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("nil verifier = %v", err)
	}

	verifier.err = errors.New("external verification failure")
	if err := VerifyExport(fixture.manifest, fixture.body, fixture.terminal, verifier); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("failed signature = %v", err)
	}
}

func TestSignedPrefixCannotProveTailCompleteness(t *testing.T) {
	t.Parallel()

	complete := newExportFixture(t)
	prefix, prefixTerminal, err := NewSegment(complete.genesis, []Event{mustRequestEvent(t, 1)})
	if err != nil {
		t.Fatal(err)
	}
	prefixBody, err := MarshalCanonicalSegment(prefix)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := DescribeExport(
		complete.genesis,
		prefix,
		testTime.Add(10),
		ClockStateSynchronized,
		SignatureAlgorithmEd25519,
		"audit-verifier-2026-09",
	)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := BindExportSignature(descriptor, complete.signature)
	if err != nil {
		t.Fatal(err)
	}
	message, err := MarshalCanonicalExportDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &recordingSignatureVerifier{
		wantAlgorithm: descriptor.Algorithm(),
		wantKeyID:     descriptor.KeyID(),
		wantMessage:   message,
		wantSignature: complete.signature,
	}
	if err := VerifyExport(manifest, prefixBody, prefixTerminal, verifier); err != nil {
		t.Fatalf("signed prefix against its own trusted head = %v", err)
	}
	if err := VerifyExport(manifest, prefixBody, complete.terminal, verifier); !errors.Is(err, ErrExpectedHead) {
		t.Fatalf("signed stale prefix against current trusted head = %v", err)
	}
}

func TestExportAndSegmentGenericJSONAreExactCanonicalDelegates(t *testing.T) {
	t.Parallel()

	fixture := newExportFixture(t)
	tests := []struct {
		name      string
		value     any
		canonical []byte
		decode    func([]byte) error
		nilDecode func([]byte) error
	}{
		{
			name:      "segment",
			value:     fixture.segment,
			canonical: fixture.body,
			decode: func(data []byte) error {
				var decoded Segment
				if err := json.Unmarshal(data, &decoded); err != nil {
					return err
				}
				reencoded, err := MarshalCanonicalSegment(decoded)
				if err != nil {
					return err
				}
				if !bytes.Equal(reencoded, data) {
					return errors.New("segment round trip changed bytes")
				}
				return nil
			},
			nilDecode: func(data []byte) error {
				var decoded *Segment
				return decoded.UnmarshalJSON(data)
			},
		},
		{
			name:  "descriptor",
			value: fixture.descriptor,
			canonical: func() []byte {
				data, err := MarshalCanonicalExportDescriptor(fixture.descriptor)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}(),
			decode: func(data []byte) error {
				var decoded ExportDescriptor
				return json.Unmarshal(data, &decoded)
			},
			nilDecode: func(data []byte) error {
				var decoded *ExportDescriptor
				return decoded.UnmarshalJSON(data)
			},
		},
		{
			name:  "manifest",
			value: fixture.manifest,
			canonical: func() []byte {
				data, err := MarshalCanonicalExportManifest(fixture.manifest)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}(),
			decode: func(data []byte) error {
				var decoded ExportManifest
				return json.Unmarshal(data, &decoded)
			},
			nilDecode: func(data []byte) error {
				var decoded *ExportManifest
				return decoded.UnmarshalJSON(data)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			generic, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(generic, test.canonical) {
				t.Fatalf("generic JSON drifted\ngot:  %s\nwant: %s", generic, test.canonical)
			}
			if err := test.decode(test.canonical); err != nil {
				t.Fatalf("generic decode = %v", err)
			}
			if err := test.nilDecode(test.canonical); err == nil {
				t.Fatal("nil receiver accepted canonical input")
			}

			unknown := bytes.Replace(test.canonical, []byte(`"contractVersion":`), []byte(`"unknown":true,"contractVersion":`), 1)
			duplicate := bytes.Replace(test.canonical, []byte(`"contractVersion":"veer.audit.v1alpha1"`), []byte(`"contractVersion":"veer.audit.v1alpha1","contractVersion":"veer.audit.v1alpha1"`), 1)
			for _, invalid := range []struct {
				name string
				data []byte
			}{
				{"unknown", unknown},
				{"duplicate", duplicate},
			} {
				if err := test.decode(invalid.data); err == nil {
					t.Fatalf("generic decode accepted %s input: %.120q", invalid.name, invalid.data)
				}
			}
		})
	}

	if _, err := UnmarshalCanonicalSegment(append(slices.Clone(fixture.body), ' ')); err == nil {
		t.Fatal("canonical segment decoder accepted trailing whitespace")
	}
	descriptorData, err := MarshalCanonicalExportDescriptor(fixture.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCanonicalExportDescriptor(append(descriptorData, ' ')); err == nil {
		t.Fatal("canonical descriptor decoder accepted trailing whitespace")
	}
	yearZeroDescriptor := bytes.Replace(
		descriptorData,
		[]byte(`"generatedAt":"2026-`),
		[]byte(`"generatedAt":"0000-`),
		1,
	)
	if _, err := UnmarshalCanonicalExportDescriptor(yearZeroDescriptor); err == nil {
		t.Fatal("canonical descriptor decoder accepted year zero")
	}
	manifestData, err := MarshalCanonicalExportManifest(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalCanonicalExportManifest(append(manifestData, ' ')); err == nil {
		t.Fatal("canonical manifest decoder accepted trailing whitespace")
	}
}

func TestExportManifestDefensiveCopiesAndStrictBounds(t *testing.T) {
	t.Parallel()

	fixture := newExportFixture(t)
	original := fixture.manifest.Signature()
	fixture.signature[0] ^= 1
	if !bytes.Equal(fixture.manifest.Signature(), original) {
		t.Fatal("manifest retained caller signature storage")
	}
	returned := fixture.manifest.Signature()
	returned[0] ^= 1
	if !bytes.Equal(fixture.manifest.Signature(), original) {
		t.Fatal("Signature returned shared storage")
	}

	if _, err := BindExportSignature(fixture.descriptor, nil); !errors.Is(err, ErrSignatureRequired) {
		t.Fatalf("empty signature = %v", err)
	}
	if _, err := BindExportSignature(fixture.descriptor, make([]byte, MaxSignatureBytes+1)); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("oversized signature = %v", err)
	}
	if _, err := DescribeExport(
		fixture.genesis,
		Segment{},
		testTime,
		ClockStateSynchronized,
		SignatureAlgorithmEd25519,
		"key",
	); !errors.Is(err, ErrInvalidExport) {
		t.Fatalf("empty segment = %v", err)
	}

	manifestData, err := MarshalCanonicalExportManifest(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExportManifest
	if err := jsonv2.Unmarshal(manifestData, &decoded); err != nil {
		t.Fatalf("json/v2 generic decode = %v", err)
	}
}
