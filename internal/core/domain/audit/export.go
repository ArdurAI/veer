package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"
	"time"
)

const exportBodyDomain = "veer.audit.export.body.v1"

// ExportDescriptor is the canonical payload that an external signer binds. It
// identifies one exact segment body and both chain boundaries.
type ExportDescriptor struct {
	initialized    bool
	stream         Stream
	sequenceRange  SequenceRange
	eventCount     uint32
	previousDigest ChainDigest
	terminalDigest ChainDigest
	bodyDigest     ExportBodyDigest
	generatedAt    string
	clockState     ClockState
	algorithm      SignatureAlgorithm
	keyID          string
}

// DescribeExport verifies and describes a non-empty canonical segment. It does
// not sign, persist, publish, or otherwise perform I/O.
func DescribeExport(
	previous Checkpoint,
	segment Segment,
	generatedAt time.Time,
	clockState ClockState,
	algorithm SignatureAlgorithm,
	keyID string,
) (ExportDescriptor, error) {
	if segment.Len() == 0 {
		return ExportDescriptor{}, fmt.Errorf("%w: empty segment", ErrInvalidExport)
	}
	terminal, err := VerifySegment(previous, segment, nil)
	if err != nil {
		return ExportDescriptor{}, fmt.Errorf("%w: invalid segment", ErrInvalidExport)
	}
	body, err := MarshalCanonicalSegment(segment)
	if err != nil {
		return ExportDescriptor{}, err
	}
	recorded, err := normalizeTimestamp(generatedAt)
	if err != nil {
		return ExportDescriptor{}, fmt.Errorf("%w: invalid generated time", ErrInvalidExport)
	}
	sequenceRange, present := segment.Range()
	if !present {
		return ExportDescriptor{}, fmt.Errorf("%w: empty segment", ErrInvalidExport)
	}
	descriptor := ExportDescriptor{
		initialized:    true,
		stream:         previous.stream,
		sequenceRange:  sequenceRange,
		eventCount:     uint32(segment.Len()),
		previousDigest: previous.digest,
		terminalDigest: terminal.digest,
		bodyDigest:     deriveExportBodyDigest(body),
		generatedAt:    recorded,
		clockState:     clockState,
		algorithm:      algorithm,
		keyID:          keyID,
	}
	if err := ValidateExportDescriptor(descriptor); err != nil {
		return ExportDescriptor{}, err
	}
	return descriptor, nil
}

func ValidateExportDescriptor(descriptor ExportDescriptor) error {
	if !descriptor.initialized || ValidateStream(descriptor.stream) != nil ||
		!descriptor.previousDigest.initialized || !descriptor.terminalDigest.initialized ||
		!descriptor.bodyDigest.initialized {
		return ErrInvalidExport
	}
	if descriptor.sequenceRange.first == 0 ||
		descriptor.sequenceRange.last < descriptor.sequenceRange.first {
		return ErrInvalidExport
	}
	wantCount := descriptor.sequenceRange.last - descriptor.sequenceRange.first + 1
	if wantCount == 0 || wantCount > MaxSegmentEvents || uint64(descriptor.eventCount) != wantCount {
		return ErrInvalidExport
	}
	previous, err := NewCheckpoint(
		descriptor.stream,
		descriptor.sequenceRange.first-1,
		descriptor.previousDigest,
	)
	if err != nil {
		return ErrInvalidExport
	}
	terminal, err := NewCheckpoint(
		descriptor.stream,
		descriptor.sequenceRange.last,
		descriptor.terminalDigest,
	)
	if err != nil || terminal.sequence <= previous.sequence {
		return ErrInvalidExport
	}
	if _, err := parseTimestamp(descriptor.generatedAt); err != nil {
		return ErrInvalidExport
	}
	if _, err := ParseClockState(descriptor.clockState.String()); err != nil {
		return ErrInvalidExport
	}
	if _, err := ParseSignatureAlgorithm(descriptor.algorithm.String()); err != nil ||
		!validateKeyID(descriptor.keyID) {
		return ErrInvalidExport
	}
	return nil
}

func (descriptor ExportDescriptor) Stream() Stream                { return descriptor.stream }
func (descriptor ExportDescriptor) Range() SequenceRange          { return descriptor.sequenceRange }
func (descriptor ExportDescriptor) EventCount() uint32            { return descriptor.eventCount }
func (descriptor ExportDescriptor) BodyDigest() ExportBodyDigest  { return descriptor.bodyDigest }
func (descriptor ExportDescriptor) ClockState() ClockState        { return descriptor.clockState }
func (descriptor ExportDescriptor) Algorithm() SignatureAlgorithm { return descriptor.algorithm }
func (descriptor ExportDescriptor) KeyID() string                 { return descriptor.keyID }
func (descriptor ExportDescriptor) GeneratedAt() time.Time {
	parsed, _ := parseTimestamp(descriptor.generatedAt)
	return parsed
}
func (descriptor ExportDescriptor) PreviousCheckpoint() (Checkpoint, error) {
	return NewCheckpoint(
		descriptor.stream,
		descriptor.sequenceRange.first-1,
		descriptor.previousDigest,
	)
}
func (descriptor ExportDescriptor) TerminalCheckpoint() (Checkpoint, error) {
	return NewCheckpoint(
		descriptor.stream,
		descriptor.sequenceRange.last,
		descriptor.terminalDigest,
	)
}

// MarshalCanonicalExportDescriptor emits exactly the bytes an external signer
// and verifier must use.
func MarshalCanonicalExportDescriptor(descriptor ExportDescriptor) ([]byte, error) {
	if err := ValidateExportDescriptor(descriptor); err != nil {
		return nil, err
	}
	data, err := encodeExportDescriptor(descriptor)
	if err != nil {
		return nil, fmt.Errorf("%w: descriptor encode", ErrInvalidExport)
	}
	if len(data) > MaxCanonicalManifestBytes {
		return nil, ErrCanonicalTooLarge
	}
	return data, nil
}

func UnmarshalCanonicalExportDescriptor(data []byte) (ExportDescriptor, error) {
	if len(data) == 0 {
		return ExportDescriptor{}, ErrNonCanonical
	}
	if len(data) > MaxCanonicalManifestBytes {
		return ExportDescriptor{}, ErrCanonicalTooLarge
	}
	var wire exportDescriptorWire
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return ExportDescriptor{}, ErrNonCanonical
	}
	descriptor, err := exportDescriptorFromWire(wire)
	if err != nil {
		return ExportDescriptor{}, err
	}
	canonical, err := MarshalCanonicalExportDescriptor(descriptor)
	if err != nil {
		return ExportDescriptor{}, err
	}
	if !bytes.Equal(data, canonical) {
		return ExportDescriptor{}, ErrNonCanonical
	}
	return descriptor, nil
}

func (descriptor ExportDescriptor) MarshalJSON() ([]byte, error) {
	return MarshalCanonicalExportDescriptor(descriptor)
}

func (descriptor *ExportDescriptor) UnmarshalJSON(data []byte) error {
	if descriptor == nil {
		return ErrInvalidExport
	}
	parsed, err := UnmarshalCanonicalExportDescriptor(data)
	if err != nil {
		return err
	}
	*descriptor = parsed
	return nil
}

// ExportManifest binds an opaque externally produced signature to one
// descriptor. Signature bytes are defensively copied.
type ExportManifest struct {
	descriptor ExportDescriptor
	signature  []byte
}

func BindExportSignature(descriptor ExportDescriptor, signature []byte) (ExportManifest, error) {
	if err := ValidateExportDescriptor(descriptor); err != nil {
		return ExportManifest{}, err
	}
	if len(signature) == 0 {
		return ExportManifest{}, ErrSignatureRequired
	}
	if len(signature) > MaxSignatureBytes {
		return ExportManifest{}, fmt.Errorf("%w: signature limit", ErrInvalidExport)
	}
	return ExportManifest{descriptor: descriptor, signature: slices.Clone(signature)}, nil
}

func ValidateExportManifest(manifest ExportManifest) error {
	if err := ValidateExportDescriptor(manifest.descriptor); err != nil {
		return ErrInvalidExport
	}
	if len(manifest.signature) == 0 {
		return ErrSignatureRequired
	}
	if len(manifest.signature) > MaxSignatureBytes {
		return ErrInvalidExport
	}
	return nil
}

func (manifest ExportManifest) Descriptor() ExportDescriptor { return manifest.descriptor }
func (manifest ExportManifest) Signature() []byte            { return slices.Clone(manifest.signature) }

func MarshalCanonicalExportManifest(manifest ExportManifest) ([]byte, error) {
	if err := ValidateExportManifest(manifest); err != nil {
		return nil, err
	}
	wire := exportManifestWire{
		Descriptor: exportDescriptorToWire(manifest.descriptor),
		Signature:  base64.RawURLEncoding.EncodeToString(manifest.signature),
	}
	data, err := jsonv2.Marshal(wire, json.DefaultOptionsV1(), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		return nil, fmt.Errorf("%w: manifest encode", ErrInvalidExport)
	}
	if len(data) > MaxCanonicalManifestBytes {
		return nil, ErrCanonicalTooLarge
	}
	return data, nil
}

func UnmarshalCanonicalExportManifest(data []byte) (ExportManifest, error) {
	if len(data) == 0 {
		return ExportManifest{}, ErrNonCanonical
	}
	if len(data) > MaxCanonicalManifestBytes {
		return ExportManifest{}, ErrCanonicalTooLarge
	}
	var wire exportManifestWire
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return ExportManifest{}, ErrNonCanonical
	}
	descriptor, err := exportDescriptorFromWire(wire.Descriptor)
	if err != nil {
		return ExportManifest{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(wire.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != wire.Signature {
		return ExportManifest{}, ErrNonCanonical
	}
	manifest, err := BindExportSignature(descriptor, signature)
	if err != nil {
		return ExportManifest{}, err
	}
	canonical, err := MarshalCanonicalExportManifest(manifest)
	if err != nil {
		return ExportManifest{}, err
	}
	if !bytes.Equal(data, canonical) {
		return ExportManifest{}, ErrNonCanonical
	}
	return manifest, nil
}

func (manifest ExportManifest) MarshalJSON() ([]byte, error) {
	return MarshalCanonicalExportManifest(manifest)
}

func (manifest *ExportManifest) UnmarshalJSON(data []byte) error {
	if manifest == nil {
		return ErrInvalidExport
	}
	parsed, err := UnmarshalCanonicalExportManifest(data)
	if err != nil {
		return err
	}
	*manifest = parsed
	return nil
}

// SignatureVerifier is supplied by the caller's independently trusted key
// boundary. The audit package provides no signer, private-key handling, public-
// key parser, or concrete verifier.
type SignatureVerifier interface {
	Verify(
		algorithm SignatureAlgorithm,
		keyID string,
		message []byte,
		signature []byte,
	) error
}

// VerifyExport verifies canonical body integrity, contiguous chain/range, the
// caller-supplied trusted terminal checkpoint, and the external signature. A
// signed manifest is not itself proof that the selected tail is current.
func VerifyExport(
	manifest ExportManifest,
	canonicalBody []byte,
	expectedTerminal Checkpoint,
	verifier SignatureVerifier,
) error {
	if err := ValidateExportManifest(manifest); err != nil {
		return err
	}
	if verifier == nil {
		return ErrSignatureVerification
	}
	if ValidateCheckpoint(expectedTerminal) != nil {
		return ErrExpectedHead
	}
	terminal, err := manifest.descriptor.TerminalCheckpoint()
	if err != nil || !terminal.Equal(expectedTerminal) {
		return ErrExpectedHead
	}
	if len(canonicalBody) == 0 || len(canonicalBody) > MaxCanonicalSegmentBytes {
		return ErrInvalidExport
	}
	if !deriveExportBodyDigest(canonicalBody).Equal(manifest.descriptor.bodyDigest) {
		return ErrBodyDigestMismatch
	}
	segment, err := UnmarshalCanonicalSegment(canonicalBody)
	if err != nil {
		return fmt.Errorf("%w: invalid body", ErrInvalidExport)
	}
	sequenceRange, present := segment.Range()
	if !present || sequenceRange != manifest.descriptor.sequenceRange ||
		segment.Len() != int(manifest.descriptor.eventCount) {
		return fmt.Errorf("%w: range mismatch", ErrInvalidExport)
	}
	previous, err := manifest.descriptor.PreviousCheckpoint()
	if err != nil {
		return ErrInvalidExport
	}
	if _, err := VerifySegment(previous, segment, &expectedTerminal); err != nil {
		return fmt.Errorf("%w: chain", ErrInvalidExport)
	}
	message, err := MarshalCanonicalExportDescriptor(manifest.descriptor)
	if err != nil {
		return err
	}
	if err := verifier.Verify(
		manifest.descriptor.algorithm,
		manifest.descriptor.keyID,
		slices.Clone(message),
		slices.Clone(manifest.signature),
	); err != nil {
		return ErrSignatureVerification
	}
	return nil
}

type sequenceRangeWire struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
}

type exportDescriptorWire struct {
	ContractVersion    string             `json:"contractVersion"`
	Stream             streamWire         `json:"stream"`
	Range              sequenceRangeWire  `json:"range"`
	EventCount         uint32             `json:"eventCount"`
	PreviousDigest     string             `json:"previousDigest"`
	TerminalDigest     string             `json:"terminalDigest"`
	BodyDigest         string             `json:"bodyDigest"`
	GeneratedAt        string             `json:"generatedAt"`
	ClockState         ClockState         `json:"clockState"`
	SignatureAlgorithm SignatureAlgorithm `json:"signatureAlgorithm"`
	KeyID              string             `json:"keyId"`
}

type exportManifestWire struct {
	Descriptor exportDescriptorWire `json:",embed"`
	Signature  string               `json:"signature"`
}

func encodeExportDescriptor(descriptor ExportDescriptor) ([]byte, error) {
	return jsonv2.Marshal(
		exportDescriptorToWire(descriptor),
		json.DefaultOptionsV1(),
		jsontext.AllowInvalidUTF8(false),
	)
}

func exportDescriptorToWire(descriptor ExportDescriptor) exportDescriptorWire {
	return exportDescriptorWire{
		ContractVersion:    ContractVersion,
		Stream:             streamToWire(descriptor.stream),
		Range:              sequenceRangeWire{First: descriptor.sequenceRange.first, Last: descriptor.sequenceRange.last},
		EventCount:         descriptor.eventCount,
		PreviousDigest:     descriptor.previousDigest.String(),
		TerminalDigest:     descriptor.terminalDigest.String(),
		BodyDigest:         descriptor.bodyDigest.String(),
		GeneratedAt:        descriptor.generatedAt,
		ClockState:         descriptor.clockState,
		SignatureAlgorithm: descriptor.algorithm,
		KeyID:              descriptor.keyID,
	}
}

func exportDescriptorFromWire(wire exportDescriptorWire) (ExportDescriptor, error) {
	if wire.ContractVersion != ContractVersion {
		return ExportDescriptor{}, ErrInvalidExport
	}
	stream, err := streamFromWire(wire.Stream)
	if err != nil {
		return ExportDescriptor{}, ErrInvalidExport
	}
	previous, err := ParseChainDigest(wire.PreviousDigest)
	if err != nil {
		return ExportDescriptor{}, ErrInvalidExport
	}
	terminal, err := ParseChainDigest(wire.TerminalDigest)
	if err != nil {
		return ExportDescriptor{}, ErrInvalidExport
	}
	body, err := ParseExportBodyDigest(wire.BodyDigest)
	if err != nil {
		return ExportDescriptor{}, ErrInvalidExport
	}
	descriptor := ExportDescriptor{
		initialized:    true,
		stream:         stream,
		sequenceRange:  SequenceRange{first: wire.Range.First, last: wire.Range.Last},
		eventCount:     wire.EventCount,
		previousDigest: previous,
		terminalDigest: terminal,
		bodyDigest:     body,
		generatedAt:    wire.GeneratedAt,
		clockState:     wire.ClockState,
		algorithm:      wire.SignatureAlgorithm,
		keyID:          wire.KeyID,
	}
	if err := ValidateExportDescriptor(descriptor); err != nil {
		return ExportDescriptor{}, err
	}
	return descriptor, nil
}

func deriveExportBodyDigest(body []byte) ExportBodyDigest {
	hasher := sha256.New()
	writeHashFrame(hasher, []byte(exportBodyDomain))
	writeHashFrame(hasher, []byte(ContractVersion))
	writeHashFrame(hasher, body)
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return ExportBodyDigest{initialized: true, digest: digest}
}
