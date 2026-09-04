package audit

import "errors"

var (
	ErrInvalidEvent           = errors.New("invalid audit event")
	ErrInvalidStream          = errors.New("invalid audit stream")
	ErrInvalidActor           = errors.New("invalid audit actor")
	ErrInvalidReference       = errors.New("invalid audit reference")
	ErrInvalidClockState      = errors.New("invalid audit clock state")
	ErrInvalidEventKind       = errors.New("invalid audit event kind")
	ErrInvalidSource          = errors.New("invalid audit source")
	ErrInvalidOutcome         = errors.New("invalid audit outcome")
	ErrInvalidAuthentication  = errors.New("invalid audit authentication method")
	ErrWorkspaceMismatch      = errors.New("audit workspace does not match")
	ErrCanonicalTooLarge      = errors.New("canonical audit representation exceeds size limit")
	ErrNonCanonical           = errors.New("audit representation is not canonical")
	ErrSerializationForbidden = errors.New("audit serialization forbidden")

	ErrInvalidDigest     = errors.New("invalid audit digest")
	ErrInvalidCheckpoint = errors.New("invalid audit checkpoint")
	ErrInvalidRecord     = errors.New("invalid audit record")
	ErrInvalidSegment    = errors.New("invalid audit segment")
	ErrInvalidSequence   = errors.New("invalid audit sequence")
	ErrIntegrity         = errors.New("audit integrity verification failed")
	ErrExpectedHead      = errors.New("audit head does not match trusted checkpoint")
	ErrSegmentTooLarge   = errors.New("audit segment limit exceeded")

	ErrInvalidExport         = errors.New("invalid audit export")
	ErrBodyDigestMismatch    = errors.New("audit export body digest does not match")
	ErrSignatureRequired     = errors.New("audit export signature is required")
	ErrSignatureVerification = errors.New("audit export signature verification failed")

	ErrInvalidRetention = errors.New("invalid audit retention evaluation")
	ErrClockRegressed   = errors.New("audit retention clock regressed")
	ErrInvalidHold      = errors.New("invalid audit hold")
	ErrTooManyHolds     = errors.New("audit hold limit exceeded")
)
