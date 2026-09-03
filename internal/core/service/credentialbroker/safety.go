package credentialbroker

import (
	"fmt"
	"io"
	"log/slog"
)

type brokerDiagnostic struct {
	initialized bool
}

func (diagnostic brokerDiagnostic) String() string {
	if !diagnostic.initialized {
		return "credential-broker(invalid)"
	}
	return "credential-broker(redacted)"
}

func (diagnostic brokerDiagnostic) GoString() string { return diagnostic.String() }

func (diagnostic brokerDiagnostic) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, diagnostic.String())
}

func (diagnostic brokerDiagnostic) LogValue() slog.Value {
	return slog.StringValue(diagnostic.String())
}

func (brokerDiagnostic) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (brokerDiagnostic) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (brokerDiagnostic) MarshalBinary() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (brokerDiagnostic) GobEncode() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

type leaseDiagnostic struct {
	initialized bool
}

func (diagnostic leaseDiagnostic) String() string {
	if !diagnostic.initialized {
		return "credential-lease(invalid)"
	}
	return "credential-lease(redacted)"
}

func (diagnostic leaseDiagnostic) GoString() string { return diagnostic.String() }

func (diagnostic leaseDiagnostic) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, diagnostic.String())
}

func (diagnostic leaseDiagnostic) LogValue() slog.Value {
	return slog.StringValue(diagnostic.String())
}

func (leaseDiagnostic) MarshalJSON() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (leaseDiagnostic) MarshalText() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (leaseDiagnostic) MarshalBinary() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (leaseDiagnostic) GobEncode() ([]byte, error) {
	return nil, ErrSerializationForbidden
}

func (*leaseState) String() string   { return "credential-lease-state(redacted)" }
func (*leaseState) GoString() string { return "credential-lease-state(redacted)" }

func (*leaseState) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "credential-lease-state(redacted)")
}

func (*leaseState) LogValue() slog.Value {
	return slog.StringValue("credential-lease-state(redacted)")
}

func (rotation Rotation) String() string {
	if !rotation.Valid() {
		return "credential-rotation(invalid)"
	}
	return "credential-rotation(redacted)"
}

func (rotation Rotation) GoString() string { return rotation.String() }

func (rotation Rotation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, rotation.String())
}

func (rotation Rotation) LogValue() slog.Value {
	return slog.StringValue(rotation.String())
}

func (Rotation) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Rotation) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Rotation) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Rotation) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

var (
	_ fmt.Formatter  = (*Broker)(nil)
	_ fmt.Stringer   = (*Broker)(nil)
	_ fmt.GoStringer = (*Broker)(nil)
	_ slog.LogValuer = (*Broker)(nil)
	_ fmt.Formatter  = Lease{}
	_ fmt.Stringer   = Lease{}
	_ fmt.GoStringer = Lease{}
	_ slog.LogValuer = Lease{}
	_ fmt.Formatter  = Rotation{}
	_ fmt.Stringer   = Rotation{}
	_ fmt.GoStringer = Rotation{}
	_ slog.LogValuer = Rotation{}
)
