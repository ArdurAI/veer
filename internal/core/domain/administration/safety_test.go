package administration

import (
	"bytes"
	"encoding"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
)

type diagnosticEnvelope struct {
	Value any
}

type nestedElevationRequest struct {
	Request ElevationRequest
}

func TestAdministrationDiagnosticsAndSerializationAreSafe(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	target := ResolvePlatformAuditExportTarget()
	request := mustRequest(
		t, testGrantID, administrator, principal, authorization.ActionAuditExport,
		target, time.Minute,
	)
	ledger := mustLedger(t, administrator)
	grant, err := mustIssue(t, ledger, testProofID, request, testNow, testNow)
	if err != nil {
		t.Fatal(err)
	}
	consumption, err := ledger.Consume(
		testNow.Add(time.Second), grant, authorization.ActionAuditExport, target,
	)
	if err != nil {
		t.Fatal(err)
	}

	revocationLedger := mustLedger(t, administrator)
	revocationRequest := mustRequest(
		t, "elv_01JADMIN00000000000000002", administrator, principal,
		authorization.ActionAuditExport, target, time.Minute,
	)
	revocationGrant, err := mustIssue(
		t, revocationLedger, "prf_01JADMIN00000000000000002",
		revocationRequest, testNow, testNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	revocation, err := revocationLedger.Revoke(testNow.Add(time.Second), revocationGrant)
	if err != nil {
		t.Fatal(err)
	}

	values := []any{
		administrator,
		&administrator,
		target,
		&target,
		request,
		&request,
		grant,
		&grant,
		consumption,
		&consumption,
		revocation,
		&revocation,
		ledger,
		&ledger,
	}
	canaries := []string{
		testIssuer,
		testSubject,
		testAdministratorID.String(),
		testGrantID.String(),
		testProofID.String(),
		testReason,
		testCaseReference,
	}
	formats := []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%o", "%f"}
	for _, value := range values {
		for _, format := range formats {
			assertNoCanary(t, fmt.Sprintf(format, value), canaries...)
			assertNoCanary(t, fmt.Sprintf(format, diagnosticEnvelope{Value: value}), canaries...)
		}
		// %p is meaningful only for pointers; applying it to a value is an
		// unsupported-verb diagnostic outside fmt.Formatter's contract.
		if strings.HasPrefix(fmt.Sprintf("%T", value), "*") {
			assertNoCanary(t, fmt.Sprintf("%p", value), canaries...)
		}

		var log bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&log, nil))
		logger.Info("administration diagnostic", "value", value)
		assertNoCanary(t, log.String(), canaries...)

		encoded, marshalErr := json.Marshal(value)
		if !errors.Is(marshalErr, ErrSerializationForbidden) || len(encoded) != 0 {
			t.Fatalf("json.Marshal(%T) = %q, %v", value, encoded, marshalErr)
		}
		assertNoCanary(t, errorText(marshalErr), canaries...)

		textMarshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatalf("%T does not implement encoding.TextMarshaler", value)
		}
		encoded, marshalErr = textMarshaler.MarshalText()
		if !errors.Is(marshalErr, ErrSerializationForbidden) || len(encoded) != 0 {
			t.Fatalf("MarshalText(%T) = %q, %v", value, encoded, marshalErr)
		}

		binaryMarshaler, ok := value.(encoding.BinaryMarshaler)
		if !ok {
			t.Fatalf("%T does not implement encoding.BinaryMarshaler", value)
		}
		encoded, marshalErr = binaryMarshaler.MarshalBinary()
		if !errors.Is(marshalErr, ErrSerializationForbidden) || len(encoded) != 0 {
			t.Fatalf("MarshalBinary(%T) = %q, %v", value, encoded, marshalErr)
		}

		var gobOutput bytes.Buffer
		gobErr := gob.NewEncoder(&gobOutput).Encode(value)
		if gobErr == nil {
			t.Fatalf("gob.Encode(%T) unexpectedly succeeded: %x", value, gobOutput.Bytes())
		}
		assertNoCanary(t, gobOutput.String(), canaries...)
		assertNoCanary(t, gobErr.Error(), canaries...)
	}

	var nested bytes.Buffer
	if err := gob.NewEncoder(&nested).Encode(nestedElevationRequest{Request: request}); err == nil {
		t.Fatal("gob encoded a nested elevation request")
	}
	assertNoCanary(t, nested.String(), canaries...)

	for name, value := range map[string]any{
		"nested struct":  struct{ Ledger Ledger }{Ledger: ledger},
		"nested slice":   []Ledger{ledger},
		"nested pointer": struct{ Ledger *Ledger }{Ledger: &ledger},
	} {
		encoded, err := json.Marshal(value)
		if err == nil {
			t.Fatalf("json.Marshal(%s) unexpectedly succeeded: %s", name, encoded)
		}
		var output bytes.Buffer
		if err := gob.NewEncoder(&output).Encode(value); err == nil {
			t.Fatalf("gob.Encode(%s) unexpectedly succeeded", name)
		}
		assertNoCanary(t, string(encoded), canaries...)
		assertNoCanary(t, output.String(), canaries...)
	}
}

func TestZeroAndTypedNilLedgerSurfacesFailClosed(t *testing.T) {
	var zero Ledger
	if zero.String() != "elevation-ledger(invalid)" ||
		zero.GoString() != "elevation-ledger(invalid)" ||
		zero.LogValue().String() != "elevation-ledger(invalid)" {
		t.Fatal("zero Ledger diagnostics are not stable")
	}
	for _, format := range []string{"%s", "%q", "%v", "%+v", "%#v", "%x", "%X", "%d", "%o", "%f"} {
		formatted := fmt.Sprintf(format, zero)
		if strings.Contains(formatted, "state:") || strings.Contains(formatted, "state=") {
			t.Fatalf("format %q of zero Ledger reflected state: %q", format, formatted)
		}
	}

	var log bytes.Buffer
	slog.New(slog.NewTextHandler(&log, nil)).Info("zero ledger", "value", zero)
	if !strings.Contains(log.String(), "elevation-ledger(invalid)") {
		t.Fatalf("slog zero Ledger = %q", log.String())
	}
	for name, encode := range map[string]func() ([]byte, error){
		"json":   zero.MarshalJSON,
		"text":   zero.MarshalText,
		"binary": zero.MarshalBinary,
		"gob":    zero.GobEncode,
	} {
		encoded, err := encode()
		if !errors.Is(err, ErrSerializationForbidden) || len(encoded) != 0 {
			t.Fatalf("zero Ledger %s encoder = %q, %v", name, encoded, err)
		}
	}

	var ledger *Ledger
	// Generic formatting recovers a nil value-receiver invocation, while
	// encoding/json short-circuits a typed nil pointer to the safe null form.
	for _, format := range []string{"%v", "%+v", "%#v", "%x", "%X", "%p"} {
		_ = fmt.Sprintf(format, ledger)
	}
	log.Reset()
	slog.New(slog.NewTextHandler(&log, nil)).Info("typed nil ledger", "value", ledger)
	encoded, err := json.Marshal(ledger)
	if err != nil || string(encoded) != "null" {
		t.Fatalf("json.Marshal(typed nil Ledger) = %q, %v", encoded, err)
	}
}

func TestConstructionErrorsNeverReflectSensitiveInputs(t *testing.T) {
	principal := mustPrincipal(t, testIssuer, testSubject)
	administrator := mustAdministrator(t, testAdministratorID, principal)
	_, err := NewElevationRequest(
		testGrantID,
		administrator,
		principal,
		authorization.ActionAuditExport,
		ResolvePlatformAuditExportTarget(),
		" sensitive-reason-canary ",
		"case-reference-canary\n",
		testNow,
		time.Minute,
	)
	if err == nil {
		t.Fatal("invalid sensitive request unexpectedly succeeded")
	}
	assertNoCanary(
		t,
		err.Error(),
		testIssuer,
		testSubject,
		"sensitive-reason-canary",
		"case-reference-canary",
		testAdministratorID.String(),
		testGrantID.String(),
	)
}

func assertNoCanary(t testing.TB, value string, canaries ...string) {
	t.Helper()
	for _, canary := range canaries {
		if canary != "" && strings.Contains(value, canary) {
			t.Fatalf("value exposed canary %q: %q", canary, value)
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var (
	_ fmt.Formatter            = Administrator{}
	_ slog.LogValuer           = Administrator{}
	_ encoding.TextMarshaler   = Administrator{}
	_ encoding.BinaryMarshaler = Administrator{}
	_ gob.GobEncoder           = Administrator{}
	_ fmt.Formatter            = Ledger{}
	_ slog.LogValuer           = Ledger{}
	_ encoding.TextMarshaler   = Ledger{}
	_ encoding.BinaryMarshaler = Ledger{}
	_ gob.GobEncoder           = Ledger{}
)
