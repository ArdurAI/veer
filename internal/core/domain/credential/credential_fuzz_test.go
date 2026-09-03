package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func FuzzSourceMaterialSafety(f *testing.F) {
	f.Add([]byte{1})
	f.Add(credentialBytes(31))
	f.Add(credentialBytes(MaxSourceMaterialBytes))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > MaxSourceMaterialBytes {
			if _, err := NewSourceMaterial(input); !errors.Is(err, ErrInvalidMaterial) {
				t.Fatalf("NewSourceMaterial(%d bytes) error = %v", len(input), err)
			}
			return
		}
		material, err := NewSourceMaterial(input)
		if err != nil {
			t.Fatal(err)
		}
		var borrowed []byte
		if err := material.WithBytes(func(value []byte) error {
			borrowed = value
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !allZero(borrowed) {
			t.Fatal("callback scratch was not cleared")
		}
		if _, err := json.Marshal(material); !errors.Is(err, ErrSerializationForbidden) {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		_ = fmt.Sprintf("%#v", material)
		material.Destroy()
	})
}

func FuzzRequestRejectsTampering(f *testing.F) {
	fixture := newCredentialFixture(f)
	f.Add(uint8(0))
	f.Add(uint8(13))
	f.Fuzz(func(t *testing.T, selector uint8) {
		request := fixture.request
		switch selector % 14 {
		case 0:
			request.initialized = false
		case 1:
			request.workspaceID = testEnvironmentA
		case 2:
			request.environmentID = testWorkspaceID
		case 3:
			request.providerConnectionID = testConnectionB
		case 4:
			request.connectionGeneration++
		case 5:
			request.operationID = testConnectionB
		case 6:
			request.targetResourceID = testApplicationA
		case 7:
			request.targetGeneration++
		case 8:
			request.provider = "kubernetes"
		case 9:
			request.recipient.name = "different-adapter"
		case 10:
			request.source.referenceID = testConnectionB
		case 11:
			request.source.version = "version_2"
		case 12:
			request.source.digest = SourceDigest{}
		case 13:
			request.binding = BindingDigest{}
		}
		if err := ValidateRequest(request); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ValidateRequest(tampered %d) error = %v", selector, err)
		}
	})
}

func FuzzIssuedSessionLifetime(f *testing.F) {
	fixture := newCredentialFixture(f)
	f.Add(int64(MinIssuedSessionTTL / time.Second))
	f.Add(int64(MaxIssuedSessionTTL / time.Second))
	f.Add(int64(MinIssuedSessionTTL/time.Second - 1))
	f.Add(int64(MaxIssuedSessionTTL/time.Second + 1))
	f.Fuzz(func(t *testing.T, seconds int64) {
		if seconds < -60 || seconds > 1_000_000 {
			return
		}
		material, err := NewSessionMaterial(credentialBytes(32))
		if err != nil {
			t.Fatal(err)
		}
		session, issueErr := NewIssuedSession(
			fixture.request,
			material,
			testNow,
			testNow.Add(time.Duration(seconds)*time.Second),
		)
		wantValid := seconds >= int64(MinIssuedSessionTTL/time.Second) &&
			seconds <= int64(MaxIssuedSessionTTL/time.Second)
		if wantValid {
			if issueErr != nil || session == nil || !session.Valid() {
				t.Fatalf("valid duration %d rejected: %v", seconds, issueErr)
			}
			session.Destroy()
			return
		}
		if !errors.Is(issueErr, ErrInvalidSessionLifetime) || session != nil {
			t.Fatalf("invalid duration %d accepted: %v, %v", seconds, session, issueErr)
		}
	})
}
