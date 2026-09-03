package ports

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func FuzzBearerCredentialIsBoundedAndNeverLeaks(f *testing.F) {
	f.Add(tokenCanary)
	f.Add("")
	f.Add("abc def")
	f.Add(strings.Repeat("a", MaxBearerTokenBytes))
	f.Add(strings.Repeat("a", MaxBearerTokenBytes+1))

	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > MaxBearerTokenBytes+1_024 {
			t.Skip()
		}
		credential, err := NewBearerCredential(token)
		if err == nil {
			if !credential.Valid() || credential.Token() != token ||
				len(credential.Token()) > MaxBearerTokenBytes {
				t.Fatal("constructed credential violated its invariant")
			}
		} else if credential.Valid() || credential.Token() != "" {
			t.Fatal("rejected credential retained state")
		}

		if credential.Error() != "bearer-credential(redacted)" ||
			credential.String() != "bearer-credential(redacted)" ||
			credential.GoString() != "bearer-credential(redacted)" ||
			fmt.Sprintf("%v", credential) != "bearer-credential(redacted)" ||
			fmt.Sprintf("%+v", credential) != "bearer-credential(redacted)" ||
			fmt.Sprintf("%#v", credential) != "bearer-credential(redacted)" {
			t.Fatal("credential diagnostic formatting was not the stable redaction")
		}
		encoded, marshalErr := json.Marshal(credential)
		if marshalErr == nil {
			t.Fatalf("json.Marshal(BearerCredential) = %q, want error", encoded)
		}
	})
}
