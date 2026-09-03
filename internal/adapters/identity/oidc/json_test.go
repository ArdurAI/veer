package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestValidateJSONObjectRejectsAmbiguousOrInvalidUnicode(t *testing.T) {
	tests := []struct {
		name     string
		document string
	}{
		{name: "duplicate", document: `{"value":1,"value":2}`},
		{name: "lone high surrogate", document: `{"value":"\ud800"}`},
		{name: "lone low surrogate", document: `{"value":"\udc00"}`},
		{name: "invalid UTF-8", document: string([]byte{'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'})},
		{name: "trailing value", document: `{"value":1}{}`},
		{name: "non-object", document: `[]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if validateJSONObject([]byte(test.document)) {
				t.Fatal("validateJSONObject accepted invalid input")
			}
		})
	}
	if !validateJSONObject([]byte(`{"value":"\ud83d\ude80","nested":{"ok":true}}`)) {
		t.Fatal("validateJSONObject rejected a valid surrogate pair")
	}
}

func TestInspectCompactTokenRejectsNonCanonicalOrOverBoundSegments(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"key","typ":"at+jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://issuer.example"}`))
	tests := []string{
		header + "." + payload + ".",
		"=" + header + "." + payload + ".AQ",
		header + "." + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxClaimsBytes)+1) + ".AQ",
		header + "." + payload + "." + strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxSignatureBytes)+1),
	}
	for _, token := range tests {
		if _, ok := inspectCompactToken(token); ok {
			t.Fatal("inspectCompactToken accepted an invalid segment envelope")
		}
	}
}

func FuzzInspectCompactToken(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add(rawCompact(
		[]byte(`{"alg":"ES256","kid":"key","typ":"at+jwt"}`),
		[]byte(`{"iss":"https://issuer.example","sub":"subject"}`),
		[]byte{1, 2, 3},
	))
	f.Fuzz(func(t *testing.T, compact string) {
		inspected, ok := inspectCompactToken(compact)
		if !ok {
			return
		}
		if inspected.header.algorithm == "" || inspected.header.keyID == "" ||
			inspected.header.typeName == "" || !validateJSONObject(inspected.payload) {
			t.Fatal("accepted compact token violated inspection postconditions")
		}
	})
}
