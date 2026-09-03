package oidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/ports"
)

const (
	maxProtectedHeaderBytes = 8 * 1024
	maxClaimsBytes          = 48 * 1024
	maxSignatureBytes       = 1024
	maxJSONDepth            = 16
	maxJSONObjectMembers    = 256
	maxJSONArrayElements    = 512
)

type inspectedToken struct {
	header  protectedHeader
	payload []byte
}

type protectedHeader struct {
	algorithm string
	keyID     string
	typeName  string
}

func inspectCompactToken(compact string) (inspectedToken, bool) {
	if compact == "" || len(compact) > ports.MaxBearerTokenBytes || strings.Count(compact, ".") != 2 {
		return inspectedToken{}, false
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return inspectedToken{}, false
	}
	headerBytes, ok := decodeCanonicalSegment(parts[0], maxProtectedHeaderBytes)
	if !ok {
		return inspectedToken{}, false
	}
	payload, ok := decodeCanonicalSegment(parts[1], maxClaimsBytes)
	if !ok {
		return inspectedToken{}, false
	}
	if _, ok := decodeCanonicalSegment(parts[2], maxSignatureBytes); !ok {
		return inspectedToken{}, false
	}
	if !validateJSONObject(headerBytes) || !validateJSONObject(payload) {
		return inspectedToken{}, false
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &members); err != nil {
		return inspectedToken{}, false
	}
	for _, forbidden := range []string{"jku", "jwk", "x5u", "x5c", "crit", "b64"} {
		if _, present := members[forbidden]; present {
			return inspectedToken{}, false
		}
	}
	algorithm, ok := requiredJSONString(members, "alg")
	if !ok {
		return inspectedToken{}, false
	}
	keyID, ok := requiredJSONString(members, "kid")
	if !ok {
		return inspectedToken{}, false
	}
	typeName, ok := requiredJSONString(members, "typ")
	if !ok {
		return inspectedToken{}, false
	}
	return inspectedToken{
		header: protectedHeader{
			algorithm: algorithm,
			keyID:     keyID,
			typeName:  typeName,
		},
		payload: payload,
	}, true
}

func decodeCanonicalSegment(encoded string, maximumDecodedBytes int) ([]byte, bool) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maximumDecodedBytes) {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > maximumDecodedBytes {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, false
	}
	return decoded, true
}

func requiredJSONString(members map[string]json.RawMessage, name string) (string, bool) {
	raw, present := members[name]
	if !present {
		return "", false
	}
	var result string
	if err := json.Unmarshal(raw, &result); err != nil || result == "" {
		return "", false
	}
	return result, true
}

func validateJSONObject(document []byte) bool {
	if !utf8.Valid(document) || !jsontext.Value(document).IsValid() {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	if !scanJSONObject(decoder, 1) {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func scanJSONObject(decoder *json.Decoder, depth int) bool {
	if depth > maxJSONDepth {
		return false
	}
	seen := make(map[string]struct{})
	count := 0
	for decoder.More() {
		name, err := decoder.Token()
		if err != nil {
			return false
		}
		memberName, ok := name.(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[memberName]; duplicate {
			return false
		}
		seen[memberName] = struct{}{}
		count++
		if count > maxJSONObjectMembers || !scanJSONValue(decoder, depth) {
			return false
		}
	}
	closing, err := decoder.Token()
	return err == nil && closing == json.Delim('}')
}

func scanJSONArray(decoder *json.Decoder, depth int) bool {
	if depth > maxJSONDepth {
		return false
	}
	count := 0
	for decoder.More() {
		count++
		if count > maxJSONArrayElements || !scanJSONValue(decoder, depth) {
			return false
		}
	}
	closing, err := decoder.Token()
	return err == nil && closing == json.Delim(']')
}

func scanJSONValue(decoder *json.Decoder, parentDepth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		return scanJSONObject(decoder, parentDepth+1)
	case '[':
		return scanJSONArray(decoder, parentDepth+1)
	default:
		return false
	}
}
