// Package httptransport contains the untrusted HTTP boundary for Veer.
package httptransport

import (
	"net/http"
	"strings"

	"github.com/ArdurAI/veer/internal/core/ports"
)

const (
	// MaxBearerTokenBytes is the largest encoded bearer token accepted at the
	// HTTP boundary. The verifier applies separate structural and claim bounds.
	MaxBearerTokenBytes = ports.MaxBearerTokenBytes

	// MaxAuthorizationHeaderBytes admits a maximum-sized token in the shortest
	// RFC 6750 header form. Additional separator spaces consume this same bound.
	MaxAuthorizationHeaderBytes = len("Bearer ") + MaxBearerTokenBytes
)

const accessTokenParameter = "access_token"

// ExtractBearer removes the Authorization field from request and extracts one
// RFC 6750 bearer credential. A missing field returns the zero credential,
// false, and nil; it represents a request with no principal. A malformed field
// or an access_token query/cookie carrier returns ErrAuthenticationInvalid.
// Divergent populated URL and RequestURI query views are likewise invalid.
//
// The function never parses the request body. Authorization is always removed;
// a rejected or divergent query view or rejected cookie carrier also clears
// its complete request metadata surface. Callers must not forward request until
// this function returns, because removal is the credential redaction boundary
// for downstream HTTP handling.
func ExtractBearer(request *http.Request) (ports.BearerCredential, bool, error) {
	if request == nil {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}

	value, headerPresent, singleValue := takeAuthorization(request.Header)
	queryCarrier, queryMismatch := inspectQueryViews(request)
	cookieCarrier := hasAccessTokenCookie(request.Header)
	if queryCarrier || queryMismatch {
		removeQuery(request)
	}
	if cookieCarrier {
		removeCookies(request.Header)
	}
	if queryCarrier || queryMismatch || cookieCarrier {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}
	if !headerPresent {
		return ports.BearerCredential{}, false, nil
	}
	if !singleValue {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}

	token, ok := parseBearer(value)
	if !ok {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}

	credential, err := ports.NewBearerCredential(token)
	if err != nil {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}
	return credential, true, nil
}

// takeAuthorization copies only the one candidate value needed for parsing and
// deletes every case variant before reporting validity. Incoming net/http
// requests use canonical keys, but checking all keys keeps manually assembled
// and middleware-modified requests inside the same fail-closed boundary.
func takeAuthorization(header http.Header) (value string, present, single bool) {
	keyCount := 0
	valueCount := 0
	for name, values := range header {
		if !asciiEqualFold(name, "Authorization") {
			continue
		}
		keyCount++
		if valueCount == 0 && len(values) > 0 {
			value = values[0]
		}
		if len(values) > 1 || valueCount > 0 && len(values) > 0 {
			valueCount = 2
		} else {
			valueCount += len(values)
		}
		delete(header, name)
	}
	return value, keyCount > 0, keyCount == 1 && valueCount == 1
}

func parseBearer(value string) (string, bool) {
	if len(value) > MaxAuthorizationHeaderBytes || len(value) < len("Bearer 0") {
		return "", false
	}
	if !asciiEqualFold(value[:len("Bearer")], "Bearer") || value[len("Bearer")] != ' ' {
		return "", false
	}

	tokenStart := len("Bearer") + 1
	for tokenStart < len(value) && value[tokenStart] == ' ' {
		tokenStart++
	}
	if tokenStart == len(value) || len(value)-tokenStart > MaxBearerTokenBytes {
		return "", false
	}
	return value[tokenStart:], true
}

func inspectQueryViews(request *http.Request) (carrier, mismatch bool) {
	var urlQuery string
	var urlHasQuery bool
	if request.URL != nil {
		urlQuery = request.URL.RawQuery
		urlHasQuery = urlQuery != "" || request.URL.ForceQuery
		carrier = hasAccessTokenQuery(urlQuery)
	}

	requestQuery, requestHasQuery := splitRequestURIQuery(request.RequestURI)
	requestCarrier := hasAccessTokenQuery(requestQuery)
	carrier = carrier || requestCarrier
	if request.URL != nil && request.RequestURI != "" &&
		(urlHasQuery != requestHasQuery || urlHasQuery && urlQuery != requestQuery) {
		mismatch = true
	}
	return carrier, mismatch
}

func splitRequestURIQuery(requestURI string) (string, bool) {
	queryStart := strings.IndexByte(requestURI, '?')
	if queryStart < 0 {
		return "", false
	}
	return requestURI[queryStart+1:], true
}

// hasAccessTokenQuery inspects an already-materialized query without parsing
// or copying attacker-controlled values. Work is linear in that existing
// string, and each field and encoded name byte is examined a bounded number of
// times.
func hasAccessTokenQuery(raw string) bool {
	for len(raw) > 0 {
		end := strings.IndexAny(raw, "&;")
		var field string
		if end < 0 {
			field = raw
			raw = ""
		} else {
			field = raw[:end]
			raw = raw[end+1:]
		}
		if equals := strings.IndexByte(field, '='); equals >= 0 {
			field = field[:equals]
		}
		if queryNameEquals(field, accessTokenParameter) {
			return true
		}
	}
	return false
}

// removeQuery drops the complete query rather than attempting to preserve
// selected fields around a rejected credential. The request is already
// invalid, and preserving a partial request target would risk forwarding or
// logging a second copy from RequestURI.
func removeQuery(request *http.Request) {
	if request.URL != nil {
		request.URL.RawQuery = ""
		request.URL.ForceQuery = false
	}
	if queryStart := strings.IndexByte(request.RequestURI, '?'); queryStart >= 0 {
		request.RequestURI = request.RequestURI[:queryStart]
	}
}

// queryNameEquals performs only the application/x-www-form-urlencoded name
// decoding needed to recognize access_token. It does not allocate, copy the
// value, or parse unrelated parameters.
func queryNameEquals(encoded, expected string) bool {
	expectedIndex := 0
	for index := 0; index < len(encoded); index++ {
		current := encoded[index]
		switch current {
		case '+':
			current = ' '
		case '%':
			if index+2 >= len(encoded) {
				return false
			}
			high, highOK := hexValue(encoded[index+1])
			low, lowOK := hexValue(encoded[index+2])
			if !highOK || !lowOK {
				return false
			}
			current = high<<4 | low
			index += 2
		}
		if expectedIndex == len(expected) || current != expected[expectedIndex] {
			return false
		}
		expectedIndex++
	}
	return expectedIndex == len(expected)
}

func hexValue(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func hasAccessTokenCookie(header http.Header) bool {
	for name, values := range header {
		if !asciiEqualFold(name, "Cookie") {
			continue
		}
		for _, value := range values {
			for len(value) > 0 {
				end := strings.IndexByte(value, ';')
				var cookie string
				if end < 0 {
					cookie = value
					value = ""
				} else {
					cookie = value[:end]
					value = value[end+1:]
				}
				cookie = strings.Trim(cookie, " \t")
				if equals := strings.IndexByte(cookie, '='); equals >= 0 &&
					cookie[:equals] == accessTokenParameter {
					return true
				}
			}
		}
	}
	return false
}

func removeCookies(header http.Header) {
	for name := range header {
		if asciiEqualFold(name, "Cookie") {
			delete(header, name)
		}
	}
}

func asciiEqualFold(value, expected string) bool {
	if len(value) != len(expected) {
		return false
	}
	for index := 0; index < len(value); index++ {
		left := value[index]
		right := expected[index]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}
