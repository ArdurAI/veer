// Package httptransport contains the untrusted HTTP boundary for Veer.
package httptransport

import (
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"

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
// Divergent populated URL and RequestURI query views and credential-capable
// Authorization/Cookie trailer declarations are likewise invalid.
//
// The function never parses the request body. Authorization is always removed;
// a rejected or divergent query view also clears cached Form/PostForm state, and
// rejected cookie or trailer carriers clear their request metadata surfaces.
// Trailer-capable bodies are guarded against values materialized at EOF even
// when no sensitive declaration is present. Callers must not forward request
// until this function returns, because removal is the credential redaction
// boundary for downstream HTTP handling. Invoke it on the original inbound
// request before Clone, WithContext, or retaining request/body aliases: Go's
// body reader owns that original request's trailer map.
func ExtractBearer(request *http.Request) (ports.BearerCredential, bool, error) {
	if request == nil {
		return ports.BearerCredential{}, false, ports.ErrAuthenticationInvalid
	}

	value, headerPresent, singleValue := takeAuthorization(request.Header)
	queryCarrier, queryMismatch := inspectQueryViews(request)
	cookieCarrier := hasAccessTokenCookie(request.Header)
	trailerCarrier := protectCredentialTrailers(request)
	if queryCarrier || queryMismatch {
		removeQuery(request)
	}
	if cookieCarrier {
		removeCookies(request.Header)
	}
	if queryCarrier || queryMismatch || cookieCarrier || trailerCarrier {
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
	clear(request.Form)
	clear(request.PostForm)
	// Keep both maps non-nil after clearing them in place. This removes values
	// from aliases to the request-owned maps and prevents a later ParseForm from
	// reparsing the rejected query or consuming the body.
	request.Form = make(url.Values)
	request.PostForm = make(url.Values)
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
				cookie = textproto.TrimString(cookie)
				name, _, _ := strings.Cut(cookie, "=")
				// net/http's cookie reader applies the same ASCII-space
				// normalization to a cookie name before matching it. Mirror
				// that boundary so alternate spelling cannot evade removal and
				// later reappear as an access_token cookie downstream.
				if textproto.TrimString(name) == accessTokenParameter {
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

func protectCredentialTrailers(request *http.Request) bool {
	rejected := hasCredentialTrailerDeclaration(request)
	if guarded, ok := request.Body.(*credentialTrailerBody); ok {
		return guarded.scrub(rejected)
	}
	if !rejected && !bodyMayMaterializeTrailers(request) {
		return false
	}

	if rejected {
		scrubCredentialTrailerSurfaces(request)
	}
	body := request.Body
	if body == nil {
		body = http.NoBody
	}
	request.Body = newCredentialTrailerBody(body, request, rejected)
	return rejected
}

func bodyMayMaterializeTrailers(request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return false
	}
	// Go's HTTP/2 server copies only predeclared terminal fields into the
	// handler's Request.Trailer. HTTP/1 chunked bodies are the exception: its
	// reader also copies undeclared terminal fields.
	if len(request.Trailer) > 0 {
		return true
	}
	for name := range request.Header {
		if asciiEqualFold(name, "Trailer") {
			return true
		}
	}
	for _, encoding := range request.TransferEncoding {
		if asciiEqualFold(encoding, "chunked") {
			return true
		}
	}
	return false
}

func hasCredentialTrailerDeclaration(request *http.Request) bool {
	for name := range request.Trailer {
		if isCredentialTrailerName(name) {
			return true
		}
	}
	for name, values := range request.Header {
		if !asciiEqualFold(name, "Trailer") {
			continue
		}
		for _, value := range values {
			if hasCredentialTrailerName(value) {
				return true
			}
		}
	}
	return false
}

func hasCredentialTrailerName(value string) bool {
	for name := range strings.SplitSeq(value, ",") {
		if isCredentialTrailerName(textproto.TrimString(name)) {
			return true
		}
	}
	return false
}

func isCredentialTrailerName(name string) bool {
	return asciiEqualFold(name, "Authorization") || asciiEqualFold(name, "Cookie")
}

func scrubCredentialTrailerSurfaces(request *http.Request) bool {
	fieldsRemoved := removeCredentialTrailerFields(request.Trailer)
	declarationsRemoved := removeCredentialTrailerDeclarations(request.Header)
	return fieldsRemoved || declarationsRemoved
}

func removeCredentialTrailerFields(trailer http.Header) bool {
	removed := false
	for name := range trailer {
		if isCredentialTrailerName(name) {
			delete(trailer, name)
			removed = true
		}
	}
	return removed
}

func removeCredentialTrailerDeclarations(header http.Header) bool {
	removedAny := false
	for name, values := range header {
		if !asciiEqualFold(name, "Trailer") {
			continue
		}

		filtered := values[:0]
		for index, value := range values {
			safe, removed := removeCredentialTrailerNames(value)
			removedAny = removedAny || removed
			values[index] = ""
			if !removed || safe != "" {
				filtered = append(filtered, safe)
			}
		}
		if len(filtered) == 0 {
			delete(header, name)
			continue
		}
		header[name] = filtered
	}
	return removedAny
}

func removeCredentialTrailerNames(value string) (string, bool) {
	if !hasCredentialTrailerName(value) {
		return value, false
	}

	var safe strings.Builder
	for name := range strings.SplitSeq(value, ",") {
		name = textproto.TrimString(name)
		if name == "" || isCredentialTrailerName(name) {
			continue
		}
		if safe.Len() > 0 {
			safe.WriteString(", ")
		}
		safe.WriteString(name)
	}
	return safe.String(), true
}

// credentialTrailerBody preserves Read and Close results while removing
// credential-capable trailer fields after a terminal Read or Close, the points
// where net/http can materialize them. Close still reaches the underlying body
// while a Read is in flight, then both calls serialize before returning.
type credentialTrailerBody struct {
	body     io.ReadCloser
	request  *http.Request
	rejected bool

	mu      sync.Mutex
	changed *sync.Cond
	reads   int
	closing bool
}

func newCredentialTrailerBody(body io.ReadCloser, request *http.Request, rejected bool) *credentialTrailerBody {
	guard := &credentialTrailerBody{body: body, request: request, rejected: rejected}
	guard.changed = sync.NewCond(&guard.mu)
	return guard
}

func (body *credentialTrailerBody) scrub(rejected bool) bool {
	body.mu.Lock()
	body.scrubLocked(rejected)
	rejected = body.rejected
	body.mu.Unlock()
	return rejected
}

func (body *credentialTrailerBody) scrubLocked(rejected bool) {
	observed := scrubCredentialTrailerSurfaces(body.request)
	body.rejected = body.rejected || rejected || observed
}

func (body *credentialTrailerBody) Read(target []byte) (int, error) {
	body.mu.Lock()
	for body.closing {
		body.changed.Wait()
	}
	body.reads++
	body.mu.Unlock()

	read, err := body.body.Read(target)

	body.mu.Lock()
	body.reads--
	body.changed.Broadcast()
	for body.closing {
		body.changed.Wait()
	}
	if err != nil {
		body.scrubLocked(false)
	}
	body.mu.Unlock()
	return read, err
}

func (body *credentialTrailerBody) Close() error {
	body.mu.Lock()
	for body.closing {
		body.changed.Wait()
	}
	body.closing = true
	body.mu.Unlock()

	err := body.body.Close()

	body.mu.Lock()
	for body.reads > 0 {
		body.changed.Wait()
	}
	body.scrubLocked(false)
	body.closing = false
	body.changed.Broadcast()
	body.mu.Unlock()
	return err
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
