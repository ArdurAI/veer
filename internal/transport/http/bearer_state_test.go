package httptransport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArdurAI/veer/internal/core/ports"
)

func TestRejectedQueryClearsParsedFormsWithoutReadingBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization []string
		urlQuery      string
		requestQuery  string
	}{
		{
			name:         "carrier without Authorization",
			urlQuery:     "page=1&access_token=" + bearerCanary,
			requestQuery: "page=1&access_token=" + bearerCanary,
		},
		{
			name:          "encoded carrier with valid Authorization",
			authorization: []string{"Bearer " + bearerCanary},
			urlQuery:      "page=1&%61ccess%5Ftoken=" + bearerCanary,
			requestQuery:  "page=1&%61ccess%5Ftoken=" + bearerCanary,
		},
		{
			name:          "mismatch with malformed Authorization",
			authorization: []string{"Bearer " + bearerCanary + "!"},
			urlQuery:      "page=1",
			requestQuery:  "page=2",
		},
		{
			name:          "mismatch with duplicate Authorization",
			authorization: []string{"Bearer " + bearerCanary, "Bearer duplicate"},
			urlQuery:      "page=1",
			requestQuery:  "trace=2",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body := &trackedReadCloser{body: io.NopCloser(strings.NewReader("unrelated=body"))}
			form := url.Values{
				accessTokenParameter: {bearerCanary},
				"page":               {"1"},
			}
			postForm := url.Values{
				accessTokenParameter: {bearerCanary},
				"unrelated":          {"body"},
			}
			request := &http.Request{
				Method:     http.MethodPost,
				Header:     header("Content-Type", "application/x-www-form-urlencoded"),
				URL:        &url.URL{Path: "/v1/resources", RawQuery: test.urlQuery},
				RequestURI: "/v1/resources?" + test.requestQuery,
				Body:       body,
				Form:       form,
				PostForm:   postForm,
			}
			if test.authorization != nil {
				request.Header["Authorization"] = append([]string(nil), test.authorization...)
			}

			credential, present, err := ExtractBearer(request)
			if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
				t.Fatal("rejected query did not fail closed")
			}
			if body.reads != 0 || body.closes != 0 || request.Body != body {
				t.Fatal("query scrubbing consumed or replaced the request body")
			}
			if request.Form == nil || request.PostForm == nil || len(request.Form) != 0 || len(request.PostForm) != 0 {
				t.Fatal("request form caches were not replaced with non-nil empty maps")
			}
			if len(form) != 0 || len(postForm) != 0 {
				t.Fatal("aliases to request form caches retained rejected values")
			}
			if err := request.ParseForm(); err != nil {
				t.Fatal("ParseForm failed after the rejected form cache was sealed")
			}
			if body.reads != 0 || len(request.Form) != 0 || len(request.PostForm) != 0 {
				t.Fatal("ParseForm reparsed a rejected request")
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", request.Form, request.PostForm, request), bearerCanary) {
				t.Fatal("rejected query credential survived in parsed request state")
			}
		})
	}
}

func TestCredentialTrailerDeclarationsFailClosedAndScrubImmediately(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization []string
		header        http.Header
		trailer       http.Header
	}{
		{
			name:          "map Authorization with valid header",
			authorization: []string{"Bearer " + bearerCanary},
			trailer: http.Header{
				"Authorization": {"Bearer " + bearerCanary},
				"X-Veer-Safe":   {"retained"},
			},
		},
		{
			name: "map Cookie case variant without header",
			trailer: http.Header{
				"cOoKiE":      {"access_token =" + bearerCanary},
				"X-Veer-Safe": {"retained"},
			},
		},
		{
			name:          "raw declaration case variants with malformed header",
			authorization: []string{"Bearer " + bearerCanary + "!"},
			header: http.Header{
				"tRaIlEr": {"X-Veer-Safe, aUtHoRiZaTiOn"},
			},
			trailer: http.Header{"X-Veer-Safe": {"retained"}},
		},
		{
			name:          "duplicate declaration values with duplicate header",
			authorization: []string{"Bearer " + bearerCanary, "Bearer duplicate"},
			header: http.Header{
				"Trailer": {"X-Veer-Safe", "COOKIE"},
			},
			trailer: http.Header{"X-Veer-Safe": {"retained"}},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body := &trackedReadCloser{body: io.NopCloser(strings.NewReader("body-remains-readable"))}
			request := &http.Request{
				Header:  test.header.Clone(),
				Trailer: test.trailer.Clone(),
				URL:     &url.URL{},
				Body:    body,
			}
			if request.Header == nil {
				request.Header = make(http.Header)
			}
			if test.authorization != nil {
				request.Header["Authorization"] = append([]string(nil), test.authorization...)
			}

			credential, present, err := ExtractBearer(request)
			if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
				t.Fatal("credential trailer declaration did not fail closed")
			}
			if body.reads != 0 || body.closes != 0 {
				t.Fatal("trailer inspection consumed or closed the request body")
			}
			if request.Body == body {
				t.Fatal("rejected trailer body was not guarded")
			}
			assertCredentialTrailerSurfacesRemoved(t, request)
			if request.Trailer.Get("X-Veer-Safe") != "retained" {
				t.Fatal("unrelated trailer field was discarded")
			}

			guardedBody := request.Body
			credential, present, err = ExtractBearer(request)
			if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
				t.Fatal("repeated extraction forgot the rejected trailer declaration")
			}
			if request.Body != guardedBody {
				t.Fatal("repeated extraction nested the body guard")
			}

			content, err := io.ReadAll(request.Body)
			if err != nil || string(content) != "body-remains-readable" {
				t.Fatal("guarded body did not preserve Read semantics")
			}
			assertCredentialTrailerSurfacesRemoved(t, request)
			if strings.Contains(fmt.Sprintf("%v %+v %#v", request.Header, request.Trailer, request), bearerCanary) {
				t.Fatal("credential trailer survived request formatting")
			}
		})
	}
}

func TestUnrelatedTrailerAndBodySemanticsArePreserved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization []string
		wantInvalid   bool
		wantPresent   bool
	}{
		{name: "missing Authorization"},
		{name: "valid Authorization", authorization: []string{"Bearer " + bearerCanary}, wantPresent: true},
		{name: "malformed Authorization", authorization: []string{"Bearer invalid token"}, wantInvalid: true},
		{name: "duplicate Authorization", authorization: []string{"Bearer " + bearerCanary, "Bearer duplicate"}, wantInvalid: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body := &trackedReadCloser{body: io.NopCloser(strings.NewReader("safe-body"))}
			request := &http.Request{
				Header: http.Header{
					"Trailer": {"X-Veer-Safe, X-Trace"},
				},
				Trailer: http.Header{
					"X-Veer-Safe": {"retained"},
					"X-Trace":     {"retained-too"},
				},
				URL:      &url.URL{},
				Body:     body,
				Form:     url.Values{"page": {"1"}},
				PostForm: url.Values{"unrelated": {"body"}},
			}
			if test.authorization != nil {
				request.Header["Authorization"] = append([]string(nil), test.authorization...)
			}

			credential, present, err := ExtractBearer(request)
			if test.wantInvalid {
				if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
					t.Fatal("Authorization-only rejection returned the wrong result")
				}
			} else if err != nil || present != test.wantPresent || credential.Valid() != test.wantPresent {
				t.Fatal("safe trailer request returned the wrong extraction result")
			}
			if request.Body == body || body.reads != 0 || body.closes != 0 {
				t.Fatal("body with trailer metadata was not guarded without being consumed")
			}
			if request.Header.Get("Trailer") != "X-Veer-Safe, X-Trace" ||
				request.Trailer.Get("X-Veer-Safe") != "retained" ||
				request.Trailer.Get("X-Trace") != "retained-too" {
				t.Fatal("unrelated trailers were changed")
			}
			if request.Form.Get("page") != "1" || request.PostForm.Get("unrelated") != "body" {
				t.Fatal("unrelated parsed form state was changed")
			}
		})
	}
}

func TestChunkedCredentialTrailersCannotRepopulateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		trailerName   string
		trailerValue  string
		authorization []string
		closeBody     bool
		wantInvalid   bool
		wantPresent   bool
		wantGuarded   bool
	}{
		{
			name:         "Authorization trailer after EOF",
			trailerName:  "Authorization",
			trailerValue: "Bearer " + bearerCanary,
			wantInvalid:  true,
			wantGuarded:  true,
		},
		{
			name:          "Cookie trailer after EOF with valid header",
			trailerName:   "Cookie",
			trailerValue:  "access_token =" + bearerCanary,
			authorization: []string{"Bearer " + bearerCanary},
			wantInvalid:   true,
			wantGuarded:   true,
		},
		{
			name:         "Authorization trailer populated by Close",
			trailerName:  "Authorization",
			trailerValue: "Bearer " + bearerCanary,
			closeBody:    true,
			wantInvalid:  true,
			wantGuarded:  true,
		},
		{
			name:          "Cookie trailer populated by Close with malformed header",
			trailerName:   "Cookie",
			trailerValue:  "access_token=" + bearerCanary,
			authorization: []string{"Bearer invalid token"},
			closeBody:     true,
			wantInvalid:   true,
			wantGuarded:   true,
		},
		{
			name:          "unrelated trailer with valid header",
			trailerName:   "X-Trace",
			trailerValue:  "safe-trace",
			authorization: []string{"Bearer " + bearerCanary},
			wantPresent:   true,
			wantGuarded:   true,
		},
		{
			name:          "unrelated trailer with duplicate header",
			trailerName:   "X-Trace",
			trailerValue:  "safe-trace",
			authorization: []string{"Bearer " + bearerCanary, "Bearer duplicate"},
			wantInvalid:   true,
			wantGuarded:   true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			results := make(chan chunkedTrailerResult, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				tracked := &trackedReadCloser{body: request.Body}
				request.Body = tracked
				originalBody := request.Body

				credential, present, extractErr := ExtractBearer(request)
				result := chunkedTrailerResult{
					invalid:       errors.Is(extractErr, ports.ErrAuthenticationInvalid),
					present:       present,
					valid:         credential.Valid(),
					readAtExtract: tracked.reads,
					guarded:       request.Body != originalBody,
				}
				if test.closeBody {
					result.bodyErr = request.Body.Close()
				} else {
					result.body, result.bodyErr = io.ReadAll(request.Body)
				}
				result.safeTrailer = request.Trailer.Get("X-Veer-Safe")
				result.credentialTrailerPresent = request.Trailer.Get("Authorization") != "" ||
					request.Trailer.Get("Cookie") != ""
				result.canaryPresent = strings.Contains(fmt.Sprintf("%v %+v %#v", request.Header, request.Trailer, request), bearerCanary)
				results <- result
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("chunked-body"))
			if err != nil {
				t.Fatal("could not construct chunked test request")
			}
			request.ContentLength = -1
			request.Trailer = http.Header{
				test.trailerName: {test.trailerValue},
				"X-Veer-Safe":    {"safe-trailer"},
			}
			if test.authorization != nil {
				request.Header["Authorization"] = append([]string(nil), test.authorization...)
			}

			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal("chunked trailer request failed")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal("close chunked trailer response body")
			}
			result := <-results

			if result.invalid != test.wantInvalid || result.present != test.wantPresent || result.valid != test.wantPresent {
				t.Fatal("chunked trailer extraction returned the wrong result")
			}
			if result.readAtExtract != 0 {
				t.Fatal("ExtractBearer read the chunked request body")
			}
			if result.guarded != test.wantGuarded {
				t.Fatal("chunked request body guard state was wrong")
			}
			if test.closeBody {
				if !errors.Is(result.bodyErr, io.EOF) {
					t.Fatal("guard changed the net/http chunked Close result")
				}
			} else {
				if result.bodyErr != nil || string(result.body) != "chunked-body" {
					t.Fatal("guard changed the chunked body Read result")
				}
			}
			if result.safeTrailer != "safe-trailer" {
				t.Fatal("unrelated chunked trailer was not preserved")
			}
			if result.credentialTrailerPresent || result.canaryPresent {
				t.Fatal("chunked credential trailer repopulated request state")
			}
		})
	}
}

func TestUndeclaredChunkedCredentialTrailersCannotRepopulateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		declaration   string
		terminal      string
		authorization string
		closeBody     bool
		wantPresent   bool
		wantSafe      string
		wantSticky    bool
	}{
		{
			name:       "undeclared Authorization after EOF",
			terminal:   "aUtHoRiZaTiOn: Bearer " + bearerCanary + "\r\n",
			wantSticky: true,
		},
		{
			name:          "safe declaration and undeclared Cookie after EOF",
			declaration:   "Trailer: X-Veer-Safe\r\n",
			terminal:      "X-Veer-Safe: retained\r\nCookie: access_token=" + bearerCanary + "\r\n",
			authorization: "Authorization: Bearer " + bearerCanary + "\r\n",
			wantPresent:   true,
			wantSafe:      "retained",
			wantSticky:    true,
		},
		{
			name:       "undeclared Cookie populated by Close",
			terminal:   "cOoKiE: access_token=" + bearerCanary + "\r\n",
			closeBody:  true,
			wantSticky: true,
		},
		{
			name:        "undeclared unrelated trailer remains available",
			terminal:    "X-Veer-Safe: retained\r\n",
			wantSafe:    "retained",
			wantPresent: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			results := make(chan chunkedTrailerResult, 1)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				originalBody := request.Body
				credential, present, extractErr := ExtractBearer(request)
				result := chunkedTrailerResult{
					invalid: errors.Is(extractErr, ports.ErrAuthenticationInvalid),
					present: present,
					valid:   credential.Valid(),
					guarded: request.Body != originalBody,
				}
				if test.closeBody {
					result.bodyErr = request.Body.Close()
				} else {
					result.body, result.bodyErr = io.ReadAll(request.Body)
				}
				result.safeTrailer = request.Trailer.Get("X-Veer-Safe")
				result.credentialTrailerPresent = request.Trailer.Get("Authorization") != "" ||
					request.Trailer.Get("Cookie") != ""
				result.canaryPresent = strings.Contains(fmt.Sprintf("%v %+v %#v", request.Header, request.Trailer, request), bearerCanary)
				repeatCredential, repeatPresent, repeatErr := ExtractBearer(request)
				result.repeatInvalid = errors.Is(repeatErr, ports.ErrAuthenticationInvalid)
				result.repeatEmpty = !repeatPresent && !repeatCredential.Valid()
				results <- result
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()

			connection, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal("could not connect to chunked test server")
			}
			t.Cleanup(func() {
				if err := connection.Close(); err != nil {
					t.Error("could not close chunked test connection")
				}
			})
			wireRequest := "POST / HTTP/1.1\r\nHost: " + server.Listener.Addr().String() + "\r\n" +
				"Transfer-Encoding: chunked\r\n" + test.declaration + test.authorization + "\r\n" +
				"c\r\nchunked-body\r\n0\r\n" + test.terminal + "\r\n"
			if _, err := io.WriteString(connection, wireRequest); err != nil {
				t.Fatal("could not write raw chunked request")
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal("could not read chunked test response")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal("could not close chunked test response body")
			}
			result := <-results

			if result.invalid || result.present != test.wantPresent || result.valid != test.wantPresent {
				t.Fatal("undeclared terminal trailer changed extraction result")
			}
			if !result.guarded {
				t.Fatal("chunked request without a sensitive declaration was not guarded")
			}
			if test.closeBody {
				if !errors.Is(result.bodyErr, io.EOF) {
					t.Fatal("guard changed the chunked Close result")
				}
			} else if result.bodyErr != nil || string(result.body) != "chunked-body" {
				t.Fatal("guard changed the chunked Read result")
			}
			if result.safeTrailer != test.wantSafe {
				t.Fatal("guard changed an unrelated terminal trailer")
			}
			if result.credentialTrailerPresent || result.canaryPresent {
				t.Fatal("undeclared credential trailer repopulated request state")
			}
			if result.repeatInvalid != test.wantSticky || !result.repeatEmpty {
				t.Fatal("post-consumption extraction did not preserve the trailer guard state")
			}
		})
	}
}

func TestTrailerCapableBodyGuardKeepsReadConcurrentWithClose(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close sentinel")
	underlying := &blockingTrailerBody{
		started:  make(chan struct{}),
		released: make(chan struct{}),
		closeErr: closeErr,
	}
	request := &http.Request{
		Header:           make(http.Header),
		Trailer:          http.Header{"X-Veer-Safe": {"retained"}},
		TransferEncoding: []string{"chunked"},
		URL:              &url.URL{},
		Body:             underlying,
	}
	underlying.request = request

	credential, present, err := ExtractBearer(request)
	if err != nil || present || credential.Valid() {
		t.Fatal("safe trailer-capable request did not remain anonymous")
	}
	guardedBody := request.Body

	readResult := make(chan error, 1)
	go func() {
		_, readErr := request.Body.Read(make([]byte, 1))
		readResult <- readErr
	}()
	select {
	case <-underlying.started:
	case <-time.After(2 * time.Second):
		t.Fatal("guarded Read did not reach the underlying body")
	}

	if err := request.Body.Close(); !errors.Is(err, closeErr) {
		t.Fatal("guard did not preserve the concurrent Close result")
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, io.EOF) {
			t.Fatal("guard did not preserve the concurrent Read result")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the guarded Read")
	}

	assertCredentialTrailerSurfacesRemoved(t, request)
	if request.Trailer.Get("X-Veer-Safe") != "retained" {
		t.Fatal("concurrent trailer scrubbing removed an unrelated field")
	}
	credential, present, err = ExtractBearer(request)
	if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() || request.Body != guardedBody {
		t.Fatal("observed credential trailer did not latch a sticky rejection")
	}
}

func TestTrailerGuardScrubsDataWithEOF(t *testing.T) {
	t.Parallel()

	underlying := &dataEOFWithTrailerBody{}
	request := &http.Request{
		Header:           make(http.Header),
		Trailer:          make(http.Header),
		TransferEncoding: []string{"chunked"},
		URL:              &url.URL{},
		Body:             underlying,
	}
	underlying.request = request

	credential, present, err := ExtractBearer(request)
	if err != nil || present || credential.Valid() {
		t.Fatal("safe chunked request did not remain anonymous")
	}
	target := make([]byte, 1)
	read, err := request.Body.Read(target)
	if read != 1 || target[0] != 'x' || !errors.Is(err, io.EOF) {
		t.Fatal("guard changed a Read returning data with EOF")
	}
	assertCredentialTrailerSurfacesRemoved(t, request)
	credential, present, err = ExtractBearer(request)
	if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
		t.Fatal("credential observed with data and EOF did not latch rejection")
	}
}

func TestHigherProtocolBodiesWithoutTrailerMetadataRemainUnwrapped(t *testing.T) {
	t.Parallel()

	for _, protocolMajor := range []int{2, 3} {
		protocolMajor := protocolMajor
		t.Run(fmt.Sprintf("HTTP/%d", protocolMajor), func(t *testing.T) {
			t.Parallel()

			body := &trackedReadCloser{body: io.NopCloser(strings.NewReader("body"))}
			request := &http.Request{
				Header:     make(http.Header),
				Trailer:    make(http.Header),
				ProtoMajor: protocolMajor,
				URL:        &url.URL{},
				Body:       body,
			}
			credential, present, err := ExtractBearer(request)
			if err != nil || present || credential.Valid() {
				t.Fatal("higher-protocol request without a credential declaration was rejected")
			}
			if request.Body != body {
				t.Fatal("higher-protocol body without trailer metadata was unnecessarily guarded")
			}
			content, err := io.ReadAll(request.Body)
			if err != nil || string(content) != "body" {
				t.Fatal("higher-protocol body Read semantics changed")
			}
		})
	}
}

type chunkedTrailerResult struct {
	invalid                  bool
	present                  bool
	valid                    bool
	readAtExtract            int
	guarded                  bool
	body                     []byte
	bodyErr                  error
	safeTrailer              string
	credentialTrailerPresent bool
	canaryPresent            bool
	repeatInvalid            bool
	repeatEmpty              bool
}

type trackedReadCloser struct {
	body   io.ReadCloser
	reads  int
	closes int
}

type blockingTrailerBody struct {
	request  *http.Request
	started  chan struct{}
	released chan struct{}
	closeErr error

	startOnce   sync.Once
	releaseOnce sync.Once
}

type dataEOFWithTrailerBody struct {
	request *http.Request
	read    bool
}

func (body *dataEOFWithTrailerBody) Read(target []byte) (int, error) {
	if body.read {
		return 0, io.EOF
	}
	body.read = true
	body.request.Trailer["Authorization"] = []string{"Bearer " + bearerCanary}
	target[0] = 'x'
	return 1, io.EOF
}

func (*dataEOFWithTrailerBody) Close() error { return nil }

func (body *blockingTrailerBody) Read([]byte) (int, error) {
	body.startOnce.Do(func() { close(body.started) })
	<-body.released
	body.request.Trailer["Authorization"] = []string{"Bearer " + bearerCanary}
	return 0, io.EOF
}

func (body *blockingTrailerBody) Close() error {
	body.request.Trailer["Cookie"] = []string{"access_token=" + bearerCanary}
	body.releaseOnce.Do(func() { close(body.released) })
	return body.closeErr
}

func (body *trackedReadCloser) Read(target []byte) (int, error) {
	body.reads++
	return body.body.Read(target)
}

func (body *trackedReadCloser) Close() error {
	body.closes++
	return body.body.Close()
}

func assertCredentialTrailerSurfacesRemoved(t *testing.T, request *http.Request) {
	t.Helper()
	for name := range request.Trailer {
		if isCredentialTrailerName(name) {
			t.Fatal("credential trailer field remained in request.Trailer")
		}
	}
	for name, values := range request.Header {
		if !asciiEqualFold(name, "Trailer") {
			continue
		}
		for _, value := range values {
			if hasCredentialTrailerName(value) {
				t.Fatal("credential trailer declaration remained in request.Header")
			}
		}
	}
}
