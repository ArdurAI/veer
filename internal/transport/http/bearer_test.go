package httptransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/ports"
)

const bearerCanary = "VeerBearerCanary-DoNotLeak.ABC_123~xyz"

func TestExtractBearer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		header      http.Header
		rawQuery    string
		wantToken   string
		wantPresent bool
		wantInvalid bool
	}{
		{name: "missing", header: http.Header{}},
		{name: "nil header", header: nil},
		{name: "canonical", header: header("Authorization", "Bearer "+bearerCanary), wantToken: bearerCanary, wantPresent: true},
		{name: "lowercase header key", header: header("authorization", "Bearer abc"), wantToken: "abc", wantPresent: true},
		{name: "lowercase scheme", header: header("Authorization", "bearer abc.def"), wantToken: "abc.def", wantPresent: true},
		{name: "uppercase scheme", header: header("Authorization", "BEARER abc"), wantToken: "abc", wantPresent: true},
		{name: "multiple literal spaces", header: header("Authorization", "Bearer    abc"), wantToken: "abc", wantPresent: true},
		{name: "complete RFC envelope", header: header("Authorization", "Bearer AZaz09-._~+/=="), wantToken: "AZaz09-._~+/==", wantPresent: true},
		{name: "one base with padding", header: header("Authorization", "Bearer a="), wantToken: "a=", wantPresent: true},
		{name: "empty header", header: header("Authorization", ""), wantInvalid: true},
		{name: "empty field value slice", header: http.Header{"Authorization": nil}, wantInvalid: true},
		{name: "wrong scheme", header: header("Authorization", "Basic abc"), wantInvalid: true},
		{name: "scheme only", header: header("Authorization", "Bearer"), wantInvalid: true},
		{name: "missing token", header: header("Authorization", "Bearer "), wantInvalid: true},
		{name: "tab separator", header: header("Authorization", "Bearer\tabc"), wantInvalid: true},
		{name: "leading whitespace", header: header("Authorization", " Bearer abc"), wantInvalid: true},
		{name: "trailing whitespace", header: header("Authorization", "Bearer abc "), wantInvalid: true},
		{name: "two tokens", header: header("Authorization", "Bearer abc def"), wantInvalid: true},
		{name: "comma combined", header: header("Authorization", "Bearer abc, Bearer def"), wantInvalid: true},
		{name: "auth parameter", header: header("Authorization", "Bearer token=abc"), wantInvalid: true},
		{name: "invalid byte", header: header("Authorization", "Bearer abc*def"), wantInvalid: true},
		{name: "non ASCII", header: header("Authorization", "Bearer café"), wantInvalid: true},
		{name: "padding before content", header: header("Authorization", "Bearer abc=def"), wantInvalid: true},
		{name: "only one padding byte", header: header("Authorization", "Bearer ="), wantInvalid: true},
		{name: "only padding bytes", header: header("Authorization", "Bearer =="), wantInvalid: true},
		{name: "duplicate field values", header: http.Header{"Authorization": {"Bearer abc", "Bearer def"}}, wantInvalid: true},
		{
			name: "duplicate casing keys",
			header: http.Header{
				"Authorization": {"Bearer abc"},
				"authorization": {"Bearer def"},
			},
			wantInvalid: true,
		},
		{name: "query carrier", header: http.Header{}, rawQuery: "access_token=" + bearerCanary, wantInvalid: true},
		{name: "empty query carrier", header: http.Header{}, rawQuery: "access_token", wantInvalid: true},
		{name: "encoded query carrier", header: http.Header{}, rawQuery: "%61ccess%5Ftoken=" + bearerCanary, wantInvalid: true},
		{name: "later query carrier", header: http.Header{}, rawQuery: "page=1&access_token=" + bearerCanary, wantInvalid: true},
		{name: "semicolon query carrier", header: http.Header{}, rawQuery: "page=1;access_token=" + bearerCanary, wantInvalid: true},
		{name: "cookie carrier", header: header("Cookie", "access_token="+bearerCanary), wantInvalid: true},
		{name: "bare cookie carrier", header: header("Cookie", "access_token"), wantInvalid: true},
		{name: "cookie carrier with space before equals", header: header("Cookie", "access_token ="+bearerCanary), wantInvalid: true},
		{name: "cookie carrier with tab before equals", header: header("Cookie", "access_token\t="+bearerCanary), wantInvalid: true},
		{name: "later cookie carrier", header: header("Cookie", "theme=dark; access_token="+bearerCanary), wantInvalid: true},
		{name: "empty cookie carrier", header: header("Cookie", "access_token="), wantInvalid: true},
		{name: "unrelated query", header: http.Header{}, rawQuery: "page=1&access-token=no", wantPresent: false},
		{name: "unrelated cookie", header: header("Cookie", "session=no; theme=dark"), wantPresent: false},
		{
			name:        "header and query carrier",
			header:      header("Authorization", "Bearer "+bearerCanary),
			rawQuery:    "access_token=other",
			wantInvalid: true,
		},
		{
			name: "header and cookie carrier",
			header: http.Header{
				"Authorization": {"Bearer " + bearerCanary},
				"Cookie":        {"access_token=other"},
			},
			wantInvalid: true,
		},
		{
			name: "header and whitespace cookie carrier",
			header: http.Header{
				"Authorization": {"Bearer " + bearerCanary},
				"Cookie":        {"theme=dark; access_token \t =other"},
			},
			wantInvalid: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			requestURI := "/v1/resources"
			if test.rawQuery != "" {
				requestURI += "?" + test.rawQuery
			}
			request := &http.Request{
				Header:     test.header.Clone(),
				URL:        &url.URL{Path: "/v1/resources", RawQuery: test.rawQuery},
				RequestURI: requestURI,
			}

			credential, present, err := ExtractBearer(request)
			if test.wantInvalid {
				if !errors.Is(err, ports.ErrAuthenticationInvalid) {
					t.Fatal("error was not ErrAuthenticationInvalid")
				}
				if present || credential.Valid() || credential.Token() != "" {
					t.Fatalf("invalid input returned credential: present=%v valid=%v", present, credential.Valid())
				}
			} else {
				if err != nil {
					t.Fatal("ExtractBearer() returned an unexpected error")
				}
				if present != test.wantPresent {
					t.Fatalf("present = %v, want %v", present, test.wantPresent)
				}
				if credential.Token() != test.wantToken {
					t.Fatal("extracted token did not match the expected value")
				}
				if credential.Valid() != test.wantPresent {
					t.Fatalf("credential.Valid() = %v, want %v", credential.Valid(), test.wantPresent)
				}
			}

			assertAuthorizationRemoved(t, request.Header)
		})
	}
}

func TestExtractBearerNilRequestIsInvalid(t *testing.T) {
	t.Parallel()

	credential, present, err := ExtractBearer(nil)
	if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
		t.Fatalf("ExtractBearer(nil) = present %v, valid %v, error %v", present, credential.Valid(), err)
	}
}

func TestExtractBearerBounds(t *testing.T) {
	t.Parallel()

	maximumToken := strings.Repeat("a", MaxBearerTokenBytes)
	tests := []struct {
		name        string
		value       string
		wantPresent bool
	}{
		{name: "maximum token", value: "Bearer " + maximumToken, wantPresent: true},
		{name: "token over maximum", value: "Bearer " + maximumToken + "a"},
		{name: "header over maximum through spaces", value: "Bearer  " + maximumToken},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := requestWithAuthorization(test.value)
			credential, present, err := ExtractBearer(request)
			if test.wantPresent {
				if err != nil || !present || credential.Token() != maximumToken {
					t.Fatal("maximum-size token was rejected")
				}
			} else if !errors.Is(err, ports.ErrAuthenticationInvalid) || present {
				t.Fatal("oversized field did not fail closed")
			}
			assertAuthorizationRemoved(t, request.Header)
		})
	}
}

func TestExtractBearerDoesNotReadBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		authorize   bool
		wantPresent bool
	}{
		{name: "accepted header", authorize: true, wantPresent: true},
		{name: "form token is not a carrier"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := &failingReader{}
			request := &http.Request{
				Header: header("Content-Type", "application/x-www-form-urlencoded"),
				URL:    &url.URL{},
				Body:   io.NopCloser(body),
				PostForm: url.Values{
					accessTokenParameter: {bearerCanary},
				},
			}
			if test.authorize {
				request.Header.Set("Authorization", "Bearer "+bearerCanary)
			}
			credential, present, err := ExtractBearer(request)
			if err != nil || present != test.wantPresent {
				t.Fatal("body-independence extraction result did not match")
			}
			if test.wantPresent && credential.Token() != bearerCanary {
				t.Fatal("accepted credential did not preserve the token")
			}
			if !test.wantPresent && credential.Valid() {
				t.Fatal("form-only request returned a credential")
			}
			if body.reads != 0 {
				t.Fatalf("request body read %d times", body.reads)
			}
		})
	}
}

func TestBearerRedactionCanary(t *testing.T) {
	t.Parallel()

	request := requestWithAuthorization("Bearer " + bearerCanary)
	credential, present, err := ExtractBearer(request)
	if err != nil || !present {
		t.Fatal("redaction canary could not be extracted")
	}

	outputs := []string{
		credential.String(),
		credential.Error(),
		credential.GoString(),
		fmt.Sprint(credential),
		fmt.Sprintf("%s", credential),
		fmt.Sprintf("%v", credential),
		fmt.Sprintf("%+v", credential),
		fmt.Sprintf("%#v", credential),
	}
	for _, output := range outputs {
		if strings.Contains(output, bearerCanary) {
			t.Fatal("credential formatting leaked bearer canary")
		}
	}

	encoded, marshalErr := json.Marshal(credential)
	if !errors.Is(marshalErr, ports.ErrCredentialSerializationForbidden) {
		t.Fatal("json.Marshal() did not return the serialization-forbidden error")
	}
	if bytes.Contains(encoded, []byte(bearerCanary)) || strings.Contains(marshalErr.Error(), bearerCanary) {
		t.Fatal("JSON path leaked bearer canary")
	}
	encoded, marshalErr = credential.MarshalText()
	if !errors.Is(marshalErr, ports.ErrCredentialSerializationForbidden) {
		t.Fatal("MarshalText() did not return the serialization-forbidden error")
	}
	if bytes.Contains(encoded, []byte(bearerCanary)) || strings.Contains(marshalErr.Error(), bearerCanary) {
		t.Fatal("text serialization path leaked bearer canary")
	}
}

func TestInvalidBearerErrorRedactionCanary(t *testing.T) {
	t.Parallel()

	tests := []*http.Request{
		requestWithAuthorization("Bearer " + bearerCanary + "!"),
		{Header: http.Header{}, URL: &url.URL{RawQuery: "access_token=" + bearerCanary}},
		{Header: header("Cookie", "access_token="+bearerCanary), URL: &url.URL{}},
	}
	for _, request := range tests {
		_, _, err := ExtractBearer(request)
		if !errors.Is(err, ports.ErrAuthenticationInvalid) {
			t.Fatal("error was not ErrAuthenticationInvalid")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), bearerCanary) {
			t.Fatal("authentication error leaked bearer canary")
		}
	}
}

func TestRejectedCarrierRequestRedactionCanary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		request           func() *http.Request
		wantQueryRemoved  bool
		wantCookieRemoved bool
	}{
		{
			name: "query",
			request: func() *http.Request {
				rawQuery := "page=1&access_token=" + bearerCanary
				return &http.Request{
					Header:     header("Authorization", "Bearer "+bearerCanary),
					URL:        &url.URL{Path: "/v1/resources", RawQuery: rawQuery, ForceQuery: true},
					RequestURI: "/v1/resources?" + rawQuery,
				}
			},
			wantQueryRemoved: true,
		},
		{
			name: "cookie variants",
			request: func() *http.Request {
				return &http.Request{
					Header: http.Header{
						"Cookie": {"theme=dark; access_token=" + bearerCanary},
						"cookie": {"preference=compact"},
					},
					URL:        &url.URL{Path: "/v1/resources"},
					RequestURI: "/v1/resources",
				}
			},
			wantCookieRemoved: true,
		},
		{
			name: "cookie name whitespace",
			request: func() *http.Request {
				return &http.Request{
					Header: http.Header{
						"Authorization": {"Bearer " + bearerCanary},
						"Cookie":        {"theme=dark; \taccess_token \t =" + bearerCanary},
					},
					URL:        &url.URL{Path: "/v1/resources"},
					RequestURI: "/v1/resources",
				}
			},
			wantCookieRemoved: true,
		},
		{
			name: "cookie name whitespace without authorization",
			request: func() *http.Request {
				return &http.Request{
					Header:     header("Cookie", "theme=dark; access_token \t ="+bearerCanary),
					URL:        &url.URL{Path: "/v1/resources"},
					RequestURI: "/v1/resources",
				}
			},
			wantCookieRemoved: true,
		},
		{
			name: "query and cookie",
			request: func() *http.Request {
				rawQuery := "%61ccess%5Ftoken=" + bearerCanary + "&page=1"
				return &http.Request{
					Header: http.Header{
						"Authorization": {"Bearer " + bearerCanary},
						"Cookie":        {"access_token=" + bearerCanary},
					},
					URL:        &url.URL{Path: "/v1/resources", RawQuery: rawQuery},
					RequestURI: "/v1/resources?" + rawQuery,
				}
			},
			wantQueryRemoved:  true,
			wantCookieRemoved: true,
		},
		{
			name: "request URI query diverges with credential",
			request: func() *http.Request {
				rawQuery := "access_token=" + bearerCanary
				return &http.Request{
					Header:     header("Authorization", "Bearer "+bearerCanary),
					URL:        &url.URL{Path: "/v1/resources", RawQuery: "page=1"},
					RequestURI: "/v1/resources?" + rawQuery,
				}
			},
			wantQueryRemoved: true,
		},
		{
			name: "URL query diverges with credential",
			request: func() *http.Request {
				return &http.Request{
					Header:     header("Authorization", "Bearer "+bearerCanary),
					URL:        &url.URL{Path: "/v1/resources", RawQuery: "access_token=" + bearerCanary},
					RequestURI: "/v1/resources?page=1",
				}
			},
			wantQueryRemoved: true,
		},
		{
			name: "nil URL with request URI credential",
			request: func() *http.Request {
				return &http.Request{
					Header:     header("Authorization", "Bearer "+bearerCanary),
					RequestURI: "/v1/resources?access_token=" + bearerCanary,
				}
			},
			wantQueryRemoved: true,
		},
		{
			name: "unrelated query mismatch",
			request: func() *http.Request {
				return &http.Request{
					Header:     header("Authorization", "Bearer "+bearerCanary),
					URL:        &url.URL{Path: "/v1/resources", RawQuery: "page=1"},
					RequestURI: "/v1/resources?trace=" + bearerCanary,
				}
			},
			wantQueryRemoved: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := test.request()

			credential, present, err := ExtractBearer(request)
			if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
				t.Fatal("alternative carrier did not fail closed")
			}
			assertAuthorizationRemoved(t, request.Header)

			if test.wantQueryRemoved {
				if request.URL != nil && (request.URL.RawQuery != "" || request.URL.ForceQuery) {
					t.Fatal("rejected query carrier remained in URL")
				}
				if request.RequestURI != "/v1/resources" {
					t.Fatal("rejected query carrier remained in RequestURI")
				}
			}
			if test.wantCookieRemoved {
				for name := range request.Header {
					if strings.EqualFold(name, "Cookie") {
						t.Fatal("rejected cookie carrier remained in the request headers")
					}
				}
			}

			formatted := fmt.Sprintf(
				"%v %+v %#v | %s | %v %+v %#v",
				request.URL,
				request.URL,
				request.URL,
				request.RequestURI,
				request.Header,
				request.Header,
				request.Header,
			)
			if strings.Contains(formatted, bearerCanary) {
				t.Fatal("rejected carrier remained in formatted request metadata")
			}
		})
	}
}

func TestUnrelatedQueryAndCookieStateIsPreserved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization []string
		requestURI    string
		wantInvalid   bool
	}{
		{
			name:          "matching query views",
			authorization: []string{"Bearer " + bearerCanary},
			requestURI:    "/v1/resources?page=1",
		},
		{
			name:          "empty request URI view",
			authorization: []string{"Bearer " + bearerCanary},
		},
		{
			name:          "malformed Authorization",
			authorization: []string{"Bearer " + bearerCanary + "!"},
			requestURI:    "/v1/resources?page=1",
			wantInvalid:   true,
		},
		{
			name:          "duplicate Authorization",
			authorization: []string{"Bearer " + bearerCanary, "Bearer duplicate"},
			requestURI:    "/v1/resources?page=1",
			wantInvalid:   true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := &http.Request{
				Header: http.Header{
					"Authorization": append([]string(nil), test.authorization...),
					"Cookie":        {"theme=dark"},
				},
				URL:        &url.URL{Path: "/v1/resources", RawQuery: "page=1"},
				RequestURI: test.requestURI,
			}

			credential, present, err := ExtractBearer(request)
			if test.wantInvalid {
				if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
					t.Fatal("invalid Authorization did not fail closed")
				}
			} else if err != nil || !present || !credential.Valid() || credential.Token() != bearerCanary {
				t.Fatal("unrelated request state changed a valid extraction result")
			}
			assertAuthorizationRemoved(t, request.Header)
			if request.URL.RawQuery != "page=1" || request.RequestURI != test.requestURI {
				t.Fatal("unrelated query state was not preserved")
			}
			if request.Header.Get("Cookie") != "theme=dark" {
				t.Fatal("unrelated cookie state was not preserved")
			}
		})
	}
}

func TestCookieNameWhitespaceDoesNotBroadenExactMatch(t *testing.T) {
	t.Parallel()

	tests := []string{
		"Access_token =" + bearerCanary,
		"access-token\t=" + bearerCanary,
		"access_tokenx \t=" + bearerCanary,
	}
	for _, cookie := range tests {
		cookie := cookie
		t.Run(cookie[:strings.IndexByte(cookie, '=')], func(t *testing.T) {
			t.Parallel()
			request := &http.Request{
				Header:     header("Cookie", cookie),
				URL:        &url.URL{Path: "/v1/resources"},
				RequestURI: "/v1/resources",
			}

			credential, present, err := ExtractBearer(request)
			if err != nil || present || credential.Valid() {
				t.Fatal("unrelated cookie was treated as an access_token carrier")
			}
			if request.Header.Get("Cookie") != cookie {
				t.Fatal("unrelated cookie was not preserved")
			}
		})
	}
}

type failingReader struct {
	reads int
}

func (reader *failingReader) Read([]byte) (int, error) {
	reader.reads++
	return 0, errors.New("body must not be read")
}

func header(name, value string) http.Header {
	return http.Header{name: {value}}
}

func requestWithAuthorization(value string) *http.Request {
	return &http.Request{
		Header: header("Authorization", value),
		URL:    &url.URL{},
	}
}

func assertAuthorizationRemoved(t *testing.T, header http.Header) {
	t.Helper()
	for name := range header {
		if strings.EqualFold(name, "Authorization") {
			t.Fatalf("Authorization header was retained under key %q", name)
		}
	}
}
