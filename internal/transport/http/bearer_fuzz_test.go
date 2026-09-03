package httptransport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/ports"
)

func FuzzExtractBearer(f *testing.F) {
	f.Add("Bearer "+bearerCanary, "page=1", "page=1", "theme=dark", false)
	f.Add("Bearer redacted", "", "", "", false)
	f.Add("Bearer credential", "", "", "", false)
	f.Add("Bearer invalid token", "", "", "", false)
	f.Add("", "access_token="+bearerCanary, "access_token="+bearerCanary, "", false)
	f.Add("Bearer "+bearerCanary, "", "", "access_token=other", true)
	f.Add("", "", "", "access_token ="+bearerCanary, false)
	f.Add("Bearer "+bearerCanary, "", "", "theme=dark; access_token\t="+bearerCanary, false)
	f.Add("Bearer "+bearerCanary, "page=1", "access_token="+bearerCanary, "", false)
	f.Add("Bearer "+bearerCanary, "page=1", "trace=2", "", false)

	f.Fuzz(func(t *testing.T, authorization, urlQuery, requestQuery, cookie string, duplicate bool) {
		if len(authorization)+len(urlQuery)+len(requestQuery)+len(cookie) > 32*1024 {
			t.Skip()
		}
		request := &http.Request{
			Header: http.Header{},
			URL:    &url.URL{Path: "/", RawQuery: urlQuery},
		}
		if requestQuery != "" {
			request.RequestURI = "/?" + requestQuery
		}
		if authorization != "" {
			request.Header.Add("Authorization", authorization)
			if duplicate {
				request.Header.Add("Authorization", "Bearer duplicate")
			}
		}
		if cookie != "" {
			request.Header.Add("Cookie", cookie)
		}
		_, standardCookieError := request.Cookie(accessTokenParameter)
		standardCookieCarrier := standardCookieError == nil
		queryCarrier, queryMismatch := inspectQueryViews(request)
		cookieCarrier := hasAccessTokenCookie(request.Header)

		credential, present, err := ExtractBearer(request)
		assertAuthorizationRemoved(t, request.Header)
		if queryCarrier || queryMismatch {
			if request.URL.RawQuery != "" || request.URL.ForceQuery || strings.Contains(request.RequestURI, "?") {
				t.Fatal("rejected query state was retained")
			}
		}
		if cookieCarrier {
			for name := range request.Header {
				if asciiEqualFold(name, "Cookie") {
					t.Fatal("rejected cookie state was retained")
				}
			}
		}
		if standardCookieCarrier {
			if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
				t.Fatal("cookie recognized by net/http did not fail closed")
			}
			for name := range request.Header {
				if asciiEqualFold(name, "Cookie") {
					t.Fatal("cookie recognized by net/http was retained")
				}
			}
		}
		if err != nil {
			if !errors.Is(err, ports.ErrAuthenticationInvalid) {
				t.Fatal("extraction returned an unclassified error")
			}
			if present || credential.Valid() || credential.Token() != "" {
				t.Fatal("failed extraction returned a credential")
			}
			return
		}
		if !present {
			if credential.Valid() || credential.Token() != "" {
				t.Fatal("missing extraction returned a credential")
			}
			return
		}

		token := credential.Token()
		if token == "" || len(token) > MaxBearerTokenBytes || !credential.Valid() {
			t.Fatal("successful extraction returned an invalid credential")
		}
		formatted := fmt.Sprintf("%s %v %+v %#v", credential, credential, credential, credential)
		const wantFormatted = "bearer-credential(redacted) bearer-credential(redacted) " +
			"bearer-credential(redacted) bearer-credential(redacted)"
		if formatted != wantFormatted {
			t.Fatal("credential formatting leaked an extracted token")
		}
	})
}

func FuzzCredentialTrailerScrubbing(f *testing.F) {
	f.Add(uint32(0), false, false, true, false, []byte("body"))
	f.Add(uint32(0xffff), true, true, false, false, []byte("chunked-like-body"))
	f.Add(uint32(0xff), false, false, true, true, []byte("undeclared-trailer-body"))

	f.Fuzz(func(t *testing.T, caseMask uint32, cookie, rawDeclaration, authorize, undeclared bool, payload []byte) {
		if len(payload) > 4*1024 {
			t.Skip()
		}
		name := "Authorization"
		value := "Bearer " + bearerCanary
		if cookie {
			name = "Cookie"
			value = "access_token =" + bearerCanary
		}
		name = asciiCaseVariant(name, caseMask)

		tracked := &trackedReadCloser{body: io.NopCloser(bytes.NewReader(payload))}
		request := &http.Request{
			Header:  make(http.Header),
			Trailer: http.Header{"X-Veer-Safe": {"retained"}},
			URL:     &url.URL{},
			Body:    tracked,
		}
		if undeclared {
			request.TransferEncoding = []string{"chunked"}
		} else if rawDeclaration {
			request.Header["tRaIlEr"] = []string{"X-Veer-Safe, " + name}
		} else {
			request.Trailer[name] = []string{value}
		}
		if authorize {
			request.Header.Set("Authorization", "Bearer "+bearerCanary)
		}

		credential, present, err := ExtractBearer(request)
		if undeclared {
			if err != nil || present != authorize || credential.Valid() != authorize {
				t.Fatal("undeclared credential trailer changed the initial extraction result")
			}
			request.Trailer[name] = []string{value}
		} else if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
			t.Fatal("declared credential trailer did not fail closed")
		}
		if tracked.reads != 0 || tracked.closes != 0 {
			t.Fatal("trailer inspection consumed the body")
		}
		content, readErr := io.ReadAll(request.Body)
		if readErr != nil || !bytes.Equal(content, payload) {
			t.Fatal("trailer guard changed body semantics")
		}
		assertCredentialTrailerSurfacesRemoved(t, request)
		repeatCredential, repeatPresent, repeatErr := ExtractBearer(request)
		if !errors.Is(repeatErr, ports.ErrAuthenticationInvalid) || repeatPresent || repeatCredential.Valid() {
			t.Fatal("observed credential trailer did not latch a repeated-extraction rejection")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", request.Header, request.Trailer, request), bearerCanary) {
			t.Fatal("credential trailer canary survived extraction or body consumption")
		}
	})
}

func asciiCaseVariant(value string, mask uint32) string {
	variant := []byte(value)
	for index := range variant {
		if mask&(1<<uint(index%32)) == 0 {
			continue
		}
		if variant[index] >= 'A' && variant[index] <= 'Z' {
			variant[index] += 'a' - 'A'
		} else if variant[index] >= 'a' && variant[index] <= 'z' {
			variant[index] -= 'a' - 'A'
		}
	}
	return string(variant)
}
