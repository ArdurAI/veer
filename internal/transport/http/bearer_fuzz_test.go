package httptransport

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/ports"
)

func FuzzExtractBearer(f *testing.F) {
	f.Add("Bearer "+bearerCanary, "page=1", "page=1", "theme=dark", false)
	f.Add("Bearer invalid token", "", "", "", false)
	f.Add("", "access_token="+bearerCanary, "access_token="+bearerCanary, "", false)
	f.Add("Bearer "+bearerCanary, "", "", "access_token=other", true)
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
		if len(token) >= 8 && strings.Contains(formatted, token) {
			t.Fatal("credential formatting leaked an extracted token")
		}
	})
}
