package httptransport

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/quick"

	"github.com/ArdurAI/veer/internal/core/ports"
)

func TestPropertyValidBearerEnvelopeRoundTrips(t *testing.T) {
	t.Parallel()

	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/"
	property := func(source []byte, spaceCount uint8, paddingCount uint8) bool {
		if len(source) > 512 {
			return true
		}
		if len(source) == 0 {
			source = []byte{0}
		}
		token := make([]byte, len(bearerCanary), len(bearerCanary)+len(source)+3)
		copy(token, bearerCanary)
		for _, value := range source {
			token = append(token, alphabet[int(value)%len(alphabet)])
		}
		token = append(token, strings.Repeat("=", int(paddingCount%4))...)
		spaces := strings.Repeat(" ", int(spaceCount%4)+1)
		request := requestWithAuthorization("bEaReR" + spaces + string(token))

		credential, present, err := ExtractBearer(request)
		if err != nil || !present || credential.Token() != string(token) || !credential.Valid() {
			return false
		}
		if strings.Contains(fmt.Sprintf("%s %v %+v %#v", credential, credential, credential, credential), bearerCanary) {
			return false
		}
		for name := range request.Header {
			if strings.EqualFold(name, "Authorization") {
				return false
			}
		}
		return true
	}

	if err := quick.Check(property, &quick.Config{
		MaxCount: 1_000,
		Rand:     rand.New(rand.NewSource(22)),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyCookieNameWhitespaceFailsClosed(t *testing.T) {
	t.Parallel()

	whitespace := []string{"", " ", "\t", " \t", "\t "}
	property := func(leadingIndex, trailingIndex uint8, authorize bool) bool {
		cookie := "theme=dark;" + whitespace[int(leadingIndex)%len(whitespace)] +
			accessTokenParameter + whitespace[int(trailingIndex)%len(whitespace)] +
			"=" + bearerCanary
		request := &http.Request{
			Header:     header("Cookie", cookie),
			URL:        &url.URL{Path: "/v1/resources"},
			RequestURI: "/v1/resources",
		}
		if authorize {
			request.Header.Set("Authorization", "Bearer "+bearerCanary)
		}
		if _, err := request.Cookie(accessTokenParameter); err != nil {
			return false
		}

		credential, present, err := ExtractBearer(request)
		if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
			return false
		}
		for name := range request.Header {
			if asciiEqualFold(name, "Authorization") || asciiEqualFold(name, "Cookie") {
				return false
			}
		}
		return !strings.Contains(fmt.Sprintf("%v %+v %#v", request.Header, request.Header, request.Header), bearerCanary)
	}

	if err := quick.Check(property, &quick.Config{
		MaxCount: 500,
		Rand:     rand.New(rand.NewSource(24)),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyInvalidBearerEnvelopeFailsClosed(t *testing.T) {
	t.Parallel()

	property := func(source []byte, position uint16) bool {
		if len(source) > 512 {
			return true
		}
		if len(source) == 0 {
			source = []byte("a")
		}
		token := make([]byte, len(source))
		for index, value := range source {
			token[index] = byte('a' + value%26)
		}
		token[int(position)%len(token)] = '!'
		request := requestWithAuthorization("Bearer " + string(token))

		credential, present, err := ExtractBearer(request)
		if !errors.Is(err, ports.ErrAuthenticationInvalid) || present || credential.Valid() {
			return false
		}
		for name := range request.Header {
			if strings.EqualFold(name, "Authorization") {
				return false
			}
		}
		return !strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), string(token))
	}

	if err := quick.Check(property, &quick.Config{
		MaxCount: 1_000,
		Rand:     rand.New(rand.NewSource(23)),
	}); err != nil {
		t.Fatal(err)
	}
}
