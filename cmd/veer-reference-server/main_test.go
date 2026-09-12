package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunServesAuthenticatedRequestOnRealListenerAndShutsDown(t *testing.T) {
	token := "reference-command-token"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listenerReady := make(chan net.Listener, 1)
	listen := func(network, _ string) (net.Listener, error) {
		listener, err := net.Listen(network, "127.0.0.1:0")
		if err == nil {
			listenerReady <- listener
		}
		return listener, err
	}
	runResult := make(chan error, 1)
	go func() {
		runResult <- run(
			ctx,
			[]string{"--listen", "127.0.0.1:0", "--token-file", tokenFile},
			io.Discard,
			listen,
			bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)),
		)
	}()
	listener := <-listenerReady
	baseURL := "http://" + listener.Addr().String()
	transport := &http.Transport{}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	defer transport.CloseIdleConnections()

	unauthorized, err := client.Get(baseURL + "/api/v1alpha1/workspaces")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(unauthorized.Body); err != nil {
		t.Fatal(err)
	}
	if unauthorized.StatusCode != http.StatusUnauthorized ||
		unauthorized.Header.Get("WWW-Authenticate") != `Bearer realm="veer"` {
		t.Fatalf("unauthorized response = %d, %q", unauthorized.StatusCode, unauthorized.Header.Get("WWW-Authenticate"))
	}
	if err := unauthorized.Body.Close(); err != nil {
		t.Fatal(err)
	}

	listRequest, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1alpha1/workspaces", nil)
	if err != nil {
		t.Fatal(err)
	}
	listRequest.Header.Set("Authorization", "Bearer "+token)
	listResponse, err := client.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}
	listBody, err := io.ReadAll(listResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := listResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(listBody, &page); err != nil {
		t.Fatal(err)
	}
	if listResponse.StatusCode != http.StatusOK || len(page.Items) != 1 {
		t.Fatalf("authorized list response = %d, %s", listResponse.StatusCode, listBody)
	}

	body := strings.NewReader(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"socket"},"spec":{}}`)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1alpha1/workspaces", body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "listener-create-0001")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var problem map[string]any
	if err := json.Unmarshal(responseBody, &problem); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden || problem["code"] != "authorization-denied" {
		t.Fatalf("reserved create response = %d, %#v", response.StatusCode, problem)
	}

	transport.CloseIdleConnections()
	cancel()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatalf("run() error = %v", err)
		}
	case <-time.After(shutdownTimeout + 2*time.Second):
		t.Fatal("reference server did not shut down within test deadline")
	}
}

func TestRunRejectsUnsafeConfigurationBeforeListening(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("reference-command-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	listenCalled := false
	listen := func(_, _ string) (net.Listener, error) {
		listenCalled = true
		return nil, nil
	}
	err := run(context.Background(), []string{
		"--listen", "0.0.0.0:8080", "--token-file", tokenFile,
	}, io.Discard, listen, bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	if err == nil || listenCalled {
		t.Fatalf("run(unsafe) error/listen = %v/%t", err, listenCalled)
	}

	err = run(context.Background(), []string{
		"--listen", "127.0.0.1:0", "--token-file", tokenFile,
	}, io.Discard, listen, bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	if err == nil || listenCalled {
		t.Fatalf("run(insecure token mode) error/listen = %v/%t", err, listenCalled)
	}

	if err := os.Chmod(tokenFile, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "token-link")
	if err := os.Symlink(tokenFile, link); err != nil {
		t.Fatal(err)
	}
	err = run(context.Background(), []string{
		"--listen", "127.0.0.1:0", "--token-file", link,
	}, io.Discard, listen, bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	if err == nil || listenCalled {
		t.Fatalf("run(symlink token) error/listen = %v/%t", err, listenCalled)
	}

	fifo := filepath.Join(t.TempDir(), "token-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- run(context.Background(), []string{
			"--listen", "127.0.0.1:0", "--token-file", fifo,
		}, io.Discard, listen, bytes.NewReader(bytes.Repeat([]byte{0x61}, 32)))
	}()
	select {
	case err := <-result:
		if err == nil || listenCalled {
			t.Fatalf("run(FIFO token) error/listen = %v/%t", err, listenCalled)
		}
	case <-time.After(time.Second):
		t.Fatal("run(FIFO token) blocked before rejecting the special file")
	}
}
