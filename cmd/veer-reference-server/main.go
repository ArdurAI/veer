// Command veer-reference-server runs Veer's loopback-only, process-local
// lifecycle contract harness. It is not the production veer-api binary.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ArdurAI/veer/internal/adapters/referenceaccess"
	"github.com/ArdurAI/veer/internal/adapters/store/memory"
	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/model/v1alpha1"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
	"github.com/ArdurAI/veer/internal/core/service/referenceauthorization"
	httptransport "github.com/ArdurAI/veer/internal/transport/http"
)

const (
	defaultListenAddress = "127.0.0.1:8080"
	shutdownTimeout      = 5 * time.Second
	maximumHeaderBytes   = 16 * 1024
)

type listenFunc func(network, address string) (net.Listener, error)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr, net.Listen, rand.Reader); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "veer reference server: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer, listen listenFunc, entropy io.Reader) error {
	flags := flag.NewFlagSet("veer-reference-server", flag.ContinueOnError)
	flags.SetOutput(output)
	address := flags.String("listen", defaultListenAddress, "literal loopback address to listen on")
	tokenFile := flags.String("token-file", "", "0600 regular file containing the reference bearer token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *tokenFile == "" || validateLoopbackAddress(*address) != nil || listen == nil || entropy == nil {
		return errors.New("invalid reference-server configuration")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	credential, err := loadCredential(*tokenFile)
	if err != nil {
		return err
	}
	principal, err := referencePrincipal()
	if err != nil {
		return fmt.Errorf("construct reference principal: %w", err)
	}
	access, err := referenceaccess.New(credential, principal)
	if err != nil {
		return fmt.Errorf("construct reference access boundary: %w", err)
	}
	pageTokenKey := make([]byte, 32)
	if _, err := io.ReadFull(entropy, pageTokenKey); err != nil {
		return errors.New("read reference page-token entropy")
	}
	rawService, err := reference.New(reference.Config{
		Store: memory.NewStore(), Clock: reference.ClockFunc(func() time.Time { return time.Now().UTC() }),
		Issuer: &reference.SequentialIssuer{}, PageTokenKey: pageTokenKey,
	})
	if err != nil {
		return fmt.Errorf("construct reference service: %w", err)
	}
	service, err := seedAuthorizationRuntime(ctx, rawService, principal)
	if err != nil {
		return fmt.Errorf("seed reference authorization runtime: %w", err)
	}
	handler, err := httptransport.NewReferenceHandler(service, access)
	if err != nil {
		return fmt.Errorf("construct reference handler: %w", err)
	}

	listener, err := listen("tcp", *address)
	if err != nil {
		return fmt.Errorf("listen on configured loopback address: %w", err)
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: maximumHeaderBytes,
		ErrorLog: log.New(output, "", 0),
	}
	_, _ = fmt.Fprintf(output, "veer reference server listening on %s\n", listener.Addr())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return fmt.Errorf("shut down reference server: %w", err)
		}
		if err := <-serveResult; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return errors.New("invalid loopback address")
	}
	ip := net.ParseIP(host)
	parsedPort, portErr := strconv.ParseUint(port, 10, 16)
	if ip == nil || !ip.IsLoopback() || portErr != nil || parsedPort > 65_535 {
		return errors.New("invalid loopback address")
	}
	return nil
}

func loadCredential(path string) (ports.BearerCredential, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() ||
		linkInfo.Mode().Perm()&0o077 != 0 {
		return ports.BearerCredential{}, errors.New("reference token file is unavailable or unsafe")
	}
	file, err := os.Open(path) // #nosec G304 -- VEER-SEC-012: explicit path is identity-checked and restricted to a private regular non-symlink file
	if err != nil {
		return ports.BearerCredential{}, errors.New("reference token file is unavailable or unsafe")
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(linkInfo, info) || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return ports.BearerCredential{}, errors.New("reference token file is unavailable or unsafe")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(ports.MaxBearerTokenBytes)+3))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(encoded) > ports.MaxBearerTokenBytes+2 {
		return ports.BearerCredential{}, errors.New("reference token file is invalid")
	}
	token := strings.TrimSuffix(string(encoded), "\n")
	token = strings.TrimSuffix(token, "\r")
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return ports.BearerCredential{}, errors.New("reference token file is invalid")
	}
	credential, err := ports.NewBearerCredential(token)
	if err != nil {
		return ports.BearerCredential{}, errors.New("reference token file is invalid")
	}
	return credential, nil
}

func referencePrincipal() (identity.Principal, error) {
	return identity.NewPrincipal(identity.PrincipalInput{
		Kind: identity.KindHuman, Issuer: "https://reference.veer.invalid",
		Subject: "local-reference-operator", Audiences: []string{"veer-api"},
	})
}

func seedAuthorizationRuntime(
	ctx context.Context,
	service *reference.Service,
	principal identity.Principal,
) (*referenceauthorization.Service, error) {
	workspaceBody, err := json.Marshal(v1alpha1.WorkspaceWrite{
		APIVersion: v1alpha1.APIVersion,
		Kind:       hierarchy.KindWorkspace.String(),
		Metadata:   v1alpha1.WriteMetadata{DisplayName: "Reference Workspace"},
		Spec:       v1alpha1.WorkspaceWriteSpec{},
	})
	if err != nil {
		return nil, err
	}
	workspace, err := service.Create(ctx, reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindWorkspace,
		CanonicalTarget: "reference:bootstrap:workspace", IdempotencyKey: "reference-bootstrap-workspace-v1",
		Body: workspaceBody,
	})
	if err != nil {
		return nil, err
	}
	memberID, err := resource.ParseID("mem_reference_admin_0001")
	if err != nil {
		return nil, err
	}
	member, err := authorization.NewMemberRecord(authorization.MemberInput{
		ID: memberID, WorkspaceID: workspace.ResourceID, Kind: principal.Kind(),
		LogicalIdentity: principal.LogicalIdentity(),
	})
	if err != nil {
		return nil, err
	}
	directory, err := authorization.NewMemberDirectory(workspace.ResourceID, []authorization.MemberRecord{member})
	if err != nil {
		return nil, err
	}
	policyBody, err := json.Marshal(v1alpha1.PolicyWrite{
		APIVersion: v1alpha1.APIVersion,
		Kind:       hierarchy.KindPolicy.String(),
		Metadata:   v1alpha1.WriteMetadata{DisplayName: "Reference Workspace Administrator"},
		Spec: authorization.PolicySpec{Bindings: []authorization.RoleBinding{{
			MemberID: memberID, Role: authorization.RoleWorkspaceAdministrator,
			Scope: authorization.Scope{Kind: authorization.ScopeKindWorkspace},
		}}},
	})
	if err != nil {
		return nil, err
	}
	parentID := workspace.ResourceID
	if _, err := service.Create(ctx, reference.CreateCommand{
		Principal: principal, Kind: hierarchy.KindPolicy, WorkspaceID: workspace.ResourceID, ParentID: &parentID,
		CanonicalTarget: "reference:bootstrap:policy", IdempotencyKey: "reference-bootstrap-policy-v1",
		Body: policyBody, Members: directory,
	}); err != nil {
		return nil, err
	}
	return referenceauthorization.New(referenceauthorization.Config{
		Reference: service, MemberDirectories: []authorization.MemberDirectory{directory},
	})
}
