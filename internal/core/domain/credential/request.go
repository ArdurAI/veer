package credential

import (
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/operation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// ContractVersion binds the request framing, scope checks, recipient
	// semantics, material bounds, and session lifetime rules.
	ContractVersion = "veer.credentials.v1alpha1"
	// MaxRecipientBytes bounds both the provider and adapter registration names.
	MaxRecipientBytes = 64
	// MaxSourceMaterialBytes matches the AWS Secrets Manager value ceiling.
	MaxSourceMaterialBytes = 64 << 10
	// MaxSessionMaterialBytes bounds an AWS STS tuple or Kubernetes bearer token.
	MaxSessionMaterialBytes = 16 << 10

	// RequestedSessionTTL is the single alpha duration requested from issuers.
	RequestedSessionTTL = 15 * time.Minute
	// MinIssuedSessionTTL is the shortest useful provider-adjusted duration.
	MinIssuedSessionTTL = 5 * time.Minute
	// MaxIssuedSessionTTL prevents an issuer from widening the alpha lifetime.
	MaxIssuedSessionTTL = 15 * time.Minute
	// SessionRefreshAhead begins renewal before new-use admission closes.
	SessionRefreshAhead = 3 * time.Minute
	// MinNewUseLifetime is the usable lifetime required to start provider work.
	MinNewUseLifetime = 2 * time.Minute
	// SessionExpirySkew stops use before the provider-reported expiration.
	SessionExpirySkew = 30 * time.Second
	// BackendTimeout bounds one resolver or issuer attempt within its caller's
	// earlier deadline.
	BackendTimeout = 10 * time.Second
)

var (
	recipientPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	versionPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// Recipient is an opaque provider-adapter registration. The broker must still
// require an exact configured registration; construction alone grants no use.
type Recipient struct {
	provider string
	name     string
}

// NewRecipient validates one exact provider and adapter registration name.
func NewRecipient(provider, name string) (Recipient, error) {
	recipient := Recipient{provider: provider, name: name}
	if !recipient.Valid() {
		return Recipient{}, ErrInvalidRecipient
	}
	return recipient, nil
}

// Provider returns the exact non-secret provider registration key.
func (recipient Recipient) Provider() string { return recipient.provider }

// Name returns the exact non-secret adapter registration key.
func (recipient Recipient) Name() string { return recipient.name }

// Valid reports whether the recipient satisfies the closed alpha envelope.
func (recipient Recipient) Valid() bool {
	return len(recipient.provider) <= MaxRecipientBytes &&
		len(recipient.name) <= MaxRecipientBytes &&
		recipientPattern.MatchString(recipient.provider) &&
		recipientPattern.MatchString(recipient.name)
}

func (recipient Recipient) String() string {
	if !recipient.Valid() {
		return "credential-recipient(invalid)"
	}
	return "credential-recipient(redacted)"
}

func (recipient Recipient) GoString() string { return recipient.String() }

func (recipient Recipient) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, recipient.String())
}

func (recipient Recipient) LogValue() slog.Value { return redactedLogValue(recipient.String()) }

func (Recipient) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Recipient) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Recipient) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Recipient) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// ResourceView is a sealed, minimal projection of an immutable resource
// envelope. It lets the credential boundary prove the Operation generation
// without accepting caller-asserted ownership fields.
type ResourceView struct {
	initialized bool
	apiVersion  string
	kind        hierarchy.Kind
	id          resource.ID
	workspaceID resource.ID
	parent      *resource.ID
	generation  resource.Generation
}

// NewResourceView projects an immutable typed resource into the exact identity
// and generation fields required by NewRequest.
func NewResourceView[Spec any, Status resource.GenerationObservations](
	value resource.Resource[Spec, Status],
) (ResourceView, error) {
	metadata := value.Metadata()
	record, err := hierarchy.RecordFrom(value.APIVersion(), value.Kind(), metadata)
	if err != nil || metadata.Generation() < 1 {
		return ResourceView{}, ErrInvalidResourceView
	}
	view := ResourceView{
		initialized: true,
		apiVersion:  record.APIVersion(),
		kind:        record.Kind(),
		id:          record.ID(),
		workspaceID: record.WorkspaceID(),
		parent:      cloneID(record),
		generation:  metadata.Generation(),
	}
	if !validResourceView(view) {
		return ResourceView{}, ErrInvalidResourceView
	}
	return view, nil
}

// ID returns the stable target resource identity.
func (view ResourceView) ID() resource.ID { return view.id }

// Kind returns the target's exact retained hierarchy kind.
func (view ResourceView) Kind() hierarchy.Kind { return view.kind }

// Generation returns the target desired-state generation.
func (view ResourceView) Generation() resource.Generation { return view.generation }

func (view ResourceView) String() string {
	if !validResourceView(view) {
		return "credential-resource-view(invalid)"
	}
	return "credential-resource-view(redacted)"
}

func (view ResourceView) GoString() string { return view.String() }

func (view ResourceView) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, view.String())
}

func (view ResourceView) LogValue() slog.Value { return redactedLogValue(view.String()) }

func (ResourceView) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ResourceView) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (ResourceView) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (ResourceView) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// SourceLookup is the opaque, versioned external-secret lookup sealed into a
// request. It contains references only, never credential material.
type SourceLookup struct {
	initialized          bool
	workspaceID          resource.ID
	environmentID        resource.ID
	providerConnectionID resource.ID
	connectionGeneration resource.Generation
	provider             string
	referenceID          resource.ID
	version              string
	digest               SourceDigest
}

func (source SourceLookup) WorkspaceID() resource.ID   { return source.workspaceID }
func (source SourceLookup) EnvironmentID() resource.ID { return source.environmentID }
func (source SourceLookup) ProviderConnectionID() resource.ID {
	return source.providerConnectionID
}
func (source SourceLookup) ConnectionGeneration() resource.Generation {
	return source.connectionGeneration
}
func (source SourceLookup) Provider() string         { return source.provider }
func (source SourceLookup) ReferenceID() resource.ID { return source.referenceID }
func (source SourceLookup) Version() string          { return source.version }
func (source SourceLookup) Digest() SourceDigest     { return source.digest }
func (source SourceLookup) Valid() bool              { return validateSourceLookup(source) == nil }

func (source SourceLookup) String() string {
	if !source.Valid() {
		return "credential-source-lookup(invalid)"
	}
	return "credential-source-lookup(redacted)"
}

func (source SourceLookup) GoString() string { return source.String() }

func (source SourceLookup) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, source.String())
}

func (source SourceLookup) LogValue() slog.Value { return redactedLogValue(source.String()) }

func (SourceLookup) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceLookup) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (SourceLookup) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (SourceLookup) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

// Request is one immutable provider authority request sealed from current
// hierarchy, connection, target, and Operation values.
type Request struct {
	initialized          bool
	workspaceID          resource.ID
	environmentID        resource.ID
	providerConnectionID resource.ID
	connectionGeneration resource.Generation
	operationID          resource.ID
	targetResourceID     resource.ID
	targetKind           hierarchy.Kind
	targetGeneration     resource.Generation
	provider             string
	action               authorization.Action
	recipient            Recipient
	source               SourceLookup
	binding              BindingDigest
}

// NewRequest proves the complete provider scope and seals it into a
// domain-separated, non-serializable request.
func NewRequest(
	snapshot hierarchy.Snapshot,
	connection resource.Resource[control.ProviderConnectionSpec, control.ProviderConnectionStatus],
	target ResourceView,
	op operation.Operation,
	action authorization.Action,
	recipient Recipient,
) (Request, error) {
	if err := operation.Validate(op); err != nil {
		return Request{}, fmt.Errorf("%w: operation", ErrInvalidRequest)
	}
	if op.Phase != operation.PhaseRunning {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrOperationNotRunning)
	}
	if !validProviderAction(action) {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrUnsupportedProviderAction)
	}
	if !recipient.Valid() {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrInvalidRecipient)
	}
	if !validResourceView(target) {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrInvalidResourceView)
	}

	metadata := connection.Metadata()
	spec, err := connection.Spec()
	if err != nil || control.ValidateProviderConnectionSpec(spec) != nil {
		return Request{}, fmt.Errorf("%w: provider connection", ErrInvalidRequest)
	}
	status, err := connection.Status()
	if err != nil || control.ValidateProviderConnectionStatus(status, metadata.Generation().Int64()) != nil {
		return Request{}, fmt.Errorf("%w: provider connection", ErrInvalidRequest)
	}
	connectionRecord, err := hierarchy.RecordFrom(
		connection.APIVersion(),
		connection.Kind(),
		metadata,
	)
	if err != nil || connectionRecord.Kind() != hierarchy.KindProviderConnection ||
		metadata.Generation() < 1 {
		return Request{}, fmt.Errorf("%w: provider connection", ErrInvalidRequest)
	}
	retainedConnection, err := snapshot.Lookup(connectionRecord.ID())
	if err != nil || !equalRecords(connectionRecord, retainedConnection) {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrConnectionNotRetained)
	}
	environmentID, present := connectionRecord.Parent()
	if !present {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrScopeMismatch)
	}

	targetRecord, err := snapshot.Lookup(target.id)
	if err != nil || !viewMatchesRecord(target, targetRecord) {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrTargetNotRetained)
	}
	targetAuthorization, err := authorization.ResolveResourceTarget(snapshot, target.id)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrTargetNotRetained)
	}
	targetEnvironmentID, present := targetAuthorization.EnvironmentID()
	if !present {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrScopeMismatch)
	}

	if op.EnvironmentID == nil || op.ProviderConnectionID == nil ||
		op.WorkspaceID != snapshot.WorkspaceID() ||
		connectionRecord.WorkspaceID() != snapshot.WorkspaceID() ||
		targetRecord.WorkspaceID() != snapshot.WorkspaceID() ||
		*op.EnvironmentID != environmentID ||
		*op.EnvironmentID != targetEnvironmentID ||
		*op.ProviderConnectionID != connectionRecord.ID() ||
		op.ResourceID != target.id ||
		recipient.provider != spec.Provider {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrScopeMismatch)
	}
	if op.Generation != target.generation.Int64() {
		return Request{}, fmt.Errorf("%w: %w", ErrInvalidRequest, ErrTargetGenerationMismatch)
	}
	referenceID, err := resource.ParseID(spec.CredentialRef.ReferenceID)
	if err != nil {
		return Request{}, fmt.Errorf("%w: provider connection", ErrInvalidRequest)
	}

	source := SourceLookup{
		initialized:          true,
		workspaceID:          snapshot.WorkspaceID(),
		environmentID:        environmentID,
		providerConnectionID: connectionRecord.ID(),
		connectionGeneration: metadata.Generation(),
		provider:             spec.Provider,
		referenceID:          referenceID,
		version:              spec.CredentialRef.Version,
	}
	source.digest = deriveSourceDigest(source)

	request := Request{
		initialized:          true,
		workspaceID:          source.workspaceID,
		environmentID:        source.environmentID,
		providerConnectionID: source.providerConnectionID,
		connectionGeneration: source.connectionGeneration,
		operationID:          op.ID,
		targetResourceID:     target.id,
		targetKind:           target.kind,
		targetGeneration:     target.generation,
		provider:             source.provider,
		action:               action,
		recipient:            recipient,
		source:               source,
	}
	request.binding = deriveBindingDigest(request)
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// ValidateRequest checks a complete sealed value without accepting replacement
// scope fields or exposing retained identifiers in an error.
func ValidateRequest(request Request) error {
	if !request.initialized || !request.recipient.Valid() ||
		validateSourceLookup(request.source) != nil ||
		!validProviderAction(request.action) ||
		request.connectionGeneration < 1 || request.targetGeneration < 1 {
		return ErrInvalidRequest
	}
	for _, id := range []resource.ID{
		request.workspaceID,
		request.environmentID,
		request.providerConnectionID,
		request.operationID,
		request.targetResourceID,
	} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidRequest
		}
	}
	if _, err := hierarchy.ParseKind(request.targetKind.String()); err != nil {
		return ErrInvalidRequest
	}
	if request.workspaceID != request.source.workspaceID ||
		request.environmentID != request.source.environmentID ||
		request.providerConnectionID != request.source.providerConnectionID ||
		request.connectionGeneration != request.source.connectionGeneration ||
		request.provider != request.source.provider ||
		request.provider != request.recipient.provider ||
		!request.binding.Equal(deriveBindingDigest(request)) {
		return ErrInvalidRequest
	}
	return nil
}

// Valid reports whether this value is a complete, internally consistent request.
func (request Request) Valid() bool { return ValidateRequest(request) == nil }

func (request Request) WorkspaceID() resource.ID          { return request.workspaceID }
func (request Request) EnvironmentID() resource.ID        { return request.environmentID }
func (request Request) ProviderConnectionID() resource.ID { return request.providerConnectionID }
func (request Request) ConnectionGeneration() resource.Generation {
	return request.connectionGeneration
}
func (request Request) OperationID() resource.ID      { return request.operationID }
func (request Request) TargetResourceID() resource.ID { return request.targetResourceID }
func (request Request) TargetKind() hierarchy.Kind    { return request.targetKind }
func (request Request) TargetGeneration() resource.Generation {
	return request.targetGeneration
}
func (request Request) Provider() string             { return request.provider }
func (request Request) Action() authorization.Action { return request.action }
func (request Request) Recipient() Recipient         { return request.recipient }
func (request Request) SourceLookup() SourceLookup   { return request.source }
func (request Request) BindingDigest() BindingDigest { return request.binding }

func (request Request) String() string {
	if !request.Valid() {
		return "credential-request(invalid)"
	}
	return "credential-request(redacted)"
}

func (request Request) GoString() string { return request.String() }

func (request Request) Format(state fmt.State, _ rune) {
	writeSafeFormat(state, request.String())
}

func (request Request) LogValue() slog.Value { return redactedLogValue(request.String()) }

func (Request) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Request) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (Request) MarshalBinary() ([]byte, error) { return nil, ErrSerializationForbidden }
func (Request) GobEncode() ([]byte, error)     { return nil, ErrSerializationForbidden }

func validateSourceLookup(source SourceLookup) error {
	if !source.initialized || source.connectionGeneration < 1 ||
		!recipientPattern.MatchString(source.provider) ||
		!versionPattern.MatchString(source.version) {
		return ErrInvalidRequest
	}
	for _, id := range []resource.ID{
		source.workspaceID,
		source.environmentID,
		source.providerConnectionID,
		source.referenceID,
	} {
		if _, err := resource.ParseID(id.String()); err != nil {
			return ErrInvalidRequest
		}
	}
	if !source.digest.Equal(deriveSourceDigest(source)) {
		return ErrInvalidDigest
	}
	return nil
}

func validProviderAction(action authorization.Action) bool {
	switch action {
	case authorization.ActionProviderDiscover,
		authorization.ActionProviderApply,
		authorization.ActionProviderObserve,
		authorization.ActionProviderDelete:
		return true
	default:
		return false
	}
}

func validResourceView(view ResourceView) bool {
	if !view.initialized || view.apiVersion != hierarchy.APIVersion || view.generation < 1 {
		return false
	}
	if _, err := hierarchy.ParseKind(view.kind.String()); err != nil {
		return false
	}
	if _, err := resource.ParseID(view.id.String()); err != nil {
		return false
	}
	if _, err := resource.ParseID(view.workspaceID.String()); err != nil {
		return false
	}
	if view.kind == hierarchy.KindWorkspace {
		return view.parent == nil && view.id == view.workspaceID
	}
	if view.parent == nil {
		return false
	}
	_, err := resource.ParseID(view.parent.String())
	return err == nil
}

func viewMatchesRecord(view ResourceView, record hierarchy.Record) bool {
	if !validResourceView(view) || view.apiVersion != record.APIVersion() ||
		view.kind != record.Kind() || view.id != record.ID() ||
		view.workspaceID != record.WorkspaceID() {
		return false
	}
	return equalParents(view.parent, record)
}

func equalRecords(left, right hierarchy.Record) bool {
	if left.APIVersion() != right.APIVersion() || left.Kind() != right.Kind() ||
		left.ID() != right.ID() || left.WorkspaceID() != right.WorkspaceID() {
		return false
	}
	leftParent, leftPresent := left.Parent()
	rightParent, rightPresent := right.Parent()
	return leftPresent == rightPresent && (!leftPresent || leftParent == rightParent)
}

func equalParents(parent *resource.ID, record hierarchy.Record) bool {
	recordParent, present := record.Parent()
	if parent == nil {
		return !present
	}
	return present && *parent == recordParent
}

func cloneID(record hierarchy.Record) *resource.ID {
	parent, present := record.Parent()
	if !present {
		return nil
	}
	return &parent
}
