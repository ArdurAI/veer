package httptransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ArdurAI/veer/internal/core/domain/admission"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
	"github.com/ArdurAI/veer/internal/core/service/reference"
	"github.com/ArdurAI/veer/internal/core/service/referenceauthorization"
)

const maxRequestBodyBytes = resource.MaxCanonicalBytes

var (
	requestIDPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	strongETagPattern       = regexp.MustCompile(`^"[A-Za-z0-9_-]{1,128}"$`)
	errPreconditionRequired = errors.New("mutation precondition is required")
)

// ReferenceHandler exposes only the routes published by veer-v1alpha1.json.
// Authentication is injected and every service call is bound to the concrete
// policy-enforcing reference runtime.
type ReferenceHandler struct {
	service       *referenceauthorization.Service
	authenticator ports.Authenticator
	requests      atomic.Uint64
}

// NewReferenceHandler creates a deterministic provider-free contract handler.
func NewReferenceHandler(
	service *referenceauthorization.Service,
	authenticator ports.Authenticator,
) (*ReferenceHandler, error) {
	if service == nil || authenticator == nil {
		return nil, reference.ErrInvalidConfiguration
	}
	return &ReferenceHandler{service: service, authenticator: authenticator}, nil
}

func (handler *ReferenceHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Cache-Control", "no-store")
	credential, credentialPresent, authenticationErr := ExtractBearer(request)
	requestID, requestIDValid := handler.requestID(request)
	if !requestIDValid {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	writer.Header().Set("Veer-Request-Id", requestID)
	principal, authenticated := handler.authenticate(
		writer, request, requestID, credential, credentialPresent, authenticationErr,
	)
	if !authenticated {
		return
	}
	if request.URL.EscapedPath() != request.URL.Path {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}

	switch {
	case request.URL.Path == "/api/v1alpha1/workspaces":
		handler.serveWorkspaceCollection(writer, request, requestID, principal)
	case strings.HasPrefix(request.URL.Path, "/api/v1alpha1/workspaces/"):
		handler.serveWorkspaceItem(writer, request, requestID, principal)
	case strings.HasPrefix(request.URL.Path, "/api/v1alpha1/operations/"):
		handler.serveOperation(writer, request, requestID, principal)
	default:
		handler.writeProblem(writer, requestID, http.StatusNotFound, "not-found", "Resource not found", nil)
	}
}

func (handler *ReferenceHandler) authenticate(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	credential ports.BearerCredential,
	present bool,
	extractionErr error,
) (identity.Principal, bool) {
	if extractionErr != nil {
		handler.writeAuthenticationRequired(writer, requestID, "invalid_request")
		return identity.Principal{}, false
	}
	if !present {
		handler.writeAuthenticationRequired(writer, requestID, "")
		return identity.Principal{}, false
	}
	principal, err := handler.authenticator.Authenticate(request.Context(), credential)
	if err == nil && identity.ValidatePrincipal(principal) == nil {
		return principal, true
	}
	if failure, recognized := ports.ClassifyAuthenticationError(err); recognized {
		if failure == ports.ErrAuthenticationUnavailable {
			handler.writeUnavailable(writer, requestID)
			return identity.Principal{}, false
		}
		handler.writeAuthenticationRequired(writer, requestID, "invalid_token")
		return identity.Principal{}, false
	}
	if errors.Is(err, request.Context().Err()) && request.Context().Err() != nil {
		handler.writeUnavailable(writer, requestID)
		return identity.Principal{}, false
	}
	handler.writeProblem(writer, requestID, http.StatusInternalServerError, "internal-failure", "Internal failure", nil)
	return identity.Principal{}, false
}

func (handler *ReferenceHandler) serveWorkspaceCollection(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal identity.Principal,
) {
	switch request.Method {
	case http.MethodGet:
		query, err := parseListQuery(request.URL.RawQuery)
		if err != nil {
			handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
			return
		}
		page, err := handler.service.List(request.Context(), reference.ListQuery{
			Principal: principal, Kind: hierarchy.KindWorkspace,
			PageSize: query.pageSize, PageToken: query.pageToken,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		encoded := encodeWorkspacePage(page)
		handler.writeJSON(writer, http.StatusOK, encoded)
	case http.MethodPost:
		if request.URL.RawQuery != "" {
			handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
			return
		}
		key, ok := idempotencyKey(request)
		if !ok {
			handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
			return
		}
		body, err := readJSONBody(writer, request)
		if err != nil {
			handler.writeBodyError(writer, requestID, err)
			return
		}
		receipt, err := handler.service.Create(request.Context(), reference.CreateCommand{
			Principal: principal, Kind: hierarchy.KindWorkspace,
			CanonicalTarget: request.URL.Path, IdempotencyKey: key, Body: body,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		writer.Header().Set("Location", "/api/v1alpha1/operations/"+receipt.OperationID.String())
		handler.writeJSONValue(writer, http.StatusAccepted, receipt)
	default:
		handler.writeMethodNotAllowed(writer, requestID, "GET, POST")
	}
}

func (handler *ReferenceHandler) serveWorkspaceItem(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal identity.Principal,
) {
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1alpha1/workspaces/")
	statusRoute := strings.HasSuffix(remainder, "/status")
	if statusRoute {
		remainder = strings.TrimSuffix(remainder, "/status")
	}
	if strings.Contains(remainder, "/") || remainder == "" || request.URL.RawQuery != "" {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	id, err := resource.ParseID(remainder)
	if err != nil {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	if statusRoute {
		handler.serveWorkspaceStatus(writer, request, requestID, principal, id)
		return
	}

	switch request.Method {
	case http.MethodGet:
		value, err := handler.service.Get(request.Context(), principal, id, id)
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		if value.Kind != hierarchy.KindWorkspace {
			handler.writeProblem(writer, requestID, http.StatusNotFound, "not-found", "Resource not found", nil)
			return
		}
		writer.Header().Set("ETag", quoteETag(value.Metadata.ResourceVersion().String()))
		handler.writeJSON(writer, http.StatusOK, value.Canonical)
	case http.MethodPut:
		key, ok := idempotencyKey(request)
		if !ok {
			handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
			return
		}
		version, err := ifMatch(request)
		if err != nil {
			handler.writePreconditionParseError(writer, requestID, err)
			return
		}
		body, err := readJSONBody(writer, request)
		if err != nil {
			handler.writeBodyError(writer, requestID, err)
			return
		}
		receipt, err := handler.service.Replace(request.Context(), reference.ReplaceCommand{
			Principal: principal, WorkspaceID: id, Kind: hierarchy.KindWorkspace,
			ResourceID: id, ExpectedResourceVersion: version,
			CanonicalTarget: request.URL.Path, IdempotencyKey: key, Body: body,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		writer.Header().Set("Location", "/api/v1alpha1/operations/"+receipt.OperationID.String())
		handler.writeJSONValue(writer, http.StatusAccepted, receipt)
	case http.MethodDelete:
		key, ok := idempotencyKey(request)
		if !ok {
			handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
			return
		}
		version, err := ifMatch(request)
		if err != nil {
			handler.writePreconditionParseError(writer, requestID, err)
			return
		}
		receipt, err := handler.service.Delete(request.Context(), reference.DeleteCommand{
			Principal: principal, WorkspaceID: id, Kind: hierarchy.KindWorkspace,
			ResourceID: id, ExpectedResourceVersion: version,
			CanonicalTarget: request.URL.Path, IdempotencyKey: key,
		})
		if err != nil {
			handler.writeServiceError(writer, requestID, err)
			return
		}
		writer.Header().Set("Location", "/api/v1alpha1/operations/"+receipt.OperationID.String())
		handler.writeJSONValue(writer, http.StatusAccepted, receipt)
	default:
		handler.writeMethodNotAllowed(writer, requestID, "DELETE, GET, PUT")
	}
}

func (handler *ReferenceHandler) serveWorkspaceStatus(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal identity.Principal,
	id resource.ID,
) {
	if request.Method != http.MethodPut {
		handler.writeMethodNotAllowed(writer, requestID, "PUT")
		return
	}
	key, ok := idempotencyKey(request)
	if !ok {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	version, err := ifMatch(request)
	if err != nil {
		handler.writePreconditionParseError(writer, requestID, err)
		return
	}
	body, err := readJSONBody(writer, request)
	if err != nil {
		handler.writeBodyError(writer, requestID, err)
		return
	}
	receipt, err := handler.service.ReplaceStatus(request.Context(), reference.StatusCommand{
		Principal: principal, WorkspaceID: id, Kind: hierarchy.KindWorkspace,
		ResourceID: id, ExpectedResourceVersion: version,
		CanonicalTarget: request.URL.Path, IdempotencyKey: key, Body: body,
	})
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	writer.Header().Set("ETag", quoteETag(receipt.ResourceVersion))
	handler.writeJSONValue(writer, http.StatusOK, receipt)
}

func (handler *ReferenceHandler) serveOperation(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal identity.Principal,
) {
	if request.Method != http.MethodGet {
		handler.writeMethodNotAllowed(writer, requestID, "GET")
		return
	}
	value := strings.TrimPrefix(request.URL.Path, "/api/v1alpha1/operations/")
	if value == "" || strings.Contains(value, "/") || request.URL.RawQuery != "" {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	id, err := resource.ParseID(value)
	if err != nil {
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
		return
	}
	operationValue, err := handler.service.GetOperation(request.Context(), principal, id)
	if err != nil {
		handler.writeServiceError(writer, requestID, err)
		return
	}
	writer.Header().Set("ETag", quoteETag(operationValue.Value.ResourceVersion))
	handler.writeJSON(writer, http.StatusOK, operationValue.Canonical)
}

type listQuery struct {
	pageSize  int
	pageToken string
}

func parseListQuery(raw string) (listQuery, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return listQuery{}, err
	}
	for key, entries := range values {
		if key != "pageSize" && key != "pageToken" || len(entries) != 1 || entries[0] == "" {
			return listQuery{}, reference.ErrInvalidCommand
		}
	}
	result := listQuery{}
	if value := values.Get("pageSize"); value != "" {
		result.pageSize, err = strconv.Atoi(value)
		if err != nil || result.pageSize < 1 || result.pageSize > reference.MaxPageSize {
			return listQuery{}, reference.ErrInvalidCommand
		}
	}
	result.pageToken = values.Get("pageToken")
	return result, nil
}

func readJSONBody(writer http.ResponseWriter, request *http.Request) ([]byte, error) {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 {
		return nil, errUnsupportedMediaType
	}
	mediaType, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		return nil, errUnsupportedMediaType
	}
	if request.ContentLength > maxRequestBodyBytes {
		return nil, errRequestTooLarge
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes))
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return nil, errRequestTooLarge
		}
		return nil, err
	}
	return body, nil
}

var (
	errRequestTooLarge      = errors.New("request body is too large")
	errUnsupportedMediaType = errors.New("unsupported request media type")
)

func idempotencyKey(request *http.Request) (string, bool) {
	values := request.Header.Values("Idempotency-Key")
	return singleHeader(values)
}

func ifMatch(request *http.Request) (string, error) {
	values := request.Header.Values("If-Match")
	if len(values) == 0 {
		return "", errPreconditionRequired
	}
	value, ok := singleHeader(values)
	if !ok || !strongETagPattern.MatchString(value) {
		return "", reference.ErrInvalidCommand
	}
	return strings.Trim(value, `"`), nil
}

func singleHeader(values []string) (string, bool) {
	if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], "\r\n") {
		return "", false
	}
	return values[0], true
}

func (handler *ReferenceHandler) requestID(request *http.Request) (string, bool) {
	values := request.Header.Values("Veer-Request-Id")
	if len(values) == 0 {
		return handler.nextRequestID(), true
	}
	value, ok := singleHeader(values)
	if !ok || !requestIDPattern.MatchString(value) {
		return handler.nextRequestID(), false
	}
	return value, true
}

func (handler *ReferenceHandler) nextRequestID() string {
	value := handler.requests.Add(1)
	return fmt.Sprintf("req_%016x", value)
}

type fieldViolation struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type problem struct {
	Type              string           `json:"type"`
	Title             string           `json:"title"`
	Status            int              `json:"status"`
	Instance          string           `json:"instance"`
	Code              string           `json:"code"`
	RequestID         string           `json:"requestId"`
	Errors            []fieldViolation `json:"errors,omitempty"`
	RetryAfterSeconds int              `json:"retryAfterSeconds,omitempty"`
}

func (handler *ReferenceHandler) writeServiceError(writer http.ResponseWriter, requestID string, err error) {
	var admissionFailure *admission.Error
	var precondition *reference.PreconditionError
	switch {
	case errors.As(err, &admissionFailure):
		if admissionFailure.Code() == admission.CodeRequestTooLarge {
			handler.writeProblem(writer, requestID, http.StatusRequestEntityTooLarge, "request-too-large", "Request body is too large", nil)
			return
		}
		if admissionFailure.Stage() == admission.StageDefault || admissionFailure.Stage() == admission.StageConversion {
			handler.writeProblem(writer, requestID, http.StatusInternalServerError, "internal-failure", "Internal failure", nil)
			return
		}
		var violations []fieldViolation
		if admissionFailure.Path() != "" {
			violations = []fieldViolation{{
				Field: admissionFailure.Path(), Code: string(admissionFailure.Code()), Message: "The request field is invalid.",
			}}
		}
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", violations)
	case errors.As(err, &precondition):
		writer.Header().Set("ETag", quoteETag(precondition.CurrentResourceVersion))
		handler.writeProblem(writer, requestID, http.StatusPreconditionFailed, "precondition-failed", "Resource version is stale", nil)
	case errors.Is(err, reference.ErrNotFound):
		handler.writeProblem(writer, requestID, http.StatusNotFound, "not-found", "Resource not found", nil)
	case errors.Is(err, reference.ErrIdempotencyConflict):
		handler.writeProblem(writer, requestID, http.StatusConflict, "idempotency-key-reused", "Request conflicts with a prior mutation", nil)
	case errors.Is(err, reference.ErrLifecycleConflict):
		handler.writeProblem(writer, requestID, http.StatusConflict, "lifecycle-conflict", "Resource lifecycle conflict", nil)
	case errors.Is(err, reference.ErrCapacity):
		handler.writeUnavailable(writer, requestID)
	case errors.Is(err, referenceauthorization.ErrDenied),
		errors.Is(err, referenceauthorization.ErrStaleAuthorization):
		handler.writeProblem(writer, requestID, http.StatusForbidden, "authorization-denied", "Authorization denied", nil)
	case errors.Is(err, referenceauthorization.ErrUnavailable):
		handler.writeUnavailable(writer, requestID)
	case errors.Is(err, reference.ErrInvalidPageToken), errors.Is(err, reference.ErrInvalidCommand):
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
	default:
		handler.writeProblem(writer, requestID, http.StatusInternalServerError, "internal-failure", "Internal failure", nil)
	}
}

func (handler *ReferenceHandler) writeBodyError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, errRequestTooLarge):
		handler.writeProblem(writer, requestID, http.StatusRequestEntityTooLarge, "request-too-large", "Request body is too large", nil)
	case errors.Is(err, errUnsupportedMediaType):
		handler.writeProblem(writer, requestID, http.StatusUnsupportedMediaType, "unsupported-media-type", "Unsupported request media type", nil)
	default:
		handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
	}
}

func (handler *ReferenceHandler) writePreconditionParseError(writer http.ResponseWriter, requestID string, err error) {
	if errors.Is(err, errPreconditionRequired) {
		handler.writeProblem(writer, requestID, http.StatusPreconditionRequired, "precondition-required", "Mutation precondition required", nil)
		return
	}
	handler.writeProblem(writer, requestID, http.StatusBadRequest, "validation-failed", "Request validation failed", nil)
}

func (handler *ReferenceHandler) writeMethodNotAllowed(writer http.ResponseWriter, requestID, allow string) {
	writer.Header().Set("Allow", allow)
	handler.writeProblem(writer, requestID, http.StatusMethodNotAllowed, "method-not-allowed", "Method not allowed", nil)
}

func (handler *ReferenceHandler) writeAuthenticationRequired(writer http.ResponseWriter, requestID, failure string) {
	challenge := `Bearer realm="veer"`
	if failure != "" {
		challenge += ", error=" + strconv.Quote(failure)
	}
	writer.Header().Set("WWW-Authenticate", challenge)
	handler.writeProblem(writer, requestID, http.StatusUnauthorized, "authentication-required", "Authentication required", nil)
}

func (handler *ReferenceHandler) writeUnavailable(writer http.ResponseWriter, requestID string) {
	const retryAfter = 10
	writer.Header().Set("Veer-Request-Id", requestID)
	writer.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writer.Header().Set("Content-Type", "application/problem+json")
	encoded, err := json.Marshal(problem{
		Type: "urn:veer:problem:unavailable", Title: "Service temporarily unavailable",
		Status: http.StatusServiceUnavailable, Instance: "urn:veer:request:" + requestID,
		Code: "unavailable", RequestID: requestID, RetryAfterSeconds: retryAfter,
	})
	if err != nil || len(encoded) > 1_024 {
		handler.writeProblem(writer, requestID, http.StatusInternalServerError, "internal-failure", "Internal failure", nil)
		return
	}
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = writer.Write(encoded)
}

func (handler *ReferenceHandler) writeProblem(
	writer http.ResponseWriter,
	requestID string,
	status int,
	code, title string,
	violations []fieldViolation,
) {
	writer.Header().Set("Veer-Request-Id", requestID)
	writer.Header().Set("Content-Type", "application/problem+json")
	encoded, err := json.Marshal(problem{
		Type: "urn:veer:problem:" + code, Title: title, Status: status,
		Instance: "urn:veer:request:" + requestID, Code: code, RequestID: requestID, Errors: violations,
	})
	if err != nil || len(encoded) > 1_024 {
		const fallbackRequestID = "internal"
		writer.Header().Set("Veer-Request-Id", fallbackRequestID)
		encoded = []byte(`{"type":"urn:veer:problem:internal-failure","title":"Internal failure","status":500,"instance":"urn:veer:request:internal","code":"internal-failure","requestId":"internal"}`)
		status = http.StatusInternalServerError
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded) // #nosec G705 -- VEER-SEC-013: JSON is escaped, typed as problem+json with nosniff, and request IDs have a safe closed grammar
}

func (handler *ReferenceHandler) writeJSONValue(writer http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		handler.writeProblem(writer, writer.Header().Get("Veer-Request-Id"), http.StatusInternalServerError, "internal-failure", "Internal failure", nil)
		return
	}
	handler.writeJSON(writer, status, encoded)
}

func (handler *ReferenceHandler) writeJSON(writer http.ResponseWriter, status int, encoded []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func encodeWorkspacePage(page reference.Page) []byte {
	var encoded bytes.Buffer
	encoded.WriteString(`{"items":[`)
	for index, item := range page.Items {
		if index > 0 {
			encoded.WriteByte(',')
		}
		encoded.Write(item.Canonical)
	}
	encoded.WriteByte(']')
	if page.NextPageToken != "" {
		encoded.WriteString(`,"nextPageToken":`)
		token, _ := json.Marshal(page.NextPageToken)
		encoded.Write(token)
	}
	encoded.WriteByte('}')
	return encoded.Bytes()
}

func quoteETag(version string) string { return strconv.Quote(version) }
