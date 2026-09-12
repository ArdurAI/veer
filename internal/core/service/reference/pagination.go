package reference

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/identity"
	"github.com/ArdurAI/veer/internal/core/domain/isolation"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

const opaquePageTokenBytes = 46 // "p1_" plus a base64url-encoded SHA-256 HMAC.

var pageTokenPattern = regexp.MustCompile(`^p1_[A-Za-z0-9_-]{43}$`)

type pageBinding struct {
	principal      string
	workspaceScope string
	kind           hierarchy.Kind
	parentID       *resource.ID
	filter         string
}

type pageTokenRecord struct {
	binding       pageBinding
	lastCreatedAt time.Time
	lastID        resource.ID
	issuedAt      time.Time
	expiresAt     time.Time
}

// List returns one deterministic keyset page ordered by (createdAt, id).
func (service *Service) List(ctx context.Context, query ListQuery) (Page, error) {
	return service.listWhere(ctx, query, nil)
}

// ListWhere returns one deterministic page after applying retain to every
// matching row. Filtering precedes ordering, page-size accounting, and cursor
// issuance so an unauthorized row cannot influence the caller's page shape.
func (service *Service) ListWhere(
	ctx context.Context,
	query ListQuery,
	retain func(Resource, AuthorizationStateResolver) (bool, error),
) (Page, error) {
	if retain == nil {
		return Page{}, ErrInvalidConfiguration
	}
	return service.listWhere(ctx, query, retain)
}

func (service *Service) listWhere(
	ctx context.Context,
	query ListQuery,
	retain func(Resource, AuthorizationStateResolver) (bool, error),
) (Page, error) {
	if service == nil {
		return Page{}, ErrInvalidConfiguration
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || identity.ValidatePrincipal(query.Principal) != nil {
		if ctx != nil && ctx.Err() != nil {
			return Page{}, ctx.Err()
		}
		return Page{}, ErrInvalidCommand
	}
	if _, err := hierarchy.ParseKind(query.Kind.String()); err != nil {
		return Page{}, ErrInvalidCommand
	}
	if query.PageSize == 0 {
		query.PageSize = DefaultPageSize
	}
	if query.PageSize < 1 || query.PageSize > MaxPageSize || len(query.PageToken) > MaxPageTokenBytes {
		return Page{}, ErrInvalidCommand
	}
	labels, err := resource.NormalizeLabels(query.MatchLabels)
	if err != nil {
		return Page{}, ErrInvalidCommand
	}
	query.MatchLabels = labels
	var workspaceScopes isolation.WorkspaceScopeSet
	if query.Kind == hierarchy.KindWorkspace {
		if query.WorkspaceID != "" || query.ParentID != nil {
			return Page{}, ErrInvalidCommand
		}
		workspaceScopes, err = isolation.NewWorkspaceScopeSet(query.WorkspaceIDs...)
	} else {
		if len(query.WorkspaceIDs) != 0 || resourceIDInvalid(query.WorkspaceID) {
			return Page{}, ErrInvalidCommand
		}
		_, workspaceScopes, err = newWorkspaceScopes(query.WorkspaceID)
	}
	if err != nil {
		return Page{}, ErrInvalidCommand
	}
	query.WorkspaceIDs = workspaceScopes.WorkspaceIDs()
	if query.ParentID != nil && resourceIDInvalid(*query.ParentID) {
		return Page{}, ErrInvalidCommand
	}

	now := service.clock.Now()
	binding := pageBinding{
		principal: query.Principal.Fingerprint().String(), workspaceScope: scopeDigest(workspaceScopes),
		kind: query.Kind, parentID: cloneID(query.ParentID), filter: filterDigest(labels),
	}
	var cursor *pageTokenRecord
	if query.PageToken != "" {
		value, err := service.resolvePageToken(query.PageToken, binding, now)
		if err != nil {
			return Page{}, err
		}
		cursor = &value
	}

	var candidates []Resource
	err = service.store.View(ctx, workspaceScopes, func(reader ports.ReferenceReader) error {
		values, err := loadResources(reader, workspaceScopes)
		if err != nil {
			return err
		}
		candidates = make([]Resource, 0, len(values))
		resolve := func(
			workspaceID resource.ID,
			members authorization.MemberDirectory,
		) (AuthorizationState, error) {
			return authorizationStateFor(values, workspaceID, members)
		}
		for _, value := range values {
			if !matchesList(value, query) {
				continue
			}
			if retain != nil {
				keep, err := retain(cloneResource(value), resolve)
				if err != nil {
					return err
				}
				if !keep {
					continue
				}
			}
			if cursor != nil && !afterCursor(value, *cursor) {
				continue
			}
			candidates = append(candidates, cloneResource(value))
		}
		return nil
	})
	if err != nil {
		return Page{}, err
	}
	sort.Slice(candidates, func(left, right int) bool {
		leftTime, rightTime := candidates[left].Metadata.CreatedAt(), candidates[right].Metadata.CreatedAt()
		if !leftTime.Equal(rightTime) {
			return leftTime.Before(rightTime)
		}
		return candidates[left].Metadata.ID().String() < candidates[right].Metadata.ID().String()
	})

	selected := make([]Resource, 0, min(query.PageSize, len(candidates)))
	for index, candidate := range candidates {
		if len(selected) == query.PageSize {
			break
		}
		willContinue := index < len(candidates)-1 || len(selected)+1 == query.PageSize && len(candidates) > len(selected)+1
		tokenBytes := 0
		if willContinue {
			tokenBytes = opaquePageTokenBytes
		}
		if encodedPageSize(append(selected, candidate), tokenBytes) > MaxPageBytes {
			if len(selected) == 0 {
				return Page{}, ErrPageTooLarge
			}
			break
		}
		selected = append(selected, candidate)
	}

	page := Page{Items: selected}
	if len(selected) < len(candidates) {
		last := selected[len(selected)-1]
		token, err := service.issuePageToken(pageTokenRecord{
			binding: binding, lastCreatedAt: last.Metadata.CreatedAt(), lastID: last.Metadata.ID(),
			issuedAt: now, expiresAt: now.Add(PageTokenLifetime),
		}, now)
		if err != nil {
			return Page{}, err
		}
		page.NextPageToken = token
	}
	if encodedPageSize(page.Items, len(page.NextPageToken)) > MaxPageBytes {
		return Page{}, fmt.Errorf("%w: encoded page bound", ErrInternal)
	}
	return page, nil
}

func matchesList(value Resource, query ListQuery) bool {
	if value.Kind != query.Kind {
		return false
	}
	if query.Kind != hierarchy.KindWorkspace && value.Metadata.WorkspaceID() != query.WorkspaceID {
		return false
	}
	if query.ParentID != nil {
		parent, present := value.Metadata.Parent()
		if !present || parent != *query.ParentID {
			return false
		}
	}
	labels := value.Metadata.Labels()
	for key, expected := range query.MatchLabels {
		actual, present := labels[key]
		if !present || actual != expected {
			return false
		}
	}
	return true
}

func afterCursor(value Resource, cursor pageTokenRecord) bool {
	createdAt := value.Metadata.CreatedAt()
	if createdAt.After(cursor.lastCreatedAt) {
		return true
	}
	return createdAt.Equal(cursor.lastCreatedAt) && value.Metadata.ID().String() > cursor.lastID.String()
}

func (service *Service) issuePageToken(record pageTokenRecord, now time.Time) (string, error) {
	service.reclaimPageTokens(now)
	if len(service.tokens) >= service.tokenLimit || record.lastID == "" || !record.expiresAt.After(record.issuedAt) {
		return "", ErrCapacity
	}
	canonical := tokenCanonical(record)
	mac := hmac.New(sha256.New, service.tokenKey)
	_, _ = mac.Write(canonical)
	token := "p1_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > MaxPageTokenBytes || !pageTokenPattern.MatchString(token) {
		return "", fmt.Errorf("%w: page-token encoding", ErrInternal)
	}
	service.tokens[token] = clonePageTokenRecord(record)
	return token, nil
}

func (service *Service) resolvePageToken(token string, binding pageBinding, now time.Time) (pageTokenRecord, error) {
	if len(token) > MaxPageTokenBytes || !pageTokenPattern.MatchString(token) {
		return pageTokenRecord{}, ErrInvalidPageToken
	}
	record, exists := service.tokens[token]
	if !exists || !now.Before(record.expiresAt) || !equalPageBinding(record.binding, binding) {
		return pageTokenRecord{}, ErrInvalidPageToken
	}
	return clonePageTokenRecord(record), nil
}

func (service *Service) reclaimPageTokens(now time.Time) {
	for token, record := range service.tokens {
		if !now.Before(record.expiresAt) {
			delete(service.tokens, token)
		}
	}
}

func tokenCanonical(record pageTokenRecord) []byte {
	parent := ""
	if record.binding.parentID != nil {
		parent = record.binding.parentID.String()
	}
	value := []string{
		"veer.reference.page-token.v1", record.binding.principal, record.binding.workspaceScope,
		record.binding.kind.String(), parent, record.binding.filter,
		record.lastCreatedAt.UTC().Format(timestampLayout), record.lastID.String(),
		record.issuedAt.UTC().Format(timestampLayout), record.expiresAt.UTC().Format(timestampLayout),
	}
	return []byte(strings.Join(value, "\x00"))
}

func filterDigest(labels map[string]string) string {
	canonical, _ := json.Marshal(labels)
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:])
}

func scopeDigest(scopes isolation.WorkspaceScopeSet) string {
	hasher := sha256.New()
	for _, workspaceID := range scopes.WorkspaceIDs() {
		_, _ = hasher.Write([]byte(workspaceID.String()))
		_, _ = hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func equalPageBinding(left, right pageBinding) bool {
	if left.principal != right.principal || left.workspaceScope != right.workspaceScope ||
		left.kind != right.kind || left.filter != right.filter {
		return false
	}
	if left.parentID == nil || right.parentID == nil {
		return left.parentID == nil && right.parentID == nil
	}
	return *left.parentID == *right.parentID
}

func clonePageTokenRecord(value pageTokenRecord) pageTokenRecord {
	value.binding.parentID = cloneID(value.binding.parentID)
	return value
}

func encodedPageSize(items []Resource, tokenBytes int) int {
	size := len(`{"items":[`) + len(`]}`)
	for index, item := range items {
		size += len(item.Canonical)
		if index > 0 {
			size++
		}
	}
	if tokenBytes > 0 {
		size += len(`,"nextPageToken":""`) + tokenBytes
	}
	return size
}
