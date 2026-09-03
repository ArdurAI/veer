package admission

import (
	"encoding/json"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

const exactTimestampLayout = "2006-01-02T15:04:05.000Z"

type failureCandidate struct {
	code Code
	path string
}

type candidateSet struct {
	minimum failureCandidate
	present bool
}

// add normalizes an exact path to bounded RFC 6901-or-empty before comparing
// normalized path and then code. Only the current minimum is retained, so
// diagnostics cannot amplify memory in proportion to the number of faults.
func (set *candidateSet) add(code Code, path string) {
	candidate := failureCandidate{code: code, path: boundedPointer(path)}
	if !set.present || candidate.path < set.minimum.path ||
		(candidate.path == set.minimum.path && candidate.code < set.minimum.code) {
		set.minimum = candidate
		set.present = true
	}
}

func (set *candidateSet) failure(stage Stage) *Error {
	if !set.present {
		return nil
	}
	return reject(stage, set.minimum.code, set.minimum.path)
}

func validateIntentSchema(value any, rawCandidates candidateSet) *Error {
	set := rawCandidates
	root := collectObject(&set, value, "", []string{"apiVersion", "kind", "metadata", "spec"}, []string{"apiVersion", "kind", "metadata", "spec"})
	if root == nil {
		return set.failure(StageSchema)
	}
	apiVersion, versionOK := collectString(&set, root, "apiVersion", "")
	if versionOK && apiVersion != hierarchy.APIVersion {
		set.add(CodeUnsupportedVersion, "/apiVersion")
	}
	kindValue, kindStringOK := collectString(&set, root, "kind", "")
	kind, kindOK := hierarchy.ParseKind(kindValue)
	if kindStringOK && kindOK != nil {
		set.add(CodeUnsupportedKind, "/kind")
	}
	if metadata, exists := root["metadata"]; exists {
		collectMetadataSchema(&set, metadata, "/metadata")
	}
	if spec, exists := root["spec"]; exists && kindStringOK && kindOK == nil {
		collectIntentSpecSchema(&set, kind, spec, "/spec")
	}
	return set.failure(StageSchema)
}

func validateStatusSchema(value any, rawCandidates candidateSet) *Error {
	set := rawCandidates
	root := collectObject(&set, value, "", []string{"apiVersion", "kind", "status"}, []string{"apiVersion", "kind", "status"})
	if root == nil {
		return set.failure(StageSchema)
	}
	apiVersion, versionOK := collectString(&set, root, "apiVersion", "")
	if versionOK && apiVersion != hierarchy.APIVersion {
		set.add(CodeUnsupportedVersion, "/apiVersion")
	}
	kindValue, kindStringOK := collectString(&set, root, "kind", "")
	kind, kindOK := hierarchy.ParseKind(kindValue)
	if kindStringOK && kindOK != nil {
		set.add(CodeUnsupportedKind, "/kind")
	}
	if status, exists := root["status"]; exists && kindStringOK && kindOK == nil {
		collectStatusSchema(&set, kind, status, "/status")
	}
	return set.failure(StageSchema)
}

func collectMetadataSchema(set *candidateSet, value any, path string) {
	object := collectObject(set, value, path, []string{"displayName"}, []string{"displayName", "labels"})
	if object == nil {
		return
	}
	if displayName, ok := collectString(set, object, "displayName", path); ok {
		length := utf8.RuneCountInString(displayName)
		if length < 1 || length > 128 {
			set.add(CodeInvalidValue, appendPointer(path, "displayName"))
		}
	}
	labelsValue, exists := object["labels"]
	if !exists {
		return
	}
	labelsPath := appendPointer(path, "labels")
	labels, ok := labelsValue.(map[string]any)
	if !ok {
		set.add(CodeInvalidType, labelsPath)
		return
	}
	if len(labels) > 64 {
		set.add(CodeInvalidValue, labelsPath)
	}
	for name, item := range labels {
		itemPath := appendPointer(labelsPath, name)
		if !labelKeyPattern.MatchString(name) {
			set.add(CodeInvalidValue, itemPath)
		}
		text, ok := item.(string)
		if !ok {
			set.add(CodeInvalidType, itemPath)
			continue
		}
		if utf8.RuneCountInString(text) > 256 {
			set.add(CodeInvalidValue, itemPath)
		}
	}
}

func collectIntentSpecSchema(set *candidateSet, kind hierarchy.Kind, value any, path string) {
	switch kind {
	case hierarchy.KindWorkspace:
		object := collectObject(set, value, path, nil, []string{"suspendReconciliation"})
		if object == nil {
			return
		}
		if flag, exists := object["suspendReconciliation"]; exists {
			if _, ok := flag.(bool); !ok {
				set.add(CodeInvalidType, appendPointer(path, "suspendReconciliation"))
			}
		}
	case hierarchy.KindPolicy:
		collectPolicySpecSchema(set, value, path)
	case hierarchy.KindProviderConnection:
		collectProviderSpecSchema(set, value, path)
	default:
		collectObject(set, value, path, nil, []string{})
	}
}

func collectPolicySpecSchema(set *candidateSet, value any, path string) {
	object := collectObject(set, value, path, []string{"bindings"}, []string{"bindings"})
	if object == nil {
		return
	}
	bindingsValue, exists := object["bindings"]
	if !exists || bindingsValue == nil {
		return
	}
	bindingsPath := appendPointer(path, "bindings")
	bindings, ok := bindingsValue.([]any)
	if !ok {
		set.add(CodeInvalidType, bindingsPath)
		return
	}
	if len(bindings) > authorization.MaxBindingsPerPolicy {
		set.add(CodeInvalidValue, bindingsPath)
	}
	for index, item := range bindings {
		itemPath := appendPointer(bindingsPath, strconv.Itoa(index))
		binding := collectObject(set, item, itemPath,
			[]string{"memberId", "role", "scope"},
			[]string{"memberId", "role", "scope"})
		if binding == nil {
			continue
		}
		collectPatternString(set, binding, "memberId", itemPath, opaqueIDPattern, 128)
		if role, valid := collectString(set, binding, "role", itemPath); valid {
			if _, err := authorization.ParseRole(role); err != nil {
				set.add(CodeInvalidValue, appendPointer(itemPath, "role"))
			}
		}
		scopeValue, exists := binding["scope"]
		if !exists || scopeValue == nil {
			continue
		}
		collectPolicyScopeSchema(set, scopeValue, appendPointer(itemPath, "scope"))
	}
}

func collectPolicyScopeSchema(set *candidateSet, value any, path string) {
	object := collectObject(set, value, path, []string{"kind"}, []string{"kind", "environmentId"})
	if object == nil {
		return
	}
	kindValue, kindValid := collectString(set, object, "kind", path)
	kind, kindErr := authorization.ParseScopeKind(kindValue)
	if kindValid && kindErr != nil {
		set.add(CodeInvalidValue, appendPointer(path, "kind"))
	}
	environmentValue, environmentPresent := object["environmentId"]
	if environmentPresent {
		if environmentValue == nil {
			set.add(CodeInvalidType, appendPointer(path, "environmentId"))
		} else {
			collectPatternString(set, object, "environmentId", path, opaqueIDPattern, 128)
		}
	}
	if !kindValid || kindErr != nil {
		return
	}
	if kind == authorization.ScopeKindWorkspace {
		if environmentPresent {
			set.add(CodeInvalidValue, appendPointer(path, "environmentId"))
		}
		return
	}
	if !environmentPresent {
		set.add(CodeMissingField, appendPointer(path, "environmentId"))
	}
}

func collectProviderSpecSchema(set *candidateSet, value any, path string) {
	object := collectObject(set, value, path, []string{"provider", "credentialRef"}, []string{"provider", "credentialRef"})
	if object == nil {
		return
	}
	if provider, ok := collectString(set, object, "provider", path); ok && !providerPattern.MatchString(provider) {
		set.add(CodeInvalidValue, appendPointer(path, "provider"))
	}
	referenceValue, exists := object["credentialRef"]
	if !exists {
		return
	}
	referencePath := appendPointer(path, "credentialRef")
	reference := collectObject(set, referenceValue, referencePath, []string{"referenceId", "version"}, []string{"referenceId", "version"})
	if reference == nil {
		return
	}
	if referenceID, ok := collectString(set, reference, "referenceId", referencePath); ok && !opaqueIDPattern.MatchString(referenceID) {
		set.add(CodeInvalidValue, appendPointer(referencePath, "referenceId"))
	}
	if version, ok := collectString(set, reference, "version", referencePath); ok && !versionPattern.MatchString(version) {
		set.add(CodeInvalidValue, appendPointer(referencePath, "version"))
	}
}

func collectStatusSchema(set *candidateSet, kind hierarchy.Kind, value any, path string) {
	allowed := []string{"observedGeneration", "conditions"}
	required := append([]string(nil), allowed...)
	if kind == hierarchy.KindProviderConnection {
		allowed = append(allowed, "capabilities", "quotaChecks")
		required = append(required, "capabilities", "quotaChecks")
	}
	object := collectObject(set, value, path, required, allowed)
	if object == nil {
		return
	}
	collectNonNegativeInt64(set, object, "observedGeneration", path)
	if conditions, exists := object["conditions"]; exists {
		collectConditionsSchema(set, conditions, appendPointer(path, "conditions"))
	}
	if kind != hierarchy.KindProviderConnection {
		return
	}
	if capabilities, exists := object["capabilities"]; exists {
		collectCapabilitiesSchema(set, capabilities, appendPointer(path, "capabilities"))
	}
	if quotas, exists := object["quotaChecks"]; exists {
		collectQuotasSchema(set, quotas, appendPointer(path, "quotaChecks"))
	}
}

func collectConditionsSchema(set *candidateSet, value any, path string) {
	values, ok := value.([]any)
	if !ok {
		set.add(CodeInvalidType, path)
		return
	}
	if len(values) > condition.MaxConditions {
		set.add(CodeInvalidValue, path)
	}
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object := collectObject(set, item, itemPath,
			[]string{"type", "status", "reason", "message", "observedGeneration", "lastTransitionAt"},
			[]string{"type", "status", "reason", "message", "observedGeneration", "lastTransitionAt"})
		if object == nil {
			continue
		}
		collectPatternString(set, object, "type", itemPath, conditionPattern, 64)
		if status, valid := collectString(set, object, "status", itemPath); valid && status != "True" && status != "False" && status != "Unknown" {
			set.add(CodeInvalidValue, appendPointer(itemPath, "status"))
		}
		collectPatternString(set, object, "reason", itemPath, conditionPattern, 64)
		if message, valid := collectString(set, object, "message", itemPath); valid && utf8.RuneCountInString(message) > 512 {
			set.add(CodeInvalidValue, appendPointer(itemPath, "message"))
		}
		collectNonNegativeInt64(set, object, "observedGeneration", itemPath)
		collectTimestamp(set, object, "lastTransitionAt", itemPath)
	}
}

func collectCapabilitiesSchema(set *candidateSet, value any, path string) {
	values, ok := value.([]any)
	if !ok {
		set.add(CodeInvalidType, path)
		return
	}
	if len(values) > 128 {
		set.add(CodeInvalidValue, path)
	}
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object := collectObject(set, item, itemPath,
			[]string{"name", "state", "source", "observedAt", "reason"},
			[]string{"name", "state", "source", "observedAt", "reason"})
		if object == nil {
			continue
		}
		collectPatternString(set, object, "name", itemPath, observationPattern, 128)
		if state, valid := collectString(set, object, "state", itemPath); valid && state != "Supported" && state != "Unsupported" && state != "Unknown" {
			set.add(CodeInvalidValue, appendPointer(itemPath, "state"))
		}
		collectPatternString(set, object, "source", itemPath, sourcePattern, 64)
		collectTimestamp(set, object, "observedAt", itemPath)
		collectPatternString(set, object, "reason", itemPath, conditionPattern, 64)
	}
}

func collectQuotasSchema(set *candidateSet, value any, path string) {
	values, ok := value.([]any)
	if !ok {
		set.add(CodeInvalidType, path)
		return
	}
	if len(values) > 128 {
		set.add(CodeInvalidValue, path)
	}
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object := collectObject(set, item, itemPath,
			[]string{"name", "state", "source", "observedAt", "reason"},
			[]string{"name", "state", "requested", "available", "source", "observedAt", "reason"})
		if object == nil {
			continue
		}
		collectPatternString(set, object, "name", itemPath, observationPattern, 128)
		state, stateOK := collectString(set, object, "state", itemPath)
		if stateOK && state != "WithinLimit" && state != "Exceeded" && state != "Unknown" {
			set.add(CodeInvalidValue, appendPointer(itemPath, "state"))
		}
		requestedPresent := collectOptionalDecimal(set, object, "requested", itemPath)
		availablePresent := collectOptionalDecimal(set, object, "available", itemPath)
		if stateOK {
			if state == "Unknown" && (requestedPresent || availablePresent) {
				set.add(CodeInvalidValue, appendPointer(itemPath, "state"))
			}
			if state == "WithinLimit" || state == "Exceeded" {
				if !availablePresent {
					set.add(CodeMissingField, appendPointer(itemPath, "available"))
				}
				if !requestedPresent {
					set.add(CodeMissingField, appendPointer(itemPath, "requested"))
				}
			}
		}
		collectPatternString(set, object, "source", itemPath, sourcePattern, 64)
		collectTimestamp(set, object, "observedAt", itemPath)
		collectPatternString(set, object, "reason", itemPath, conditionPattern, 64)
	}
}

func collectObject(
	set *candidateSet,
	value any,
	path string,
	required []string,
	allowed []string,
) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		set.add(CodeInvalidType, path)
		return nil
	}
	for _, name := range required {
		if member, exists := object[name]; !exists {
			set.add(CodeMissingField, appendPointer(path, name))
		} else if member == nil {
			set.add(CodeInvalidType, appendPointer(path, name))
		}
	}
	if allowed == nil {
		return object
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range object {
		if _, valid := allowedSet[name]; !valid {
			set.add(CodeUnknownField, appendPointer(path, name))
		}
	}
	return object
}

func collectString(set *candidateSet, object map[string]any, name, path string) (string, bool) {
	value, exists := object[name]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		set.add(CodeInvalidType, appendPointer(path, name))
		return "", false
	}
	return text, true
}

func collectPatternString(set *candidateSet, object map[string]any, name, path string, pattern interface{ MatchString(string) bool }, maxRunes int) {
	if text, ok := collectString(set, object, name, path); ok &&
		(utf8.RuneCountInString(text) > maxRunes || !pattern.MatchString(text)) {
		set.add(CodeInvalidValue, appendPointer(path, name))
	}
}

func collectNonNegativeInt64(set *candidateSet, object map[string]any, name, path string) {
	value, exists := object[name]
	if !exists || value == nil {
		return
	}
	number, ok := value.(json.Number)
	if !ok {
		set.add(CodeInvalidType, appendPointer(path, name))
		return
	}
	_, valid := nonNegativeInt64(number)
	if !valid {
		set.add(CodeInvalidValue, appendPointer(path, name))
	}
}

func collectTimestamp(set *candidateSet, object map[string]any, name, path string) {
	text, ok := collectString(set, object, name, path)
	if !ok {
		return
	}
	parsed, err := time.Parse(exactTimestampLayout, text)
	if err != nil || parsed.Format(exactTimestampLayout) != text {
		set.add(CodeInvalidValue, appendPointer(path, name))
	}
}

func collectOptionalDecimal(set *candidateSet, object map[string]any, name, path string) bool {
	value, exists := object[name]
	if !exists {
		return false
	}
	text, ok := value.(string)
	if !ok {
		set.add(CodeInvalidType, appendPointer(path, name))
		return true
	}
	if len(text) > 64 || !decimalPattern.MatchString(text) {
		set.add(CodeInvalidValue, appendPointer(path, name))
	}
	return true
}
