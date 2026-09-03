package admission

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/authorization"
	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

var (
	labelKeyPattern    = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,62}$`)
	providerPattern    = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	observationPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,127}$`)
	sourcePattern      = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	conditionPattern   = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,63}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	opaqueIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$`)
	decimalPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$`)
)

type sourceMetadata struct {
	displayName string
	labels      map[string]string
}

type sourceWorkspaceSpec struct {
	suspendReconciliation *bool
}

type sourceIntent struct {
	apiVersion string
	kind       hierarchy.Kind
	metadata   sourceMetadata
	workspace  sourceWorkspaceSpec
	policy     model.PolicySpec
	provider   model.ProviderConnectionSpec
}

type sourceStatus struct {
	apiVersion string
	kind       hierarchy.Kind
	common     model.CommonStatus
	provider   model.ProviderConnectionStatus
}

func schemaIntent(document rawDocument) (sourceIntent, *Error) {
	if failure := validateIntentSchema(document.value, document.candidates); failure != nil {
		return sourceIntent{}, failure
	}
	value := document.value
	object, failure := schemaObject(value, "")
	if failure != nil {
		return sourceIntent{}, failure
	}
	if failure := rejectUnknown(object, "", "apiVersion", "kind", "metadata", "spec"); failure != nil {
		return sourceIntent{}, failure
	}
	apiVersion, failure := requiredString(object, "apiVersion", "")
	if failure != nil {
		return sourceIntent{}, failure
	}
	if apiVersion != hierarchy.APIVersion {
		return sourceIntent{}, reject(StageSchema, CodeUnsupportedVersion, "/apiVersion")
	}
	kindValue, failure := requiredString(object, "kind", "")
	if failure != nil {
		return sourceIntent{}, failure
	}
	kind, err := hierarchy.ParseKind(kindValue)
	if err != nil {
		return sourceIntent{}, reject(StageSchema, CodeUnsupportedKind, "/kind")
	}
	metadataValue, failure := required(object, "metadata", "")
	if failure != nil {
		return sourceIntent{}, failure
	}
	metadata, failure := schemaMetadata(metadataValue, "/metadata")
	if failure != nil {
		return sourceIntent{}, failure
	}
	specValue, failure := required(object, "spec", "")
	if failure != nil {
		return sourceIntent{}, failure
	}

	result := sourceIntent{apiVersion: apiVersion, kind: kind, metadata: metadata}
	switch kind {
	case hierarchy.KindWorkspace:
		result.workspace, failure = schemaWorkspaceSpec(specValue, "/spec")
	case hierarchy.KindPolicy:
		result.policy, failure = schemaPolicySpec(specValue, "/spec")
	case hierarchy.KindProviderConnection:
		result.provider, failure = schemaProviderSpec(specValue, "/spec")
	default:
		failure = schemaEmptySpec(specValue, "/spec")
	}
	if failure != nil {
		return sourceIntent{}, failure
	}
	return result, nil
}

func schemaStatus(document rawDocument) (sourceStatus, *Error) {
	if failure := validateStatusSchema(document.value, document.candidates); failure != nil {
		return sourceStatus{}, failure
	}
	value := document.value
	object, failure := schemaObject(value, "")
	if failure != nil {
		return sourceStatus{}, failure
	}
	if failure := rejectUnknown(object, "", "apiVersion", "kind", "status"); failure != nil {
		return sourceStatus{}, failure
	}
	apiVersion, failure := requiredString(object, "apiVersion", "")
	if failure != nil {
		return sourceStatus{}, failure
	}
	if apiVersion != hierarchy.APIVersion {
		return sourceStatus{}, reject(StageSchema, CodeUnsupportedVersion, "/apiVersion")
	}
	kindValue, failure := requiredString(object, "kind", "")
	if failure != nil {
		return sourceStatus{}, failure
	}
	kind, err := hierarchy.ParseKind(kindValue)
	if err != nil {
		return sourceStatus{}, reject(StageSchema, CodeUnsupportedKind, "/kind")
	}
	statusValue, failure := required(object, "status", "")
	if failure != nil {
		return sourceStatus{}, failure
	}

	result := sourceStatus{apiVersion: apiVersion, kind: kind}
	if kind == hierarchy.KindProviderConnection {
		result.provider, failure = schemaProviderStatus(statusValue, "/status")
	} else {
		result.common, failure = schemaCommonStatus(statusValue, "/status")
	}
	if failure != nil {
		return sourceStatus{}, failure
	}
	return result, nil
}

func schemaMetadata(value any, path string) (sourceMetadata, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return sourceMetadata{}, failure
	}
	if failure := rejectUnknown(object, path, "displayName", "labels"); failure != nil {
		return sourceMetadata{}, failure
	}
	displayName, failure := requiredString(object, "displayName", path)
	if failure != nil {
		return sourceMetadata{}, failure
	}
	if count := utf8.RuneCountInString(displayName); count < 1 || count > 128 {
		return sourceMetadata{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "displayName"))
	}
	result := sourceMetadata{displayName: displayName}
	labelsValue, present := object["labels"]
	if !present {
		return result, nil
	}
	labelsObject, failure := schemaObject(labelsValue, appendPointer(path, "labels"))
	if failure != nil {
		return sourceMetadata{}, failure
	}
	if len(labelsObject) > 64 {
		return sourceMetadata{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "labels"))
	}
	keys := sortedKeys(labelsObject)
	result.labels = make(map[string]string, len(keys))
	for _, key := range keys {
		keyPath := appendPointer(appendPointer(path, "labels"), key)
		if !labelKeyPattern.MatchString(key) {
			return sourceMetadata{}, reject(StageSchema, CodeInvalidValue, keyPath)
		}
		text, ok := labelsObject[key].(string)
		if !ok {
			return sourceMetadata{}, reject(StageSchema, CodeInvalidType, keyPath)
		}
		if utf8.RuneCountInString(text) > 256 {
			return sourceMetadata{}, reject(StageSchema, CodeInvalidValue, keyPath)
		}
		result.labels[key] = text
	}
	return result, nil
}

func schemaWorkspaceSpec(value any, path string) (sourceWorkspaceSpec, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return sourceWorkspaceSpec{}, failure
	}
	if failure := rejectUnknown(object, path, "suspendReconciliation"); failure != nil {
		return sourceWorkspaceSpec{}, failure
	}
	value, present := object["suspendReconciliation"]
	if !present {
		return sourceWorkspaceSpec{}, nil
	}
	flag, ok := value.(bool)
	if !ok {
		return sourceWorkspaceSpec{}, reject(StageSchema, CodeInvalidType, appendPointer(path, "suspendReconciliation"))
	}
	return sourceWorkspaceSpec{suspendReconciliation: &flag}, nil
}

func schemaPolicySpec(value any, path string) (model.PolicySpec, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return model.PolicySpec{}, failure
	}
	if failure := rejectUnknown(object, path, "bindings"); failure != nil {
		return model.PolicySpec{}, failure
	}
	bindingsValue, failure := required(object, "bindings", path)
	if failure != nil {
		return model.PolicySpec{}, failure
	}
	values, ok := bindingsValue.([]any)
	if !ok {
		return model.PolicySpec{}, reject(StageSchema, CodeInvalidType, appendPointer(path, "bindings"))
	}
	if len(values) > authorization.MaxBindingsPerPolicy {
		return model.PolicySpec{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "bindings"))
	}

	bindings := make([]authorization.RoleBinding, len(values))
	for index, item := range values {
		itemPath := appendPointer(appendPointer(path, "bindings"), strconv.Itoa(index))
		binding, failure := schemaPolicyBinding(item, itemPath)
		if failure != nil {
			return model.PolicySpec{}, failure
		}
		bindings[index] = binding
	}
	return model.PolicySpec{Bindings: bindings}, nil
}

func schemaPolicyBinding(value any, path string) (authorization.RoleBinding, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return authorization.RoleBinding{}, failure
	}
	if failure := rejectUnknown(object, path, "memberId", "role", "scope"); failure != nil {
		return authorization.RoleBinding{}, failure
	}
	memberID, failure := requiredPatternString(object, "memberId", path, opaqueIDPattern, 128)
	if failure != nil {
		return authorization.RoleBinding{}, failure
	}
	roleValue, failure := requiredString(object, "role", path)
	if failure != nil {
		return authorization.RoleBinding{}, failure
	}
	role, err := authorization.ParseRole(roleValue)
	if err != nil {
		return authorization.RoleBinding{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "role"))
	}
	scopeValue, failure := required(object, "scope", path)
	if failure != nil {
		return authorization.RoleBinding{}, failure
	}
	scope, failure := schemaPolicyScope(scopeValue, appendPointer(path, "scope"))
	if failure != nil {
		return authorization.RoleBinding{}, failure
	}
	return authorization.RoleBinding{MemberID: resource.ID(memberID), Role: role, Scope: scope}, nil
}

func schemaPolicyScope(value any, path string) (authorization.Scope, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return authorization.Scope{}, failure
	}
	if failure := rejectUnknown(object, path, "kind", "environmentId"); failure != nil {
		return authorization.Scope{}, failure
	}
	kindValue, failure := requiredString(object, "kind", path)
	if failure != nil {
		return authorization.Scope{}, failure
	}
	kind, err := authorization.ParseScopeKind(kindValue)
	if err != nil {
		return authorization.Scope{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "kind"))
	}
	environmentValue, environmentPresent := object["environmentId"]
	if kind == authorization.ScopeKindWorkspace {
		if environmentPresent {
			if _, ok := environmentValue.(string); !ok {
				return authorization.Scope{}, reject(StageSchema, CodeInvalidType, appendPointer(path, "environmentId"))
			}
			return authorization.Scope{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "environmentId"))
		}
		return authorization.Scope{Kind: kind}, nil
	}
	if !environmentPresent {
		return authorization.Scope{}, reject(StageSchema, CodeMissingField, appendPointer(path, "environmentId"))
	}
	environmentID, failure := requiredPatternString(object, "environmentId", path, opaqueIDPattern, 128)
	if failure != nil {
		return authorization.Scope{}, failure
	}
	parsedEnvironmentID := resource.ID(environmentID)
	return authorization.Scope{Kind: kind, EnvironmentID: &parsedEnvironmentID}, nil
}

func schemaEmptySpec(value any, path string) *Error {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return failure
	}
	return rejectUnknown(object, path)
}

func schemaProviderSpec(value any, path string) (model.ProviderConnectionSpec, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	if failure := rejectUnknown(object, path, "provider", "credentialRef"); failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	provider, failure := requiredString(object, "provider", path)
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	if !providerPattern.MatchString(provider) {
		return model.ProviderConnectionSpec{}, reject(StageSchema, CodeInvalidValue, appendPointer(path, "provider"))
	}
	referenceValue, failure := required(object, "credentialRef", path)
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	referenceObject, failure := schemaObject(referenceValue, appendPointer(path, "credentialRef"))
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	if failure := rejectUnknown(referenceObject, appendPointer(path, "credentialRef"), "referenceId", "version"); failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	referenceID, failure := requiredString(referenceObject, "referenceId", appendPointer(path, "credentialRef"))
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	if !opaqueIDPattern.MatchString(referenceID) {
		return model.ProviderConnectionSpec{}, reject(StageSchema, CodeInvalidValue, appendPointer(appendPointer(path, "credentialRef"), "referenceId"))
	}
	version, failure := requiredString(referenceObject, "version", appendPointer(path, "credentialRef"))
	if failure != nil {
		return model.ProviderConnectionSpec{}, failure
	}
	if !versionPattern.MatchString(version) {
		return model.ProviderConnectionSpec{}, reject(StageSchema, CodeInvalidValue, appendPointer(appendPointer(path, "credentialRef"), "version"))
	}
	return model.ProviderConnectionSpec{
		Provider:      provider,
		CredentialRef: model.CredentialReference{ReferenceID: referenceID, Version: version},
	}, nil
}

func schemaCommonStatus(value any, path string) (model.CommonStatus, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	if failure := rejectUnknown(object, path, "observedGeneration", "conditions"); failure != nil {
		return model.CommonStatus{}, failure
	}
	observed, failure := requiredNonNegativeInt64(object, "observedGeneration", path)
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	conditionsValue, failure := required(object, "conditions", path)
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	conditions, failure := schemaConditions(conditionsValue, appendPointer(path, "conditions"))
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	return model.CommonStatus{ObservedGeneration: observed, Conditions: conditions}, nil
}

func schemaProviderStatus(value any, path string) (model.ProviderConnectionStatus, *Error) {
	object, failure := schemaObject(value, path)
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	if failure := rejectUnknown(object, path, "observedGeneration", "conditions", "capabilities", "quotaChecks"); failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	common, failure := schemaCommonStatusFields(object, path)
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	capabilitiesValue, failure := required(object, "capabilities", path)
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	capabilities, failure := schemaCapabilities(capabilitiesValue, appendPointer(path, "capabilities"))
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	quotaValue, failure := required(object, "quotaChecks", path)
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	quotas, failure := schemaQuotaChecks(quotaValue, appendPointer(path, "quotaChecks"))
	if failure != nil {
		return model.ProviderConnectionStatus{}, failure
	}
	return model.ProviderConnectionStatus{
		ObservedGeneration: common.ObservedGeneration,
		Conditions:         common.Conditions,
		Capabilities:       capabilities,
		QuotaChecks:        quotas,
	}, nil
}

func schemaCommonStatusFields(object map[string]any, path string) (model.CommonStatus, *Error) {
	observed, failure := requiredNonNegativeInt64(object, "observedGeneration", path)
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	conditionsValue, failure := required(object, "conditions", path)
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	conditions, failure := schemaConditions(conditionsValue, appendPointer(path, "conditions"))
	if failure != nil {
		return model.CommonStatus{}, failure
	}
	return model.CommonStatus{ObservedGeneration: observed, Conditions: conditions}, nil
}

func schemaConditions(value any, path string) ([]condition.Condition, *Error) {
	values, ok := value.([]any)
	if !ok {
		return nil, reject(StageSchema, CodeInvalidType, path)
	}
	if len(values) > condition.MaxConditions {
		return nil, reject(StageSchema, CodeInvalidValue, path)
	}
	result := make([]condition.Condition, len(values))
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object, failure := schemaObject(item, itemPath)
		if failure != nil {
			return nil, failure
		}
		if failure := rejectUnknown(object, itemPath, "type", "status", "reason", "message", "observedGeneration", "lastTransitionAt"); failure != nil {
			return nil, failure
		}
		typeName, failure := requiredPatternString(object, "type", itemPath, conditionPattern, 64)
		if failure != nil {
			return nil, failure
		}
		status, failure := requiredString(object, "status", itemPath)
		if failure != nil {
			return nil, failure
		}
		if status != "True" && status != "False" && status != "Unknown" {
			return nil, reject(StageSchema, CodeInvalidValue, appendPointer(itemPath, "status"))
		}
		reason, failure := requiredPatternString(object, "reason", itemPath, conditionPattern, 64)
		if failure != nil {
			return nil, failure
		}
		message, failure := requiredString(object, "message", itemPath)
		if failure != nil {
			return nil, failure
		}
		if utf8.RuneCountInString(message) > 512 {
			return nil, reject(StageSchema, CodeInvalidValue, appendPointer(itemPath, "message"))
		}
		observed, failure := requiredNonNegativeInt64(object, "observedGeneration", itemPath)
		if failure != nil {
			return nil, failure
		}
		lastTransitionAt, failure := requiredString(object, "lastTransitionAt", itemPath)
		if failure != nil {
			return nil, failure
		}
		result[index] = condition.Condition{
			Type: typeName, Status: condition.Status(status), Reason: reason, Message: message,
			ObservedGeneration: observed, LastTransitionAt: lastTransitionAt,
		}
	}
	return result, nil
}

func schemaCapabilities(value any, path string) ([]model.ProviderCapability, *Error) {
	values, ok := value.([]any)
	if !ok {
		return nil, reject(StageSchema, CodeInvalidType, path)
	}
	if len(values) > 128 {
		return nil, reject(StageSchema, CodeInvalidValue, path)
	}
	result := make([]model.ProviderCapability, len(values))
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object, failure := schemaObject(item, itemPath)
		if failure != nil {
			return nil, failure
		}
		if failure := rejectUnknown(object, itemPath, "name", "state", "source", "observedAt", "reason"); failure != nil {
			return nil, failure
		}
		name, failure := requiredPatternString(object, "name", itemPath, observationPattern, 128)
		if failure != nil {
			return nil, failure
		}
		state, failure := requiredString(object, "state", itemPath)
		if failure != nil {
			return nil, failure
		}
		if state != "Supported" && state != "Unsupported" && state != "Unknown" {
			return nil, reject(StageSchema, CodeInvalidValue, appendPointer(itemPath, "state"))
		}
		source, failure := requiredPatternString(object, "source", itemPath, sourcePattern, 64)
		if failure != nil {
			return nil, failure
		}
		observedAt, failure := requiredString(object, "observedAt", itemPath)
		if failure != nil {
			return nil, failure
		}
		reason, failure := requiredPatternString(object, "reason", itemPath, conditionPattern, 64)
		if failure != nil {
			return nil, failure
		}
		result[index] = model.ProviderCapability{Name: name, State: model.CapabilityState(state), Source: source, ObservedAt: observedAt, Reason: reason}
	}
	return result, nil
}

func schemaQuotaChecks(value any, path string) ([]model.QuotaCheck, *Error) {
	values, ok := value.([]any)
	if !ok {
		return nil, reject(StageSchema, CodeInvalidType, path)
	}
	if len(values) > 128 {
		return nil, reject(StageSchema, CodeInvalidValue, path)
	}
	result := make([]model.QuotaCheck, len(values))
	for index, item := range values {
		itemPath := appendPointer(path, strconv.Itoa(index))
		object, failure := schemaObject(item, itemPath)
		if failure != nil {
			return nil, failure
		}
		if failure := rejectUnknown(object, itemPath, "name", "state", "requested", "available", "source", "observedAt", "reason"); failure != nil {
			return nil, failure
		}
		name, failure := requiredPatternString(object, "name", itemPath, observationPattern, 128)
		if failure != nil {
			return nil, failure
		}
		state, failure := requiredString(object, "state", itemPath)
		if failure != nil {
			return nil, failure
		}
		if state != "WithinLimit" && state != "Exceeded" && state != "Unknown" {
			return nil, reject(StageSchema, CodeInvalidValue, appendPointer(itemPath, "state"))
		}
		requested, failure := optionalDecimal(object, "requested", itemPath)
		if failure != nil {
			return nil, failure
		}
		available, failure := optionalDecimal(object, "available", itemPath)
		if failure != nil {
			return nil, failure
		}
		source, failure := requiredPatternString(object, "source", itemPath, sourcePattern, 64)
		if failure != nil {
			return nil, failure
		}
		observedAt, failure := requiredString(object, "observedAt", itemPath)
		if failure != nil {
			return nil, failure
		}
		reason, failure := requiredPatternString(object, "reason", itemPath, conditionPattern, 64)
		if failure != nil {
			return nil, failure
		}
		result[index] = model.QuotaCheck{Name: name, State: model.QuotaState(state), Requested: requested, Available: available, Source: source, ObservedAt: observedAt, Reason: reason}
	}
	return result, nil
}

func schemaObject(value any, path string) (map[string]any, *Error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, reject(StageSchema, CodeInvalidType, path)
	}
	return object, nil
}

func required(object map[string]any, name, path string) (any, *Error) {
	value, present := object[name]
	memberPath := appendPointer(path, name)
	if !present {
		return nil, reject(StageSchema, CodeMissingField, memberPath)
	}
	if value == nil {
		return nil, reject(StageSchema, CodeInvalidType, memberPath)
	}
	return value, nil
}

func requiredString(object map[string]any, name, path string) (string, *Error) {
	value, failure := required(object, name, path)
	if failure != nil {
		return "", failure
	}
	text, ok := value.(string)
	if !ok {
		return "", reject(StageSchema, CodeInvalidType, appendPointer(path, name))
	}
	return text, nil
}

func requiredPatternString(object map[string]any, name, path string, pattern *regexp.Regexp, maxRunes int) (string, *Error) {
	text, failure := requiredString(object, name, path)
	if failure != nil {
		return "", failure
	}
	if utf8.RuneCountInString(text) > maxRunes || !pattern.MatchString(text) {
		return "", reject(StageSchema, CodeInvalidValue, appendPointer(path, name))
	}
	return text, nil
}

func requiredNonNegativeInt64(object map[string]any, name, path string) (int64, *Error) {
	value, failure := required(object, name, path)
	if failure != nil {
		return 0, failure
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, reject(StageSchema, CodeInvalidType, appendPointer(path, name))
	}
	parsed, valid := nonNegativeInt64(number)
	if !valid {
		return 0, reject(StageSchema, CodeInvalidValue, appendPointer(path, name))
	}
	return parsed, nil
}

func optionalDecimal(object map[string]any, name, path string) (*string, *Error) {
	value, present := object[name]
	if !present {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, reject(StageSchema, CodeInvalidType, appendPointer(path, name))
	}
	if len(text) > 64 || !decimalPattern.MatchString(text) {
		return nil, reject(StageSchema, CodeInvalidValue, appendPointer(path, name))
	}
	return &text, nil
}

func rejectUnknown(object map[string]any, path string, allowed ...string) *Error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	unknown := make([]string, 0)
	for name := range object {
		if _, ok := allowedSet[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return reject(StageSchema, CodeUnknownField, appendPointer(path, unknown[0]))
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
