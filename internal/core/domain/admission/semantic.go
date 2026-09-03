package admission

import (
	"errors"
	"strconv"

	"github.com/ArdurAI/veer/internal/core/domain/condition"
	"github.com/ArdurAI/veer/internal/core/domain/control"
	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func semanticIntent(source sourceIntent) *Error {
	if err := resource.ValidateDisplayName(source.metadata.displayName); err != nil {
		return reject(StageSemantic, CodeInvalidSpec, "/metadata/displayName")
	}
	if _, err := resource.NormalizeLabels(source.metadata.labels); err != nil {
		return reject(StageSemantic, CodeInvalidSpec, "/metadata/labels")
	}
	if source.kind != hierarchy.KindProviderConnection {
		return nil
	}
	if err := model.ValidateProviderConnectionSpec(source.provider); err != nil {
		if errors.Is(err, control.ErrInvalidCredentialReference) {
			return reject(StageSemantic, CodeInvalidSpec, "/spec/credentialRef/referenceId")
		}
		return reject(StageSemantic, CodeInvalidSpec, "/spec")
	}
	return nil
}

func semanticStatus(source sourceStatus, generation int64) *Error {
	set := candidateSet{}
	if generation < 1 {
		set.add(CodeInvalidStatus, "/status/observedGeneration")
	}
	if source.kind == hierarchy.KindProviderConnection {
		collectSemanticProviderStatus(&set, source.provider, generation)
		return set.failure(StageSemantic)
	}
	collectSemanticCommonStatus(&set, source.common, generation, "/status")
	if set.present {
		return set.failure(StageSemantic)
	}
	if source.kind == hierarchy.KindPolicy {
		status := model.PolicyStatus{
			ObservedGeneration: source.common.ObservedGeneration,
			Conditions:         condition.CloneSet(source.common.Conditions),
		}
		if err := model.ValidatePolicyStatus(status, generation); err != nil {
			return reject(StageSemantic, CodeInvalidStatus, "/status")
		}
		return nil
	}
	if err := model.ValidateCommonStatus(source.common, generation); err != nil {
		return reject(StageSemantic, CodeInvalidStatus, "/status")
	}
	return nil
}

func collectSemanticCommonStatus(set *candidateSet, status model.CommonStatus, generation int64, path string) {
	if status.ObservedGeneration > generation {
		set.add(CodeFutureObservation, appendPointer(path, "observedGeneration"))
	}
	conditionsPath := appendPointer(path, "conditions")
	seen := make(map[string]struct{}, len(status.Conditions))
	for index, value := range status.Conditions {
		itemPath := appendPointer(conditionsPath, integerToken(index))
		if value.ObservedGeneration > generation {
			set.add(CodeFutureObservation, appendPointer(itemPath, "observedGeneration"))
		}
		if err := condition.Validate(value, generation); err != nil {
			set.add(CodeInvalidStatus, conditionErrorPath(err, itemPath))
		}
		if _, duplicate := seen[value.Type]; duplicate {
			set.add(CodeDuplicateItem, appendPointer(itemPath, "type"))
		}
		seen[value.Type] = struct{}{}
		if index > 0 && status.Conditions[index-1].Type > value.Type {
			set.add(CodeInvalidOrder, appendPointer(itemPath, "type"))
		}
	}
}

func collectSemanticProviderStatus(set *candidateSet, status model.ProviderConnectionStatus, generation int64) {
	common := model.CommonStatus{
		ObservedGeneration: status.ObservedGeneration,
		Conditions:         condition.CloneSet(status.Conditions),
	}
	collectSemanticCommonStatus(set, common, generation, "/status")
	seenCapabilities := make(map[string]struct{}, len(status.Capabilities))
	for index, capability := range status.Capabilities {
		itemPath := appendPointer("/status/capabilities", integerToken(index))
		if err := control.ValidateProviderCapability(capability); err != nil {
			set.add(CodeInvalidStatus, observationErrorPath(err, itemPath))
		}
		if _, duplicate := seenCapabilities[capability.Name]; duplicate {
			set.add(CodeDuplicateItem, appendPointer(itemPath, "name"))
		}
		seenCapabilities[capability.Name] = struct{}{}
		if index > 0 && status.Capabilities[index-1].Name > capability.Name {
			set.add(CodeInvalidOrder, appendPointer(itemPath, "name"))
		}
	}
	seenQuotas := make(map[string]struct{}, len(status.QuotaChecks))
	for index, quota := range status.QuotaChecks {
		itemPath := appendPointer("/status/quotaChecks", integerToken(index))
		if err := control.ValidateQuotaCheck(quota); err != nil {
			set.add(CodeInvalidStatus, quotaErrorPath(err, itemPath))
		}
		if _, duplicate := seenQuotas[quota.Name]; duplicate {
			set.add(CodeDuplicateItem, appendPointer(itemPath, "name"))
		}
		seenQuotas[quota.Name] = struct{}{}
		if index > 0 && status.QuotaChecks[index-1].Name > quota.Name {
			set.add(CodeInvalidOrder, appendPointer(itemPath, "name"))
		}
	}
	if set.present {
		return
	}
	if err := model.ValidateProviderConnectionStatus(status, generation); err != nil {
		set.add(CodeInvalidStatus, "/status")
	}
}

func conditionErrorPath(err error, itemPath string) string {
	switch {
	case errors.Is(err, condition.ErrInvalidConditionType):
		return appendPointer(itemPath, "type")
	case errors.Is(err, condition.ErrInvalidStatus):
		return appendPointer(itemPath, "status")
	case errors.Is(err, condition.ErrInvalidReason):
		return appendPointer(itemPath, "reason")
	case errors.Is(err, condition.ErrInvalidMessage):
		return appendPointer(itemPath, "message")
	case errors.Is(err, condition.ErrObservedGeneration):
		return appendPointer(itemPath, "observedGeneration")
	case errors.Is(err, condition.ErrInvalidTimestamp):
		return appendPointer(itemPath, "lastTransitionAt")
	default:
		return itemPath
	}
}

func observationErrorPath(err error, itemPath string) string {
	switch {
	case errors.Is(err, control.ErrInvalidObservationName):
		return appendPointer(itemPath, "name")
	case errors.Is(err, control.ErrInvalidCapabilityState):
		return appendPointer(itemPath, "state")
	case errors.Is(err, control.ErrInvalidObservationSource):
		return appendPointer(itemPath, "source")
	case errors.Is(err, control.ErrInvalidObservationTimestamp):
		return appendPointer(itemPath, "observedAt")
	case errors.Is(err, control.ErrInvalidObservationReason):
		return appendPointer(itemPath, "reason")
	default:
		return itemPath
	}
}

func quotaErrorPath(err error, itemPath string) string {
	if errors.Is(err, control.ErrInvalidQuotaState) || errors.Is(err, control.ErrInvalidCostState) {
		return appendPointer(itemPath, "state")
	}
	return observationErrorPath(err, itemPath)
}

func integerToken(value int) string {
	return strconv.Itoa(value)
}
