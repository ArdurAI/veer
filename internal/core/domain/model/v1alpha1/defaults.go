package v1alpha1

// DefaultWorkspaceWriteSpec returns an independent, explicit source value.
// Omission becomes false; an explicit true or false value is preserved.
func DefaultWorkspaceWriteSpec(source WorkspaceWriteSpec) WorkspaceWriteSpec {
	value := false
	if source.SuspendReconciliation != nil {
		value = *source.SuspendReconciliation
	}
	return WorkspaceWriteSpec{SuspendReconciliation: &value}
}

// DefaultWorkspaceWrite applies Workspace defaults without mutating or
// retaining aliases to the source write.
func DefaultWorkspaceWrite(source WorkspaceWrite) WorkspaceWrite {
	result := cloneDesiredWrite(source)
	result.Spec = DefaultWorkspaceWriteSpec(source.Spec)
	return result
}

// DefaultEnvironmentWrite returns an independent source value. The current
// closed Environment spec has no fields to default.
func DefaultEnvironmentWrite(source EnvironmentWrite) EnvironmentWrite {
	return cloneDesiredWrite(source)
}

// DefaultApplicationWrite returns an independent source value. The current
// closed Application spec has no fields to default.
func DefaultApplicationWrite(source ApplicationWrite) ApplicationWrite {
	return cloneDesiredWrite(source)
}

// DefaultComponentWrite returns an independent source value. The current
// closed Component spec has no fields to default.
func DefaultComponentWrite(source ComponentWrite) ComponentWrite {
	return cloneDesiredWrite(source)
}

// DefaultPolicyWrite returns an independent source value. Policy intent is a
// closed object until its owning policy issue adopts fields.
func DefaultPolicyWrite(source PolicyWrite) PolicyWrite {
	return cloneDesiredWrite(source)
}

// DefaultProviderConnectionWrite returns an independent source value. Its
// current required fields have no defaults.
func DefaultProviderConnectionWrite(source ProviderConnectionWrite) ProviderConnectionWrite {
	return cloneDesiredWrite(source)
}

func cloneDesiredWrite[Spec any](source DesiredWrite[Spec]) DesiredWrite[Spec] {
	result := source
	result.Metadata.Labels = cloneLabels(source.Metadata.Labels)
	return result
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
