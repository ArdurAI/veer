package model

import "testing"

func FuzzInvalidIntentOperationsArePanicFree(f *testing.F) {
	for variant := uint8(0); variant < 6; variant++ {
		f.Add(variant, false)
		f.Add(variant, true)
	}
	f.Fuzz(func(t *testing.T, variant uint8, publicZero bool) {
		var value Intent
		switch variant % 6 {
		case 0:
			var pointer *WorkspaceIntent
			if publicZero {
				pointer = &WorkspaceIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		case 1:
			var pointer *EnvironmentIntent
			if publicZero {
				pointer = &EnvironmentIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		case 2:
			var pointer *ApplicationIntent
			if publicZero {
				pointer = &ApplicationIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		case 3:
			var pointer *ComponentIntent
			if publicZero {
				pointer = &ComponentIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		case 4:
			var pointer *PolicyIntent
			if publicZero {
				pointer = &PolicyIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		case 5:
			var pointer *ProviderConnectionIntent
			if publicZero {
				pointer = &ProviderConnectionIntent{}
			}
			_ = pointer.Spec()
			value = pointer
		}
		_ = value.Kind()
		_ = value.Metadata()
		if ValidateIntent(value) == nil {
			t.Fatal("invalid Intent unexpectedly validated")
		}
		if CloneIntent(value) != nil {
			t.Fatal("invalid Intent unexpectedly cloned")
		}
		if EqualIntent(value, value) {
			t.Fatal("invalid Intent unexpectedly compared equal")
		}
	})
}

func FuzzInvalidStatusWriteOperationsArePanicFree(f *testing.F) {
	for variant := uint8(0); variant < 6; variant++ {
		f.Add(variant, false)
		f.Add(variant, true)
	}
	f.Fuzz(func(t *testing.T, variant uint8, publicZero bool) {
		var value StatusWrite
		switch variant % 6 {
		case 0:
			var pointer *WorkspaceStatusWrite
			if publicZero {
				pointer = &WorkspaceStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		case 1:
			var pointer *EnvironmentStatusWrite
			if publicZero {
				pointer = &EnvironmentStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		case 2:
			var pointer *ApplicationStatusWrite
			if publicZero {
				pointer = &ApplicationStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		case 3:
			var pointer *ComponentStatusWrite
			if publicZero {
				pointer = &ComponentStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		case 4:
			var pointer *PolicyStatusWrite
			if publicZero {
				pointer = &PolicyStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		case 5:
			var pointer *ProviderConnectionStatusWrite
			if publicZero {
				pointer = &ProviderConnectionStatusWrite{}
			}
			_ = pointer.Status()
			value = pointer
		}
		_ = value.Kind()
		_ = value.ObservedGenerations()
		_ = value.ResourceGeneration()
		if ValidateStatusWrite(value, 1) == nil {
			t.Fatal("invalid StatusWrite unexpectedly validated")
		}
		if CloneStatusWrite(value) != nil {
			t.Fatal("invalid StatusWrite unexpectedly cloned")
		}
		if EqualStatusWrite(value, value) {
			t.Fatal("invalid StatusWrite unexpectedly compared equal")
		}
	})
}
