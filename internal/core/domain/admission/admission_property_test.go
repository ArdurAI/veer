package admission

import (
	"testing"
	"testing/quick"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

func TestPropertyMemberOrderDoesNotAffectAdmission(t *testing.T) {
	t.Parallel()

	context := createContext(hierarchy.KindWorkspace, hierarchy.Snapshot{})
	canonical, err := AdmitCreate([]byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"example","labels":{"a":"1","z":"2"}},"spec":{}}`), context)
	if err != nil {
		t.Fatal(err)
	}
	encodings := [][]byte{
		[]byte(`{"spec":{},"metadata":{"labels":{"z":"2","a":"1"},"displayName":"example"},"kind":"Workspace","apiVersion":"v1alpha1"}`),
		[]byte(`{"kind":"Workspace","apiVersion":"v1alpha1","spec":{},"metadata":{"displayName":"example","labels":{"a":"1","z":"2"}}}`),
		[]byte(`{"metadata":{"displayName":"example","labels":{"z":"2","a":"1"}},"apiVersion":"v1alpha1","kind":"Workspace","spec":{}}`),
	}
	property := func(choice uint8) bool {
		result, admitErr := AdmitCreate(encodings[int(choice)%len(encodings)], context)
		return admitErr == nil && modelIntentAndPlacementEqual(canonical, result)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 250}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyErrorSelectionIsWireOrderInvariant(t *testing.T) {
	t.Parallel()

	encodings := [][]byte{
		[]byte(`{"z":1,"z":2,"a":1,"a":2}`),
		[]byte(`{"a":1,"z":1,"z":2,"a":2}`),
		[]byte(`{"z":1,"a":1,"a":2,"z":2}`),
	}
	property := func(choice uint8) bool {
		_, failure := parseRawForTest(encodings[int(choice)%len(encodings)])
		return failure != nil && failure.Stage() == StageSchema &&
			failure.Code() == CodeDuplicateField && failure.Path() == "/a"
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 250}); err != nil {
		t.Fatal(err)
	}
}
