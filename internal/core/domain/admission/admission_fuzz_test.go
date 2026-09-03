package admission

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
	"github.com/ArdurAI/veer/internal/core/domain/model"
)

func FuzzAdmitRaw(f *testing.F) {
	for _, kind := range testKinds {
		f.Add(intentJSON(kind, false))
		f.Add(statusJSON(kind))
	}
	f.Add([]byte(`{"z":1,"z":2,"a":1,"a":2}`))
	f.Add([]byte(`{"apiVersion":"v1alpha1","kind":"Workspace","metadata":{"displayName":"x","unknown":true},"spec":{}}`))
	f.Add([]byte(`"\ud800"`))
	f.Add([]byte(`"\udc00"`))
	f.Add([]byte(`"\ud83d\ude00"`))
	f.Add([]byte("[[[[[[[[[[0]]]]]]]]]]"))
	f.Add([]byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)))
	f.Add(numberArray(MaxJSONNodes))
	f.Add([]byte("{} {}"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		if len(raw) > MaxRawBytes {
			_, failure := parseRawForTest(raw)
			assertFailure(t, failure, StageSchema, CodeRequestTooLarge, "")
			return
		}

		firstDocument, firstFailure := parseRaw(raw)
		secondDocument, secondFailure := parseRaw(raw)
		if !bytes.Equal(raw, before) {
			t.Fatal("parseRaw mutated fuzz input")
		}
		if !reflect.DeepEqual(firstDocument.value, secondDocument.value) ||
			firstDocument.candidates != secondDocument.candidates || !sameFailure(firstFailure, secondFailure) {
			t.Fatalf("parseRaw is nondeterministic: %#v/%v versus %#v/%v", firstDocument, firstFailure, secondDocument, secondFailure)
		}

		context := CreateContext{ID: createID(hierarchy.KindWorkspace)}
		first, firstErr := AdmitCreate(raw, context)
		second, secondErr := AdmitCreate(raw, context)
		if !sameAdmissionError(firstErr, secondErr) {
			t.Fatalf("AdmitCreate errors differ: %v / %v", firstErr, secondErr)
		}
		if firstErr == nil && !modelIntentAndPlacementEqual(first, second) {
			t.Fatal("AdmitCreate results differ")
		}
	})
}

func sameFailure(left, right *Error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Stage() == right.Stage() && left.Code() == right.Code() && left.Path() == right.Path()
}

func sameAdmissionError(left, right error) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	var leftFailure, rightFailure *Error
	if !errors.As(left, &leftFailure) || !errors.As(right, &rightFailure) {
		return false
	}
	return sameFailure(leftFailure, rightFailure)
}

func modelIntentAndPlacementEqual(left, right CreateResult) bool {
	leftPlacement, rightPlacement := left.Placement(), right.Placement()
	leftParent, leftHasParent := leftPlacement.Parent()
	rightParent, rightHasParent := rightPlacement.Parent()
	return leftPlacement.ID() == rightPlacement.ID() &&
		leftPlacement.Kind() == rightPlacement.Kind() &&
		leftPlacement.WorkspaceID() == rightPlacement.WorkspaceID() &&
		leftHasParent == rightHasParent && leftParent == rightParent &&
		model.EqualIntent(left.Intent(), right.Intent())
}
