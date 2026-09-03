package admission

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/hierarchy"
)

func TestRawSizeDepthAndNodeBounds(t *testing.T) {
	t.Parallel()

	exact := append([]byte(`{}`), bytes.Repeat([]byte{' '}, MaxRawBytes-2)...)
	if _, failure := parseRawForTest(exact); failure != nil {
		t.Fatalf("parseRaw(exact bytes) error = %v", failure)
	}
	_, failure := parseRawForTest(append(exact, ' '))
	assertFailure(t, failure, StageSchema, CodeRequestTooLarge, "")

	depth64 := []byte(strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64))
	if _, failure := parseRawForTest(depth64); failure != nil {
		t.Fatalf("parseRaw(depth 64) error = %v", failure)
	}
	depth65 := []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65))
	_, failure = parseRawForTest(depth65)
	assertFailure(t, failure, StageSchema, CodeJSONTooDeep, "")
	extreme := []byte(strings.Repeat("[", 10_000) + "0" + strings.Repeat("]", 10_000))
	_, failure = parseRawForTest(extreme)
	assertFailure(t, failure, StageSchema, CodeJSONTooDeep, "")

	if _, failure := parseRawForTest(numberArray(MaxJSONNodes - 1)); failure != nil {
		t.Fatalf("parseRaw(%d nodes) error = %v", MaxJSONNodes, failure)
	}
	_, failure = parseRawForTest(numberArray(MaxJSONNodes))
	assertFailure(t, failure, StageSchema, CodeTooManyJSONNodes, "")

	// Work ceilings are terminal in traversal order: after the shallow array
	// crosses the node ceiling, admission never walks the later depth-65 tail.
	nodeBeforeDeepTail := []byte("[" + strings.Repeat("0,", MaxJSONNodes) +
		strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "]")
	_, failure = parseRawForTest(nodeBeforeDeepTail)
	assertFailure(t, failure, StageSchema, CodeTooManyJSONNodes, "")
}

func TestRawStrictUnicodeAndSingleValue(t *testing.T) {
	t.Parallel()

	for _, raw := range [][]byte{
		[]byte(`"\ud800"`),
		[]byte(`"\udc00"`),
		{'"', 0xff, '"'},
		[]byte(`{} {}`),
		[]byte(`{"unterminated":`),
	} {
		_, failure := parseRawForTest(raw)
		assertFailure(t, failure, StageSchema, CodeInvalidJSON, "")
	}
	value, failure := parseRawForTest([]byte(`"\ud83d\ude00"`))
	if failure != nil || value != "😀" {
		t.Fatalf("valid surrogate pair = %#v, %v", value, failure)
	}
}

func TestDuplicateSelectionAndEscaping(t *testing.T) {
	t.Parallel()

	_, failure := parseRawForTest([]byte(`{"z":1,"z":2,"a":1,"a":2}`))
	assertFailure(t, failure, StageSchema, CodeDuplicateField, "/a")

	_, failure = parseRawForTest([]byte(`{"outer":{"a/b~c":1,"a/b~c":2}}`))
	assertFailure(t, failure, StageSchema, CodeDuplicateField, "/outer/a~1b~0c")
}

func TestInvalidJSONIsTerminalBeforeCollectedCandidates(t *testing.T) {
	t.Parallel()

	name := strings.Repeat("a", MaxFieldPathRunes)
	raw := []byte(`{"` + name + `":1,"` + name + `":2,`)
	_, failure := parseRawForTest(raw)
	assertFailure(t, failure, StageSchema, CodeInvalidJSON, "")
}

func TestRawAndTypedSchemaCandidatesUseOneOracle(t *testing.T) {
	t.Parallel()

	// The missing path sorts before the duplicate/unknown path even though the
	// duplicate is discovered by the raw token pass.
	raw := []byte(`{"z":1,"z":2,"kind":"Workspace","metadata":{"displayName":"x"},"spec":{}}`)
	_, err := AdmitCreate(raw, CreateContext{})
	assertFailure(t, err, StageSchema, CodeMissingField, "/apiVersion")

	// Here the duplicate's normalized path sorts first. At /a,
	// duplicate-field also wins the code tie against unknown-field.
	raw = []byte(`{"a":1,"a":2,"kind":"Workspace","metadata":{"displayName":"x"},"spec":{}}`)
	_, err = AdmitCreate(raw, CreateContext{})
	assertFailure(t, err, StageSchema, CodeDuplicateField, "/a")

	statusRaw := []byte(`{"a":1,"a":2,"kind":"Workspace","status":{"observedGeneration":0,"conditions":[]}}`)
	_, err = AdmitStatus(statusRaw, hierarchy.Record{}, 1, hierarchy.Snapshot{})
	assertFailure(t, err, StageSchema, CodeDuplicateField, "/a")
}

func TestPointerContract(t *testing.T) {
	t.Parallel()

	if got := appendPointer("/metadata/labels", "a/b~c"); got != "/metadata/labels/a~1b~0c" {
		t.Fatalf("appendPointer() = %q", got)
	}
	if got := boundedPointer("/a~1b/~0"); got != "/a~1b/~0" {
		t.Fatalf("boundedPointer(valid) = %q", got)
	}
	for _, invalid := range []string{"not-a-pointer", "/bad~", "/bad~2escape"} {
		if got := boundedPointer(invalid); got != "" {
			t.Fatalf("boundedPointer(%q) = %q, want empty", invalid, got)
		}
	}
	if got := boundedPointer("/" + strings.Repeat("a", 95)); got == "" {
		t.Fatal("96-rune, 98-byte encoded pointer was omitted")
	}
	if got := boundedPointer("/" + strings.Repeat("a", 96)); got != "" {
		t.Fatalf("97-rune pointer = %q, want empty", got)
	}
	if got := boundedPointer("/" + strings.Repeat("é", 48)); got != "" {
		t.Fatalf("over-encoded pointer = %q, want empty", got)
	}
	maxParent := "/" + strings.Repeat("a", 95)
	if got := appendPointer(maxParent, ""); got != unrepresentablePointer {
		t.Fatalf("empty child beyond exact path bound = %q, want sentinel", got)
	}
	_, failure := parseRawForTest([]byte(fmt.Sprintf(`{%q:{"":0,"":1}}`, strings.Repeat("a", 95))))
	assertFailure(t, failure, StageSchema, CodeDuplicateField, "")
}

func TestCandidateCodeTieBreak(t *testing.T) {
	t.Parallel()

	set := candidateSet{}
	set.add(CodeUnknownField, "/same")
	set.add(CodeInvalidValue, "/same")
	set.add(CodeInvalidType, "/same")
	set.add(CodeMissingField, "/zz-later")
	failure := set.failure(StageSchema)
	assertFailure(t, failure, StageSchema, CodeInvalidType, "/same")
}

var allocationCandidateSink candidateSet

func TestUnrepresentablePathNormalizationAndStorageBound(t *testing.T) {
	largePrefix := strings.Repeat("credential-prefix-", 20_000)
	unrepresentableA := appendPointer("", largePrefix+"a")
	unrepresentableB := appendPointer("", largePrefix+"b")
	if unrepresentableA != unrepresentablePointer || unrepresentableB != unrepresentablePointer {
		t.Fatal("oversized path was not replaced by the internal sentinel")
	}
	if got := appendPointer(unrepresentableA, "child"); got != unrepresentablePointer {
		t.Fatalf("sentinel child = %q", got)
	}

	set := candidateSet{}
	set.add(CodeUnknownField, "/representable")
	set.add(CodeDuplicateField, unrepresentableA)
	assertFailure(t, set.failure(StageSchema), StageSchema, CodeDuplicateField, "")

	set = candidateSet{}
	set.add(CodeUnknownField, unrepresentableA)
	set.add(CodeInvalidType, unrepresentableB)
	assertFailure(t, set.failure(StageSchema), StageSchema, CodeInvalidType, "")

	// Root and unrepresentable both normalize to empty before selection, so
	// the lexical code tie-break is authoritative.
	set = candidateSet{}
	set.add(CodeUnknownField, "")
	set.add(CodeInvalidValue, unrepresentableA)
	assertFailure(t, set.failure(StageSchema), StageSchema, CodeInvalidValue, "")

	allocations := testing.AllocsPerRun(25, func() {
		bounded := candidateSet{}
		path := appendPointer("", largePrefix)
		for index := 0; index < 10_000; index++ {
			bounded.add(CodeDuplicateField, path)
		}
		allocationCandidateSink = bounded
	})
	if allocations > 1 {
		t.Fatalf("large-prefix duplicate candidate storage allocated %.0f times, want <= 1", allocations)
	}

	// One large prefix followed by many duplicate descendants used to copy the
	// prefix once per diagnostic. The scanner must retain only one bounded
	// candidate and allocate within a constant multiple of the raw input.
	prefix := strings.Repeat("p", 80_000)
	descendants := strings.Repeat(`"x":0,`, 9_000) + `"x":0`
	raw := []byte(`{"` + prefix + `":{` + descendants + `}}`)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	candidates, terminal := scanJSONStructure(raw)
	runtime.ReadMemStats(&after)
	if terminal != nil {
		t.Fatalf("scanJSONStructure() terminal error = %v", terminal)
	}
	assertFailure(t, candidates.failure(StageSchema), StageSchema, CodeDuplicateField, "")
	allocated := after.TotalAlloc - before.TotalAlloc
	limit := uint64(len(raw)*8 + 1<<20)
	if allocated > limit {
		t.Fatalf("large-prefix duplicate scan allocated %d bytes, bound %d", allocated, limit)
	}
}

func TestSemanticSamePathCodeTieBreak(t *testing.T) {
	t.Parallel()

	raw := []byte(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":1,"conditions":[{"type":"Ready","status":"True","reason":"Observed","message":"","observedGeneration":2,"lastTransitionAt":"2026-09-02T01:02:03.000Z"}]}}`)
	snapshot, records := admissionFixture(t, testWorkspaceID)
	_, err := AdmitStatus(raw, records[hierarchy.KindWorkspace], 1, snapshot)
	assertFailure(t, err, StageSemantic, CodeFutureObservation, "/status/conditions/0/observedGeneration")
}

func TestSemanticLexicalIndexSelection(t *testing.T) {
	t.Parallel()

	types := []string{"T00", "T01", "T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T08", "T09"}
	items := make([]string, len(types))
	for index, typeName := range types {
		items[index] = fmt.Sprintf(`{"type":%q,"status":"True","reason":"Observed","message":"","observedGeneration":1,"lastTransitionAt":"2026-09-02T01:02:03.000Z"}`, typeName)
	}
	raw := []byte(fmt.Sprintf(`{"apiVersion":"v1alpha1","kind":"Workspace","status":{"observedGeneration":1,"conditions":[%s]}}`, strings.Join(items, ",")))
	snapshot, records := admissionFixture(t, testWorkspaceID)
	_, err := AdmitStatus(raw, records[hierarchy.KindWorkspace], 1, snapshot)
	assertFailure(t, err, StageSemantic, CodeDuplicateItem, "/status/conditions/10/type")
}

func numberArray(items int) []byte {
	if items == 0 {
		return []byte(`[]`)
	}
	return []byte("[" + strings.Repeat("0,", items-1) + "0]")
}

func parseRawForTest(raw []byte) (any, *Error) {
	document, failure := parseRaw(raw)
	if failure != nil {
		return nil, failure
	}
	if failure := document.candidates.failure(StageSchema); failure != nil {
		return document.value, failure
	}
	return document.value, nil
}
