package admission

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"unicode/utf8"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

const (
	// MaxRawBytes bounds work and retained input before any JSON decoding.
	MaxRawBytes = resource.MaxCanonicalBytes
	// MaxJSONDepth counts the root value at depth zero.
	MaxJSONDepth = 64
	// MaxJSONNodes counts values; object member names are not values.
	MaxJSONNodes = 50_000
)

type rawFailure struct {
	code Code
	path string
}

type rawDocument struct {
	value      any
	candidates candidateSet
}

// parseRaw returns terminal syntax/work-ceiling errors immediately. Duplicate
// names are non-terminal schema candidates carried with the decoded value so
// typed missing, unknown, type, and value candidates share one selection
// oracle in schemaIntent or schemaStatus.
func parseRaw(raw []byte) (rawDocument, *Error) {
	if len(raw) > MaxRawBytes {
		return rawDocument{}, reject(StageSchema, CodeRequestTooLarge, "")
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return rawDocument{}, reject(StageSchema, CodeInvalidJSON, "")
	}
	candidates, failure := scanJSONStructure(raw)
	if failure != nil {
		return rawDocument{}, reject(StageSchema, failure.code, failure.path)
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return rawDocument{}, reject(StageSchema, CodeInvalidJSON, "")
	}
	return rawDocument{value: value, candidates: candidates}, nil
}

type scanFrame struct {
	kind          jsontext.Kind
	path          string
	seen          map[string]struct{}
	pendingPath   string
	expectingName bool
	nextIndex     int
}

// scanJSONStructure uses an iterative token walk so even maximally nested
// bounded input cannot consume the Go call stack. It collects duplicates
// within admitted work ceilings so the shared oracle is wire-order invariant;
// crossing a depth or node ceiling terminates traversal immediately.
func scanJSONStructure(raw []byte) (candidateSet, *rawFailure) {
	decoder := jsontext.NewDecoder(bytes.NewReader(raw), jsontext.AllowDuplicateNames(true))
	set := candidateSet{}
	frames := make([]scanFrame, 0, MaxJSONDepth+1)
	nodes := 0
	rootStarted := false
	for {
		token, err := decoder.ReadToken()
		if err == io.EOF {
			if !rootStarted || len(frames) != 0 {
				return candidateSet{}, &rawFailure{code: CodeInvalidJSON}
			}
			return set, nil
		}
		if err != nil {
			return candidateSet{}, &rawFailure{code: CodeInvalidJSON}
		}
		kind := token.Kind()
		if kind == jsontext.KindEndObject || kind == jsontext.KindEndArray {
			if len(frames) == 0 ||
				(kind == jsontext.KindEndObject && frames[len(frames)-1].kind != jsontext.KindBeginObject) ||
				(kind == jsontext.KindEndArray && frames[len(frames)-1].kind != jsontext.KindBeginArray) {
				return candidateSet{}, &rawFailure{code: CodeInvalidJSON}
			}
			frames = frames[:len(frames)-1]
			continue
		}

		if len(frames) > 0 {
			parent := &frames[len(frames)-1]
			if parent.kind == jsontext.KindBeginObject && parent.expectingName {
				if kind != jsontext.KindString {
					return candidateSet{}, &rawFailure{code: CodeInvalidJSON}
				}
				name := token.String()
				memberPath := appendPointer(parent.path, name)
				if _, duplicate := parent.seen[name]; duplicate {
					set.add(CodeDuplicateField, memberPath)
				}
				parent.seen[name] = struct{}{}
				parent.pendingPath = memberPath
				parent.expectingName = false
				continue
			}
		}

		path := ""
		depth := len(frames)
		if len(frames) == 0 {
			if rootStarted {
				return candidateSet{}, &rawFailure{code: CodeInvalidJSON}
			}
			rootStarted = true
		} else {
			parent := &frames[len(frames)-1]
			if parent.kind == jsontext.KindBeginObject {
				path = parent.pendingPath
				parent.pendingPath = ""
				parent.expectingName = true
			} else {
				path = appendPointer(parent.path, integerToken(parent.nextIndex))
				parent.nextIndex++
			}
		}
		nodes++
		if depth > MaxJSONDepth {
			// Stop before retaining another frame. Depth is a whole-document
			// bound and therefore carries the root pointer.
			return candidateSet{}, &rawFailure{code: CodeJSONTooDeep}
		}
		if nodes > MaxJSONNodes {
			// Node cardinality is a whole-document bound, so its stable path is
			// the root rather than whichever wire-ordered node crossed it.
			return candidateSet{}, &rawFailure{code: CodeTooManyJSONNodes}
		}
		switch kind {
		case jsontext.KindBeginObject:
			frames = append(frames, scanFrame{
				kind: jsontext.KindBeginObject, path: path,
				seen: make(map[string]struct{}), expectingName: true,
			})
		case jsontext.KindBeginArray:
			frames = append(frames, scanFrame{kind: jsontext.KindBeginArray, path: path})
		}
	}
}
