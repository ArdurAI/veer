package hierarchy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func FuzzSnapshot(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{3, 2, 1, 0, 255, 128})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			t.Skip()
		}
		root := rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")
		records := []Record{root}
		nodeCount := len(data) / 4
		if nodeCount > 64 {
			nodeCount = 64
		}
		for index := 0; index < nodeCount; index++ {
			offset := index * 4
			kind := []Kind{KindEnvironment, KindApplication, KindComponent, Kind("Unsupported")}[int(data[offset])%4]
			workspaceID := workspaceAID
			if data[offset+1]&1 != 0 {
				workspaceID = workspaceBID
			}
			id := generatedID(index + 10_000)
			var parent resource.ID
			if data[offset+2]&1 != 0 {
				parentIndex := int(data[offset+3]) % (nodeCount + 1)
				if parentIndex == 0 {
					parent = workspaceAID
				} else {
					parent = generatedID(parentIndex - 1 + 10_000)
				}
			}
			records = append(records, rawRecord(id, kind, workspaceID, parent))
		}

		_, err := NewSnapshot(workspaceAID, records)
		if err != nil && !isHierarchySentinel(err) {
			t.Fatalf("NewSnapshot() returned unclassified error: %v", err)
		}
	})
}

func FuzzWorkspaceDivergence(f *testing.F) {
	f.Add([]byte{}, false)
	f.Add([]byte{1, 2, 3}, true)

	f.Fuzz(func(t *testing.T, data []byte, diverge bool) {
		if len(data) > 128 {
			t.Skip()
		}
		records := []Record{rawRecord(workspaceAID, KindWorkspace, workspaceAID, "")}
		count := len(data)%63 + 1
		for index := 0; index < count; index++ {
			id := resource.ID(fmt.Sprintf("env_%024x", index+100_000))
			records = append(records, rawRecord(id, KindEnvironment, workspaceAID, workspaceAID))
		}
		if diverge {
			records[len(records)-1].workspaceID = workspaceBID
		}

		_, err := NewSnapshot(workspaceAID, records)
		if diverge {
			if !errors.Is(err, ErrWorkspaceMismatch) {
				t.Fatalf("NewSnapshot(divergent) error = %v, want ErrWorkspaceMismatch", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("NewSnapshot(local siblings) error = %v", err)
		}
	})
}

func isHierarchySentinel(err error) bool {
	for _, sentinel := range []error{
		ErrUnsupportedAPIVersion,
		ErrUnsupportedKind,
		ErrInvalidSnapshot,
		ErrSnapshotTooLarge,
		ErrInvalidPlacement,
		ErrDuplicateID,
		ErrWorkspaceRootMissing,
		ErrWorkspaceMismatch,
		ErrRootHasParent,
		ErrParentRequired,
		ErrParentNotFound,
		ErrParentKindMismatch,
		ErrCycle,
		ErrResourceNotFound,
		ErrImmutableID,
		ErrImmutableKind,
		ErrImmutableParent,
		ErrImmutableWorkspaceID,
		ErrDeleteRestricted,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}
