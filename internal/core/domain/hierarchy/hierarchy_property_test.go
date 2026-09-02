package hierarchy

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
)

func TestPropertyRecordOrderDoesNotAffectValidation(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	property := func(seed uint64) bool {
		records := cloneRecords(fixture.records)
		random := rand.New(rand.NewSource(int64(seed)))
		random.Shuffle(len(records), func(left, right int) {
			records[left], records[right] = records[right], records[left]
		})
		snapshot, err := NewSnapshot(workspaceAID, records)
		if err != nil || snapshot.Len() != len(records) {
			return false
		}
		id := resource.ID(fmt.Sprintf("cmp_%024x", seed))
		placement, err := snapshot.DeriveChild(KindComponent, id, applicationAID)
		return err == nil && placement.WorkspaceID() == workspaceAID
	}
	checkHierarchyProperty(t, property)
}

func TestPropertyDisplayNamesDoNotAffectHierarchy(t *testing.T) {
	t.Parallel()

	placement, err := DeriveWorkspace(workspaceAID)
	if err != nil {
		t.Fatalf("DeriveWorkspace() error = %v", err)
	}
	initial := mustNewResource(t, placement, "initial", "rv_initial", fixtureWorkspaceSpec{})
	initialRecord := mustRecordFromResource(t, initial)

	property := func(value uint64) bool {
		displayName := fmt.Sprintf("display-%016x", value)
		updated, err := initial.Rename(
			displayName,
			fmt.Sprintf("rv_%016x", value),
			fixtureTime.Add(time.Duration(value%10_000+1)*time.Millisecond),
		)
		if err != nil {
			return false
		}
		updatedRecord, err := RecordFrom(updated.APIVersion(), updated.Kind(), updated.Metadata())
		return err == nil && reflect.DeepEqual(initialRecord, updatedRecord) &&
			CheckTransition(initialRecord, updatedRecord) == nil
	}
	checkHierarchyProperty(t, property)
}

func TestPropertyWorkspaceDivergenceIsOrderInvariant(t *testing.T) {
	t.Parallel()

	fixture := newHierarchyFixture(t, workspaceAID, "w", "e", "a", "c")
	property := func(seed uint64, selected uint8) bool {
		records := cloneRecords(fixture.records)
		index := int(selected) % len(records)
		records[index].workspaceID = workspaceBID
		random := rand.New(rand.NewSource(int64(seed)))
		random.Shuffle(len(records), func(left, right int) {
			records[left], records[right] = records[right], records[left]
		})
		_, err := NewSnapshot(workspaceAID, records)
		return errors.Is(err, ErrWorkspaceMismatch)
	}
	checkHierarchyProperty(t, property)
}

func TestPropertyInvalidShapeClassificationIsOrderInvariant(t *testing.T) {
	t.Parallel()

	records := []Record{
		rawRecord(workspaceAID, KindWorkspace, workspaceAID, workspaceAID),
		rawRecord(environmentAID, KindEnvironment, workspaceAID, ""),
	}
	property := func(seed uint64) bool {
		candidate := cloneRecords(records)
		random := rand.New(rand.NewSource(int64(seed)))
		random.Shuffle(len(candidate), func(left, right int) {
			candidate[left], candidate[right] = candidate[right], candidate[left]
		})
		_, err := NewSnapshot(workspaceAID, candidate)
		return errors.Is(err, ErrRootHasParent)
	}
	checkHierarchyProperty(t, property)
}

func checkHierarchyProperty(t *testing.T, property any) {
	t.Helper()
	configuration := &quick.Config{
		MaxCount: 250,
		Rand:     rand.New(rand.NewSource(18)),
	}
	if err := quick.Check(property, configuration); err != nil {
		t.Fatal(err)
	}
}
