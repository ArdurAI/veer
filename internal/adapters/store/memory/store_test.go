package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ArdurAI/veer/internal/core/domain/resource"
	"github.com/ArdurAI/veer/internal/core/ports"
)

var fixtureID = resource.ID("wsp_000000000001")

func TestUpdateIsAtomicAndOwnershipSafe(t *testing.T) {
	t.Parallel()

	store := NewStore()
	original := []byte(`{"state":"initial"}`)
	if err := store.Update(context.Background(), func(tx ports.ReferenceTransaction) error {
		tx.PutResource(fixtureID, original)
		return nil
	}); err != nil {
		t.Fatalf("seed Update() error = %v", err)
	}
	original[0] = 'x'

	wantFailure := errors.New("injected failure")
	if err := store.Update(context.Background(), func(tx ports.ReferenceTransaction) error {
		value, exists := tx.GetResource(fixtureID)
		if !exists {
			t.Fatal("working transaction did not see seeded resource")
		}
		value[0] = 'x'
		tx.PutResource(fixtureID, []byte(`{"state":"changed"}`))
		return wantFailure
	}); !errors.Is(err, wantFailure) {
		t.Fatalf("failed Update() error = %v, want injected failure", err)
	}

	if err := store.View(context.Background(), func(reader ports.ReferenceReader) error {
		value, exists := reader.GetResource(fixtureID)
		if !exists || string(value) != `{"state":"initial"}` {
			t.Fatalf("stored resource = %q / %t", value, exists)
		}
		value[0] = 'x'
		again, _ := reader.GetResource(fixtureID)
		if string(again) != `{"state":"initial"}` {
			t.Fatalf("reader alias mutated stored value: %q", again)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func TestConcurrentUpdatesAreSerializable(t *testing.T) {
	t.Parallel()

	store := NewStore()
	const workers = 32
	var group sync.WaitGroup
	group.Add(workers)
	for index := 0; index < workers; index++ {
		index := index
		go func() {
			defer group.Done()
			id := resource.ID("wsp_" + leftPad(index))
			if err := store.Update(context.Background(), func(tx ports.ReferenceTransaction) error {
				tx.PutResource(id, []byte(id))
				return nil
			}); err != nil {
				t.Errorf("Update(%d) error = %v", index, err)
			}
		}()
	}
	group.Wait()

	if err := store.View(context.Background(), func(reader ports.ReferenceReader) error {
		if got := len(reader.ListResources()); got != workers {
			t.Fatalf("resource count = %d, want %d", got, workers)
		}
		return nil
	}); err != nil {
		t.Fatalf("View() error = %v", err)
	}
}

func leftPad(value int) string {
	digits := []byte("000000000000")
	for index := len(digits) - 1; value > 0; index-- {
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits)
}
