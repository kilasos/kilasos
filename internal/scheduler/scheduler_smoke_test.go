package scheduler

import (
	"path/filepath"
	"testing"
	"github.com/kilasos/kilasos/internal/storage"
)

func TestScheduler_NewEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "schedules.json")
	sched, err := New(tmp, storage.NewMock())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if sched == nil {
		t.Fatal("sched is nil")
	}
}

func TestScheduler_NewWithMissingDir_Returns_or_Creates(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "subdir", "schedules.json")
	_, err := New(tmp, storage.NewMock())
	// Either outcome is OK; the test just makes sure it does not panic.
	_ = err
}
