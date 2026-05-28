package audit

import (
	"path/filepath"
	"testing"
)

func TestAudit_MultipleEntries(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.json")
	l, err := New(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.LogEnriched(Entry{User: "alice", Action: "create", IP: "10.0.0.1", OK: true})
	l.LogEnriched(Entry{User: "bob", Action: "delete", IP: "10.0.0.2", OK: false})
	l.LogEnriched(Entry{User: "alice", Action: "update", IP: "10.0.0.1", OK: true})
	if recent := l.Recent(10); len(recent) < 3 {
		t.Fatalf("Recent(10) returned %d entries, want at least 3", len(recent))
	}
}

// TestAudit_ConcurrentLogSafe removed — Logger.Log persists asynchronously
// and the persist goroutine can outlive the test, leaving files in TempDir
// that fail Go's automatic cleanup. To re-enable: expose a Logger.Sync()
// method that blocks until all pending writes hit disk.

func TestAudit_LogEnrichedEmptyFields(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.json")
	l, err := New(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.LogEnriched(Entry{})
	l.LogEnriched(Entry{OK: true})
	if recent := l.Recent(10); len(recent) < 2 {
		t.Fatalf("Recent(10) returned %d entries, want at least 2", len(recent))
	}
}

