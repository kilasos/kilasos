package audit

import (
	"path/filepath"
	"testing"
)

func TestAudit_New_CreatesFileIfMissing(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "new_audit.json")
	logger, err := New(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if logger == nil {
		t.Fatal("New returned nil logger")
	}
}
