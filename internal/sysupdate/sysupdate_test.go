package sysupdate

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.jobs == nil {
		t.Fatal("jobs map is nil")
	}
}

func TestInfo_Initial(t *testing.T) {
	m := NewManager()
	info := m.Info()
	if info.Upgradable != 0 {
		t.Fatalf("expected 0 upgradable, got %d", info.Upgradable)
	}
	if info.LastChecked != 0 {
		t.Fatalf("expected 0 last_checked, got %d", info.LastChecked)
	}
}

func TestGetJob_NotFound(t *testing.T) {
	m := NewManager()
	_, ok := m.GetJob("nonexistent")
	if ok {
		t.Fatal("expected false for nonexistent job")
	}
}

func TestNewJob_CreatesEntry(t *testing.T) {
	m := NewManager()
	j := m.newJob("check")
	if j.ID == "" {
		t.Fatal("job ID should not be empty")
	}
	if j.Status != "running" {
		t.Fatalf("expected status running, got %s", j.Status)
	}
	if j.Action != "check" {
		t.Fatalf("expected action check, got %s", j.Action)
	}
}

func TestGetJob_Found(t *testing.T) {
	m := NewManager()
	j := m.newJob("apply")
	v, ok := m.GetJob(j.ID)
	if !ok {
		t.Fatal("expected job to be found")
	}
	if v.ID != j.ID {
		t.Fatalf("job ID mismatch: %s != %s", v.ID, j.ID)
	}
	if v.Status != "running" {
		t.Fatalf("expected status running, got %s", v.Status)
	}
}

func TestJob_Emit(t *testing.T) {
	j := &job{ID: "test", Action: "check", Status: "running"}
	j.emit("line 1")
	j.emit("line 2")
	if len(j.Lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(j.Lines))
	}
	if j.Lines[0] != "line 1" {
		t.Fatalf("expected 'line 1', got '%s'", j.Lines[0])
	}
}

func TestJob_Finish_Success(t *testing.T) {
	j := &job{ID: "test", Action: "check", Status: "running"}
	j.finish(nil)
	if j.Status != "done" {
		t.Fatalf("expected status done, got %s", j.Status)
	}
	if j.FinishedAt == nil {
		t.Fatal("FinishedAt should be set")
	}
}

func TestJob_Finish_Error(t *testing.T) {
	j := &job{ID: "test", Action: "apply", Status: "running"}
	j.finish(assertError{msg: "something went wrong"})
	if j.Status != "failed" {
		t.Fatalf("expected status failed, got %s", j.Status)
	}
	if j.FinishedAt == nil {
		t.Fatal("FinishedAt should be set")
	}
}

func TestCountUpgradable(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty", "", 0},
		{"header only", "Listing...\n", 0},
		{"one package", "bash/focal 5.0 amd64\n", 1},
		{"three packages", "bash/focal 5.0 amd64\ncurl/focal 7.68 arm64\nvim/focal 8.1 amd64\n", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countUpgradable(tt.input)
			if got != tt.expected {
				t.Fatalf("countUpgradable(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSplitLines(t *testing.T) {
	input := "line 1\nline 2\nline 3"
	lines := splitLines(input)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}

func TestGenID(t *testing.T) {
	id := genID()
	if len(id) != 16 {
		t.Fatalf("expected 16-char hex ID, got %d chars", len(id))
	}
	id2 := genID()
	if id == id2 {
		t.Fatal("two generated IDs should not be equal")
	}
}

type assertError struct{ msg string }

func (e assertError) Error() string { return e.msg }
