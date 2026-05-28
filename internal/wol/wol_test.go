package wol

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		t.Fatal("store is nil")
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(s.List()))
	}
}

func TestNewStore_NonExistent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(s.List()))
	}
}

func TestAddAndList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	target, err := s.Add("Desktop", "00:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	if target.Name != "Desktop" {
		t.Fatalf("expected name Desktop, got %s", target.Name)
	}
	if target.MAC == "" {
		t.Fatal("expected non-empty MAC")
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 target, got %d", len(list))
	}
}

func TestAdd_DuplicateMac(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, _ := NewStore(path)
	_, err := s.Add("A", "00:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Add("B", "00:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(s.List()))
	}
}

func TestAdd_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, _ := NewStore(path)
	_, err := s.Add("", "00:11:22:33:44:55")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	_, err = s.Add("Desktop", "")
	if err == nil {
		t.Fatal("expected error for empty mac")
	}
	_, err = s.Add("Desktop", "invalid")
	if err == nil {
		t.Fatal("expected error for invalid mac")
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, _ := NewStore(path)
	target, _ := s.Add("Desktop", "00:11:22:33:44:55")
	if err := s.Delete(target.ID); err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatalf("expected 0 targets after delete, got %d", len(s.List()))
	}
}

func TestDelete_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, _ := NewStore(path)
	err := s.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}

func TestWake_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wol.json")
	s, _ := NewStore(path)
	err := s.Wake("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}

func TestParseMac(t *testing.T) {
	tests := []struct {
		name    string
		mac     string
		wantErr bool
	}{
		{"standard colons", "00:11:22:33:44:55", false},
		{"dashes", "00-11-22-33-44-55", false},
		{"uppercase", "AA:BB:CC:DD:EE:FF", false},
		{"no separator", "001122334455", false},
		{"dot separator", "0011.2233.4455", true},
		{"invalid hex", "xx:11:22:33:44:55", true},
		{"too short", "00:11:22", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseMac(tt.mac)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseMac(%q) error=%v, wantErr=%v", tt.mac, err, tt.wantErr)
			}
		})
	}
}

func TestNormaliseMac(t *testing.T) {
	mac := normaliseMac("00-11-22-33-44-55")
	if mac != "00:11:22:33:44:55" {
		t.Fatalf("expected '00:11:22:33:44:55', got '%s'", mac)
	}
}

func TestGenID(t *testing.T) {
	id := genID()
	if len(id) != 12 {
		t.Fatalf("expected 12-char hex ID, got %d chars", len(id))
	}
	id2 := genID()
	if id == id2 {
		t.Fatal("two generated IDs should not be equal")
	}
}

func TestNewStore_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unreadable.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0000); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path)
	if err == nil {
		t.Fatal("expected error for unreadable file")
	}
}
