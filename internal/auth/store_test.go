package auth

import (
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *UserStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewUserStore(filepath.Join(dir, "users.json"), filepath.Join(dir, "sessions.json"), 0)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	return store
}

func TestUserStore_RegisterAndCount(t *testing.T) {
	s := newTestStore(t)
	if err := s.Register("alice", "AlicePass1!", "admin"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if c := s.Count(); c != 1 {
		t.Fatalf("expected count=1, got %d", c)
	}
}

func TestUserStore_LoginGoodPassword(t *testing.T) {
	s := newTestStore(t)
	if err := s.Register("bob", "BobPass1!", "user"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, role, _, err := s.Login("bob", "BobPass1!", "")
	if err != nil {
		t.Fatalf("Login good: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}
	if role != "user" {
		t.Errorf("expected role=user, got %q", role)
	}
}

func TestUserStore_LoginBadPassword(t *testing.T) {
	s := newTestStore(t)
	_ = s.Register("carol", "CarolPass1!", "user")
	if _, _, _, err := s.Login("carol", "WrongPassword", ""); err == nil {
		t.Fatal("expected error on bad password")
	}
}

func TestUserStore_SetRole(t *testing.T) {
	s := newTestStore(t)
	_ = s.Register("eve", "EvePass1!", "user")
	if err := s.SetRole("eve", "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
}

func TestUserStore_Exists(t *testing.T) {
	s := newTestStore(t)
	_ = s.Register("frank", "FrankPass1!", "user")
	if !s.Exists("frank") {
		t.Error("Exists returned false for registered user")
	}
	if s.Exists("ghost") {
		t.Error("Exists returned true for nonexistent user")
	}
}
