package storage

import (
	"errors"
	"testing"
)

func resetMigrationsForTest() {
	migrationsMu.Lock()
	migrations = nil
	migrationsMu.Unlock()
}

func TestRegisterMigration_RejectsInvalid(t *testing.T) {
	t.Run("FromGreaterThanOrEqualToTo", func(t *testing.T) {
		resetMigrationsForTest()
		if err := RegisterMigration(Migration{From: 5, To: 3, Apply: func(string) error { return nil }}); err == nil {
			t.Fatal("expected error for From >= To")
		}
	})
	t.Run("NilApply", func(t *testing.T) {
		resetMigrationsForTest()
		if err := RegisterMigration(Migration{From: 1, To: 2, Apply: nil}); err == nil {
			t.Fatal("expected error for nil Apply")
		}
	})
	t.Run("DuplicateEdge", func(t *testing.T) {
		resetMigrationsForTest()
		if err := RegisterMigration(Migration{From: 1, To: 2, Apply: func(string) error { return nil }}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := RegisterMigration(Migration{From: 1, To: 2, Apply: func(string) error { return nil }}); err == nil {
			t.Fatal("expected error for duplicate edge")
		}
	})
}

func TestDetectSchemaVersion_Missing(t *testing.T) {
	resetMigrationsForTest()
	stateDir := t.TempDir()
	v, err := DetectSchemaVersion(stateDir)
	if !errors.Is(err, ErrNoSchemaVersion) {
		t.Fatalf("expected ErrNoSchemaVersion, got %v", err)
	}
	if v != 0 {
		t.Fatalf("expected version 0, got %d", v)
	}
}

func TestWriteAndDetect_Roundtrip(t *testing.T) {
	resetMigrationsForTest()
	stateDir := t.TempDir()
	v := SchemaVersion(3)
	if err := WriteSchemaVersion(stateDir, v); err != nil {
		t.Fatalf("WriteSchemaVersion failed: %v", err)
	}
	detected, err := DetectSchemaVersion(stateDir)
	if err != nil {
		t.Fatalf("DetectSchemaVersion failed: %v", err)
	}
	if detected != v {
		t.Fatalf("expected %d, got %d", v, detected)
	}
}

func TestMigrateForward_AppliesInOrder(t *testing.T) {
	resetMigrationsForTest()
	stateDir := t.TempDir()
	var applied []int
	migrationsMu.Lock()
	migrations = []Migration{
		{From: 0, To: 1, Apply: func(string) error { applied = append(applied, 1); return nil }},
		{From: 1, To: 2, Apply: func(string) error { applied = append(applied, 2); return nil }},
		{From: 2, To: 3, Apply: func(string) error { applied = append(applied, 3); return nil }},
	}
	migrationsMu.Unlock()

	if err := MigrateForward(stateDir, 3, nil); err != nil {
		t.Fatalf("MigrateForward failed: %v", err)
	}

	expected := []int{1, 2, 3}
	if len(applied) != len(expected) {
		t.Fatalf("expected %d steps, got %d", len(expected), len(applied))
	}
	for i := range expected {
		if applied[i] != expected[i] {
			t.Fatalf("expected applied[%d]=%d, got %d", i, expected[i], applied[i])
		}
	}

	// Verify on-disk version
	detected, err := DetectSchemaVersion(stateDir)
	if err != nil {
		t.Fatalf("DetectSchemaVersion failed: %v", err)
	}
	if detected != 3 {
		t.Fatalf("expected version 3, got %d", detected)
	}
}

func TestMigrateForward_RefusesBackward(t *testing.T) {
	resetMigrationsForTest()
	stateDir := t.TempDir()
	// Write initial version 5
	if err := WriteSchemaVersion(stateDir, 5); err != nil {
		t.Fatalf("WriteSchemaVersion failed: %v", err)
	}

	if err := MigrateForward(stateDir, 3, nil); err == nil {
		t.Fatal("expected error for backward migration")
	} else if !errors.Is(err, ErrBackwardMigration) {
		t.Fatalf("expected ErrBackwardMigration, got %v", err)
	}
}

func TestMigrateForward_NoPath(t *testing.T) {
	resetMigrationsForTest()
	stateDir := t.TempDir()
	// Register only 0->1, but target is 2
	if err := RegisterMigration(Migration{From: 0, To: 1, Apply: func(string) error { return nil }}); err != nil {
		t.Fatalf("RegisterMigration failed: %v", err)
	}

	if err := MigrateForward(stateDir, 2, nil); err == nil {
		t.Fatal("expected error for missing path")
	}
}
