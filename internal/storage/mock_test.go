package storage

import (
	"context"
	"testing"
)

func TestNewToolRegistry_ContextOK(t *testing.T) {
	ctx := context.Background()
	_, err := NewToolRegistry(ctx)
	if err != nil && err.Error() == "" {
		t.Log("NewToolRegistry returned error (expected if tools missing):", err)
	}
}

func TestToolRegistry_AsMap(t *testing.T) {
	ctx := context.Background()
	registry, err := NewToolRegistry(ctx)
	if err != nil {
		t.Skip("required tools missing, skipping AsMap test")
	}
	m := registry.AsMap()
	if m == nil {
		t.Fatal("AsMap() returned nil")
	}
	if _, ok := m["zfs"]; !ok {
		t.Error("AsMap() missing expected key 'zfs'")
	}
}
