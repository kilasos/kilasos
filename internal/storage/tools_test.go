package storage

import (
	"context"
	"errors"
	"testing"
)

func TestNewToolRegistry_Smoke(t *testing.T) {
	_, err := NewToolRegistry(context.Background())
	if err != nil && !errors.Is(err, ErrRequiredToolMissing) {
		t.Fatalf("expected nil or ErrRequiredToolMissing, got: %v", err)
	}
}

func TestAsMap_HasExpectedKeys(t *testing.T) {
	registry, err := NewToolRegistry(context.Background())
	if err != nil {
		if !errors.Is(err, ErrRequiredToolMissing) {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Skip("skipping because required tools are missing")
	}

	m := registry.AsMap()
	expected := []string{
		"borg", "restic", "rclone", "trivy", "lynis", "jdupes", "smartctl",
		"caddy", "wireguard", "btrfs", "zfs", "samba", "nfs", "docker",
		"upnpc", "cloudflared", "tailscale", "lsof", "hdparm", "badblocks", "jq",
	}
	for _, key := range expected {
		if _, ok := m[key]; !ok {
			t.Errorf("expected key %q to be present", key)
		}
	}
}

func TestAsMap_AllValuesAreBool(t *testing.T) {
	registry, err := NewToolRegistry(context.Background())
	if err != nil {
		if !errors.Is(err, ErrRequiredToolMissing) {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Skip("skipping because required tools are missing")
	}

	m := registry.AsMap()
	for k, v := range m {
		if _, ok := interface{}(v).(bool); !ok {
			t.Errorf("value for key %q is not a bool: %T", k, v)
		}
	}
}
