package storage

import (
	"context"
	"testing"
)

func TestMock_Disks(t *testing.T) {
	p := NewMock()
	if _, err := p.Disks(context.Background()); err != nil {
		t.Fatalf("Disks: %v", err)
	}
}

func TestMock_Arrays(t *testing.T) {
	p := NewMock()
	if _, err := p.Arrays(context.Background()); err != nil {
		t.Fatalf("Arrays: %v", err)
	}
}

func TestMock_Shares(t *testing.T) {
	p := NewMock()
	if _, err := p.Shares(context.Background()); err != nil {
		t.Fatalf("Shares: %v", err)
	}
}

func TestMock_Containers(t *testing.T) {
	p := NewMock()
	if _, err := p.Containers(context.Background()); err != nil {
		t.Fatalf("Containers: %v", err)
	}
}

func TestMock_Metrics(t *testing.T) {
	p := NewMock()
	if _, err := p.Metrics(context.Background()); err != nil {
		t.Fatalf("Metrics: %v", err)
	}
}

func TestMock_Snapshots(t *testing.T) {
	p := NewMock()
	if _, err := p.Snapshots(context.Background(), ""); err != nil {
		t.Fatalf("Snapshots: %v", err)
	}
}

func TestMock_GetSettings(t *testing.T) {
	p := NewMock()
	if _, err := p.GetSettings(context.Background()); err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
}

func TestMock_NetInterfaces(t *testing.T) {
	p := NewMock()
	if _, err := p.NetInterfaces(context.Background()); err != nil {
		t.Fatalf("NetInterfaces: %v", err)
	}
}
