package storage

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestRunPriv_RejectsUnallowedBinary(t *testing.T) {
	ctx := context.Background()
	_, _, err := RunPriv(ctx, "/usr/bin/whoami")
	if !errors.Is(err, ErrPrivBinaryNotAllowed) {
		t.Fatalf("expected ErrPrivBinaryNotAllowed, got %v", err)
	}
}

func TestRunPlain_SucceedsOnTrueBinary(t *testing.T) {
	ctx := context.Background()
	// Skip if /bin/true is not found
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true binary not found")
	}
	_, _, err := RunPlain(ctx, "/bin/true")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunPriv_RejectsNonAbsoluteUnknown(t *testing.T) {
	ctx := context.Background()
	_, _, err := RunPriv(ctx, "definitely-not-a-real-binary-xyzzy")
	if !errors.Is(err, ErrPrivBinaryNotAllowed) {
		t.Fatalf("expected ErrPrivBinaryNotAllowed, got %v", err)
	}
}

func TestRunPrivWithStdin_RejectsUnallowed(t *testing.T) {
	ctx := context.Background()
	_, _, err := RunPrivWithStdin(ctx, strings.NewReader("data"), "/usr/bin/whoami")
	if !errors.Is(err, ErrPrivBinaryNotAllowed) {
		t.Fatalf("expected ErrPrivBinaryNotAllowed, got %v", err)
	}
}

func TestRunPrivWithStdout_RejectsUnallowed(t *testing.T) {
	ctx := context.Background()
	var buf strings.Builder
	_, err := RunPrivWithStdout(ctx, &buf, "/usr/bin/whoami")
	if !errors.Is(err, ErrPrivBinaryNotAllowed) {
		t.Fatalf("expected ErrPrivBinaryNotAllowed, got %v", err)
	}
}

func TestRunPlainWithIO_SucceedsOnTrueBinary(t *testing.T) {
	ctx := context.Background()
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true binary not found")
	}
	var outBuf, errBuf strings.Builder
	err := RunPlainWithIO(ctx, &outBuf, &errBuf, "/bin/true")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunPlainWithEnv_Succeeds(t *testing.T) {
	ctx := context.Background()
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true binary not found")
	}
	_, _, err := RunPlainWithEnv(ctx, []string{"FOO=bar"}, "/bin/true")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunPlainWithDir_Succeeds(t *testing.T) {
	ctx := context.Background()
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("true binary not found")
	}
	_, _, err := RunPlainWithDir(ctx, "/tmp", "/bin/true")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRunPlainWithStdin_Succeeds(t *testing.T) {
	ctx := context.Background()
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("cat binary not found")
	}
	stdout, _, err := RunPlainWithStdin(ctx, strings.NewReader("hello"), "cat")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(stdout) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(stdout))
	}
}
