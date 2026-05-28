package storage

// RunPriv invokes allowlisted binaries directly; privileges come from the
// unit's AmbientCapabilities (sudo doesn't work — the hardened unit implicitly
// sets kernel NoNewPrivs=1, blocking setuid escalation).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrPrivBinaryNotAllowed = errors.New("binary not in privileged allowlist")

var privAllowlist = map[string]bool{
	"/usr/sbin/zfs":         true,
	"/usr/sbin/zpool":       true,
	"/usr/sbin/iptables":    true,
	"/usr/sbin/iptables-save": true,
	"/usr/sbin/exportfs":    true,
	"/usr/sbin/smbd":        true,
	"/usr/sbin/ufw":         true,
	"/usr/sbin/fail2ban-client": true,
	"/usr/bin/smartctl":     true,
	"/usr/bin/systemctl":    true,
	"/usr/bin/hostnamectl":  true,
	"/usr/bin/timedatectl":  true,
	"/usr/bin/journalctl":   true,
	"/sbin/mount":           true,
	"/sbin/umount":          true,
	"/sbin/ip":              true,
	"/usr/bin/wg":           true,
	"/usr/bin/btrfs":        true,
	"/usr/bin/smbcontrol":   true,
	"/usr/bin/smbstatus":    true,
	"/usr/bin/net":          true,
	"/sbin/shutdown":        true,
	"/bin/ping":             true,
	"/usr/bin/ping":         true,
	"/usr/sbin/modprobe":    true,  // SEC-05: USB allowlist enforcement
	"/usr/sbin/udevadm":     true,  // SEC-05: reload udev rules after USB allowlist change
	"/usr/sbin/aa-enforce":  true,  // SEC-08: AppArmor profile enforce mode
	"/usr/sbin/aa-complain": true,  // SEC-08: AppArmor profile complain mode
}

func RunPriv(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	// Resolve binary path if not absolute
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
		}
		absBin = resolved
	}

	// Check allowlist
	if !privAllowlist[absBin] {
		return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPrivWithStdin(ctx context.Context, stdin io.Reader, bin string, args ...string) ([]byte, []byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
		}
		absBin = resolved
	}

	if !privAllowlist[absBin] {
		return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Stdin = stdin
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPlain(ctx context.Context, bin string, args ...string) ([]byte, []byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		absBin = resolved
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPlainWithStdin(ctx context.Context, stdin io.Reader, bin string, args ...string) ([]byte, []byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		absBin = resolved
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Stdin = stdin
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPlainWithEnv(ctx context.Context, env []string, bin string, args ...string) ([]byte, []byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		absBin = resolved
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Env = append(cmd.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPlainWithDir(ctx context.Context, dir, bin string, args ...string) ([]byte, []byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		absBin = resolved
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.Stderr, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		return nil, nil, fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
	}
	return out, nil, nil
}

func RunPrivWithStdout(ctx context.Context, stdout io.Writer, bin string, args ...string) ([]byte, error) {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
		}
		absBin = resolved
	}

	if !privAllowlist[absBin] {
		return nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), ErrPrivBinaryNotAllowed)
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Stdout = stdout
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return []byte(stderrBuf.String()), fmt.Errorf("runpriv %s: %w", filepath.Base(bin), exitErr)
		}
		return nil, fmt.Errorf("runpriv %s: %w", filepath.Base(bin), err)
	}
	return nil, nil
}

func RunPlainWithIO(ctx context.Context, stdout, stderr io.Writer, bin string, args ...string) error {
	absBin := bin
	if !filepath.IsAbs(bin) {
		resolved, err := exec.LookPath(bin)
		if err != nil {
			return fmt.Errorf("runplain %s: %w", filepath.Base(bin), err)
		}
		absBin = resolved
	}

	cmd := exec.CommandContext(ctx, absBin, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}