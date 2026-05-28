package storage

import (
	"context"
	"fmt"
	"os/exec"
)

type ToolRegistry struct {
	Borg, Restic, Rclone, Trivy, Lynis, JDupes, SmartCtl, Caddy,
	WireGuard, Btrfs, ZFS, Samba, NFS, Docker, UPnPC, Cloudflared,
	Tailscale, Lsof, Hdparm, Badblocks, Jq bool
}

var ErrRequiredToolMissing = fmt.Errorf("required tool missing")

func NewToolRegistry(_ context.Context) (*ToolRegistry, error) {
	required := []string{"zfs", "zpool", "systemctl", "journalctl", "ip", "mount"}
	for _, name := range required {
		if _, err := exec.LookPath(name); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrRequiredToolMissing, name)
		}
	}

	registry := &ToolRegistry{}
	registry.ZFS = exists("zfs")
	registry.Borg = exists("borg")
	registry.Restic = exists("restic")
	registry.Rclone = exists("rclone")
	registry.Trivy = exists("trivy")
	registry.Lynis = exists("lynis")
	registry.JDupes = exists("jdupes")
	registry.SmartCtl = exists("smartctl")
	registry.Caddy = exists("caddy")
	registry.WireGuard = exists("wg") || exists("wg-quick")
	registry.Btrfs = exists("btrfs")
	registry.Samba = exists("smbd") || exists("smbpasswd")
	registry.NFS = exists("exportfs") || exists("mount.nfs")
	registry.Docker = exists("docker")
	registry.UPnPC = exists("upnpc")
	registry.Cloudflared = exists("cloudflared")
	registry.Tailscale = exists("tailscale")
	registry.Lsof = exists("lsof")
	registry.Hdparm = exists("hdparm")
	registry.Badblocks = exists("badblocks")
	registry.Jq = exists("jq")

	return registry, nil
}

func exists(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func (r *ToolRegistry) AsMap() map[string]bool {
	return map[string]bool{
		"borg":         r.Borg,
		"restic":       r.Restic,
		"rclone":       r.Rclone,
		"trivy":        r.Trivy,
		"lynis":        r.Lynis,
		"jdupes":       r.JDupes,
		"smartctl":     r.SmartCtl,
		"caddy":        r.Caddy,
		"wireguard":    r.WireGuard,
		"btrfs":        r.Btrfs,
		"zfs":          r.ZFS,
		"samba":        r.Samba,
		"nfs":          r.NFS,
		"docker":       r.Docker,
		"upnpc":        r.UPnPC,
		"cloudflared":  r.Cloudflared,
		"tailscale":    r.Tailscale,
		"lsof":         r.Lsof,
		"hdparm":       r.Hdparm,
		"badblocks":    r.Badblocks,
		"jq":           r.Jq,
	}
}