# KilasOS

A self-hosted NAS distribution built on Debian. Web UI for ZFS pools, shares,
backups, and containerized apps — managed by a single Go daemon (`nasd`).

> **Status:** alpha. M450 of the M1–M450 roadmap is complete; the project is in
> Phase 4 (beta + 1.0) per [`coordinator/NEXT-STAGE-PLAN.md`](coordinator/NEXT-STAGE-PLAN.md).
> Not yet recommended for production data. Take backups.

## What you get

- **ZFS-first storage.** Mirror, raidz, raidz2, raidz3. Pool/dataset/snapshot
  management. Scrubs, trims, expansions, replacements. Send/receive over SSH.
  L2ARC, SLOG, dedup, compression, per-dataset encryption.
- **Shares.** SMB (Samba), NFS, per-user permissions, AD/LDAP integration,
  public share-link endpoint with optional expiry.
- **File manager.** Browse, upload, search, preview, trash, restore.
- **Backups.** Borg, Restic, rclone — scheduled, with restore points.
- **Apps.** 34-template catalog (Jellyfin, Nextcloud, Vaultwarden, *arr suite,
  Uptime Kuma, Portainer, …) via docker-compose.
- **Network.** Interface config, firewall (iptables/nft), WireGuard,
  Cloudflare Tunnel, Tailscale, mDNS, dnsmasq DHCP, UPnP, Wake-on-LAN.
- **Auth.** Local users with roles (admin / user / readonly), OIDC, LDAP,
  WebAuthn, TOTP, API keys, brute-force tracker.
- **Observability.** Metrics (Prometheus-compatible), alerts, webhook + SMTP
  channels, log search, journal aggregation, optional Loki push.
- **Security.** AppArmor, Lynis, Trivy (container scanning), fail2ban,
  audit log, GDPR/privacy mode.

The web UI is a single HTML/JS file (~11k LOC) talking to a Go HTTP API
(~28k LOC across `cmd/` + `internal/`). No Node.js, no frontend build step.

## Quick start

Pre-built `.deb` packages are not yet published. Build and install from source:

```sh
# Requirements: Go 1.23+, libc, zfsutils-linux, samba, smartmontools.
git clone https://github.com/kilasos/kilasos.git
cd kilasos
bash scripts/build.sh
sudo install -m 0755 bin/nasd /usr/local/sbin/nasd
sudo install -m 0644 packaging/systemd/nasd.service /etc/systemd/system/nasd.service
sudo install -m 0644 packaging/sshd_config.d/99-kilasos.conf /etc/ssh/sshd_config.d/
sudo bash packaging/postinst.sh
sudo systemctl start nasd
```

Open `http://<host>:8080` and complete the first-boot setup. The full install
guide lives in [`docs/INSTALL.md`](docs/INSTALL.md).

## Documentation

- [Install](docs/INSTALL.md) — from `.deb`, container, source, ISO (when shipped)
- [Admin guide](docs/admin/overview.md) — concepts, day-to-day operation
  - [Storage](docs/admin/storage.md) (ZFS pools, datasets, snapshots)
  - [Shares](docs/admin/shares.md) (SMB, NFS, permissions, AD)
  - [Files](docs/admin/files.md) (web file manager)
  - [Network](docs/admin/network.md) (firewall, VPN, tunnels)
  - [Apps](docs/admin/apps.md) (catalog, containers, compose)
  - [Users & auth](docs/admin/users-auth.md) (local, OIDC, LDAP, TOTP)
  - [Backups](docs/admin/backups.md) (Borg, Restic, rclone)
  - [Alerts](docs/admin/alerts.md) (channels, rules)
  - [Security](docs/admin/security.md) (TLS, fail2ban, audit, scanners)
  - [Recovery](docs/admin/recovery.md) (rescue, pool import, lost auth)

## Architecture in one paragraph

`nasd` is a single Go binary that listens on `:8080` and serves the web UI plus
a JSON HTTP API at `/api/v1/`. The daemon runs as the unprivileged `kilasos`
system user under a sandboxed systemd unit; required kernel capabilities are
granted via `AmbientCapabilities=` and inherited to child processes (`zfs`,
`zpool`, `iptables`, `smbd`, etc.). State files live in `/var/lib/kilasos/`;
config in `/etc/kilasos/`; logs in `/var/log/kilasos/` and the journal.

## Hardware compatibility

See [`os-installer/hcl/hardware-compatibility.md`](os-installer/hcl/hardware-compatibility.md).
ZFS is the primary storage backend, so HBA cards in IT/JBOD mode are preferred
over RAID controllers. Minimum: 2 GB RAM (8 GB+ recommended for ZFS dedup/L2ARC),
amd64 or arm64.

## License

GPL-3.0. See `packaging/copyright`.
