# KilasOS admin guide — Overview

This guide is for the person operating a KilasOS NAS — adding storage, sharing
files, configuring backups, dealing with the occasional broken pool. It
assumes Linux comfort but not ZFS expertise. Each chapter is a separate page;
this one orients you.

## Mental model

KilasOS is a single service (`nasd`) that orchestrates a small set of standard
Linux components. There is no proprietary storage layer or daemon zoo. If you
know how to use `zpool`, `samba`, `systemctl`, and `iptables`, you already know
how KilasOS works under the hood — the WebUI is a structured front-end over
those tools.

```
┌─ Browser ──────────────────────────────────────────────────────┐
│         WebUI (single index.html, ~11k LOC, no build step)     │
└────────────────────────────────────────────────────────────────┘
                              │  HTTP + bearer token / session
                              ▼
┌─ nasd (Go daemon, runs as user `kilasos`) ─────────────────────┐
│  HTTP API (/api/v1/...)                                        │
│  ────────────────────────────────────────────────────────────  │
│  ZFS  •  Samba  •  NFS  •  Docker  •  iptables  •  WireGuard   │
│  Backups (Borg/Restic/rclone)  •  Auth (OIDC/LDAP/TOTP)        │
│  Monitor + alerts  •  Audit log  •  Scheduler  •  File mgr     │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─ Host kernel + standard userspace tools ──────────────────────┐
│  zfs, zpool, smbd, exportfs, iptables, systemctl, journalctl  │
└────────────────────────────────────────────────────────────────┘
```

The daemon does not embed ZFS or Samba; it shells out to the standard tools
(with required capabilities granted by the systemd unit's `AmbientCapabilities=`
directive — no sudo involved). Every privileged invocation is gated by an
allowlist in `internal/storage/priv.go`.

## Where things live

| Path | Owner | Contents |
|---|---|---|
| `/usr/local/sbin/nasd` | root | the daemon binary |
| `/etc/systemd/system/nasd.service` | root | systemd unit (capabilities, sandbox) |
| `/etc/ssh/sshd_config.d/99-kilasos.conf` | root | makes sshd consult the WebUI-managed authorized_keys |
| `/etc/kilasos/` | root | config: `env`, `authorized_keys`, TLS cert (when set) |
| `/var/lib/kilasos/` | kilasos | state: `users.json`, `sessions.json`, `audit.json`, `schedules.json`, `apps.json`, `webhook.json`, `smtp.json`, `wol.json`, `rsync.json`, `remotes.json` |
| `/var/log/kilasos/` | kilasos | application logs (most logging goes to the journal) |
| `/mnt/` | (varies) | ZFS pool mountpoints |
| `/opt/kilasos-apps/` | kilasos | docker-compose stacks created from the app catalog |

All state files are plain JSON — readable, hand-editable when the WebUI is
unreachable. The daemon detects schema version on startup and migrates forward
(see `internal/storage/migrate.go`); never edit while `nasd` is running.

## The WebUI tabs

The nav bar maps directly to chapters in this guide:

| Tab | Chapter |
|---|---|
| Overview | this page (real-time host stats — CPU, RAM, network, disk I/O) |
| Storage | [storage.md](storage.md) — pools, datasets, snapshots, disks |
| Files | [files.md](files.md) — web file manager + shares config |
| Network | [network.md](network.md) — interfaces, firewall, VPN, diagnostics |
| Containers | [apps.md](apps.md) (Docker engine view) |
| Apps | [apps.md](apps.md) — catalog templates, deployed stacks |
| Settings | covers [users-auth.md](users-auth.md), [alerts.md](alerts.md), [security.md](security.md), system settings, updates |
| Console | live shell streaming (admin only) — for emergencies |

## Day-to-day operation

A working KilasOS instance needs almost no daily attention. The things you
will routinely interact with:

1. **Snapshots.** Configure once in Storage → Snapshots. The scheduler takes
   them at hourly/daily/weekly intervals and prunes old ones.
2. **Backups.** Configure a Borg/Restic/rclone job in Settings → Backups.
   Watch the job list; runs are logged.
3. **Alerts.** Storage failures, scrub errors, disk-temperature spikes, and
   container restart loops fire alerts to your configured channels (webhook,
   Discord, Slack, SMTP). Configure in Settings → Notifications.
4. **Audit log.** Every destructive HTTP action is logged with user + IP. View
   in Settings → Audit log. Retention defaults to 90 days / 5 GB.

## Service management

```sh
# Status
systemctl status nasd
journalctl -u nasd -f                 # follow live log
journalctl -u nasd -p err --since today

# Restart cleanly (drops sessions briefly; ZFS pools unaffected)
sudo systemctl restart nasd

# Configuration changes via /etc/kilasos/env take effect on restart.

# Tail audit + alert logs
sudo journalctl -u nasd -t audit
```

The unit is sandboxed (read-only `/etc` and `/usr`, no namespace creation,
syscall filter). If you find `nasd` failing to perform an operation that
worked in an unsandboxed environment, see the
[security model notes in security.md](security.md#sandbox-limits).

## Backing up the config

The fastest way to "back up KilasOS itself" is to back up the state directory:

```sh
sudo tar -czf kilasos-state-$(date +%F).tar.gz \
  -C / \
  etc/kilasos \
  var/lib/kilasos
```

Drop that tarball alongside your data backups. To restore on a fresh host,
install the daemon (see [INSTALL.md](../INSTALL.md)), unpack the tarball over
`/`, then `systemctl start nasd`. Pools are imported automatically by the
unit's `After=zfs.target` ordering.

## Getting help

- **Logs:** `journalctl -u nasd` is the first stop.
- **Healthcheck endpoint:** `curl http://localhost:8080/healthz` returns
  version + commit + build date even when the WebUI looks unwell.
- **Capability sanity check:** `cat /proc/$(pidof nasd)/status | grep ^Cap` —
  `CapAmb` should be non-zero (the daemon inherits CAP_SYS_ADMIN, CAP_NET_ADMIN
  and friends from the unit).
- **Smoke tests:** `bash coordinator/smoke-tests.sh` (with `TOKEN=` set) runs
  33 read-only API checks against a live daemon. Useful for confirming a
  deploy didn't regress anything.

If something is broken in a way that the UI can't reach, see [recovery.md](recovery.md).

---

**Next:** [Storage →](storage.md)
