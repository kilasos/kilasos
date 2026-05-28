# Installing KilasOS

KilasOS ships in three forms:

| Form | When to use | Status |
|---|---|---|
| **`.deb` package** | Adding `nasd` to an existing Debian/Ubuntu host | Buildable from source today; signed apt repo planned for Phase 4 |
| **Bootable ISO** | Turning a bare machine into a NAS | Built in Phase 3, not yet published — see `os-installer/` |
| **Container image** | Test environment, NAS-in-a-VM, hobbyist setups | Buildable from source today; `ghcr.io` publishing planned for Phase 4 |

Until release artifacts ship, install from source. The instructions below
assume **Debian 12 (bookworm)** or **Ubuntu 24.04 (noble)** on amd64 or arm64.

---

## Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Debian 12, Ubuntu 24.04 | same |
| Arch | amd64, arm64 | amd64 |
| RAM | 2 GB | 8 GB+ (more for dedup/L2ARC) |
| Boot disk | 16 GB | 32 GB SSD |
| Data disks | one device | two+ (mirror) |
| Network | one NIC | DHCP reservation or static IP |

### Required packages

```sh
sudo apt update
sudo apt install -y \
  golang-1.23 git \
  zfsutils-linux zfs-zed \
  samba samba-common-bin \
  smartmontools \
  systemd
```

### Optional packages (used by individual features)

```sh
sudo apt install -y \
  docker.io \
  restic borgbackup rclone \
  jdupes fail2ban lynis \
  wireguard cloudflared
```

Each is gated by the daemon's tool registry — missing tools degrade gracefully
(the corresponding UI panels show "feature unavailable" rather than 500-ing).

---

## Option A — build from source and install manually

```sh
git clone https://github.com/kilasos/kilasos.git
cd kilasos
bash scripts/build.sh
```

`bash scripts/build.sh` produces `bin/nasd` with version + commit + build-date
stamped in. Verify:

```sh
./bin/nasd --version
# nasd 0.45.0+abc1234+2026-05-21T... (commit abc1234, built 2026-05-21T...)
```

Install the binary, unit, sshd drop-in, then run `postinst.sh` to create the
service account and seed directories:

```sh
sudo install -m 0755 bin/nasd /usr/local/sbin/nasd
sudo install -m 0644 packaging/systemd/nasd.service \
                     /etc/systemd/system/nasd.service
sudo install -m 0644 packaging/sshd_config.d/99-kilasos.conf \
                     /etc/ssh/sshd_config.d/99-kilasos.conf
sudo bash packaging/postinst.sh
sudo systemctl start nasd
sudo systemctl status nasd
```

What `postinst.sh` does:

1. Creates the `kilasos` system user + group (no login, no home).
2. Adds `kilasos` to the `docker` group if Docker is installed.
3. Creates `/var/lib/kilasos`, `/var/log/kilasos`, `/etc/kilasos` with correct
   ownership and modes.
4. Enables and reloads the systemd unit.
5. Validates and reloads `sshd` so the WebUI-managed authorized_keys file is
   honored.

---

## Option B — build a `.deb` and install via dpkg

Requires `nfpm`:

```sh
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
```

Then:

```sh
bash scripts/build.sh
nfpm pkg --config packaging/nfpm.yaml --packager deb --target dist/
sudo apt install ./dist/kilasos-nasd_*_amd64.deb
```

The `.deb` carries the same artifacts that Option A installs by hand, plus
package metadata, the man page, and conffile-managed sudoers + sshd drop-ins.

---

## Option C — container image

A multi-stage `Dockerfile` lives in `packaging/Dockerfile`. The image is
based on `debian:bookworm-slim` and bundles ZFS userspace tools, Samba,
fail2ban, jdupes, etc. ZFS requires `--privileged` (or `CAP_SYS_ADMIN` plus
`/dev/zfs` passthrough). Volumes:

| Container path | What lives there |
|---|---|
| `/mnt` | mount point for pools |
| `/var/lib/kilasos` | state (users, sessions, audit, schedules, …) |
| `/etc/kilasos` | config (env, authorized_keys, certs) |

Build + run:

```sh
docker build -f packaging/Dockerfile -t kilasos/nasd:dev .
docker run -d --name nasd --privileged \
  -p 8080:8080 \
  -v /mnt:/mnt \
  -v kilasos-state:/var/lib/kilasos \
  -v kilasos-etc:/etc/kilasos \
  kilasos/nasd:dev
```

---

## First-boot setup

1. Open `http://<host>:8080` in a browser.
2. The WebUI shows a setup form on first launch — create the initial admin user
   (username + password; TOTP optional). After submit, the form converts to a
   login screen and `/var/lib/kilasos/users.json` is created.
3. Log in. Land on the **Overview** tab.
4. Go to **Storage → Pools** and create a ZFS pool from attached disks. The
   wizard handles mirror / raidz / raidz2 layouts.
5. Create datasets, configure shares, optionally schedule snapshots and
   backups. See the [admin guide](admin/overview.md).

The legacy environment-variable token (`KILASOS_TOKEN`, used by smoke tests)
remains supported for headless automation; the WebUI uses session cookies +
session-bound bearer tokens.

---

## Configuring environment

`nasd.service` reads `/etc/kilasos/env` (if present) via systemd's
`EnvironmentFile=`. Common overrides — see `packaging/env.example` for the
canonical list:

```sh
# /etc/kilasos/env
KILASOS_LOG_LEVEL=info        # debug | info | warn | error
KILASOS_TOKEN=                # legacy bearer token (leave blank to disable)
KILASOS_WEBHOOK=              # fallback webhook URL for alerts
```

Daemon flags (in `nasd.service`) override the same settings; run
`/usr/local/sbin/nasd --help` for the full list.

---

## Verify

After install:

```sh
# Service alive and running as `kilasos`
systemctl status nasd
ps -o pid,user,cmd -p "$(systemctl show -p MainPID --value nasd)"

# API responds
curl -s http://localhost:8080/healthz
# {"status":"ok","version":"...","commit":"...","build_date":"..."}

# Smoke suite (read-only checks against the daemon)
TOKEN=<your-bearer-token> bash coordinator/smoke-tests.sh
# Expected: PASS: 33   FAIL: 0
```

---

## Upgrading

### From the `.deb`

```sh
sudo apt install ./kilasos-nasd_<new>_amd64.deb
# prerm stops the daemon; postinst restarts it.
```

State files in `/var/lib/kilasos/` are conffile-protected — they survive
upgrades and purges. The daemon runs schema-version migrations on startup
when needed; downgrades are not supported.

### From source

```sh
cd kilasos
git pull
bash scripts/build.sh
sudo systemctl stop nasd
sudo install -m 0755 bin/nasd /usr/local/sbin/nasd
sudo systemctl start nasd
```

---

## Uninstall

```sh
sudo systemctl stop nasd
sudo systemctl disable nasd
sudo rm /etc/systemd/system/nasd.service
sudo rm /etc/ssh/sshd_config.d/99-kilasos.conf
sudo systemctl daemon-reload
sudo systemctl reload ssh
sudo rm /usr/local/sbin/nasd
# State (preserves your config; remove only if you really mean it):
sudo rm -rf /var/lib/kilasos /var/log/kilasos /etc/kilasos
# Service account (only if nothing else uses it):
sudo userdel kilasos
sudo groupdel kilasos
```

`apt purge kilasos-nasd` does all of the above except removing
`/var/lib/kilasos` and `/var/log/kilasos` — those are deliberately preserved
across purges to protect your audit log and saved schedules.

---

## Troubleshooting installs

- **`systemctl status nasd` shows `code=exited, status=1/FAILURE`** — run
  `journalctl -u nasd -n 50` and check for a missing state-directory or
  permission error. Re-run `postinst.sh`.
- **WebUI loads but every API call returns 500** — usually means the required
  tools (`zfs`, `zpool`, etc.) aren't installed. Check `journalctl -u nasd`
  for a "missing tool" message at startup.
- **SSH login as root fails after install** — the postinst should have reloaded
  sshd, but if `sshd -t` printed warnings, the reload may have been skipped.
  Run `sudo sshd -t` to diagnose and `sudo systemctl reload ssh` to retry.
- **"Permission denied" on ZFS operations** — `/dev/zfs` must be readable by
  the process. Confirm `nasd` is running with `CapAmb` including `cap_sys_admin`:
  `grep ^Cap /proc/$(pidof nasd)/status`.

For deeper issues, see the [recovery guide](admin/recovery.md).
