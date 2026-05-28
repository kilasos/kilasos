# Operator Playbook

Concrete failure modes and recovery steps for KilasOS operators.

## Daemon won't start

**Symptoms:** `systemctl status nasd` shows `failed` or `inactive`.

**Check journal:**
```bash
journalctl -u nasd -n 50 --no-pager
```

**Common causes and fixes:**

| Cause | Fix |
|-------|-----|
| Port 8080 already in use | `ss -tlnp \| grep 8080` — stop the conflicting process or change `--addr` in `/etc/kilasos/env` |
| Missing `/etc/kilasos/env` | `sudo touch /etc/kilasos/env` (empty file is fine; defaults apply) |
| Capability denied | Ensure `AmbientCapabilities=` in `nasd.service` matches the deployed service file. `systemctl cat nasd` and compare with `packaging/systemd/nasd.service` |
| Required tool missing (zfs/zpool) | `which zfs zpool` — install with `apt install zfsutils-linux` |
| No ZFS pools imported | `sudo zpool import -a` then restart nasd |

## Pool disappears

**Symptoms:** Storage tab shows no pools, shares return 500.

```bash
# List importable pools
sudo zpool import

# Import the missing pool
sudo zpool import <pool-name>

# If the pool was force-exported or has a different hostid
sudo zpool import -f <pool-name>

# Then restart nasd
sudo systemctl restart nasd
```

If the pool is damaged, try:
```bash
sudo zpool import -F <pool-name>   # roll back to last good txg
sudo zpool import -o readonly=on <pool-name>  # import read-only for recovery
```

## All shares return 403

**Symptoms:** Every authenticated share/file request returns HTTP 403.

**Check auth tokens:**
```bash
cat /var/lib/kilasos/users.json | python3 -m json.tool
```
Verify at least one user with `"role": "admin"` exists.

**If users.json is corrupt:**
```bash
# Restore from the audit trail or backup
sudo cp /var/lib/kilasos/users.json.bak /var/lib/kilasos/users.json
sudo systemctl restart nasd
```

## Audit log fills disk

**Symptoms:** `/var/lib/kilasos/audit.json` grows large, disk space low.

```bash
# Check size
du -sh /var/lib/kilasos/audit.json

# Set retention via API (admin-only)
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_age_days":30,"max_size_mb":100}' \
  http://localhost:8080/api/v1/audit/retention

# Manually rotate
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/audit/rotate
```

Rotated logs land gzipped in `/var/lib/kilasos/audit-archives/`.

## Container deploys fail

**Symptoms:** "Deploy" button returns an error or the container never starts.

**Check Docker installation:**
```bash
docker --version
systemctl is-active docker
```
If Docker is not installed: `sudo apt install docker.io && sudo usermod -aG docker kilasos`.

**Check image registry:**
```bash
docker pull linuxserver/jellyfin:latest
```
If pull fails from the KilasOS host, check DNS and network access.

**Check app data directory:**
```bash
ls -la /var/lib/kilasos/apps/<app-name>/
cat /var/lib/kilasos/apps/<app-name>/docker-compose.yml
```

## GDPR export hangs

**Symptoms:** `GET /api/v1/security/gdpr/export` times out or returns 500.

If the `/mnt` walk is large, the export can take minutes. Kill the stuck process:
```bash
sudo pkill -f "gdpr-export"
```
Then retry. If it consistently hangs, file an issue with the pool sizes
and approximate file counts.

## Certificate expires

**Symptoms:** Browser shows certificate warning, HTTPS connections fail.

**Generate a new self-signed cert via WebUI:**
1. Navigate to Settings → Security → Server Certificate.
2. Enter a Common Name (e.g., `kilasos.local`).
3. Click "Generate".

**Or via API:**
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"common_name":"kilasos.local"}' \
  http://localhost:8080/api/v1/system/server-certificate/generate
```

## Update breaks something

**Symptoms:** After an `apt upgrade` of `kilasos-nasd`, some feature stops working.

```bash
# Hold back the package
sudo apt-mark hold kilasos-nasd

# Restore from backup
# (if you backed up /var/lib/kilasos/ before the upgrade)
sudo systemctl stop nasd
sudo cp -a /var/lib/kilasos-backup/* /var/lib/kilasos/
sudo systemctl start nasd
```

Schema migrations run forward on startup — downgrading may lose data.
Always back up before an upgrade.

## safePath blocks legitimate path

**Symptoms:** A file operation returns 403 with "invalid path" for a path
you know is valid.

Verify the path follows the `/mnt/<pool>/<dataset>/...` convention.
`safePath()` requires:
- No `..` in the path
- Must start with `/mnt/` (not a subdirectory like `/mntfoo`)
- Full path must clean to under `/mnt/`

If your pool is mounted at an unexpected path, adjust the mount or
file an issue with the path and pool configuration.
