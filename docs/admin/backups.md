# Backups

KilasOS supports three backup engines, picked per-job: **Borg**, **Restic**,
**rclone**. ZFS snapshots + send/receive are managed separately under
[Storage](storage.md#send--receive-replication) — they're the right tool for
replicating between KilasOS hosts, but not for cloud or offsite destinations.

The three engines are thin wrappers around the upstream CLI tools. KilasOS
does not embed them — the daemon shells out to `borg`, `restic`, and `rclone`
on the host. If the binary is missing, the corresponding section in the WebUI
hides itself (gated on `GET /api/v1/system/capabilities`). Install them via
your distribution's package manager before configuring jobs.

## Chapter map

1. Choosing an engine (Borg vs Restic vs rclone)
2. First backup — the wizard
3. Repositories: Borg, Restic, B2 / S3 / SFTP via rclone
4. Scheduling, prune, and retention
5. Restore points and restore wizard
6. Bandwidth / cost estimation
7. Validating a backup (test restore, verify)
8. Encryption and key management
9. Off-host monitoring and webhooks

## Choosing an engine

| Concern | Borg | Restic | rclone |
|---|---|---|---|
| Deduplication | Content-defined chunks, per-repo | Content-defined chunks, per-repo | None — file-level mirror |
| Encryption | AES-256-CTR + HMAC-SHA256 (`repokey` default) | AES-256 + Poly1305 | Provider-side, optional crypt remote |
| Best target | Local disk, SSH-reachable host | Local disk, S3-compatible object store, B2 | Cloud buckets, Dropbox, Drive, Swift |
| Wire efficiency | Excellent (delta + dedup) | Excellent (delta + dedup) | Poor (full file re-upload on change) |
| Restore granularity | Per-archive, per-path | Per-snapshot, per-path | File-tree mirror — restore = reverse sync |
| Retention model | `--keep-hourly/daily/weekly/monthly/yearly` | `forget --keep-*` policy | No native retention — destination versioning only |
| Bidirectional | No | No | Yes (`bisync`) |

Rough defaults:

- **Borg** for the second copy on a local disk or another KilasOS host.
- **Restic** when the destination is S3, B2, Wasabi, or another object store
  and you want dedup + encryption without paying egress on every change.
- **rclone** when you want a plain mirror of files into a consumer cloud
  (Drive, Dropbox, Swift) and don't need point-in-time recovery — the cloud
  provider's own versioning is your safety net.

Engines do not stack. A backup job picks one type. Run multiple jobs if you
want belt-and-braces (e.g. nightly Borg to local, weekly Restic to B2).

## First backup — the wizard

There is no single multi-step wizard; the workflow is split across three
panels in **Storage → Backups** (admin only). To do a first Borg backup of
`/mnt/datapool`:

1. **Init the repo.** In *Borg Backup Repositories*, fill in a repo name
   (`daily-pool`), an encryption passphrase, and pick the encryption mode
   (`repokey` is the default and recommended). Click **Init Repo**. The
   repository is created under `/var/lib/kilasos/backups/borg-<name>/` and
   the passphrase is written to `/etc/kilasos/backup-secrets.json` with
   `0600` permissions.
2. **Create the first archive.** In *Create Backup*, enter the repo name,
   an archive name (`backup-2026-05-21`, anything unique), and the path to
   back up (`/mnt/datapool`). Click **Backup**. Borg's stdout (file count,
   compressed size) is shown when it completes.
3. **Wire it into a job.** In *Backup Job Scheduler*, create a job of type
   `borg`, source `/mnt/datapool`, destination `daily-pool`, and a cron
   expression (`0 2 * * *`). Save it. See [Scheduling](#scheduling-prune-retention)
   below for the caveat about cron not actually firing in-process.

The Restic and rclone panels follow the same pattern: init/add the
destination, do one manual run, then create the job.

## Repositories

Repositories are filesystem paths on the KilasOS host. There is no built-in
support for `borg serve` over SSH or HTTPS — Borg and Restic repos live on
local disk under `/var/lib/kilasos/backups/`, and you back up that directory
via a separate mechanism if you need an offsite copy (rclone job, ZFS send,
external USB).

### Borg

```
POST /api/v1/backup/borg/init       {name, passphrase, encryption}
POST /api/v1/backup/borg/create     {repo_name, archive_name, paths}
GET  /api/v1/backup/borg/archives?repo=<name>
POST /api/v1/backup/borg/prune      {repo_name, policy}
POST /api/v1/backup/borg/restore    {repo_name, archive_name, target_path}
POST /api/v1/backup/borg/verify     {repo_name, archive_name}
DELETE /api/v1/backup/borg/archives/{repo}/{archive}
```

`encryption` accepts the standard Borg modes — `repokey`, `keyfile`,
`repokey-blake2`, `keyfile-blake2`, `authenticated`, `none`. The wrapper
does not validate the value; whatever you pass goes to `borg init
--encryption=<mode>`.

Paths in `paths` are space-separated and passed verbatim to `borg create`.
Exclude patterns are accepted both via the UI form (one pattern per line) and
the API's `excludes[]` field; each pattern is passed as a separate `--exclude`
argument. Patterns follow standard Borg syntax (e.g. `.cache/**`,
`/mnt/datapool/*.tmp`).

### Restic

```
POST /api/v1/backup/restic/init       {name, passphrase}
POST /api/v1/backup/restic/backup     {repo_name, paths, tags[]}
GET  /api/v1/backup/restic/snapshots?repo=<name>
POST /api/v1/backup/restic/restore    {repo_name, snapshot_id, target_path}
POST /api/v1/backup/restic/verify     {repo_name, snapshot_id}
DELETE /api/v1/backup/restic/snapshots/{repo}/{snapshot}
```

`restic init` accepts a `backend` field (`local`, `s3`, `b2`, `azure`, `gs`,
`swift`, `rest`) and per-backend credential fields. Local repos use the
local filesystem path (`/var/lib/kilasos/backups/restic-<name>/`). Object-store
backends are addressed by URI — e.g. `s3:s3.wasabisys.com/bucket` for S3.
Credentials are stored in `backup-secrets.json` and never echoed in API
responses.

Tags are exposed in the WebUI form (comma-separated input, e.g.
`daily,home`) and via the API's `tags[]` field. Tags are visible in
`restic snapshots --json` output and are useful for filtering retention
policies (`restic forget --tag daily --keep-daily 7`).

### Rclone

```
POST /api/v1/backup/rclone/remote      {name, type, endpoint}
GET  /api/v1/backup/rclone/remotes
POST /api/v1/backup/rclone/sync        {name, one_way}
DELETE /api/v1/backup/rclone/remote/{name}
```

Rclone remotes are stored in `/root/.config/rclone/rclone.conf` (or
`~kilasos/.config/rclone/rclone.conf` depending on the unit; check
`systemctl show nasd -p User`). Adding a remote runs `rclone config create
<name> <type> --non-interactive` with the endpoint string split on
whitespace and appended as extra arguments. For an S3-compatible remote you
will usually need to pass `provider=Wasabi access_key_id=... secret_access_key=...`
as the endpoint string — anything `rclone config create` accepts works.

The `sync` endpoint accepts `source_path` and `dest_path` per remote.
When not specified, defaults are `source_path=/mnt` and
`dest_path=<remote>:/kilasos-backup` (preserving existing behavior).
`one_way=true` runs `rclone sync` (destination becomes a mirror);
`one_way=false` runs `rclone bisync` (changes propagate both ways — read
the [rclone bisync docs](https://rclone.org/bisync/) before enabling).

### Where the secrets live

| Path | Purpose |
|---|---|
| `/etc/kilasos/backup-secrets.json` | Borg + Restic passphrases, `0600`, owned by `kilasos`. Keys are the repo name (Borg) or `restic-<name>` (Restic). |
| `~kilasos/.config/rclone/rclone.conf` | rclone remote credentials, managed by `rclone config` itself. |
| `/var/lib/kilasos/backup-jobs.json` | Job definitions (name, type, source, destination, cron, last-run state). |

`GET /api/v1/backup/status` returns the active jobs and reports
`secrets_path` so a recovery tool can find the passphrase file without
hard-coding the location.

Back these three files up alongside the rest of `/etc/kilasos/` and
`/var/lib/kilasos/` (see [overview.md](overview.md#backing-up-the-config)).
If you lose `backup-secrets.json` you have lost the data — see
[Encryption](#encryption-and-key-management).

## Scheduling, prune, retention

> **[BACKUP-01 + BACKUP-02 complete]** — Scheduled backup jobs now fire
> automatically at their cron expression time, and each successful backup
> run automatically invokes retention policy (borg prune / restic forget).
> rclone has no native retention (use bucket lifecycle rules instead).

## Restore points and wizard

The **Restore Wizard** panel lists archives (Borg) or snapshots (Restic)
from a given repo. Pick the engine and type the repo name, click **Load
Points**, then either click **Select** on a row to copy the ID into the
form, or paste it manually.

The wizard takes a target path. Restore writes the archive contents into
that path; for Borg this is `borg extract` invoked with the target as
CWD, for Restic it is `restic restore --target`. The browser pops a
`confirm()` dialog warning that existing data will be overwritten — there
is no separate "overwrite-on-restore" toggle, and no built-in copy-to-
staging mode. The pattern to use is:

1. Create a fresh ZFS dataset for staging: `zfs create datapool/restore`.
2. Restore into `/mnt/datapool/restore`.
3. Inspect, then `mv` or `rsync` selected files back into place.

Restoring directly over a live dataset is supported but unwise. Mount-on-
restore (the Borg/Restic FUSE mount mode) is not exposed through the API.

## Bandwidth and cost estimation

The **Cloud Storage Cost Estimation** panel (Storage tab, visible to all
authenticated users) gives a rough monthly/yearly number from a hardcoded
price table:

| Provider | Price per GB-month (USD) |
|---|---|
| AWS S3 | 0.023 |
| Google Cloud Storage | 0.020 |
| Azure Blob | 0.0184 |
| Backblaze B2 | 0.006 |
| Wasabi | 0.006 |
| Dropbox | 0.020 |
| Google Drive | 0.026 |
| OpenStack Swift | 0.030 |
| other / fallback | 0.020 |

The table lives in `cloudPricing` in `internal/storage/linux.go` and is not
fetched from any provider API. Treat the figures as order-of-magnitude;
egress, request, and class-transition costs are not modelled.

**Bandwidth caps.** Set `RcloneRemote.Bandwidth` (e.g. `10M`, `1G`, or
`10M:1G` for peak/off-peak) on the remote; `RcloneSync` passes it through
as `--bwlimit <value>`. Empty value means unlimited. The string is validated
against shell-metacharacter injection before being passed to rclone.

There is no off-peak scheduler. If you run backups from host cron (above),
schedule them for off-peak hours yourself.

## Validating a backup

Both engines have a built-in check:

```
POST /api/v1/backup/borg/verify     {repo_name, archive_name}
POST /api/v1/backup/restic/verify   {repo_name, snapshot_id}
```

Borg's wrapper invokes `borg check --json` on the archive; Restic's invokes
`restic check --read-data-subset <snapshot_id> --json`, which validates only
the packs that the requested snapshot references (fast, per-snapshot). A
nonexistent snapshot ID surfaces as an error rather than a misleading
"OK". Both return a `BackupVerification` object with `ok`, `files_checked`,
`errors`, and a free-text `message`. The UI surfaces verify as a per-archive
button in the Borg archive list and via API only for Restic.

A `check` walks the repository structure and the requested snapshot's pack
files; it does **not** verify that the files inside the archive match the
live filesystem. To get there, run a fire-drill restore against a scratch
dataset (not automated by KilasOS — do this on a schedule of your own):

```sh
zfs create datapool/firedrill
curl -X POST -H "Authorization: Bearer …" \
  -d '{"repo_name":"daily-pool","archive_name":"backup-2026-05-21","target_path":"/mnt/datapool/firedrill"}' \
  http://localhost:8080/api/v1/backup/borg/restore
diff -r /mnt/datapool/some/known/subset /mnt/datapool/firedrill/mnt/datapool/some/known/subset
zfs destroy -r datapool/firedrill
```

Expected runtime is roughly linear in the size of the archive — Borg and
Restic both stream from the repo at disk speed for local repos, network
speed otherwise. Plan for a full restore to take at least as long as the
backup did.

## Encryption and key management

| Engine | Default mode | Where the key is |
|---|---|---|
| Borg | `repokey` (key stored inside the repo, encrypted with the passphrase) | passphrase in `/etc/kilasos/backup-secrets.json` |
| Restic | Standard Restic encryption (always on) | password in `/etc/kilasos/backup-secrets.json` under `restic-<name>` |
| rclone | None unless you stack a `crypt` remote on top | provider-side; not managed by KilasOS |

The Borg `keyfile` and `keyfile-blake2` modes store the key outside the
repo. KilasOS will pass the mode through but will not move the key off the
host — you still have to do that yourself (back it up to a password
manager, write it to paper, etc.).

If you lose the passphrase, the data is gone. Borg and Restic encryption is
designed so that there is no recovery path. The realistic plan is:

1. Write the passphrase down somewhere durable (password manager, paper in
   a safe, sealed envelope).
2. Back up `/etc/kilasos/backup-secrets.json` to a separate location (it is
   `0600` and only contains passphrases, not key material for `keyfile`
   mode — so it's safer to back up than a full keyfile, but still
   sensitive).
3. Periodically practice a restore from a host that does not have access to
   the live system, to confirm the passphrase you wrote down still works.

For rclone, encryption is whatever the destination provides. Backblaze B2,
AWS S3, and most object stores offer server-side encryption with a
provider-managed key; that protects against disk theft at the provider but
not against credential compromise. If you want client-side encryption,
configure a `crypt` remote that wraps your destination remote — `rclone
config` supports this and the resulting remote is selectable in the KilasOS
remote dropdown like any other.

## Monitoring

A backup job records its last-run state in `backup-jobs.json`:

```json
{
  "id": "bk-1716300000000000000",
  "name": "Daily Datapool",
  "type": "borg",
  "source": "/mnt/datapool",
  "destination": "daily-pool",
  "schedule": "0 2 * * *",
  "enabled": true,
  "last_run": 1716386400,
  "last_result": "ok",
  "last_size": 487326921728
}
```

`last_result` is one of `ok`, `failed`, or empty (never run). The UI shows
the last-result as a coloured badge in the *Backup Jobs* list and a size
in human-readable units.

Per-run logs are persisted under `/var/lib/kilasos/backup-job-logs/<jobID>/`
with a 100 MB per-job cap (oldest runs prune first). List + fetch via:

```
GET /api/v1/backup/jobs/{id}/runs         → [{run_id, started, result, size, log_bytes}]
GET /api/v1/backup/jobs/{id}/runs/{runID} → run metadata
GET /api/v1/backup/jobs/{id}/runs/{runID}/log → raw stdout+stderr
```

The WebUI exposes these as a "Runs" expander on each job row. The journal
under the `nasd` unit also captures the same output as a fallback:

```sh
journalctl -u nasd -g borg --since "1 hour ago"
journalctl -u nasd -g restic --since today
```

The monitor fires an alert when a job's `last_result == failed` (severity
`warn` on first failure, `crit` after three consecutive failures), and an
`info` alert on recovery. Suppression state lives in
`/var/lib/kilasos/monitor-state.json` so the same failure doesn't spam a
channel — one alert per job per 24h while still failing. Configure
channels under [alerts.md](alerts.md).

The webhook payload schema is documented in
[alerts.md](alerts.md#webhook-payload). A reasonable on-call runbook:

1. Page on first failure (transient network errors do happen — give the
   next scheduled run a chance before escalating).
2. After two consecutive failures, treat as a hard incident: pull the
   journal, check disk space on the destination, confirm the passphrase
   file is intact, retry from the WebUI.
3. If the repo itself is corrupt, do not delete it — copy it aside first,
   then `borg check --repair` (Borg) or `restic rebuild-index` (Restic) on
   the copy. Both operations can lose data; the original is your evidence.

---

**Previous:** [Users & auth ←](users-auth.md)
**Next:** [Alerts →](alerts.md)
