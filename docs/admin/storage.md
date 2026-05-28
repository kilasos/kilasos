# Storage

> **Status:** expanded (STORAGE-10, 2026-05-22). All 13 chapters filled.

ZFS is the primary storage backend. Other supported on-disk formats (Btrfs,
ext4, mdraid) are managed through the same UI but with reduced functionality.

## Chapter map

1. [ZFS in 30 seconds](#zfs-in-30-seconds) `[draft]`
2. [Creating your first pool](#creating-your-first-pool)
3. [Datasets and properties](#datasets-and-properties)
4. [Snapshots and the scheduler](#snapshots-and-the-scheduler)
5. [Scrubs, trims, and pool health](#scrubs-trims-and-pool-health)
6. [Send / receive (replication)](#send--receive-replication)
7. [Expansion and replacement](#expansion-and-replacement)
8. [Encryption](#encryption)
9. [L2ARC, SLOG, dedup, compression](#l2arc-slog-dedup-compression)
10. [Btrfs subvolumes and snapshots](#btrfs-subvolumes-and-snapshots)
11. [Disk lifecycle: burn-in, SMART, APM](#disk-lifecycle-burn-in-smart-apm)
12. [Storage tiering and lifecycle policies](#storage-tiering-and-lifecycle-policies)
13. [Dedup deferred (jdupes) and ARC tuning](#dedup-deferred-jdupes-and-arc-tuning)

## ZFS in 30 seconds

A **pool** is one or more **vdevs** (virtual devices). A vdev is a single
disk, a mirror, or a raidz group. Within a pool, you create **datasets** —
named slices that mount as filesystems. Snapshots are per-dataset and
copy-on-write: instant, free until data diverges, immutable until destroyed.

Recommended layouts:

| Disks | Layout | Tolerates failure of |
|---|---|---|
| 2 | `mirror` | 1 disk |
| 3 | `raidz1` | 1 disk |
| 4 | `raidz2` or 2× mirror | 2 disks |
| 5–6 | `raidz2` | 2 disks |
| 7+ | `raidz3` or stripe of mirrors | 3 / multiple |

KilasOS does not support **expanding raidz** vdevs at runtime (an OpenZFS
feature still maturing as of 2026). To grow a raidz pool, attach an additional
vdev (same layout) — total capacity scales with the new vdev, no rebalance.

## Creating your first pool

The **Storage → Pools** panel lists all pools with health, capacity bars,
and vdev detail. Click **Create Pool** to open the wizard.

1. **Select disks** — raw devices are listed with size and health.
   Select one or more and choose a layout (mirror / raidz1 / raidz2 / raidz3).
2. **Name the pool** — dataset names follow `pool/dataset` hierarchy.
   Avoid spaces, slashes, or leading digits.
3. **Mountpoint** — defaults to `/mnt/<pool>` or `/mnt/<pool>/<dataset>`.
   Set to `none` for raw pool.
4. **First snapshot toggle** — creating a first snapshot immediately
   gives a rollback point before any further changes.
5. **Result page** — shows pool name, vdev layout, capacity, and
   a quick link to create the first dataset.

Pool creation calls `zpool create` via `CreateArray` in `linux.go`. The
pool is registered in `/var/lib/kilasos/arrays.json`.

## Datasets and properties

Datasets are created from the **Storage → Pools** panel → pool row →
**Create Dataset** button. Fill in name and mountpoint; leave options
at default unless you have specific requirements.

Key properties (accessible via **Properties** button on each dataset):

| Property | Default | Meaning |
|---|---|---|
| `recordsize` | 128K | Max block size; 1M for large sequential files (DB, VM images) |
| `atime` | on | Access time updates on every read — disable for flash or high-IO |
| `compression` | lz4 | lz4 is always-on unless you have a proven reason to disable |
| `quota` | none | Max dataset size; prevents runaway datasets from filling pool |
| `reservation` | none | Guaranteed minimum space for this dataset regardless of others |

Changing a property takes effect immediately: `zfs set property=value pool/dataset`.

## Snapshots and the scheduler

The **Storage → Pools → [pool] → Snapshots** tab shows all snapshots for
that pool. Click **Create Snapshot** to take one immediately. To schedule:

1. Go to **Scheduler** (navigation bar).
2. Create a schedule with **Kind = snapshot**, select pool, enter
   a cron expression (e.g. `0 2 * * *` for 02:00 daily).
3. Set **Keep** to how many snapshots to retain (oldest are destroyed).

Snapshot **Holds** (`ZFS Holds` in the snapshot row — click **Holds**
to open the modal) prevent accidental deletion. A hold with tag `backup`
is released with `zfs release backup pool/dataset@snap`. Holds survive
across restarts.

**Rolling back** a snapshot (`↩` button in the snapshot row) destroys
all intermediate changes since that snapshot. Use **Clone** instead
to create a new dataset from a snapshot without affecting the original.

**Browse from snapshot** (`Clone` → mount → access old files) is the
pattern for SMB shares with `shadow_copy2` — clone the snapshot, share it
alongside the live dataset, users navigate to `.zfs/snapshot/<name>`.

## Scrubs, trims, and pool health

Pool health is shown in the **Storage → Pools** list with color coding:
**green** (healthy), **yellow** (degraded), **red** (faulted). Click a
pool row for the detail panel which shows vdev state, CKSUM error counts,
and last scrub time.

**Scrub** runs via the scheduler (Kind = scrub, select pool). Weekly
scrubs are recommended for early detection of media errors. Scrub
priority is low — it pauses when I/O demand is high.

To interpret errors:

| Error type | Likely cause | Action |
|---|---|---|
| CKSUM (checksum) errors | Disk unreadable sectors, cable issue | Check SMART, replace disk |
| I/O errors | Controller, cable, or disk failure | Swap cables, check disk |
| DEGRADED vdev | One disk in mirror/raidz failed | Replace disk, watch resilver |

Clearing errors (`zpool clear pool`): do this only after physically
correcting the root cause. If errors recur, replace the disk.

**TRIM** (`zpool trim`): run periodically on flash devices to reclaim
unused space. Enable via the pool detail panel → **Trim** button.
Not needed for spinning disks.

## Send / receive (replication)

Replication sends dataset contents to a remote ZFS pool via SSH.
Configure a **Remote** (System → Remotes → Add) with SSH host, user,
and key. The remote must have the receiving pool imported and visible to
`zfs receive`.

**Replication job** (Scheduler → Kind = replication):
- **Pool**: source pool
- **Remote**: the configured remote
- **Dataset**: source dataset to replicate
- **Schedule**: cron expression
- **Incremental**: yes (send only changed blocks since last snapshot)

The sender creates a temporary snapshot, sends incrementally to the
receiver's matching dataset, and destroys the temp snapshot. On failure,
the last received snapshot is kept — rerunning resumes from where it
stopped (ZFS replication is resumable).

**Retention on receiver**: the replication schedule does not manage
retention on the remote. Set a separate schedule on the receiver or
manually run `zfs destroy` to prune old received snaps.

## Expansion and replacement

**Adding a vdev** (pool detail → **Expand**): select new raw disks and
choose a layout. The new vdev is added and the pool auto-reshards data
in the background (no downtime). This only adds vdevs — you cannot
re-shard an existing raidz group.

**Replacing a failed disk**: in the degraded pool detail, click the
vdev row → **Replace** button. Pull the failed disk, insert the
replacement (same size or larger), select it. ZFS copies parity to
the new disk and the vdev returns to healthy. Do not offline a disk
until the replacement is physically installed — ZFS will complain.

**Attaching to a stripe** (2-disk mirror): if you have a single-stripe
pool and want mirror protection, click **Attach** on the vdev, select
a new disk of at least the same size, and ZFS mirrors the existing data.

## Encryption

KilasOS supports per-dataset ZFS encryption (`aes-256-gcm`). Encryption
is set at dataset creation time — you cannot encrypt an existing dataset.

**Create an encrypted dataset** (Storage → Pools → [pool] → Create
Dataset → check **Encrypted**): the UI prompts for a passphrase. The
dataset key is stored in `/var/lib/kilasos/keys/<pool>-<dataset>.key`,
encrypted with a master key in `/var/lib/kilasos/keys/master.key`.

**Unlock at boot**: enable the **Unlock at boot** toggle so the dataset
is usable after a nasd restart. Without this, you must manually run
`zfs load-key pool/dataset` with the passphrase.

**Key change** (dataset Properties → Change Key): generates a new key
and re-wraps the dataset's data under the new key. The old key is
destroyed.

**Note:** encrypted datasets cannot be sent to an unencrypted pool and
vice versa without decrypting first. Replication of encrypted datasets
requires the receiver to also have encryption enabled.

## L2ARC, SLOG, dedup, compression

These are **cache and special vdevs** that improve performance for
specific workloads.

**L2ARC** (SSD cache for reads): add a raw SSD via **Storage → Pools
→ [pool] → L2ARC → Add Cache Device**. The SSD must be at least as
large as the ARC size (typically 5–10% of RAM) or it will thrash.
L2ARC is read-only cache — writes always hit main pool.

**SLOG** (SSD log for synchronous writes): if you run databases,
NFS exports, or `sync=always` workloads, add an SSD as a SLOG (separate
from L2ARC). SLOG does not need to be large — it holds the ZFS Intent
Log (ZIL) between transactions. Mirrored SLOGs are strongly recommended;
a single SLOG failure causes data loss.

**Special VDEV** (special allocation class): SSD space used for
metadata and small file blocks (≤ "recordsize" threshold). Configure
via **Storage → Storage → Special VDEV → Add**. Requires same
redundancy level as the data vdevs — mirror pools need mirrored special
vdevs.

**Dedup** (`dedup=log` property): not recommended for most workloads.
The dedup table consumes RAM and a mis-sized dedup table can degrade
performance more than it helps. Only enable after benchmarking with
real data.

**Compression** (`compression=on` or `lz4`): nearly always beneficial.
L2ARC is incompressible by ZFS but compresses well in main ARC. For
databases and VM images, `recordsize=1M` with compression is optimal.
For SMB shares with already-compressed media (JPEG, MP4), leave
compression off.

ARC and L2ARC hit rates are visible in the **Storage Analytics** panel
(ZFS Analytics tab). Watch the **L2ARC efficiency** metric — a low
ratio means the SSD cache is thrashing and should be removed.

## Btrfs subvolumes and snapshots

Btrfs support is a thinner layer than ZFS. Use **Storage → Btrfs**
panel to list subvolumes and snapshots.

**Subvolumes**: click **Create Subvolume** to make a new Btrfs subvolume.
The path must be within `/mnt`. Subvolumes support compression and
quota via `btrfs property set`.

**Snapshots**: from the **Btrfs → [subvolume]** tab, click **Create
Snapshot**, name it, and optionally set it as read-only. Btrfs snapshots
are instantaneous (copy-on-write at the extent level).

**Restore** (`POST /storage/btrfs/snapshots/restore`): renames the current
subvolume to `<path>-old-<timestamp>` and clones the snapshot into the
original path. The `‑old‑` subvolume is left in place — delete it
manually after confirming the restore succeeded. If the subvolume is
busy (open files, running processes), the rename fails with EBUSY — stop
the processes first.

**Delete** removes the subvolume or snapshot. For read-write snapshots,
deletion is immediate. For read-only snapshots, deletion is deferred
until no holds reference it.

## Disk lifecycle: burn-in, SMART, APM

Before putting a disk into production, run a **burn-in test**
(System → Disks → [disk] → **Burn In**). The test runs `badblocks`
pattern write + read cycles and reports errors. Disks that report
any uncorrectable errors should be rejected and returned.

**SMART monitoring** (`smartctl`): enabled per-disk in System → Disks.
Click **Run SMART Test** to execute a short test (immediate), a
conveyance test (some drives), or a long test (full surface scan).
Results are retained in the disk history and alerts fire if a
pre-failure attribute crosses its threshold.

**APM (Advanced Power Management)** via `hdparm -B`:
- **Level 1** (minimum power, max battery life): aggressive spin-down
- **Level 128**: intermediate power management
- **Level 254** (max performance): APM disabled

Set APM via **System → Disks → [disk] → Settings → APM Level**.
Databases and high-IO disks should stay at 254. Archive disks can use
lower levels to save power.

**Temperature alerts**: SMART `Temperature_Celsius` attributes are
polled every 60s. Alerts fire at 45°C (warn) and 55°C (crit). Replace
disks that run above 50°C under load.

## Storage tiering and lifecycle policies

Tier policy migrates cold data (no access for N days) to a cheaper
pool. Configure via **Storage → Tier Policy** (Storage tab):

1. **Enable** the policy toggle.
2. **Hot pool**: the primary pool receiving writes.
3. **Cold pool**: the destination for cold data (usually larger, cheaper).
4. **Threshold days**: number of days without access before migration.
5. **Retention**: minimum days to keep data on cold tier before cleanup.

The migration scans access times via `zfs get atime` and `zfs get used`.  
**Important**: tier migration is a **config-only scheduler** — it
populates a candidate list but requires a manual **Run Now** button
or external cron to execute. Automated migration tick is not yet
implemented. See `docs/admin/backups.md` for how to wire the execution.

## Dedup deferred (jdupes) and ARC tuning

ZFS inline deduplication (`dedup=on`) requires ~1 GB of RAM per TB of
deduplicated data in the DDT (dedup table). For most NAS workloads,
this trade-off is not worth it — data is already compressed, and the
RAM cost often exceeds the space saved.

**Offline dedup** (jdupes): run `jdupes --detect-hardlinks /mnt` to
find duplicate files across datasets. jdupes is a separate binary not
installed by default — install via `apt install jdupes`. Use it as a
pre-snapshot step in a replication job rather than enabling inline
dedup.

**ARC tuning** (`/etc/modprobe.d/zfs.conf`): the primary ARC size is
controlled by `zfs_arc_max` in kernel module parameters. Default is
half of RAM. For a 32 GB machine with a 512 GB SSD L2ARC, the ARC can
be reduced to leave more memory for applications:

```
options zfs zfs_arc_max=8589934592   # 8 GB
```

Reload with `update-initramfs -u` and reboot. Watch L2ARC efficiency
in the Storage Analytics panel — if L2ARC hit rate is low even with
a large SSD, the ARC is too small and is evicting entries before they
can be promoted.

---

**Previous:** [Overview ←](overview.md)
**Next:** [Shares →](shares.md)