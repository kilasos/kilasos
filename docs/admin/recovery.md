# Recovery

> **Status:** outline.

When the UI is unreachable or a pool won't import, these are the things to
try, in roughly the order to try them. Always check the journal first:
`journalctl -u nasd -p err -n 200`.

## Chapter map

1. Lost admin password
2. nasd won't start
3. ZFS pool won't import after reboot
4. Disk replaced; resilver stuck
5. SMB / NFS share suddenly inaccessible
6. Docker daemon dead but apps "running"
7. Boot from rescue ISO
8. Restoring from `/var/lib/kilasos/` tarball
9. Rebuilding the host from data alone

## Lost admin password

`[TODO]` stop nasd, edit `/var/lib/kilasos/users.json`, replace the
password hash with a known value or delete the user record entirely
(forces first-boot reseting), restart nasd. Audit-log entry to acknowledge
the reset.

## nasd won't start

`[TODO]` common causes:

- Missing required tools (zfs, zpool, systemctl, journalctl, ip, mount).
  `nasd` fails fast at startup and prints which tool is absent.
- `/var/lib/kilasos/` permission broken (must be owned by `kilasos:kilasos`).
- Port 8080 already in use.
- Capability missing — check `/proc/$(pidof nasd)/status` `CapAmb`.

## Pool won't import

`[TODO]` `zpool import` (no args) shows discovery state.
`zpool import -f <pool>` for force-import. `zpool import -F <pool>` to
walk back transactions. When to give up and `zpool import -nF` (dry run
of catastrophic recovery).

## Resilver stuck

`[TODO]` `zpool status -v <pool>` reads, what 0 B/s means, when to cancel
and restart, replacement-disk gotchas.

## Share inaccessible

`[TODO]` smbd / nmbd alive? `systemctl restart smbd nmbd`. `testparm -s`
for config syntax. AD trust expired? `kinit`, `klist`.

## Docker dead

`[TODO]` `systemctl status docker`, `journalctl -u docker -n 100`,
common cause: ran out of disk in `/var/lib/docker/`. The Apps tab still
shows the stack as "running" because state is in `/var/lib/kilasos/apps.json`;
the truth is `docker ps`.

## Boot from rescue ISO

`[TODO]` Phase 3 rescue ISO build (`os-installer/`), boot, `zpool import`
read-only, mount via `mount -t zfs <pool>/<dataset> /mnt`, `chroot` to
fix the install.

## Restoring from a state tarball

`[TODO]` the tarball from [overview.md](overview.md#backing-up-the-config):
unpack over `/`, `chown -R kilasos:kilasos /var/lib/kilasos
/var/log/kilasos`, restart nasd.

## Rebuilding from data alone

`[TODO]` worst case: only your ZFS pools survive. Fresh install, import
pools, recreate users (lose audit history), reconfigure shares/backups
from scratch. Plan to keep `/var/lib/kilasos/` backed up to make this
unnecessary.

---

**Previous:** [Security ←](security.md)
