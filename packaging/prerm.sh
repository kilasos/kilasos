#!/bin/sh
# prerm — runs BEFORE the nasd binary is removed/upgraded.
# Stop the daemon gracefully so the upgrade doesn't leave a stale process
# pointing at an unlinked binary path.  Failures are non-fatal: if nasd
# wasn't running, that's fine; if systemctl isn't available (mid-bootstrap),
# proceed without blocking the package operation.
set -e

if command -v deb-systemd-invoke >/dev/null 2>&1; then
    deb-systemd-invoke stop nasd.service >/dev/null 2>&1 || true
elif command -v systemctl >/dev/null 2>&1; then
    systemctl stop nasd.service >/dev/null 2>&1 || true
fi

exit 0
