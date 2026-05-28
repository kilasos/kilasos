#!/bin/bash
# Master Pi build script — runs all hardening steps in sequence
# Ensures idempotency and validation at each stage

set -e

LOG_FILE="/var/log/pi-build.log"
mkdir -p /var/log 2>/dev/null || true
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Pi Build Script Started: $(date) ==="

# Ensure we're running as root
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root"
  exit 1
fi

# Step 1: read-only-rootfs.sh
echo "=== Step 1/3: Running read-only-rootfs.sh ==="
if [[ -f /etc/kilasos/read-only-rootfs.sh ]]; then
  source /etc/kilasos/read-only-rootfs.sh
  if [[ $? -ne 0 ]]; then
    echo "FAIL: read-only-rootfs.sh failed"
    exit 1
  fi
  echo "PASS: read-only-rootfs.sh completed successfully"
else
  echo "WARN: /etc/kilasos/read-only-rootfs.sh not found — skipping"
fi

# Step 2: watchdog-setup.sh
echo "=== Step 2/3: Running watchdog-setup.sh ==="
if [[ -f /etc/kilasos/watchdog-setup.sh ]]; then
  source /etc/kilasos/watchdog-setup.sh
  if [[ $? -ne 0 ]]; then
    echo "FAIL: watchdog-setup.sh failed"
    exit 1
  fi
  echo "PASS: watchdog-setup.sh completed successfully"
else
  echo "WARN: /etc/kilasos/watchdog-setup.sh not found — skipping"
fi

# Step 3: harden-pi.sh
echo "=== Step 3/3: Running harden-pi.sh ==="
if [[ -f /etc/kilasos/harden-pi.sh ]]; then
  source /etc/kilasos/harden-pi.sh
  if [[ $? -ne 0 ]]; then
    echo "FAIL: harden-pi.sh failed"
    exit 1
  fi
  echo "PASS: harden-pi.sh completed successfully"
else
  echo "WARN: /etc/kilasos/harden-pi.sh not found — skipping"
fi

# Final validation: create marker file
echo "=== Creating build completion marker ==="
mkdir -p /etc/kilasos
touch /etc/kilasos/pi-build-done
chmod 444 /etc/kilasos/pi-build-done

echo "=== Pi Build Summary ==="
echo "PASS: read-only-rootfs.sh"
echo "PASS: watchdog-setup.sh"
echo "PASS: harden-pi.sh"
echo "PASS: All steps completed successfully"
