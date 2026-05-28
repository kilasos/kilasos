#!/bin/bash
# Pi-specific hardening script — v1.0
set -euo pipefail

# Ensure running as root
if [[ $EUID -ne 0 ]]; then
  echo "[!] This script must be run as root" >&2
  exit 1
fi

echo "[+] Starting Pi hardening..."

# 1. Disable Bluetooth and WiFi (for server use)
# Check if /boot/config.txt exists (Raspberry Pi OS)
if [[ -f /boot/config.txt ]]; then
  echo "[+] Disabling Bluetooth and WiFi in /boot/config.txt"
  # Append if not present
  if ! grep -q "^dtoverlay=disable-bt" /boot/config.txt 2>/dev/null; then
    echo "dtoverlay=disable-bt" >> /boot/config.txt
  fi
  if ! grep -q "^dtoverlay=disable-wifi" /boot/config.txt 2>/dev/null; then
    echo "dtoverlay=disable-wifi" >> /boot/config.txt
  fi
else
  echo "[!] /boot/config.txt not found — skipping Bluetooth/WiFi overlay config"
fi

# 2. Set GPU memory to minimal (16MB)
if [[ -f /boot/config.txt ]]; then
  if ! grep -q "^gpu_mem=16" /boot/config.txt; then
    echo "gpu_mem=16" >> /boot/config.txt
  fi
fi

# 3. Enable cgroup memory accounting (for systemd-based systems)
if command -v systemctl >/dev/null 2>&1; then
  if grep -q "cgroup_memory" /etc/cmdline.txt 2>/dev/null || grep -q "cgroup_memory" /boot/cmdline.txt 2>/dev/null; then
    echo "[+] cgroup memory accounting already enabled"
  else
    echo "[+] Enabling cgroup memory accounting in cmdline.txt"
    # Backup first
    cp /boot/cmdline.txt /boot/cmdline.txt.bak 2>/dev/null || true
    # Append cgroup memory option safely
    sed -i 's/$/ cgroup_memory=1/' /boot/cmdline.txt 2>/dev/null || \
      echo "cgroup_memory=1" >> /boot/cmdline.txt
  fi
fi

# 4. Configure UFW firewall
echo "[+] Configuring UFW..."
if command -v ufw >/dev/null 2>&1; then
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  ufw allow 22/tcp comment 'ssh' >/dev/null 2>&1 || true
  ufw allow 8080/tcp comment 'http-alt' >/dev/null 2>&1 || true
  # Enable silently if not already active
  if ! ufw status | grep -q "Status: active"; then
    echo "y" | ufw enable >/dev/null 2>&1 || true
  fi
else
  echo "[!] UFW not installed — skipping firewall config"
fi

# 5. Disable password authentication, enforce pubkey-only SSH
echo "[+] Hardening SSH..."
if command -v sshd >/dev/null 2>&1 || dpkg -l | grep -q "^ii.*opensshd"; then
  # Ensure PubkeyAuthentication is enabled and PasswordAuthentication disabled
  if [[ -f /etc/ssh/sshd_config ]]; then
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i 's/^#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
    # Ensure PermitRootLogin is no
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true
  else
    echo "[!] sshd_config not found — skipping SSH hardening"
  fi
fi

# 6. Disable pi user password (if default) and ensure it's not in sudo group
if id pi >/dev/null 2>&1; then
  # Check if pi user has a password set (not locked)
  if passwd -S pi | grep -q "^[^ ]\+ L "; then
    echo "[+] pi user password already locked"
  else
    echo "[+] Locking pi user password..."
    passwd -l pi >/dev/null 2>&1 || true
  fi
  # Remove pi from sudo group (if not already)
  if groups pi | grep -q "sudo"; then
    echo "[+] Removing pi from sudo group..."
    deluser pi sudo >/dev/null 2>&1 || true
  fi
fi

# 7. Install and enable fail2ban for SSH protection
echo "[+] Installing fail2ban..."
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq fail2ban >/dev/null 2>&1 || true
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
else
  echo "[!] apt-get not available — fail2ban installation skipped"
fi

echo "[+] Pi hardening complete."
