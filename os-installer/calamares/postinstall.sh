#!/usr/bin/env bash
set -eu

# Install required packages
apt-get update
apt-get install -y zfsutils zfs-zed openssh-server curl sudo smartmontools

# Install local NASD package
if [[ -f /tmp/kilasos-nasd*.deb ]]; then
    dpkg -i /tmp/kilasos-nasd*.deb || true
    apt-get install -f -y
fi

# Enable services
systemctl enable nasd
systemctl enable ssh

# Run ZFS-specific GRUB setup if present
if [[ -f /usr/share/calamares/modules/grub-zfs-setup.sh ]]; then
    /usr/share/calamares/modules/grub-zfs-setup.sh
fi

# Clean up Calamares post-install artifacts
rm -f /tmp/kilasos-nasd*.deb
rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true

echo "TASK_COMPLETE"
