#!/bin/bash
# Script to configure read-only rootfs with overlay + tmpfs on Raspberry Pi
# Assumes /boot is mounted separately and /dev/mmcblk0p1 (or similar) is root

set -e

# Ensure we're running on a Pi-like system (optional check)
if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    echo "⚠️  Warning: This system may not be a Raspberry Pi."
fi

# Install required package if missing
if ! command -v overlayroot &>/dev/null; then
    echo "📦 Installing overlayroot package..."
    apt update && apt install -y overlayroot
fi

# Create config if missing
mkdir -p /etc/overlayroot.d 2>/dev/null || true
if [[ ! -f /etc/overlayroot.conf ]]; then
    echo "Creating default /etc/overlayroot.conf..."
    cat > /etc/overlayroot.conf <<EOF
# Overlayroot configuration
# Enable overlayfs with tmpfs for writable layer
overlayroot_enabled="yes"
overlayroot_tmpfs="yes"
overlayroot_mountpoint="/"
overlayroot_upperdir="/.overlay/upper"
overlayroot_workdir="/.overlay/work"
overlayroot_options="lowerdir=/,upperdir=/.overlay/upper,workdir=/.overlay/work,merge_dir=/.overlay/merged"
EOF
fi

# Ensure /boot is mounted read-write (common on Pi: /dev/mmcblk0p1)
if ! grep -q " /boot " /etc/fstab; then
    echo "⚠️  /boot not found in /etc/fstab — ensure /boot is mounted separately."
else
    # Mark /boot as rw in fstab if not already
    sed -i 's|/boot.*|/boot /boot auto defaults 0 2|' /etc/fstab 2>/dev/null || true
fi

# Update kernel cmdline to include overlayroot=tmpfs
if ! grep -q "overlayroot=tmpfs" /boot/cmdline.txt 2>/dev/null; then
    echo "🔧 Updating /boot/cmdline.txt..."
    # Backup
    cp /boot/cmdline.txt /boot/cmdline.txt.bak 2>/dev/null || true
    # Append overlayroot=tmpfs if not present
    if ! grep -q "overlayroot=tmpfs" /boot/cmdline.txt; then
        sed -i 's/$/ overlayroot=tmpfs/' /boot/cmdline.txt
    fi
fi

# Update initramfs to include overlay support
echo "🔄 Updating initramfs..."
update-initramfs

# Add writable mounts for /var, /tmp, /home
if ! grep -q "tmpfs.*\/var" /etc/fstab; then
    echo "tmpfs /var tmpfs defaults,noatime,size=100M 0 0" >> /etc/fstab
fi
if ! grep -q "tmpfs.*\/tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noatime,size=50M 0 0" >> /etc/fstab
fi
if ! grep -q "tmpfs.*\/home" /etc/fstab; then
    echo "tmpfs /home tmpfs defaults,noatime,size=20M 0 0" >> /etc/fstab
fi

# Ensure directories exist
mkdir -p /var /tmp /home 2>/dev/null || true

# Final warning
echo "✅ Done! Reboot to apply changes."
echo "⚠️  After reboot, verify with: mount | grep -E 'overlay|tmpfs'"
