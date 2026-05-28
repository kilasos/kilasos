#!/usr/bin/env bash
set -eu

# os-installer/grub-zfs-setup.sh
# Configure GRUB2 for ZFS-on-root booting in Debian installer environment
# Must run in late_command or post-install chroot

# Step a) Create /etc/default/zfs with ZFS_INITRD_ADDITIONAL_DATASETS
if ! grep -q "ZFS_INITRD_ADDITIONAL_DATASETS" /etc/default/zfs 2>/dev/null; then
    echo 'ZFS_INITRD_ADDITIONAL_DATASETS="rpool/ROOT"' > /etc/default/zfs
fi

# Step b) Add zfs module to initramfs-tools/modules
if [ -f /etc/initramfs-tools/modules ]; then
    if ! grep -q "^zfs$" /etc/initramfs-tools/modules 2>/dev/null; then
        echo "zfs" >> /etc/initramfs-tools/modules
    fi
fi

# Step c) Update initramfs
if command -v update-initramfs >/dev/null 2>&1; then
    update-initramfs -u -k all || exit 1
fi

# Step d) Verify /boot/grub/grub.cfg mentions root=ZFS=rpool/ROOT
if [ -f /boot/grub/grub.cfg ]; then
    if ! grep -q "root=ZFS=rpool/ROOT" /boot/grub/grub.cfg 2>/dev/null; then
        echo "WARNING: /boot/grub/grub.cfg does not contain root=ZFS=rpool/ROOT" >&2
    fi
fi

# Step e) Copy zpool.cache to initramfs hook if it exists
if [ -f /etc/zfs/zpool.cache ] && [ -d /etc/initramfs-tools/hooks ]; then
    cp /etc/zfs/zpool.cache /etc/initramfs-tools/hooks/ 2>/dev/null || true
fi

# Step f) Set GRUB_CMDLINE_LINUX in /etc/default/grub
if [ -f /etc/default/grub ]; then
    if ! grep -q "^GRUB_CMDLINE_LINUX=" /etc/default/grub 2>/dev/null; then
        echo 'GRUB_CMDLINE_LINUX="root=ZFS=rpool/ROOT quiet splash"' >> /etc/default/grub
    else
        # Ensure the line exists and contains the required parameters
        sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="root=ZFS=rpool\/ROOT quiet splash"/' /etc/default/grub
    fi
fi

# Step g) Run update-grub
if command -v update-grub >/dev/null 2>&1; then
    update-grub || exit 1
fi

# TASK_COMPLETE
echo "GRUB/ZFS configuration completed successfully."
