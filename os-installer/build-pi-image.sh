#!/usr/bin/env bash
set -eu

# Variables
IMG_SIZE=4G
IMG_NAME=kilasos-rpi-arm64.img
BOOT_SIZE=256M
ROOT_SIZE=$((IMG_SIZE - BOOT_SIZE))
DEBOOTSTRAP_DIR=/tmp/kilasos-debootstrap
CHROOT_DIR=/tmp/kilasos-chroot
NASD_DEB="nasd_0.1.0_arm64.deb"

# Ensure required tools exist
command -v qemu-arm-static >/dev/null 2>&1 || { echo "qemu-user-static required"; exit 1; }

# Create sparse disk image
truncate -s "$IMG_SIZE" "$IMG_NAME"

# Partition with sgdisk (FAT32 /boot + ext4 /)
sgdisk -g "$IMG_NAME" 2>/dev/null || true
sgdisk -n 1:0:+$BOOT_SIZE:boot -t 1:fat32 -n 2:0:+$ROOT_SIZE:root -t 2:ext4 "$IMG_NAME" 2>/dev/null || \
  { echo "sgdisk failed"; exit 1; }

# Setup loopback device
LOOP_DEV=$(losetup -f --show -P "$IMG_NAME")
BOOT_DEV="${LOOP_DEV}p1"
ROOT_DEV="${LOOP_DEV}p2"

# Format partitions
mkfs.vfat -F -n boot "$BOOT_DEV" >/dev/null 2>&1 || mkfs.fat -F -n boot "$BOOT_DEV" >/dev/null 2>&1 || true
mkfs.ext4 -F "$ROOT_DEV" >/dev/null 2>&1 || true

# Mount partitions
mkdir -p "$CHROOT_DIR" "$CHROOT_DIR/boot"
mount "$BOOT_DEV" "$CHROOT_DIR/boot"
mount "$ROOT_DEV" "$CHROOT_DIR"

# Bootstrap base system
debootstrap --arch=arm64 --foreign --keyring=/usr/share/keyrings/debian-archive-keyring.gpg bookworm "$CHROOT_DIR" http://deb.debian.org/debian

# Copy qemu for cross-arch
cp /usr/bin/qemu-arm-static "$CHROOT_DIR/usr/bin/" 2>/dev/null || cp /usr/bin/qemu-aarch64-static "$CHROOT_DIR/usr/bin/" 2>/dev/null || true

# Bootstrap inside chroot
mount --bind "$CHROOT_DIR" "$CHROOT_DIR"
mount --bind /dev "$CHROOT_DIR/dev"
mount --bind /proc "$CHROOT_DIR/proc"
mount --bind /sys "$CHROOT_DIR/sys"
cp /usr/bin/qemu-arm-static "$CHROOT_DIR/usr/bin/" 2>/dev/null || cp /usr/bin/qemu-aarch64-static "$CHROOT_DIR/usr/bin/" 2>/dev/null || true

# Install base system and deps
chroot "$CHROOT_DIR" /debootstrap/debootstrap --second-stage

# Install firmware and kernel
chroot "$CHROOT_DIR" apt-get update
chroot "$CHROOT_DIR" apt-get install -y --no-install-recommends \
  firmware-brcm firmware-rpi \
  linux-image-arm64 \
  grub-efi-arm64 \
  grub-pc \
  raspi-firmware \
  openssh-server \
  || { echo "apt install failed"; exit 1; }

# Install nasd
cp "$NASD_DEB" "$CHROOT_DIR/tmp/"
chroot "$CHROOT_DIR" dpkg -i /tmp/nasd_*.deb || true

# Configure fstab
echo "UUID=$(blkid -s UUID -p "$BOOT_DEV" | cut -d= -f2 | tr -d '"') /boot vfat defaults 0 2" > "$CHROOT_DIR/etc/fstab"
echo "UUID=$(blkid -s UUID -p "$ROOT_DEV" | cut -d= -f2 | tr -d '"') / ext4 defaults 0 1" >> "$CHROOT_DIR/etc/fstab"

# Configure /boot/config.txt
mkdir -p "$CHROOT_DIR/boot"
cat > "$CHROOT_DIR/boot/config.txt" <<EOF
# KilasOS config
arm_64bit=1
kernel=kernel8.img
gpu_mem=16
enable_uart=1
EOF

# Install GRUB EFI
chroot "$CHROOT_DIR" apt-get install -y --no-install-recommends grub-efi-arm64 || true
chroot "$CHROOT_DIR" grub-install --target=arm64-efi --boot-directory=/boot || true

# Set hostname
echo "kilasos" > "$CHROOT_DIR/etc/hostname"
echo "127.0.0.1 kilasos" >> "$CHROOT_DIR/etc/hosts"

# Enable SSH
chroot "$CHROOT_DIR" systemctl enable ssh

# Cleanup mounts
chroot "$CHROOT_DIR" apt-get clean
umount "$CHROOT_DIR/dev" "$CHROOT_DIR/proc" "$CHROOT_DIR/sys" "$CHROOT_DIR/boot" "$CHROOT_DIR" 2>/dev/null || true
losetup -d "$LOOP_DEV" 2>/dev/null || true

# Compress image
xz -9 -c "$IMG_NAME" > "${IMG_NAME}.xz"
echo "Built: ${IMG_NAME}.xz"
echo "TASK_COMPLETE"
