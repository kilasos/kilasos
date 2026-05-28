#!/usr/bin/env bash
set -eu

# os-installer/live-build-config.sh — Configure and build KilasOS live ISO via debian-live (lb)

# Create working directory and enter it
mkdir -p /tmp/kilasos-live && cd /tmp/kilasos-live

# Run lb config with specified options for a bootable, minimal live system
# distribution: bookworm (Debian 12-based)
# architecture: amd64
# binary-images: iso-hybrid (produces ISO usable as both CD/DVD and USB)
# bootloader: grub-efi (supports UEFI booting)
# debian-installer: live (enables live session installer)
# debian-installer-gui: false (disable installer GUI for lightweight build)
# archive-areas: include main, contrib, non-free for full package availability
# linux-packages: explicitly include kernel and headers for ZFS support
# apt-recommends: false (avoid unnecessary recommends to keep image small)
# memtest: none (disable memtest for smaller ISO)
lb config --distribution bookworm \
  --architectures amd64 \
  --binary-images iso-hybrid \
  --bootloader grub-efi \
  --debian-installer live \
  --debian-installer-gui false \
  --archive-areas "main contrib non-free" \
  --linux-packages "linux-image-amd64 linux-headers-amd64" \
  --apt-recommends false \
  --memtest none

# Create package list with essential tools for KilasOS
mkdir -p config/packages
mkdir -p config/package-lists
cat > config/package-lists/kilasos.list.chroot <<'EOF'
# KilasOS live package list
zfsutils-linux
zfs-zed
zfs-dkms
openssh-server
curl
sudo
smartmontools
samba
samba-common-bin
ca-certificates
EOF

# Create placeholder directory and copy nasd .deb (if present in build env)
mkdir -p config/packages.chroot
# Note: actual .deb must be provided at build time; placeholder here ensures dir exists

# Add firstboot hook: creates systemd service that runs only on first boot
mkdir -p config/hooks/normal
cat > config/hooks/normal/0999-kilasos-firstboot.hook.chroot <<'EOF'
#!/bin/sh
# Hook to install a systemd firstboot service
# ConditionFirstBoot=yes ensures it runs only once, on first boot after install
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/kilasos-firstboot.service <<'SERVICE'
[Unit]
Description=KilasOS First Boot Tasks
ConditionFirstBoot=yes

[Service]
Type=oneshot
ExecStart=/usr/local/bin/kilasos-firstboot.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

# Create minimal firstboot script
mkdir -p /usr/local/bin
cat > /usr/local/bin/kilasos-firstboot.sh <<'SCRIPT'
#!/bin/sh
# Minimal KilasOS firstboot script — placeholder for real logic
# Could include: hostname setup, user creation, ZFS pool init, etc.
exit 0
SCRIPT
chmod +x /usr/local/bin/kilasos-firstboot.sh
chmod +x /etc/systemd/system/kilasos-firstboot.service
EOF

# Build the live ISO
lb build 2>&1 | tee /tmp/kilasos-live-build.log

# Output path (expected by lb)
echo "Live ISO built at: /tmp/kilasos-live/live-image-amd64.hybrid.iso"
TASK_COMPLETE
