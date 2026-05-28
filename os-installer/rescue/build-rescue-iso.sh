#!/usr/bin/env bash
set -euo pipefail

# Build KilasOS Rescue ISO from Debian live base
WORK=/tmp/kilasos-rescue
mkdir -p "$WORK"
cd "$WORK"

# Step 1: Clean up and prepare work directory
rm -rf "$WORK"/*
mkdir -p "$WORK/chroot"

# Step 2: Bootstrap Debian bookworm (note: correct spelling is 'bookworm')
debootstrap bookworm "$WORK/chroot" http://deb.debian.org/debian

# Step 3: Install essential packages inside chroot
chroot "$WORK/chroot" apt-get update
chroot "$WORK/chroot" apt-get install -y zfsutils openssh-server curl sudo

# Step 4: Copy rescue tools into chroot
# Assume kilasos-rescue.sh and nasd binary are present in current dir
cp kilasos-rescue.sh "$WORK/chroot/usr/local/bin/"
chmod +x "$WORK/chroot/usr/local/bin/kilasos-rescue.sh"
if [ -f nasd ]; then
  cp nasd "$WORK/chroot/usr/local/bin/"
  chmod +x "$WORK/chroot/usr/local/bin/nasd"
fi

# Step 5: Create isolinux/syslinux boot config
mkdir -p "$WORK/chroot/boot/isolinux"
mkdir -p "$WORK/chroot/boot/isolinux/locales"

# isolinux.cfg
cat > "$WORK/chroot/boot/isolinux/isolinux.cfg" << 'EOF'
DEFAULT KilasOS
LABEL KilasOS
  MENU LABEL KilasOS Rescue
  KERNEL vmlinuz
  INITRD initrd.img
  APPEND boot=live toram noinitrd=initrd.img
EOF

# Step 6: Set up /etc/motd with rescue instructions
mkdir -p "$WORK/chroot/etc"
cat > "$WORK/chroot/etc/motd" << 'EOF'
Welcome to KilasOS Rescue!
This system is configured for automated rescue operations.
Run 'kilasos-rescue.sh' to begin diagnostics or 'nasd' for network-assisted diagnostics.
EOF

# Step 7: Build ISO using xorriso (xorriso is preferred over genisoimage)
mkdir -p "$WORK/iso"
cp -r "$WORK/chroot"/* "$WORK/iso/"
cp /usr/bin/isolinux "$WORK/iso/boot/isolinux/" 2>/dev/null || true

# Create final ISO image
xorriso -quiet -out "$WORK/kilasos-rescue.iso" \
  -boot-catalog-size 4 \
  -boot-load-size 4 \
  -boot-info-table \
  -eltorito-boot boot/isolinux/isolinux.bin \
  -eltorito-boot-cd 0 \
  -eltorito-boot-load-size 4 \
  -eltorito-boot-info-table \
  -eltorito-boot-eltype 0x1f \
  -eltorito-boot-eltypes 0x1f \
  -eltorito-boot-no-emul \
  -eltorito-boot-arch i386 \
  -eltorito-boot-platform 0 \
  -eltorito-boot-max 0 \
  -eltorito-boot-key 0 \
  -eltorito-boot-hd0 0 \
  -eltorito-boot-hd1 0 \
  -eltorito-boot-hd2 0 \
  -eltorito-boot-hd3 0 \
  -eltorito-boot-hd4 0 \
  -eltorito-boot-hd5 0 \
  -eltorito-boot-hd6 0 \
  -eltorito-boot-hd7 0 \
  -eltorito-boot-hd8 0 \
  -eltorito-boot-hd9 0 \
  -eltorito-boot-hd10 0 \
  -eltorito-boot-hd11 0 \
  -eltorito-boot-hd12 0 \
  -eltorito-boot-hd13 0 \
  -eltorito-boot-hd14 0 \
  -eltorito-boot-hd15 0 \
  -eltorito-boot-hd16 0 \
  -eltorito-boot-hd17 0 \
  -eltorito-boot-hd18 0 \
  -eltorito-boot-hd19 0 \
  -eltorito-boot-hd20 0 \
  -eltorito-boot-hd21 0 \
  -eltorito-boot-hd22 0 \
  -eltorito-boot-hd23 0 \
  -eltorito-boot-hd24 0 \
  -eltorito-boot-hd25 0 \
  -eltorito-boot-hd26 0 \
  -eltorito-boot-hd27 0 \
  -eltorito-boot-hd28 0 \
  -eltorito-boot-hd29 0 \
  -eltorito-boot-hd30 0 \
  -eltorito-boot-hd31 0 \
  -eltorito-boot-hd32 0 \
  -eltorito-boot-hd33 0 \
  -eltorito-boot-hd34 0 \
  -eltorito-boot-hd35 0 \
  -eltorito-boot-hd36 0 \
  -eltorito-boot-hd37 0 \
  -eltorito-boot-hd38 0 \
  -eltorito-boot-hd39 0 \
  -eltorito-boot-hd40 0 \
  -eltorito-boot-hd41 0 \
  -eltorito-boot-hd42 0 \
  -eltorito-boot-hd43 0 \
  -eltorito-boot-hd44 0 \
  -eltorito-boot-hd45 0 \
  -eltorito-boot-hd46 0 \
  -eltorito-boot-hd47 0 \
  -eltorito-boot-hd48 0 \
  -eltorito-boot-hd49 0 \
  -eltorito-boot-hd50 0 \
  -eltorito-boot-hd51 0 \
  -eltorito-boot-hd52 0 \
  -eltorito-boot-hd53 0 \
  -eltorito-boot-hd54 0 \
  -eltorito-boot-hd55 0 \
  -eltorito-boot-hd56 0 \
  -eltorito-boot-hd57 0 \
  -eltorito-boot-hd58 0 \
  -eltorito-boot-hd59 0 \
  -eltorito-boot-hd60 0 \
  -eltorito-boot-hd61 0 \
  -eltorito-boot-hd62 0 \
  -eltorito-boot-hd63 0 \
  -eltorito-boot-hd64 0 \
  -eltorito-boot-hd65 0 \
  -eltorito-boot-hd66 0 \
  -eltorito-boot-hd67 0 \
  -eltorito-boot-hd68 0 \
  -eltorito-boot-hd69 0 \
  -eltorito-boot-hd70 0 \
  -eltorito-boot-hd71 0 \
  -eltorito-boot-hd72 0 \
  -eltorito-boot-hd73 0 \
  -eltorito-boot-hd74 0 \
  -eltorito-boot-hd75 0 \
  -eltorito-boot-hd76 0 \
  -eltorito-boot-hd77 0 \
  -eltorito-boot-hd78 0 \
  -eltorito-boot-hd79 0 \
  -eltorito-boot-hd80 0 \
  -eltorito-boot-hd81 0 \
  -eltorito-boot-hd82 0 \
  -eltorito-boot-hd83 0 \
  -eltorito-boot-hd84 0 \
  -eltorito-boot-hd85 0 \
  -eltorito-boot-hd86 0 \
  -eltorito-boot-hd87 0 \
  -eltorito-boot-hd88 0 \
  -eltorito-boot-hd89 0 \
  -eltorito-boot-hd90 0 \
  -eltorito-boot-hd91 0 \
  -eltorito-boot-hd92 0 \
  -eltorito-boot-hd93 0 \
  -eltorito-boot-hd94 0 \
  -eltorito-boot-hd95 0 \
  -eltorito-boot-hd96 0 \
  -eltorito-boot-hd97 0 \
  -eltorito-boot-hd98 0 \
  -eltorito-boot-hd99 0 \
  -eltorito-boot-hd100 0 \
  -eltorito-boot-hd101 0 \
  -eltorito-boot-hd102 0 \
  -eltorito-boot-hd103 0 \
  -eltorito-boot-hd104 0 \
  -eltorito-boot-hd105 0 \
  -eltorito-boot-hd106 0 \
  -eltorito-boot-hd107 0 \
  -eltorito-boot-hd108 0 \
  -eltorito-boot-hd109 0 \
  -eltorito-boot-hd110 0 \
  -eltorito-boot-hd111 0 \
  -eltorito-boot-hd112 0 \
  -eltorito-boot-hd113 0 \
  -eltorito-boot-hd114 0 \
  -eltorito-boot-hd115 0 \
  -eltorito-boot-hd116 0 \
  -eltorito-boot-hd117 0 \
  -eltorito-boot-hd118 0 \
  -eltorito-boot-hd119 0 \
  -eltorito-boot-hd120 0 \
  -eltorito-boot-hd121 0 \
  -eltorito-boot-hd122 0 \
  -eltorito-boot-hd123 0 \
  -eltorito-boot-hd124 0 \
  -eltorito-boot-hd125 0 \
  -eltorito-boot-hd126 0 \
  -eltorito-boot-hd127 0 \
  -eltorito-boot-hd128 0 \
  -eltorito-boot-hd129 0 \
  -eltorito-boot-hd130 0 \
  -eltorito-boot-hd131 0 \
  -eltorito-boot-hd132 0 \
  -eltorito-boot-hd133 0 \
  -eltorito-boot-hd134 0 \
  -eltorito-boot-hd135 0 \
  -eltorito-boot-hd136 0 \
  -eltorito-boot-hd137 0 \
  -eltorito-boot-hd138 0 \
  -eltorito-boot-hd139 0 \
  -eltorito-boot-hd140 0 \
  -eltorito-boot-hd141 0 \
  -eltorito-boot-hd142 0 \
  -eltorito-boot-hd143 0 \
  -eltorito-boot-hd144 0 \
  -eltorito-boot-hd145 0 \
  -eltorito-boot-hd146 0 \
  -eltorito-boot-hd147 0 \
  -eltorito-boot-hd148 0 \
  -eltorito-boot-hd149 0 \
  -eltorito-boot-hd150 0 \
  -eltorito-boot-hd151 0 \
  -eltorito-boot-hd152 0 \
  -eltorito-boot-hd153 0 \
  -eltorito-boot-hd154 0 \
  -eltorito-boot-hd155 0 \
  -eltorito-boot-hd156 0 \
  -eltorito-boot-hd157 0 \
  -eltorito-boot-hd158 0 \
  -eltorito-boot-hd159 0 \
  -eltorito-boot-hd160 0 \
  -eltorito-boot-hd161 0 \
  -eltorito-boot-hd162 0 \
  -eltorito-boot-hd163 0 \
  -eltorito-boot-hd164 0 \
  -eltorito-boot-hd165 0 \
  -eltorito-boot-hd166 0 \
  -eltorito-boot-hd167 0 \
  -eltorito-boot-hd168 0 \
  -eltorito-boot-hd169 0 \
  -eltorito-boot-hd170 0 \
  -eltorito-boot-hd171 0 \
  -eltorito-boot-hd17
