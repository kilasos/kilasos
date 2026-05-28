#!/usr/bin/env bash
set -euo pipefail

# Build a pre-installed KilasOS QCOW2 image
# Assumes ISO is available at ./kilasos-0.45.0-amd64.iso

ISO_FILE="kilasos-0.45.0-amd64.iso"
QCOW2_RAW="kilasos-raw.qcow2"
QCOW2_FINAL="kilasos-0.45.0-amd64.qcow2"
TEMP_DIR=$(mktemp -d)

cleanup() {
  rm -rf "$TEMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Step 1: Create base qcow2 image
echo "[+] Creating 8GB qcow2 image..."
qemu-img create -f qcow2 "$QCOW2_RAW" 8G

# Step 2: Boot ISO unattended with preseeded installer
echo "[+] Booting installer unattended (no GUI, serial console)..."
# Use -nographic for serial console, -nodefaults to avoid extra devices
# Assume preseeded seed file exists at ./kilasos.seed
qemu-system-x86_64 \
  -nographic \
  -nodefaults \
  -drive file="$QCOW2_RAW",if=virtio,cache=none \
  -cdrom "$ISO_FILE" \
  -boot d \
  -m 2048 \
  -smp 2 \
  -append "auto=true priority=critical" \
  -initrd "$TEMP_DIR/initrd.gz" \
  -kernel "$TEMP_DIR/vmlinuz" \
  -no-reboot \
  -serial \
  -monitor none \
  -stdin \
  -device qemu-system-x86_64-serial \
  -device qemu-system-x86_64-virtio-net,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -name kilasos-installer \
  -daemonize \
  -pidfile "$TEMP_DIR/qemu.pid" \
  -D "$TEMP_DIR/qemu.log"

# Wait for installer to complete (timeout 30 min)
echo "[+] Waiting for installer to complete (max 30 min)..."
for i in $(seq 1 60); do
  if [ -f "$TEMP_DIR/install_done" ]; then
    echo "[+] Installation completed successfully."
    break
  fi
  sleep 30
done

# If no signal file, assume failure
if [ ! -f "$TEMP_DIR/install_done" ]; then
  echo "[!] Installation may have failed or timed out."
  exit 1
fi

# Step 3: Shutdown and convert to final compressed image
echo "[+] Shutting down VM..."
pkill -f qemu-system-x86_64 || true
sleep 2

# Step 4: Compress final image
echo "[+] Compressing final image..."
qemu-img convert -c -O qcow2 "$QCOW2_RAW" "$QCOW2_FINAL"

# Step 5: Verify
echo "[+] Verifying final image..."
qemu-img info "$QCOW2_FINAL"

echo "[+] Done. Final image: $QCOW2_FINAL"
