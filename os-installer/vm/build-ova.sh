#!/usr/bin/env bash
set -euo pipefail

VERSION="0.45.0"
VM_NAME="kilasos-${VERSION}"
DISK_SIZE="8G"
RAM="2048"
CPUS="2"
ISO_FILE="kilasos-${VERSION}-amd64.iso"
OVF_FILE="kilasos.ovf"
VMDK_FILE="kilasos.vmdk"
OVA_FILE="${VM_NAME}-amd64.ova"

if [[ ! -f "${ISO_FILE}" ]]; then
  echo "ERROR: ISO file '${ISO_FILE}' not found." >&2
  exit 1
fi

echo "[*] Creating raw disk image..."
qemu-img create -f raw disk.img "${DISK_SIZE}"

echo "[*] Installing guest OS via qemu-system..."
qemu-system-x86_64 \
  -name "${VM_NAME}" \
  -machine q35 \
  -cpu host \
  -smp "${CPUS}" \
  -m "${RAM}M" \
  -drive file=disk.img,if=virtio,format=raw \
  -cdrom "${ISO_FILE}" \
  -boot d \
  -nographic \
  -no-reboot \
  -serial stdio \
  -device qemu-xhci \
  -device usb-kbd \
  -device usb-mouse \
  -device usb-tablet

echo "[*] Converting raw disk to VMDK..."
qemu-img convert -f raw disk.img -O vmdk "${VMDK_FILE}"

echo "[*] Creating OVA package..."
tar -cf "${OVA_FILE}" "${VMDK_FILE}" "${OVF_FILE}"
rm -f disk.img

echo "[+] Done: ${OVA_FILE}"