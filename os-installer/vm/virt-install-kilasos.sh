#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <iso_path> [--unattended]"
  echo "  iso_path: Path to the Debian installer ISO"
  echo "  --unattended: Enable unattended install (requires preseeded answers)"
  exit 1
}

# Validate arguments
if [[ $# -lt 1 ]]; then
  usage
fi

ISO_PATH="$1"
shift

UNATTENDED=false
if [[ "$1" == "--unattended" ]]; then
  UNATTENDED=true
  shift
fi

# Validate ISO exists
if [[ ! -f "$ISO_PATH" ]]; then
  echo "Error: ISO file '$ISO_PATH' not found" >&2
  exit 1
fi

# Build virt-install command
CMD=(
  virt-install
  --name kilasos
  --vcpus 2
  --ram 2048
  --disk size=8
  --network bridge=virbr0
  --graphics spice
  --cdrom "$ISO_PATH"
  --os-variant debian12
  --autostart
)

# Append unattended-specific flags if needed
if [[ "$UNATTENDED" == true ]]; then
  # Preseed minimal answers for unattended install (Debian installer defaults)
  # Note: This assumes ISO supports preseeded answers (e.g., netinstall)
  # Add --unattended flag and preseed file handling if needed
  CMD+=(
    --unattended
  )
fi

# Execute
"${CMD[@]}"
echo "[+] VM '${VM_NAME}' started."
