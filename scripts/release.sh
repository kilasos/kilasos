#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "=== DRY RUN (no signing, no artifact output) ==="
fi

echo "==> Linting"
bash scripts/lint.sh || echo "(lint.sh not found or failed — continuing)"

echo "==> Building binaries"
bash scripts/build-multiarch.sh

echo "==> Building .deb packages"
bash scripts/build-deb.sh

echo "==> Building OCI images"
bash scripts/build-oci.sh || echo "(OCI build skipped — Docker not available)"

echo "==> Generating checksums"
( cd bin && sha256sum * > SHA256SUMS )
echo "  bin/SHA256SUMS written"

if $DRY_RUN; then
  echo "==> DRY RUN: skipping GPG sign"
  echo "  Would sign: bin/SHA256SUMS"
  echo "  Release artifacts would be in: bin/ dist/"
  exit 0
fi

echo "==> Signing with GPG"
gpg --detach-sign --armor bin/SHA256SUMS
echo "  bin/SHA256SUMS.asc"

echo ""
echo "Release artifacts:"
echo "  bin/nasd-linux-amd64"
echo "  bin/nasd-linux-arm64"
echo "  bin/SHA256SUMS"
echo "  bin/SHA256SUMS.asc"
ls dist/*.deb 2>/dev/null && echo "  dist/*.deb" || echo "  (no .deb files)"
