#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-rc1")}"

echo "Building .deb packages for KilasOS $VERSION"

if ! command -v nfpm &>/dev/null; then
  echo "ERROR: nfpm not found. Install with:"
  echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
  echo "  or download from https://github.com/goreleaser/nfpm/releases"
  exit 1
fi

for arch in amd64 arm64; do
  echo "  → $arch"
  nfpm package --config packaging/nfpm.yaml --target "dist/kilasos-nasd_${VERSION}_${arch}.deb" \
    --env "ARCH=$arch" --env "VERSION=$VERSION" || \
    nfpm package --config packaging/nfpm.yaml --packager deb \
      --target "dist/kilasos-nasd_${VERSION}_${arch}.deb"
done

echo "Done. Artifacts in dist/"
ls -lh dist/*.deb 2>/dev/null || echo "(no .deb files produced — nfpm may need arch override in nfpm.yaml)"
