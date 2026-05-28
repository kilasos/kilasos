#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-rc1")}"
COMMIT="$(git rev-parse --short HEAD)"

echo "Building KilasOS $VERSION ($COMMIT) for linux/amd64 linux/arm64"

for arch in amd64 arm64; do
  echo "  → linux/$arch"
  GOOS=linux GOARCH=$arch go build -trimpath \
    -ldflags="-s -w -X main.Version=$VERSION -X main.Commit=$COMMIT" \
    -o "bin/nasd-linux-$arch" ./cmd/nasd
done

echo "Generating SHA256SUMS"
( cd bin && sha256sum nasd-linux-* > SHA256SUMS )
echo "Done. Artifacts in bin/"
ls -lh bin/nasd-linux-* bin/SHA256SUMS
