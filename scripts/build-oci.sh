#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-rc1")}"
COMMIT="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Building OCI container image for KilasOS $VERSION"

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker not found. Install docker before building the container image."
  exit 1
fi

PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
IMAGE="${IMAGE:-kilasos/nasd}"

docker buildx build --platform "$PLATFORMS" \
  -t "$IMAGE:$VERSION" \
  -t "$IMAGE:latest" \
  -f packaging/Dockerfile \
  --build-arg VERSION="$VERSION" \
  --build-arg COMMIT="$COMMIT" \
  --build-arg BUILD_DATE="$BUILD_DATE" \
  --load \
  .

echo "Done. Image: $IMAGE:$VERSION"
docker images "$IMAGE"
