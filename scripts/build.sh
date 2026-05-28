#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.45.0)}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p bin
# Build flags:
#   -trimpath    : reproducible paths
#   -buildmode=pie : address-space layout randomisation (lintian hardening-no-pie)
#   -s -w        : strip debug + symbol tables (lintian unstripped-binary-or-object)
#   -X main.X=Y  : stamp version metadata
go build \
  -trimpath \
  -buildmode=pie \
  -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" \
  -o bin/nasd ./cmd/nasd

echo "Built bin/nasd  version=${VERSION}  commit=${COMMIT}  date=${BUILD_DATE}"
