#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

TAGS=""
if [[ "${RACE:-0}" == "1" ]]; then
  TAGS="-race"
  echo "==> Race detector ENABLED"
fi

echo "==> Running all unit tests"
go test $TAGS -count=1 -timeout 120s ./internal/... 2>&1

echo ""
echo "All tests passed."
