#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

COVERAGE_DIR="test-coverage"
THRESHOLD="${COVERAGE_THRESHOLD:-40}"

echo "==> Running unit tests with coverage"
mkdir -p "$COVERAGE_DIR"

go test -coverprofile="$COVERAGE_DIR/coverage.out" -covermode=atomic -coverpkg=./internal/... ./internal/... 2>&1 | tee "$COVERAGE_DIR/test-output.log"

echo ""
echo "==> Coverage summary"
go tool cover -func="$COVERAGE_DIR/coverage.out" | tail -1

TOTAL=$(go tool cover -func="$COVERAGE_DIR/coverage.out" | tail -1 | awk '{print $NF}' | sed 's/%//')

echo ""
echo "==> Package-level coverage"
go tool cover -func="$COVERAGE_DIR/coverage.out" | grep -E 'internal/(auth|storage|api|audit|monitor|network|apps|security|backup|scheduler|sysupdate|wol|zfssend)/.*\.go:' | awk '{print $1, $NF}' | sort -t/ -k2 | column -t

echo ""
echo "==> Generating HTML report → $COVERAGE_DIR/coverage.html"
go tool cover -html="$COVERAGE_DIR/coverage.out" -o "$COVERAGE_DIR/coverage.html"

echo ""
echo "Total coverage: ${TOTAL}%  (threshold: ${THRESHOLD}%)"
if (( $(echo "$TOTAL < $THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
  echo "WARNING: Coverage ${TOTAL}% is below threshold ${THRESHOLD}% (non-blocking)"
fi

echo ""
echo "Artifacts:"
echo "  $COVERAGE_DIR/coverage.out  — raw coverage data"
echo "  $COVERAGE_DIR/coverage.html — HTML report"
echo "  $COVERAGE_DIR/test-output.log — test run log"
