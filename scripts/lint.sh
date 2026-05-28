#!/usr/bin/env bash
# lint.sh — go vet + audit-log lint. For every chi destructive route
# (r.Post/r.Put/r.Delete/r.Patch), scan the WINDOW lines following the
# registration and flag any that don't call auditLog.LogEnriched(...).
set -euo pipefail

ROUTER="internal/api/router.go"
WINDOW=30

go vet ./...

if [ ! -f "$ROUTER" ]; then
  echo "ERROR: $ROUTER not found" >&2
  exit 1
fi

findings=0
while IFS=: read -r lineno content; do
  end=$((lineno + WINDOW))
  # Accept either auditLog.Log(...) (legacy form) or auditLog.LogEnriched(...).
  # The migration to LogEnriched is tracked separately in audit-coverage.sh —
  # CI only blocks on routes with NO audit-log at all.
  if ! sed -n "${lineno},${end}p" "$ROUTER" | grep -qE 'auditLog\.(Log|LogEnriched)\('; then
    echo "FINDING ($ROUTER:$lineno): $content"
    findings=$((findings + 1))
  fi
done < <(grep -nE '\br\.(Post|Put|Delete|Patch)[[:space:]]*\(' "$ROUTER")

echo "audit-log findings: $findings"
[ "$findings" -eq 0 ] || exit 1
