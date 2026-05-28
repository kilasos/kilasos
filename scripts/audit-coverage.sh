#!/usr/bin/env bash
# audit-coverage.sh — for every chi destructive route registration in
# router.go, locate the handler factory by name and scan its body for
# auditLog.Log(...) or auditLog.LogEnriched(...). Emits a Markdown table
# plus a summary suitable for pasting into AUDIT-LOG-AUDIT-COVERAGE.md.
#
# Usage:  bash scripts/audit-coverage.sh [path/to/router.go]
# Default: internal/api/router.go
#
# Limits:
#   - Only inspects ROUTER (the file passed in / defaulted). Handlers defined
#     in a different file under internal/api will be reported as "?" (not
#     found). For most of router.go's handler factories this is enough since
#     they are co-located.
#   - WINDOW is a heuristic: we read up to WINDOW lines after the handler's
#     "func name(" line. Handlers larger than WINDOW lines are under-reported.
set -euo pipefail

ROUTER="${1:-internal/api/router.go}"
WINDOW=120

if [ ! -f "$ROUTER" ]; then
  echo "ERROR: router file not found: $ROUTER" >&2
  exit 1
fi

declare -A handler_line_cache

find_handler_def() {
  local name="$1"
  if [ -n "${handler_line_cache[$name]+x}" ]; then
    printf '%s' "${handler_line_cache[$name]}"
    return
  fi
  # Match top-level `func name(` and method `func (recv) name(`.
  local line
  line=$(grep -nE "^func[[:space:]]+(\([^)]*\)[[:space:]]+)?${name}[[:space:]]*\(" "$ROUTER" \
         | head -1 | cut -d: -f1 || true)
  handler_line_cache[$name]="$line"
  printf '%s' "$line"
}

total=0
none=0
legacy=0
enriched=0
not_found=0
no_user=0
no_ip=0

printf '| METHOD | ROUTE | HANDLER | LOG | USER | IP |\n'
printf '|---|---|---|---|---|---|\n'

while IFS=: read -r lineno content; do
  method=$(printf '%s\n' "$content" \
    | sed -nE 's/.*\br\.(Post|Put|Delete|Patch)[[:space:]]*\(.*/\1/p' \
    | tr '[:lower:]' '[:upper:]')
  route=$(printf '%s\n' "$content" \
    | sed -nE 's/.*\br\.(Post|Put|Delete|Patch)[[:space:]]*\([[:space:]]*"([^"]+)".*/\2/p')
  handler=$(printf '%s\n' "$content" \
    | sed -nE 's/.*\br\.(Post|Put|Delete|Patch)[[:space:]]*\([[:space:]]*"[^"]*"[[:space:]]*,[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\2/p')
  [ -z "$method" ] && continue
  total=$((total + 1))

  if [ -z "$handler" ]; then
    log_ok='?'; user_ok='?'; ip_ok='?'
    not_found=$((not_found + 1))
  else
    def_line=$(find_handler_def "$handler")
    if [ -z "$def_line" ]; then
      log_ok='?'; user_ok='?'; ip_ok='?'
      not_found=$((not_found + 1))
    else
      end=$((def_line + WINDOW))
      body=$(sed -n "${def_line},${end}p" "$ROUTER")
      if grep -q 'auditLog\.LogEnriched(' <<<"$body"; then
        log_ok=enriched
        enriched=$((enriched + 1))
        if grep -qE 'r\.Context\(\)\.Value|ctxUsername' <<<"$body"; then
          user_ok=yes
        else
          user_ok=no; no_user=$((no_user + 1))
        fi
        if grep -q 'r\.RemoteAddr' <<<"$body"; then
          ip_ok=yes
        else
          ip_ok=no; no_ip=$((no_ip + 1))
        fi
      elif grep -q 'auditLog\.Log(' <<<"$body"; then
        log_ok=legacy
        legacy=$((legacy + 1))
        user_ok='?'; ip_ok='?'
      else
        log_ok=NONE
        none=$((none + 1))
        user_ok='-'; ip_ok='-'
      fi
    fi
  fi

  printf '| %s | %s | %s | %s | %s | %s |\n' \
    "$method" "${route:-?}" "${handler:-?}" "$log_ok" "$user_ok" "$ip_ok"
done < <(grep -nE '\br\.(Post|Put|Delete|Patch)[[:space:]]*\(' "$ROUTER")

printf '\n'
printf '**SUMMARY:** total=%d  no-log=%d  legacy=%d  enriched=%d  handler-not-found=%d  (enriched missing user-from-ctx=%d, missing IP=%d)\n' \
  "$total" "$none" "$legacy" "$enriched" "$not_found" "$no_user" "$no_ip"
