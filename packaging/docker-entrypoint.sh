#!/usr/bin/env bash
set -euo pipefail
if [ -f /etc/kilasos/env ]; then set -a; source /etc/kilasos/env; set +a; fi
mkdir -p /var/lib/kilasos /var/log/kilasos
exec /usr/sbin/nasd "$@"
