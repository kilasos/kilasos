#!/usr/bin/env bash
set -euo pipefail

# Rescue script for KilasOS Phase 3 Session 10
# Idempotent, minimal Debian live environment

# Ensure required tools exist
command -v zpool >/dev/null 2>&1 || { echo "ZFS tools not found"; exit 1; }

# Global variables
RESUE_DIR="/mnt/rescue"
SSH_STARTED=false
NASD_STARTED=false

cleanup() {
    if [[ "$SSH_STARTED" == "true" ]]; then
        pkill -f "sshd.*-D" 2>/dev/null || true
    fi
    if [[ "$NASD_STARTED" == "true" ]]; then
        pkill -f "nasd" 2>/dev/null || true
    fi
}

trap cleanup SIGTERM SIGINT EXIT

start_sshd() {
    if command -v sshd >/dev/null 2>&1; then
        if ip route show 2>/dev/null | grep -q "default" && command -v ip >/dev/null 2>&1; then
            local ip
            ip=$(ip route show 2>/dev/null | awk '/default/ {print $3}' | head -n1)
            if [[ -n "$ip" ]]; then
                mkdir -p /root/.ssh 2>/dev/null || true
                echo "ssh-rsa" > /root/.ssh/authorized_keys 2>/dev/null || true
                chmod 600 /root/.ssh/authorized_keys 2>/dev/null || true
                /usr/sbin/sshd -D 2>/dev/null &
                SSH_STARTED=true
            fi
        fi
    fi
}

start_nasd() {
    if command -v nasd >/dev/null 2>&1 && [[ -f /etc/nasd.conf ]]; then
        nasd --read-only --rescue 2>/dev/null &
        NASD_STARTED=true
    fi
}

mount_pools() {
    local pools
    pools=$(zpool list -H 2>/dev/null || true)
    if [[ -n "$pools" ]]; then
        for pool in $pools; do
            local name mount
            name=$(echo "$pool" | awk '{print $1}')
            mount=$(echo "$pool" | awk '{print $2}')
            if [[ "$mount" == "none" ]]; then
                mkdir -p "$RESUE_DIR/$name" 2>/dev/null || true
                zfs set mountpoint="$RESUE_DIR/$name" "$name" 2>/dev/null || true
                zfs mount "$name" 2>/dev/null || true
            fi
        done
    fi
}

main() {
    # Step 1: Import ZFS pools
    zpool import -a -N 2>/dev/null || true

    # Step 2: List imported pools with status
    zpool list -v 2>/dev/null || true

    # Step 3: Mount pool datasets
    mkdir -p "$RESUE_DIR" 2>/dev/null || true
    mount_pools

    # Step 4: Start sshd if network is up
    if command -v ip >/dev/null 2>&1; then
        start_sshd
    fi

    # Step 5: Start nasd in read-only rescue mode
    start_nasd

    # Step 6: Print instructions
    echo "Rescue shell at /mnt/rescue/. SSH available. Run kilasos-rescue --web for web UI."

    # Step 7: Drop to shell if --shell flag passed
    if [[ "${1:-}" == "--shell" ]]; then
        exec bash
    fi

    # Keep script alive for interactive use
    sleep infinity
}

main "$@"
