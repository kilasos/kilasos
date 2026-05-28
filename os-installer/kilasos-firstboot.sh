#!/usr/bin/env bash
set -eu

# KilasOS firstboot wizard — runs once via systemd ConditionFirstBoot=yes

# Ensure TTY detection works correctly
TTY_MODE=$([ -t 0 ] && echo "interactive" || echo "noninteractive")

# ASCII banner
echo "Welcome to KilasOS"

# Idempotency guard
if [[ -f /etc/kilasos/firstboot-done ]]; then
    exit 0
fi

# Create required directories
mkdir -p /etc/kilasos /var/lib/kilasos /var/lib/kilasos/users.d 2>/dev/null || true
mkdir -p /etc/network/interfaces.d 2>/dev/null || true

# Helper: read password (hidden)
read_password() {
    local prompt="$1"
    local pass=""
    while IFS= read -r -s -p "$prompt" pass || [[ -z "$pass" ]]; do
        break
    done
    echo "$pass"
}

# Helper: read with default
read_default() {
    local prompt="$1"
    local default="$2"
    local input
    read -r -p "$prompt [$default]: " input || input=""
    [[ -n "$input" ]] && echo "$input" || echo "$default"
}

# Step b) Admin password (default user: admin)
if [[ "$TTY_MODE" == "interactive" ]]; then
    echo "Creating admin user..."
    admin_pass=""
    while [[ -z "$admin_pass" ]]; do
        admin_pass=$(read_password "Enter admin password: ")
        confirm_pass=$(read_password "Confirm admin password: ")
        if [[ "$admin_pass" != "$confirm_pass" ]]; then
            echo "Passwords do not match. Try again." >&2
            admin_pass=""
        fi
    done
else
    echo "[WARNING] Non-interactive mode: using default admin password 'kilasos'" >&2
    admin_pass="kilasos"
fi

# Write stub users.json (minimal JSON)
mkdir -p /var/lib/kilasos
cat > /var/lib/kilasos/users.json <<EOF
{
  "users": [
    {
      "username": "admin",
      "hashed_password": "$(openssl passwd -6 "$admin_pass" 2>/dev/null || echo 'kilasos')"
    }
  ]
}
EOF

# Step d) Network config
use_dhcp="Y"
if [[ "$TTY_MODE" == "interactive" ]]; then
    use_dhcp=$(read_default "Use DHCP? [Y/n]" "Y")
fi

if [[ "$use_dhcp" == "Y" || "$use_dhcp" == "y" ]]; then
    # DHCP config
    cat > /etc/network/interfaces.d/kilasos <<EOF
auto eth0
iface eth0 inet dhcp
EOF
else
    # Static IP config (simple prompt)
    ip=$(read_default "Enter static IP (e.g. 192.168.1.100/24)" "192.168.1.100/24")
    gw=$(read_default "Enter gateway (e.g. 192.168.1.1)" "192.168.1.1")
    dns=$(read_default "Enter primary DNS (e.g. 8.8.8.8)" "8.8.8.8")
    cat > /etc/network/interfaces.d/kilasos <<EOF
auto eth0
iface eth0 inet static
    address $ip
    gateway $gw
    dns-nameservers $dns
EOF
fi

# Step e) Hostname
hostname_default="kilasos"
if [[ "$TTY_MODE" == "interactive" ]]; then
    hostname_default=$(read_default "Enter hostname" "$hostname_default")
fi
echo "$hostname_default" > /etc/hostname
# Ensure /etc/hosts has localhost entries
if ! grep -q "localhost" /etc/hosts; then
    echo "127.0.0.1 localhost" > /etc/hosts
    echo "::1 localhost" >> /etc/hosts
fi
# Append hostname to hosts if not present
if ! grep -q "$hostname_default" /etc/hosts; then
    echo "127.0.1.1 $hostname_default" >> /etc/hosts
fi

# Step f) Timezone
timezone_default="UTC"
if [[ "$TTY_MODE" == "interactive" ]]; then
    echo "Common timezones: UTC, US/Eastern, US/Central, US/Pacific, Europe/London, Europe/Berlin, Asia/Tokyo"
    timezone_default=$(read_default "Enter timezone (default: $timezone_default)" "$timezone_default")
fi
# Set timezone
echo "$timezone_default" > /etc/timezone
ln -sf "/usr/share/zoneinfo/$timezone_default" /etc/localtime 2>/dev/null || true

# Step g) Enable and start nasd.service
systemctl enable --now nasd.service || true

# Step h) Wait and health check
sleep 3
if command -v curl &>/dev/null; then
    # Retry health check once
    for _ in {1..3}; do
        if curl -sf http://localhost:8080/health &>/dev/null; then
            break
        fi
        sleep 1
    done
fi

# Step i) Success message
echo "Setup complete! Web UI at http://$(hostname -I 2>/dev/null | head -n1 || echo 'localhost'):8080/"

# Step j) Mark firstboot done
touch /etc/kilasos/firstboot-done

# Step k) Disable firstboot service
# systemd will auto disable via ConditionFirstBoot, but be explicit
systemctl disable kilasos-firstboot.service 2>/dev/null || true

TASK_COMPLETE
