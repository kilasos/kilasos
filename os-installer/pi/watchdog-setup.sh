#!/usr/bin/env bash
# Hardware watchdog + GPIO fan control setup for Raspberry Pi

# Ensure script runs as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run as root" >&2
   exit 1
fi

# Step 1: Enable bcm2835_wdt module
echo "Enabling bcm2835_wdt module..."
if ! grep -q "^bcm2835_wdt$" /etc/modules; then
   echo "bcm2835_wdt" >> /etc/modules
fi

# Step 2: Install watchdog package (if not already installed)
if ! command -v watchdog >/dev/null 2>&1; then
   echo "Installing watchdog package..."
   apt-get update && apt-get install -y watchdog
fi

# Step 3: Configure /etc/watchdog.conf
echo "Configuring /etc/watchdog.conf..."
cp /etc/watchdog.conf /etc/watchdog.conf.bak

cat > /etc/watchdog.conf <<EOF
max-load-1 = 4
max-load-5 = 3
max-load-15 = 2
temp-device = /dev/temperature
interval = 10
realtime = yes
watchdog-device = /dev/watchdog
EOF

# Step 4: Enable and start watchdog service
echo "Enabling watchdog service..."
systemctl enable watchdog
systemctl start watchdog

# Step 5: GPIO fan control setup (using sysfs for simplicity)
echo "Setting up GPIO fan control..."

# Detect GPIO pin (assume GPIO18 as default; user may override)
GPIO_PIN=${GPIO_PIN:-18}

# Export GPIO if not already exported
if [[ ! -d /sys/class/gpio/gpio${GPIO_PIN} ]]; then
   echo "${GPIO_PIN}" > /sys/class/gpio/export 2>/dev/null || true
fi

# Set direction to output
echo "out" > /sys/class/gpio/gpio${GPIO_PIN}/direction

# Create systemd service for fan control
cat > /etc/systemd/system/fan-control.service <<EOF
[Unit]
Description=GPIO Fan Control Service
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/bin/bash -c 'echo 1 > /sys/class/gpio/gpio${GPIO_PIN}/value'
ExecStop=/usr/bin/bash -c 'echo 0 > /sys/class/gpio/gpio${GPIO_PIN}/value'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "Setup complete. Watchdog and GPIO fan control are active."
