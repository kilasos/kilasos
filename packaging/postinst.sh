#!/bin/sh
set -e

# Create kilasos system group + user with system-allocated UID/GID.
if ! getent group kilasos >/dev/null 2>&1; then
    groupadd --system kilasos
fi
if ! getent passwd kilasos >/dev/null 2>&1; then
    useradd --system --gid kilasos --no-create-home \
            --home-dir /var/lib/kilasos --shell /usr/sbin/nologin kilasos
fi

# Add kilasos to docker group if docker is installed (non-fatal).
if getent group docker >/dev/null 2>&1; then
    usermod -aG docker kilasos 2>/dev/null || true
fi

# State + config + log directories owned by the service account.
mkdir -p /var/lib/kilasos /var/log/kilasos /etc/kilasos
chown kilasos:kilasos /var/lib/kilasos /var/log/kilasos
chmod 750 /var/lib/kilasos /var/log/kilasos
chmod 755 /etc/kilasos

# Pick up the new unit file.
if command -v deb-systemd-invoke >/dev/null 2>&1; then
    deb-systemd-invoke daemon-reload >/dev/null 2>&1 || true
    deb-systemd-invoke enable nasd.service >/dev/null 2>&1 || true
else
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable nasd.service >/dev/null 2>&1 || true
fi

# Validate + reload sshd so the AuthorizedKeysFile drop-in takes effect.
# (Only if sshd is installed; the drop-in itself was placed by nfpm.)
if command -v sshd >/dev/null 2>&1 && [ -d /etc/ssh/sshd_config.d ]; then
    if sshd -t >/dev/null 2>&1; then
        if systemctl is-active --quiet ssh 2>/dev/null; then
            systemctl reload ssh >/dev/null 2>&1 || true
        elif systemctl is-active --quiet sshd 2>/dev/null; then
            systemctl reload sshd >/dev/null 2>&1 || true
        fi
    else
        echo "warning: sshd -t reported a problem; not reloading. Run 'sshd -t' to inspect." >&2
    fi
fi
