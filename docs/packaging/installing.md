# Installing KilasOS

How to add the KilasOS apt repository and install the `nasd` daemon.

## Prerequisites

- Debian 12 (Bookworm) or Ubuntu 24.04 or later
- `systemd` (already present on all supported distros)
- Root or sudo access

## Home tier — install in one minute

The Home tier is the free, GPL-3.0 public release. Add the repository and install:

```bash
echo "deb [trusted=yes] https://apt.kilasos.org stable main" \
  | sudo tee /etc/apt/sources.list.d/kilasos.list
sudo apt update
sudo apt install kilasos-nasd
```

> **About `trusted=yes`:** the v1.0 repository is not yet GPG-signed. The
> `trusted=yes` flag tells apt to install unsigned packages from this source.
> KilasOS v1.1 will ship with a GPG-signed Release file; this section will
> update at that time to use `[signed-by=/usr/share/keyrings/kilasos.gpg]`
> instead. The package itself, the daemon, and all `/etc` files install with
> the same content either way — signing only verifies the publisher.

## Pro tier — coming soon

The Pro tier (OIDC/LDAP, ZFS send/receive replication, Borg/Restic/Rclone
cloud backups, full GDPR + security compliance bundle) is not yet available
for self-service apt install. It will be distributed from a separate gated
apt repository (`apt-pro.kilasos.org`) requiring HTTP Basic auth credentials
issued at purchase.

If you want to be notified when Pro is available for self-service install,
contact `support@kilasos.org`. For now Pro customers receive their
`.deb` package + license key by email after purchase.

## Start KilasOS

The `nasd` daemon starts automatically after install. Verify:

```bash
sudo systemctl status nasd
curl http://localhost:8080/healthz
```

Open `http://<your-server>:8080/` in a browser.

## Upgrading

Standard apt upgrade keeps you on the latest Home release:

```bash
sudo apt update
sudo apt upgrade
```

The daemon detects schema version changes at startup and migrates state
files forward automatically. Downgrades are not supported — restore a
backup if you need to go back.

## Troubleshooting

### Repository not found / 404 on `apt update`

Verify the source line is correct and `apt.kilasos.org` resolves:

```bash
cat /etc/apt/sources.list.d/kilasos.list
# Should show:
#   deb [trusted=yes] https://apt.kilasos.org stable main

dig +short apt.kilasos.org
# Should return Cloudflare IP addresses (172.x.x.x or 104.x.x.x).
```

### `nasd` starts but shows the Home tier banner persistently

That's expected for the Home tier — it's the free tier and runs uncapped
features within the Home cap limits (25 TB raw / 1 pool / 1 node).

### Port 8080 already in use

Change the listen address:

```bash
sudo systemctl edit nasd
# Add:
#   [Service]
#   ExecStart=
#   ExecStart=/usr/sbin/nasd -addr 0.0.0.0:9090
sudo systemctl daemon-reload
sudo systemctl restart nasd
```

## Uninstalling

```bash
sudo apt remove kilasos-nasd        # keeps /var/lib/kilasos data
sudo apt purge kilasos-nasd         # removes data + config too
```

State files in `/var/lib/kilasos/` and `/etc/kilasos/` are preserved on
`remove` and deleted on `purge`.

## Reporting issues

- Bugs / feature requests: [github.com/kilasos/kilasos/issues](https://github.com/kilasos/kilasos/issues)
- Security disclosures: `security@kilasos.org`
- General support: `support@kilasos.org` or
  [community Discord (link on kilasos.org)](https://kilasos.org)
