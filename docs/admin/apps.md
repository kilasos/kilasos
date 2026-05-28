# Apps and containers

> **Status:** written 2026-05-23.

KilasOS bundles a 32-template catalog of common self-hosted apps. The catalog
generates `docker-compose.yml` per app; Docker Engine is the runtime. The
**Apps** tab is the catalog view, the **Containers** tab is the Docker-engine
view (all containers, including those not deployed via the catalog).

## Chapter map

1. [The app catalog](#the-app-catalog)
2. [Deploying a catalog app](#deploying-a-catalog-app)
3. [Stacks, services, and the compose model](#stacks-services-and-the-compose-model)
4. [Volumes, networks, and persistent data](#volumes-networks-and-persistent-data)
5. [Containers tab — Docker management](#containers-tab)
6. [Custom apps](#custom-apps)
7. [Updating and rolling back apps](#updating-and-rolling-back-apps)
8. [Removing apps cleanly](#removing-apps-cleanly)
9. [Resource limits and isolation](#resource-limits-and-isolation)
10. [Security considerations](#security-considerations)

## The app catalog

The catalog lives in `internal/appcatalog/catalog.go` and contains **32
unique templates** spanning Media, PVR, Download, Productivity, Security,
and System categories.

**Browsing** — the Apps tab shows the full catalog as cards (icon, name,
description, category badges, port). Use the search bar and category filter
to narrow results. Star apps to add them to your **Favorites** list (stored
in `/var/lib/kilasos/app-favorites.json`).

**Key templates by category:**

| Category | Examples |
|----------|---------|
| Media | Jellyfin, Plex, Immich, Photoprism, Audiobookshelf |
| PVR | Sonarr, Radarr, Lidarr, Readarr, Prowlarr |
| Download | qBittorrent, Transmission, NZBGet |
| Productivity | Nextcloud, Joplin, BookStack, FreshRSS, Paperless |
| Security | Vaultwarden |
| System | Portainer, Watchtower, Uptime Kuma, Grafana |

**Port conflicts** — Pi-hole and qBittorrent both use host port 8080.
Deploy only one at a time, or edit the compose YAML before deploying to
change one of the ports.

## Deploying a catalog app

1. Click **Deploy** on any app card in the Apps tab or Containers-tab catalog.
2. A dialog opens with the pre-filled `docker-compose.yml`. Review and edit
   as needed.
3. Click **Deploy**. The compose file is written to
   `/var/lib/kilasos/apps/<template-id>/docker-compose.yml` with two
   substitutions:
   - `{{NAME}}` → the template ID (e.g. `jellyfin`)
   - `{{DATA_PATH}}` → `/var/lib/kilasos/apps/<template-id>/data`
4. KilasOS runs `docker compose pull` then `docker compose up -d`.
5. Deploy progress is shown in the job log modal (polls `GET /app-jobs/{id}`).

**Deploying from the Containers tab** — the Containers-tab catalog
provides the same deploy flow but opens a compose-editor dialog before
deploying, giving you the chance to modify ports, volumes, or env vars.

## Stacks, services, and the compose model

**Each deployed app is a single Docker Compose project** — one compose file
per app. Apps like BookStack define multiple services (bookstack + mariadb)
in a single compose file; they are deployed, started, and stopped as one unit.

**App Stacks** are pre-configured groups of apps. Two stacks are available:
- **Servarr Stack** — Sonarr, Radarr, Lidarr, Readarr, Prowlarr, qBittorrent
- **Media Core Stack** — Jellyfin, Jellyseerr, Bazarr

Stacks use `hotio/<template-id>:latest` images (a community-maintained
Docker organization). Stack deployment writes a single compose file with
all services and runs `docker compose up -d`.

## Volumes, networks, and persistent data

**Data persistence** — all app data lives under
`/var/lib/kilasos/apps/<app-name>/data/`. This directory is bind-mounted
into containers via `{{DATA_PATH}}` in the compose template.

**Media access** — apps that need access to your media (Jellyfin, Plex,
Sonarr, etc.) bind-mount the host's `/mnt` directory. Any app with this
bind-mount can read **all** your stored files. Be careful which apps you
give `/mnt` access to.

**Networks** — most apps use Docker's default bridge network. Jellyfin and
Plex use `network_mode: host` for DLNA/HDHR discovery. Containers on the
same bridge network can reach each other by service name.

**Volume cleanup** — removing an app runs `docker compose down -v` followed
by `rm -rf` on the entire app directory. **All app data is permanently
deleted.** Export your config (`POST /app-config/{name}`) before removing
an app if you want to preserve settings.

## Containers tab

The Containers tab shows **every Docker container** on the system, not just
catalog-deployed apps. Each container card shows:

- Name, image, state (running/paused/stopped)
- Live CPU, memory, and network stats (polled every 30s)
- Mapped ports

**Container actions** (admin-only):
- **Start / Stop / Restart / Pause / Unpause** — lifecycle control
- **Logs** — stream the last 200 lines of stdout/stderr
- **Inspect** — full Docker inspect JSON in a modal
- **Limits** — set CPU and memory limits (`docker update`)
- **Remove** — delete the container

Additional Docker management panels (admin-only):
- **Pull Image** — pull any image from Docker Hub
- **Images** — list and remove Docker images
- **Volumes** — list and remove Docker volumes
- **Compose Projects** — view and manage all `docker compose` projects
- **Docker Daemon Config** — edit `/etc/docker/daemon.json`
- **System Prune** — run `docker system prune` to reclaim disk space

## Custom apps

Use the **Custom App Builder** in the Apps tab to deploy any
`docker-compose.yml`:

1. Paste your compose YAML into the textarea.
2. Click **Deploy Custom App**. KilasOS creates a template with a random
   ID (`custom-XXXXXX`) and deploys it through the standard deploy pipeline.
3. The app appears in your deployed-apps list alongside catalog apps.

**Caveat:** Custom apps don't get `{{NAME}}`/`{{DATA_PATH}}` substitution
unless you include those placeholders in your YAML. Data path for custom
apps defaults to `/var/lib/kilasos/apps/custom-XXXXXX/data/`.

## Updating and rolling back apps

**Update check** — admin-only. KilasOS compares the image tag in your
`docker-compose.yml` against the latest tag from the registry. The check
pulls the image and reports whether an update is available. **Limitation:**
floating tags like `:latest` and `:release` always show "update available"
— the comparison is tag-based, not digest-based.

**Applying an update** — admin-only. Runs `docker compose pull` then
`docker compose up -d`. Optionally backs up the app's data directory
before updating.

**Rollback** — admin-only. Restore a previous backup directory and
re-run `docker compose up -d`. Backups are stored under
`/var/lib/kilasos/apps/<name>/backups/`.

## Removing apps cleanly

**Removing a deployed app** (admin-only):

1. Runs `docker compose down -v` to stop containers and remove volumes.
2. Runs `rm -rf` on the entire app directory under `/var/lib/kilasos/apps/`.
3. Removes the app from the deployed-apps list.

**⚠️ This permanently deletes all app data.** Export your config with
`GET /app-config/{name}` before removal. There is no trash/recycle for
app data.

## Resource limits and isolation

**Per-container limits** — set via the Containers tab "Limits" button.
Runs `docker update --memory=<bytes> --cpus=<float> <id>`. Changes are
immediate and persist across container restarts.

**AppStack limits** — AppStack templates define CPU and memory limits per
service. These are written into the generated compose file as
`deploy.resources.limits`.

**Host-wide limits** — not enforced by KilasOS. The Docker daemon handles
resource isolation. Monitor host CPU/memory via the Overview dashboard.

## Security considerations

**Docker socket access** — Portainer, Homepage, and Watchtower templates
bind-mount `/var/run/docker.sock`. These apps have **full control over
the Docker daemon**, including the ability to start/stop any container,
create new containers, and access all container volumes. Only deploy
these apps if you trust them fully.

**Host networking** — Jellyfin and Plex use `network_mode: host`. They
share the host's network namespace and can bind any port.

**Bind-mounted `/mnt`** — apps that mount `/mnt` (Jellyfin, Plex,
Transmission, Sonarr, Radarr, etc.) can read all files under `/mnt`.
Consider using read-only binds (`/mnt:/mnt:ro`) for apps that only need
read access.

**Trivy scanning** — available via the Security section in Settings
(`data-requires-tool="trivy"`). Scans Docker images for known
vulnerabilities before deploying.

**AppArmor** — profiles can be applied in the Security section. These
profiles live in `/etc/apparmor.d/` and restrict container capabilities.

---

**Previous:** [Network ←](network.md)
**Next:** [Users & auth →](users-auth.md)
