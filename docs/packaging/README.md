# Packaging

KilasOS is distributed as:

- **A `.deb` package** for Debian 12 (Bookworm) and Ubuntu 24.04
- **An OCI container image** for Docker/Podman
- **Raw Go binaries** for amd64 and arm64

## Files

| File | Purpose |
|------|---------|
| `packaging/nfpm.yaml` | nfpm configuration for .deb generation |
| `packaging/Dockerfile` | Multi-stage Go build → Debian bookworm-slim container |
| `packaging/systemd/nasd.service` | Hardened systemd unit file |
| `packaging/postinst.sh` | Post-install script (creates `kilasos` user, sets permissions) |
| `packaging/sshd_config.d/99-kilasos.conf` | SSHD config to accept `/etc/kilasos/authorized_keys` |
| `packaging/apt-repo/` | Apt repository layout documentation |

## Build scripts

| Script | Purpose |
|--------|---------|
| `scripts/build-multiarch.sh` | Cross-compile `nasd` for amd64 and arm64 |
| `scripts/build-deb.sh` | Build `.deb` packages for both architectures via nfpm |
| `scripts/build-oci.sh` | Build multi-arch OCI image via Docker buildx |
| `scripts/release.sh` | Orchestrate full release: lint → build → deb → oci → checksum → sign |
| `scripts/signing.md` | GPG signing guide |

## Prerequisites

- **Go 1.23+** for compilation
- **nfpm** for .deb packaging — `go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest`
- **Docker buildx** for multi-arch container images
- **GPG** for release signing (optional for local builds)
