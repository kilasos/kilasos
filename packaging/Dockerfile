FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildDate=${BUILD_DATE}" -o /out/nasd ./cmd/nasd

FROM debian:bookworm-slim
# ZFS userspace lives in Debian's `contrib` repo component, which the slim
# base image does not enable by default.  Switch to a sources list that
# includes contrib + non-free + non-free-firmware before apt-get install.
RUN echo "deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && echo "deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list \
    && echo "deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    zfsutils-linux zfs-zed btrfs-progs samba samba-common-bin smartmontools sudo ca-certificates \
    restic borgbackup rclone jdupes fail2ban lynis iproute2 util-linux systemd \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 990 kilasos && useradd --system --uid 990 --gid 990 --home-dir /var/lib/kilasos --shell /usr/sbin/nologin kilasos
COPY --from=builder /out/nasd /usr/sbin/nasd
COPY packaging/sudoers.d/kilasos /etc/sudoers.d/kilasos
RUN chmod 0440 /etc/sudoers.d/kilasos
COPY packaging/docker-entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
RUN mkdir -p /var/lib/kilasos /var/log/kilasos /etc/kilasos && chown -R kilasos:kilasos /var/lib/kilasos /var/log/kilasos
VOLUME ["/mnt", "/var/lib/kilasos", "/etc/kilasos"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD curl -fsSk https://localhost:8443/healthz || exit 1
USER kilasos
ENTRYPOINT ["/entrypoint.sh"]
LABEL org.opencontainers.image.source="https://github.com/kilas/kilasos" \
      org.opencontainers.image.licenses="GPL-3.0" \
      org.opencontainers.image.title="KilasOS-nasd" \
      org.opencontainers.image.description="KilasOS NAS administration daemon"
