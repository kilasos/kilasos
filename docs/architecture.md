# Architecture

## Component overview

```mermaid
graph TB
    Browser[Web Browser] -->|HTTPS :8080| Nasd[nasd daemon]
    Nasd -->|chi router| Auth[Auth middleware]
    Auth -->|session token| Handlers[Route handlers]
    Handlers -->|RunPriv/RunPlain| Binaries[Host binaries]
    Handlers -->|Docker API| Docker[Docker daemon]
    Handlers -->|read/write| State[State files]
    State -->|JSON| Disk[(/var/lib/kilasos/)]
    Binaries -->|ambient caps| Kernel[Linux kernel]
    Docker -->|containerd| Containers[Containers]
```

**Components:**
- **nasd** — single Go binary (~14 MB), HTTP server on :8080
- **chi v5 router** — dispatches ~300 routes to handler functions
- **Auth middleware** — validates Bearer tokens, injects `ctxUsername`/`ctxRole` into context
- **Audit middleware** — auto-logs every POST/PUT/DELETE/PATCH via `responseRecorder`
- **Handlers** — call `storage.Provider` methods; most return JSON via `writeJSON`
- **RunPriv/RunPlain** — privilege-separation layer in `internal/storage/priv.go`
- **State** — JSON files under `/var/lib/kilasos/` (users.json, apps.json, etc.)

## Trust boundaries

```mermaid
graph LR
    subgraph Untrusted
        Browser
    end
    subgraph "nasd (kilasos user, ambient caps)"
        Router[chi router]
        Handlers[Handler funcs]
        Audit[Audit middleware]
    end
    subgraph "Host binaries (root-owned, CAPs inherited)"
        ZFS[zfs/zpool]
        SMB[smbd/net]
        IP[ip/iptables]
        WG[wg]
        Docker
    end
    subgraph Kernel
        Caps[ambient capabilities]
        Net[netlink]
        FS[filesystem]
    end
    Browser -->|HTTPS| Router
    Router -->|ctxUsername| Handlers
    Handlers -->|RunPriv allowlist| ZFS
    Handlers -->|RunPriv allowlist| SMB
    Handlers -->|RunPlain| IP
    Handlers -->|RunPriv| WG
    ZFS -->|CAP_SYS_ADMIN| Caps
    WG -->|CAP_NET_ADMIN| Net
    IP -->|CAP_NET_ADMIN| Net
```

**Key boundaries:**

1. **Browser ↔ nasd** — HTTPS (optional, HTTP default on :8080). Session
   tokens in `Authorization: Bearer <token>` header. Public routes
   (`/auth/login`, `/auth/register`, `/share/<token>`) have no token.

2. **nasd ↔ Kernel** — Ambient capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
   `CAP_NET_BIND_SERVICE`, etc.) inherited from the systemd unit. `NoNewPrivileges=true`
   prevents setuid escalation. All privileged calls go through `RunPriv`
   which checks the allowlist in `priv.go`.

3. **nasd ↔ Host binaries** — `RunPriv` invokes only allowlisted paths
   (e.g. `/usr/sbin/zpool`, `/usr/bin/wg`). `RunPlain` is used for
   non-privileged binaries (e.g. `hostname`, `lsblk`).

4. **Handlers ↔ State files** — JSON under `/var/lib/kilasos/`, mode
   0600 for secrets (`auth_tokens.json`), 0644 for configs. Path is
   `ReadWritePaths`-gated in the systemd unit.

5. **safePath gating** — all file operations (upload, download, delete,
   zip, trash, search) validate paths through `safePath()` which rejects
   `..` traversal and requires the path to start with `/mnt/`.

## Data flow — POST /files/delete

```mermaid
sequenceDiagram
    participant Browser
    participant Router
    participant Handler as fileDeleteHandler
    participant Provider as linuxProvider
    participant FS as Filesystem

    Browser->>Router: POST /files/delete {"path":"/mnt/datapool/foo.txt"}
    Router->>Handler: authMiddleware → requireAdmin → handler
    Handler->>Handler: json.Decode → req.Path
    Handler->>Handler: safePath(req.Path) → check ".." + /mnt prefix
    Handler->>Provider: p.FileDelete(ctx, path)
    Provider->>Provider: resolve poolMount from p.Arrays()
    Provider->>FS: os.Rename(path, <pool>/.kilasos-trash/<name>.<ts>)
    Provider->>FS: os.WriteFile(<trash-path>.meta, {original_path, deleted_at})
    Provider-->>Handler: nil (or error)
    Handler->>Handler: auditLog.Log("file-delete", ..., ok)
    Handler-->>Browser: {"ok":true}
```

**Auth gate:** `requireAdmin(w, r)` reads `ctxRole` from context (set
by auth middleware). Non-admin requests return 403 before reaching the
provider.

**safePath gate:** `strings.Contains(path, "..")` → reject.
`filepath.Clean(path)` → must start with `/mnt/`.

**Per-pool trash:** `FileDelete` determines the originating pool's
mount path from `p.Arrays()`, moves the file to
`/mnt/<pool>/.kilasos-trash/`, and writes a `.meta` sidecar with the
original absolute path for accurate restore.

**Audit log:** both success and failure paths call
`auditLog.LogEnriched(...)` with the caller, action, resource path, IP,
and OK status. The audit middleware auto-logs the same request as
`POST /api/v1/files/delete`.
