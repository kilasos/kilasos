# External Audit Scope

For the Phase 4.1 external security audit.

## In scope

- **Web UI** — login page, TOTP enrollment, session management,
  WebAuthn registration/login, all authenticated pages (Overview,
  Storage, Network, Containers, Apps, Settings, Console, Alerts)
- **File manager** — upload, download, rename, delete, folder-zip,
  trash routes, share-link creation/revocation
- **Public share endpoint** (`/share/<token>`) — unauthenticated
  access, token enumeration, path traversal
- **Authentication surface** — password login, OIDC redirect/callback,
  LDAP bind, WebAuthn assertion, API key validation, session token
  generation and validation
- **SMB/NFS permission flows** — share creation with NFS export,
  Samba global config, user quota enforcement
- **RunPriv/RunPlain gates** — allowlist completeness, binary path
  injection, argument injection, ambient capability scoping
- **safePath gates** — path traversal bypass, symlink escape, null
  byte injection, unicode normalization bypass
- **Audit log integrity** — entry completeness (every destructive
  handler logs on success+failure), time-ordering, CSV export,
  search endpoint
- **GDPR endpoints** — export archive contents, delete completeness,
  protected-user rejection

## Out of scope

- ZFS itself (upstream OpenZFS)
- Linux kernel (upstream Debian)
- Samba/NFS implementations (upstream)
- Docker daemon (upstream)
- Third-party tunnel services (Tailscale, Cloudflare)
- Physical security of the NAS hardware
- Social engineering

## Test artifacts available

- **Smoke suite:** 153-entry `coordinator/smoke-tests.sh` covering
  all major API surfaces
- **Endpoint sweep:** 162-endpoint GET sweep against the live VM
- **Threat model:** `docs/security/threat-model.md`
- **Security architecture:** `docs/security/architecture.md`
- **Source tree:** `internal/` — ~28k LOC of Go, 1 HTML file (~11k LOC)
- **Build output:** `bin/nasd` single binary

## Success criteria

- **Zero critical findings** — any critical must be fixed before
  the audit is considered complete
- **All high findings remediated before 1.0 cut** — may require
  multiple fixup rounds
- **Medium findings addressed or acknowledged** — tracked in the
  issue tracker with severity labels

## Deliverables expected from auditor

- Written report (PDF) with severity-classified findings
- Walkthrough of critical/high findings (remote, 1-2h)
- Retest verification after remediation
