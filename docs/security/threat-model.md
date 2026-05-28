# Threat Model

STRIDE analysis of the KilasOS NAS daemon and its trust boundaries.

## Assets

| Asset | Sensitivity | Storage |
|-------|-------------|---------|
| NAS data files (under `/mnt/`) | High — user's personal data, media, backups | ZFS pools, bind-mounted into containers |
| User credentials (passwords, TOTP secrets) | Critical — root access to NAS | `/var/lib/kilasos/users.json` (salthash format) |
| Session tokens (48-char hex) | High — impersonation for 24h | `/var/lib/kilasos/sessions.json` |
| Audit log entries | Medium — operational history | `/var/lib/kilasos/audit.json` (1000-entry ring buffer) |
| System config (network, shares, apps) | Medium — configuration state | `/var/lib/kilasos/*.json` |

## Trust boundaries

1. **Browser ↔ nasd (HTTPS)** — the user interface. Session tokens travel
   in the `Authorization` header. XSS in the WebUI could steal tokens.
2. **nasd ↔ Kernel (ambient caps)** — the daemon inherits ambient
   capabilities from the systemd unit. The allowlist in `priv.go`
   restricts which binaries RunPriv invokes.
3. **nasd ↔ Host binaries (RunPriv/RunPlain)** — privileged binaries
   (`zpool`, `zfs`, `wg`, `iptables`) are invoked via RunPriv which
   checks the allowlist. Non-privileged binaries (`lsblk`, `hostname`)
   use RunPlain.
4. **nasd ↔ ZFS** — pool import, dataset creation, snapshot management.
   CAP_SYS_ADMIN is required.
5. **nasd ↔ Samba** — SMB share configuration via `smb.conf` writes.
   Daemon reloads Samba via `smbcontrol`.
6. **nasd ↔ Docker** — container lifecycle via Docker API (`/var/run/docker.sock`).

## Threats by category

### Spoofing
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| Stolen session token | Data files, config | Tokens are 48-char random hex; session TTL 24h configurable | Token stored in `sessionStorage` — XSS could exfiltrate |
| Fake OIDC provider | User identity | OIDC state+nonce validation; HTTPS required for callbacks | Configurable `InsecureSkipVerify` weakens this |
| API key leakage | Config | Keys are SHA-256 hashed; full key shown only once | Keys have optional TTL; no rotation mechanism |

### Tampering
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| Malicious compose YAML in app deploy | Container data | Template substitution limits user input to `{{NAME}}`/`{{DATA_PATH}}` | Custom compose input accepts arbitrary YAML |
| Path traversal in file operations | Data files | `safePath()` rejects `..` and requires `/mnt/` prefix | `EvalSymlinks` resolution added for folder-zip |
| Audit log modification | Audit log | `audit.json` written async; no integrity checks | An attacker with filesystem access can modify the JSON |

### Repudiation
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| User denies destructive action | Audit log | Every POST/PUT/DELETE/PATCH logged with user, IP, timestamp | Audit middleware captures all mutating routes; handler-level audit adds detail |
| Admin claims non-admin performed action | Audit log | `requireAdmin` gate + audit-log on both success and failure | Admin token compromise would produce clean audit entries |

### Information disclosure
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| Audit log read by non-admin | Audit log | `requireAdmin` on `/audit-log` and `/audit/search` | 3 read-side handlers still ungated (Lynis, Trivy, SSH audit) |
| User list enumeration | User credentials | `/users` requires admin token | API returns full user list to authenticated admins |
| Failed login detail leakage | Credentials | Login returns generic "invalid credentials" | Username enumeration via timing? Not measured |
| GDPR export intercepted | Data files | Export returns tar.gz; transport over HTTPS | File written to disk before streaming — window for local read |

### Denial of service
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| Login brute-force | Credentials | Per-IP rate limiter (10 req/15min) + per-username lockout (5/10min) + fail2ban integration | OIDC/LDAP login rate-limited; WebAuthn path not rate-limited |
| Backup job flood | Data files | Concurrent-run suppression via `sync.Map` | No per-user backup job limit |
| Container resource exhaustion | System config | Per-container CPU/memory limits via `docker update` | No global resource cap at the daemon level |
| ZIP bomb via folder-zip | Disk space | safePath gate prevents reads outside `/mnt` | No size limit on ZIP generation — large directories can fill tmp |

### Elevation of privilege
| Threat | Asset | Mitigation | Residual |
|--------|-------|-----------|----------|
| OIDC/LDAP config modification by non-admin | User credentials | `requireAdmin` on config GET/PUT handlers | Fixed in AUTH-02/03 |
| Container exec as non-admin | System config | `requireAdmin` on `/containers/{id}/exec` | Fixed in APPS-04 |
| App deploy as non-admin | Data files | `requireAdmin` on `/apps` POST/PUT/DELETE | Fixed in APPS-04 |
| Via compromised container (Docker socket) | All assets | Containers using bind-mounted `/var/run/docker.sock` (Portainer, Homepage, Watchtower) have full Docker daemon access | Template-level — operator must trust those images |
| Via ambient capabilities | Kernel | `NoNewPrivileges=true` prevents setuid escalation; capabilities are inherited but restricted to the allowlisted binaries | CAP_SYS_ADMIN is broad — attacker with nasd process access can do significant damage |

## Out of scope

- Physical access to the NAS hardware
- OS-level compromise of the host (root access bypasses all daemon-level controls)
- Supply-chain attacks on the binaries KilasOS shells out to (`zpool`, `wg`, etc.)
- Third-party services (Tailscale, Cloudflare, Telegram, Discord) — these have their own security models
