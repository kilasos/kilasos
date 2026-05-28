# Security Architecture

Auth flows, session lifecycle, access control, and privilege separation.

## Authentication flows

### Password login
```
Browser → POST /auth/login {username, password, totp_code?}
  → UserStore.Login() → validate password + TOTP
  → IssueToken() → 48-char hex session token
  → BruteForceTracker.RecordSuccess(ip, username)
  ← {token, username, role}
```

### OIDC login
```
Browser → GET /auth/oidc/login
  → OIDCManager.BeginLogin() → redirect to provider
  → Provider callback → OIDCManager.HandleCallback()
  → Verify ID token (nonce, audience, issuer)
  → Map groups → roles via GroupRoleMapping
  → Auto-provision user if enabled
  → IssueToken() → redirect to UI with token in URL
```

### LDAP login
```
Browser → POST /auth/ldap/login {username, password}
  → LDAPManager.Authenticate() → connect + bind + search
  → Map groups → roles
  → Auto-provision if enabled
  ← {token, username, role}
```

### API key
```
Browser → Authorization: Bearer <id.secret>
  → APIKeyStore.Validate(key) → SHA-256 comparison
  → Extract role from key metadata
  → Inject ctxUsername/ctxRole into request context
```

## Session lifecycle

```
Creation:   IssueToken() → genToken() → session{Username, Role, Expires, Source, IP}
Validation: authMiddleware → ValidateToken(token) → check expiry
Expiry:     TTL defaults to 24h (configurable via SESSION_TTL_HOURS)
Revocation: POST /auth/logout → Logout(token)
            DELETE /auth/sessions/{token} → RevokeSessionByPrefix(token)
            POST /auth/sessions/revoke-all → RevokeAllSessionsForUser(username)
Pruning:    PruneExpiredSessions() called on token validation — expired sessions are deleted on access
```

## Access control — requireAdmin

`requireAdmin(w, r) bool` reads `ctxRole` from the request context (set by
auth middleware) and returns false if the role is not `"admin"`. All
destructive handlers call `requireAdmin` as their first check:

```
func handler(p storage.Provider) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !requireAdmin(w, r) { return }  // 403 before any work
        // ... handler body
    }
}
```

Read-sensitive handlers (audit log, security reports, GDPR export) also
call `requireAdmin`. GET-only status endpoints (`/metrics`, `/network`)
are open to all authenticated users.

## RunPriv privilege separation

`internal/storage/priv.go`:

- `RunPriv(ctx, bin, args...)` — executes an allowlisted binary with
  inherited ambient capabilities. Returns (stdout, stderr, error).
  Panics if the binary is not in the `privAllowlist`.
- `RunPlain(ctx, bin, args...)` — executes a binary without capability
  requirements. Uses `exec.CommandContext` internally.
- `privAllowlist` — map of binary paths → `true`. Currently 22 entries.

The systemd unit grants ambient capabilities (`CAP_SYS_ADMIN`,
`CAP_NET_ADMIN`, `CAP_NET_BIND_SERVICE`, etc.) via
`AmbientCapabilities=`. `NoNewPrivileges=true` prevents setuid
escalation — all privileged actions must go through RunPriv.

## safePath gating

`internal/api/files.go::safePath(path)`:

1. Rejects any path containing `..` (blocks traversal)
2. Calls `filepath.Clean(path)` to normalize
3. Requires the clean path to start with `/mnt/` (not `/mntfoo`)

All file handlers (upload, download, delete, rename, copy, folder-zip,
trash, search) call `safePath()` before any filesystem operation.

## GDPR data flow

### Export
```
GET /security/gdpr/export
  → GDPRExport() → create temp directory
  → Copy /var/lib/kilasos/users.json
  → Copy /var/lib/kilasos/sessions.json
  → Copy /etc/kilasos/authorized_keys
  → Archive /var/lib/kilasos/apps/ → apps.tar.gz
  → SearchAuditLogs(limit=10000) → audit-log.json
  → tar czf → temp-dir.tar.gz
  ← download binary stream
```

### Delete
```
DELETE /security/gdpr/user/{username}
  → GDPRDelete(username)
  → Reject admin/root/empty usernames
  → Remove from /var/lib/kilasos/users.json
  → Remove from /var/lib/kilasos/sessions.json
  → Remove matching SSH keys from authorized_keys
  → Remove matching API keys from api-keys.json
  ← {ok: true}
```
