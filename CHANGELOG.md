# Changelog

All notable changes to KilasOS are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
### Changed
### Fixed
### Removed
### Security

## [0.45.0-rc1] - 2026-05-24

### Added
- WebAuthn passkey login (`/auth/webauthn/login`) on login page
- Per-username account lockout in brute-force tracker (5 attempts / 10 min)
- Session TTL configurable via `SESSION_TTL_HOURS` environment variable
- Password expiry enforcement via `MaxAgeDays` policy field
- Login rate-limiting on OIDC and LDAP auth paths
- Recovery alerts for disk and pool health conditions
- Security dashboard panel on Overview tab (Fail2ban, AppArmor, SELinux, Lynis)
- ZFS Special VDEV WebUI panel (add/view/status)
- Data-requires-tool UI annotations extended to 5 additional panels
- AppArmor enforce/complain via WebUI
- Server certificate upload and self-signed generation

### Changed
- All 314 commits rewritten to single author: Arturo Lopez
- RunPriv/RunPlain ctx-threading: 189 RunPriv/RunPlain call sites threaded
- exec.Command sites in linux.go reduced from 315 to 1 (irreducible)
- NoNewPrivileges=true in systemd unit (hardening enabled)
- Per-pool trash directories (`/mnt/<pool>/.kilasos-trash/`)
- TrashRestore sidecar metadata: original-path preservation
- Monitor thresholds now configurable at runtime
- Docs/admin/*.md: all 12 chapters filled (was sketches/stubs)

### Fixed
- ContextUsernameKey type mismatch — all audit-log entries had empty User field
- OIDC and LDAP config handlers lacked requireAdmin (privilege escalation)
- RotateAuditLogs wrote zero-byte .gz files (data-loss bug)
- Fake CIS compliance checks replaced with real system queries (12 of 14)
- 21 auth handler error paths missing explicit audit-log entries
- 14 network handler failure paths missing explicit audit-log entries
- 9 security handler functions lacked requireAdmin gating
- Folder-zip TOCTOU: EvalSymlinks resolution added
- 4 data-requires-tool panels gated for non-admin users
- safePath() traversal: all 6 knownBug cases now rejected
- JS function shadowing in apps-tab (deployApp/appAction/removeApp)
- Duplicate catalog template IDs removed (vaultwarden, immich)
- loadDeployedApps + loadAppStacks response format mismatch

### Security
- 18 container/app handlers require admin gating
- 10 container/app handlers now log explicit audit entries
- Audit-log retention enforcement added
- GDPR export extended to include sessions, SSH keys, and app data
- USB allowlist enforcement via udev rules
- Privacy mode IP anonymization in audit log
- BATCH-B monitoring routes secured (10 handlers with requireAdmin + audit)
