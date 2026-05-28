# Security

> **Status:** outline.

This chapter is descriptive: what KilasOS does on its own, and what you should
configure on top. It is not a hardening checklist for everything Linux —
existing Debian/Ubuntu security guides apply unchanged.

## Chapter map

1. The sandbox — what the systemd unit enforces
2. Sandbox limits — what nasd cannot do
3. TLS — server certificate
4. fail2ban integration
5. AppArmor profiles
6. Lynis system audit
7. Trivy container scanning
8. Audit log
9. GDPR / privacy mode
10. SSH key management
11. USB allowlist
12. Compliance reports

## The sandbox

`[TODO]` `nasd.service` directives explained: `ProtectSystem=strict`,
`ProtectHome=read-only`, `ProtectKernelTunables/Modules/ControlGroups`,
`MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`,
`RestrictNamespaces=true`, `RestrictSUIDSGID=true`. Why these matter,
what kind of attack each blocks.

## Sandbox limits

`[TODO]` known consequences:

- **Sudo doesn't work** under this unit. The implicit kernel `NoNewPrivs=1`
  blocks setuid escalation. nasd invokes privileged tools directly via
  inherited `AmbientCapabilities=` instead.
- **Ambient cap set is broad** (CAP_SYS_ADMIN is near-root). Compromising
  nasd grants significant capability, partially mitigated by the other
  hardenings. Scoped for the Phase 4.1 security audit.
- **`/root/.ssh` is read-only** (`ProtectHome=read-only`). WebUI-managed SSH
  keys live in `/etc/kilasos/authorized_keys`, declared by a sshd_config.d
  drop-in.

## TLS

`[TODO]` cert path candidates (`/etc/kilasos/cert.pem`,
`/etc/ssl/certs/kilasos.pem`, Let's Encrypt live dir), self-signed vs
public CA, ACME via Caddy or external.

## fail2ban

`[TODO]` shipped jail (`nasd-login`), tuning bantime / maxretry / findtime,
viewing banned IPs, manual unban.

## AppArmor

`[TODO]` per-container profiles, the profile catalog, enforcement vs
complain mode.

## Lynis

`[TODO]` running `lynis audit system`, where the state file lives,
WebUI panel reads results, suppressing warnings.

## Trivy

`[TODO]` scanning a Docker image before deploy, embedding scans in the
catalog workflow, severity threshold.

## Audit log

`[TODO]` cross-link to [users-auth.md#audit-log](users-auth.md#audit-log).

## GDPR / privacy mode

`[TODO]` opt-in/out telemetry, log scrubbing toggles, "delete user data"
action.

## SSH key management

`[TODO]` cross-link to [users-auth.md#api-keys](users-auth.md#api-keys);
explain the `/etc/kilasos/authorized_keys` path (root-owned, mode 0600,
chown'd by nasd after every write), and the sshd_config.d drop-in.

## USB allowlist

`[TODO]` enforcing which USB devices can attach, listing currently
allowed, removing.

## Compliance reports

`[TODO]` CIS / PCI / HIPAA-flavored reports, format options (JSON, PDF
when wkhtmltopdf is present), interpreting results.

---

**Previous:** [Alerts ←](alerts.md)
**Next:** [Recovery →](recovery.md)
