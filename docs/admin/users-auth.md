# Users and authentication

> **Status:** outline.

Auth options range from "local user + password" to "OIDC + WebAuthn + TOTP".
Mix as needed; the audit log records which method authenticated each request.

## Chapter map

1. Local users and roles
2. First-boot setup
3. Password policy and brute-force tracking
4. TOTP (RFC 6238)
5. WebAuthn / passkeys
6. OIDC (Okta, Authelia, Keycloak, generic)
7. LDAP / Active Directory
8. API keys (machine-to-machine)
9. Sessions and session management
10. Audit log (who did what, when)
11. Login customization (branding, MOTD)

## Local users and roles

`[TODO]` three roles: `admin`, `user`, `readonly`. What each can do, the
role check in the API (`requireAdmin`), `/var/lib/kilasos/users.json` schema.

## First-boot setup

`[TODO]` the bootstrap form, no anonymous access after it's run, recovery
if you forget the admin password ([see recovery.md](recovery.md)).

## Password policy

`[TODO]` minimum length, complexity, history, expiry. Brute-force tracker
windows + lockout.

## TOTP

`[TODO]` enrollment QR, validation window, backup codes.

## WebAuthn

`[TODO]` registering a passkey, hardware keys (YubiKey), browser keys
(passkey on macOS / Android / 1Password).

## OIDC

`[TODO]` configure issuer URL + client ID + secret, group-to-role mapping
(`oidc-group-mapping` config), token refresh, claims used.

## LDAP / AD

`[TODO]` bind DN, base DN, attribute mapping, group-to-role.

## API keys

`[TODO]` create, scope (admin / user / readonly), revoke, listing.

## Sessions

`[TODO]` session storage (`sessions.json`), idle timeout, absolute timeout,
"sign out everywhere".

## Audit log

`[TODO]` schema (user, ip, action, resource, success), retention
(`/audit/retention`), how the middleware enriches entries, export.

## Login customization

`[TODO]` branding (logo, colors), MOTD before login, login banner.

---

**Previous:** [Apps ←](apps.md)
**Next:** [Backups →](backups.md)
