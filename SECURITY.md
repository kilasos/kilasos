# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.45.x  | ✅ Latest release receives security patches |
| 0.44.x  | ❌ No longer supported |

## Reporting a Vulnerability

If you discover a security vulnerability in KilasOS, please report it
promptly. Do NOT open a public GitHub issue — the issue tracker is a
public channel and would expose the vulnerability before a fix is
available.

**Email:** security@kilasos.org

**Response SLA:**
- Acknowledgement within 72 hours
- Confirmed high-severity findings: fix aimed within 30 days
- Critical findings: coordinated emergency release

**Please include:**
- A clear description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Any potential mitigations you've identified

## Disclosure Policy

KilasOS follows a 90-day coordinated disclosure policy:
1. You report the vulnerability privately.
2. We acknowledge and triage within 72 hours.
3. We develop and test a fix.
4. We coordinate a release date with you.
5. On the release date, we publish the advisory and credit you (unless
   you prefer anonymity).

## PGP Key

```
Fingerprint: TBD
```

A release-signing GPG key will be published before the first stable
release. Until then, verify commit signatures against the GitHub
verified badge or contact the maintainer directly.

## Out of Scope

- Third-party services that KilasOS integrates with but does not
  control: Tailscale, Cloudflare Tunnels, Docker Hub, Telegram API,
  Pushover, Discord, ntfy. Please report vulnerabilities in those
  services through their respective disclosure programs.
- Physical access or compromised host OS — if an attacker has root on
  the host, they already control the NAS.
- Social engineering of individual KilasOS users.
