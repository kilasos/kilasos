<!-- Release notes template for KilasOS. Copy this into the GitHub
     release body, fill in the placeholders, and delete unused
     sections. Use bullets from CHANGELOG.md's matching version
     section as the source of truth. -->

# KilasOS vX.Y.Z

<!-- One-paragraph elevator pitch: what is this release about?
     Examples: "Phase 4 release candidate — closes the security
     hardening backlog and adds per-pool trash." -->

## Highlights

<!-- 3-5 bullets the operator will care about most. -->

- 
- 
- 

## Breaking changes

<!-- Delete this section if none. List each breaking change with the
     migration steps. -->

- 

## Added

<!-- Mirror CHANGELOG.md ## [vX.Y.Z] ### Added. -->

- 

## Changed

<!-- Mirror CHANGELOG.md ## [vX.Y.Z] ### Changed. Note any
     behavior changes operators should be aware of even if not
     strictly breaking. -->

- 

## Fixed

<!-- Mirror CHANGELOG.md ## [vX.Y.Z] ### Fixed. Link to the issue
     number where one exists. -->

- 

## Security

<!-- Mirror CHANGELOG.md ## [vX.Y.Z] ### Security. Include
     CVE numbers if assigned, and link to the SECURITY.md advisory
     section. -->

- 

## Upgrade notes

<!-- Anything the operator needs to do beyond the standard
     `apt upgrade` / `docker pull`. Include schema migrations,
     config-file changes, deprecation removals. -->

- Standard upgrade path: `apt update && apt upgrade kilasos-nasd` or
  pull the new OCI image and restart the container.
- Schema migrations (if any): applied automatically on first
  daemon start; see `docs/admin/recovery.md` for rollback.

## Known issues

<!-- Outstanding bugs that didn't make this release. Delete if
     none. -->

- 

## Artifacts

| Artifact | Size | SHA256 |
|---|---|---|
| `nasd-linux-amd64` | <SIZE> | `<HASH>` |
| `nasd-linux-arm64` | <SIZE> | `<HASH>` |
| `kilasos-nasd_<version>_amd64.deb` | <SIZE> | `<HASH>` |
| `kilasos-nasd_<version>_arm64.deb` | <SIZE> | `<HASH>` |
| OCI image | — | `<DIGEST>` |

All artifacts are signed. Verify with the project release key:

```
gpg --recv-keys <KEY_FINGERPRINT>
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

The public key is also available at
`packaging/apt-repo/kilasos-release.asc`.

## Contributors

<!-- Pre-1.0 the project has a single author; this section is a
     placeholder for when the contributor pool grows. -->

- 

---

Full changelog: [`CHANGELOG.md`](../CHANGELOG.md#vXYZ---YYYY-MM-DD)
Release process: [`docs/RELEASE.md`](../docs/RELEASE.md)
Reporting issues: [`SECURITY.md`](../SECURITY.md) for vulnerabilities,
GitHub issues for everything else.
