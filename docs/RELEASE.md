# Release process

This document describes how KilasOS releases are versioned, cut, and
distributed. The step-by-step checklist lives at
[`docs/release-checklist.md`](release-checklist.md); this file
explains the policy behind it.

## Versioning

KilasOS follows [Semantic Versioning](https://semver.org/) with one
pre-1.0 convention:

- **Pre-1.0** (`0.x.y`): the minor version (`x`) may include breaking
  changes. The patch version (`y`) is reserved for fixes and
  non-breaking additions. Release candidates use the `-rcN` suffix:
  `0.45.0-rc1`, `0.45.0-rc2`, ...
- **Post-1.0** (`x.y.z`): strict semver. Breaking changes bump major;
  features bump minor; fixes bump patch.

The current pre-1.0 series is `0.45.x`. The `0.45.0` final release
will close out Phase 4 of the
[`coordinator/NEXT-STAGE-PLAN.md`](../coordinator/NEXT-STAGE-PLAN.md).

## Release cadence

| Channel | Cadence | Audience |
|---|---|---|
| `rcN` (release candidate) | Weekly during beta phases | Closed beta cohort |
| `0.x.y` (patch) | As needed for fixes | All users |
| `0.x.0` (minor) | Monthly | All users |
| `1.0.0` and later | Quarterly minor; ad-hoc patch | All users |

A release is only cut from `master`. Hotfix branches (`hotfix/X.Y.Z`)
are allowed for critical fixes to a published version when `master`
already contains incompatible changes.

## Branch and tag conventions

- `master` — always releasable. CI must pass before merge.
- `hotfix/<version>` — branched from the published tag for emergency
  fixes; merged back to `master` after release.
- Tags are signed (`git tag -s vX.Y.Z -m "..."`) using the
  maintainer's GPG release key. The public key is published at
  `packaging/apt-repo/kilasos-release.asc` and at the project
  website.

## Cutting a release

Follow [`docs/release-checklist.md`](release-checklist.md). The
short version:

1. Update `CHANGELOG.md`: promote `[Unreleased]` content to the new
   version section; reset `[Unreleased]` to empty group headers.
2. Bump `version:` in `packaging/nfpm.yaml` and any other
   version-stamped files.
3. Run `bash scripts/release.sh` (or `--dry-run` first) to build
   and verify all artifacts.
4. `git tag -s vX.Y.Z -m "Release vX.Y.Z"` and push (when remote is
   live; currently local-only per carryover #9).
5. The `release.yml` workflow attaches binaries, `.deb`s, the OCI
   image, and signed checksums to the GitHub release.
6. Write release notes from
   [`.github/release-notes-template.md`](../.github/release-notes-template.md),
   sourcing bullets from the just-promoted CHANGELOG section.

## Artifacts published per release

- `bin/nasd-linux-amd64`, `bin/nasd-linux-arm64`
- `kilasos-nasd_<version>_amd64.deb`, `kilasos-nasd_<version>_arm64.deb`
- `ghcr.io/<org>/nasd:<version>` multi-arch image
- `SHA256SUMS` with detached signature (`SHA256SUMS.asc`)

apt repo metadata at `packaging/apt-repo/` is regenerated on every
release; see [`packaging/apt-repo/README.md`](../packaging/apt-repo/README.md).

## Pre-1.0 caveats

- Schema migrations are forward-only; downgrades require restoring
  from backup.
- WebUI behavior may change between minor releases — operators should
  read the release notes before upgrading.
- The OCI image base may change without a major bump pre-1.0.
- API endpoints documented in [`docs/api/openapi.yaml`](api/openapi.yaml)
  are considered stable for the duration of a minor version.

## Rollback

If a release introduces a critical bug:

1. Document the regression in `CHANGELOG.md` under a new patch entry.
2. Hold the broken version in apt with `apt-mark hold kilasos-nasd`
   (operator-side advice in the release notes).
3. Cut a patch release from a hotfix branch that reverts the
   offending commit(s).
4. Yank instructions for OCI: re-tag the previous good image as the
   current channel tag; document in release notes.
5. Do NOT delete or re-tag the broken release — leave it in place so
   the upgrade path is auditable. The successor release supersedes it.

## Security releases

Security fixes follow [`SECURITY.md`](../SECURITY.md). High-severity
fixes ship as a patch release immediately after coordinated
disclosure; the release note marks the entry with `**SECURITY**` and
references the advisory.
