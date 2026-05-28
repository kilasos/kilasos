# Release Checklist

Checklist for cutting a new KilasOS release.

## Pre-release

- [ ] `git checkout master` — ensure on latest master
- [ ] `git pull origin master` — sync with upstream
- [ ] `go test ./...` — all tests pass
- [ ] `go vet ./...` — no vet findings
- [ ] `scripts/lint.sh` — lint clean (or no new warnings)
- [ ] `bash coordinator/smoke-tests.sh` — smoke passes (126/126 default, 153/153 `--all`)
- [ ] `bash coordinator/smoke-tests.sh --all` — full endpoint sweep
- [ ] `git diff --stat origin/master` — review pending changes

## Version bump

- [ ] Update `VERSION` constant in `cmd/nasd/main.go` or wherever version is baked
- [ ] Update `packaging/nfpm.yaml` — bump `version:` field
- [ ] Update `packaging/changelog.Debian.gz` — add new entry
- [ ] Run `bash scripts/build-multiarch.sh` — verify both arches compile
- [ ] Run `bash scripts/build-deb.sh` (if nfpm installed) — verify .deb packaging
- [ ] Commit: `git commit -am "chore: bump version to vX.Y.Z"`

## Tag and push

- [ ] `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
- [ ] `git push origin master`
- [ ] `git push origin vX.Y.Z`

## Post-release (CI handles these automatically via `.github/workflows/release.yml`)

- Binaries for linux/amd64 and linux/arm64 are attached to the GitHub release
- .deb packages for both architectures are attached
- OCI multi-arch image is pushed to `ghcr.io/kilas/kilasos/nasd`
- SHA256SUMS and GPG signature are generated

## Post-release manual steps

- [ ] Verify release artifacts downloaded correctly from GitHub
- [ ] Verify `ghcr.io/kilas/kilasos/nasd:latest` pulled correctly
- [ ] Update documentation if API surface changed
- [ ] Announce in relevant channels (Discord, Reddit, mailing list)

## GPG signing (if not automated in CI)

- [ ] `gpg --detach-sign --armor bin/SHA256SUMS` — sign checksums
- [ ] Upload `bin/SHA256SUMS.asc` to the release
- [ ] Verify: `gpg --verify bin/SHA256SUMS.asc bin/SHA256SUMS`
- [ ] Verify: `sha256sum -c bin/SHA256SUMS`

## Rollback procedure

If a critical bug is discovered post-release:

1. `git tag -d vX.Y.Z` (local)
2. `git push origin :refs/tags/vX.Y.Z` (delete remote tag)
3. Delete the GitHub release
4. Delete the OCI image tags from ghcr.io
5. Fix the bug, bump patch version, re-tag
