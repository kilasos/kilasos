# Contributing to KilasOS

## Build prerequisites

- **Go 1.23+** — install from [go.dev](https://go.dev/dl/)
- **Linux development host** — the daemon shells out to Linux binaries
  (`zfs`, `zpool`, `docker`, etc.) and will not build/test on macOS or
  Windows without a Linux VM
- **ZFS** — for full integration testing, the host (or a Linux VM) must
  have the ZFS kernel module and userspace tools installed
- **Docker** — for app-catalog deployment tests (optional; most tests
  pass without it)

## Quick start

```bash
# Build the daemon binary
bash scripts/build.sh

# Run tests
bash scripts/test.sh

# Smoke-test against the live VM (requires access)
bash coordinator/smoke-tests.sh
```

## Commit message convention

We use conventional-commit prefixes:

| Prefix | Use for |
|--------|---------|
| `feat` | New user-facing feature |
| `fix` | Bug fix |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `docs` | Documentation only |
| `test` | Adding or updating tests |
| `chore` | Build process, CI, repo hygiene |
| `ci` | CI configuration changes |

Examples:
```
feat(storage): add per-pool trash directories
fix(files): close folder-zip TOCTOU
docs(api): fill OpenAPI spec for /storage endpoints
```

## Pull request flow

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Make your changes, following the coding style below.
4. Run `bash scripts/build.sh` and `bash scripts/test.sh` locally.
5. Push and open a PR.
6. A reviewer will check build/vet/smoke before merging.

## Coding style

- **`go fmt`** — run before every commit. CI enforces it.
- **`golangci-lint`** — the `.golangci.yml` config covers `gofmt`,
  `govet`, `staticcheck`, `ineffassign`, `unused`.
- **No comments explaining WHAT the code does** — the code is the
  specification. Comments should explain WHY when the reason is
  non-obvious (e.g. "must use RunPriv, not RunPlain, because this
  writes to the kernel's WireGuard netlink socket").
- **Pass `ctx context.Context`** as the first parameter to every
  provider method. Thread it into RunPriv/RunPlain, never use
  `context.Background()` unless the caller genuinely has no context.
- **Audit-log** every destructive handler (POST/PUT/DELETE/PATCH) with
  `audit.LogEnriched(...)` on BOTH the success path and every error
  path. The audit middleware covers the broad stroke; the handler's
  explicit calls carry the detail (resource, action name, caller).

## Project structure

```
cmd/nasd/           — daemon entrypoint
internal/
  api/              — chi router, handlers, middleware, static UI
  appcatalog/       — 32-template app catalog + deploy manager
  audit/            — audit log ring buffer + persistence
  auth/             — user store, TOTP, WebAuthn, OIDC, LDAP, API keys
  monitor/          — health poller + alert raising + backup tracking
  notify/           — SMTP mailer
  scheduler/        — snapshot/scrub/replication scheduler
  storage/          — Provider interface + linuxProvider + RunPriv + tools
  sysupdate/        — .deb update manager
  wol/              — Wake-on-LAN store
  zfssend/          — ZFS send/receive replication engine
coordinator/        — smoke tests, backlogs, prompts, session plans
docs/               — admin guide, API spec, operator playbook, security
packaging/          — nfpm, Dockerfile, systemd unit, apt-repo layout
scripts/            — build, test, lint, coverage, release scripts
```
