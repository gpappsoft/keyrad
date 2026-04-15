# Changelog

All notable changes to this project will be documented in this file.

## [2.0.1] - 2026-04-15

### Added
- Multi-stage `Dockerfile` using `cgr.dev/chainguard/wolfi-base`; builder clones the repo from GitHub and compiles a static binary (`CGO_ENABLED=0`), final image runs as the built-in `nonroot` user (UID/GID 65532)
- `VERSION` build arg in `Dockerfile` to select a specific release tag at build time (defaults to `main`)
- `docker-publish.yml` GitHub Actions workflow: builds and pushes multi-arch images (`linux/amd64`, `linux/arm64`) to Docker Hub and GHCR, signs images with cosign, generates SBOM and provenance attestations
- `go.yml` GitHub Actions workflow: builds, tests, and publishes a release binary artifact — triggered only on version tags

### Changed
- `go.yml` trigger changed from branch pushes/PRs to tag-only (`[0-9].[0-9].[0-9]`); release steps gated with `if: startsWith(github.ref, 'refs/tags/')`
- `docker-compose.example.yml` image updated to `gpappsoft/keyrad:latest`
- Version bumped to `2.0.1`

---

## [2.0.0] - 2026-04-14

### Added
- `radiussrv` package: split server logic into focused modules (`handle.go`, `msgauth.go`, `attributes.go`, `utils.go`, `types.go`)
- Message-Authenticator support (RFC 2869)
- Calling-Station-Id attribute support
- `RLock` for challenge store reads; garbage collection handles old challenge cleanup
- RADIUS password decryption via the radius package
- CIDR matching with longest-prefix selection
- Docker support: `Dockerfile`, `.dockerignore`, `docker-compose.example.yml`
- `makefile` for build automation
- Comprehensive test suites for all new packages

### Changed
- Major refactor: monolithic `main.go` / `server.go` decomposed into `radiussrv` sub-packages
- Keycloak client rewritten with improved error handling and test coverage
- `request_id` moved to `utils.go`
- Default IDE directory and test fixtures added

### Removed
- `auth/otp.go` — OTP logic moved into the keycloak package

---

## [1.1.1] - 2026-04-05

### Fixed
- Version bump follow-up after 1.1.0 security release

---

## [1.1.0] - 2026-04-05

### Security
- **Race condition** — added `sync.RWMutex` to `ChallengeStateStore`; all Get/Set/Delete operations are now synchronized
- **Secret logging** — removed RADIUS shared secrets, passwords, OTPs, client secrets, and response bodies from log output
- **OTP bypass** — passwords ≤ 6 characters are now rejected instead of authenticating with an empty OTP
- **Auth on parse error** — `AuthenticateUser` now returns `false` + error on JSON unmarshal failure instead of `true`
- **Predictable state** — `GenerateRandomState` returns an error instead of falling back to deterministic bytes
- **Ignored errors** — `http.NewRequest` errors are now checked and propagated

### Changed
- Expanded README with configuration reference and security notes
- Updated `keyrad.yaml` configuration options

### Removed
- MS-CHAPv2 feature (`radiussrv/mschapv2.go`) removed pending re-evaluation

---

## [1.0.0] - 2026-01-13

### Added
- Refactored RADIUS server into `radiussrv` package (`server.go`, `challenge.go`)
- Keycloak authentication client (`keycloak/keycloak.go`)
- Auth types (`auth/types.go`)
- Debug mode and extended configuration options
- MS-CHAPv2 stub

---

## [0.1.0] - 2026-01-11

### Added
- Initial release
- Go-based RADIUS server authenticating users against Keycloak
- Password and OTP (TOTP) authentication flows
- `keyrad.yaml` configuration file
- `clients.conf` for RADIUS client definitions
