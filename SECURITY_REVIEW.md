# SECURITY_REVIEW.md — gpappsoft/keyrad

Review date: 2026-09-09 · Branch: `8-support-secrets-settings-via-env` · Go 1.26.5 (local), module `go 1.25.5`

Scope: `main.go`, `config.go` (new ENV-override code), `radiussrv/`, `keycloak/`,
`ports/security/keyrad/`, `Dockerfile`, `keyrad.yaml`, `clients.conf`,
`docker-compose.example.yml`, `go.mod`/`go.sum`/`vendor/`, CI workflows.

Method: manual code review + `go vet`, `go test -race ./...`, and `govulncheck`
(`golang.org/x/vuln v1.8.0`).

---

## Executive summary

No **reachable** critical or high severity vulnerability was found in the default
configuration. The most important items are:

1. **Build toolchain carries known Go stdlib CVEs** (reachable via the outbound HTTPS
   Keycloak client) — fix is a toolchain bump, do it promptly (Medium).
2. **`ChallengeStateStore` has a lazy-init data race** and its `Get` does not enforce the
   TTL — two small correctness/security fixes proposed (Medium).
3. **`insecure_skip_tls_verify: true`** exposes the client secret and user credentials to a
   TLS MITM. It is off by default; a startup warning is proposed (Medium / conditional High).
4. Message-Authenticator is verified when present but **not enforced as mandatory** for
   non-EAP PAP; replay protection is absent; JWT roles are not signature-checked. These are
   defense-in-depth gaps consistent with the RFC/common deployments (Low).

Secret handling for the **new ENV mechanism is correct**: secrets are never logged in
plaintext (including debug), never appear in error messages, and there is no config-dump or
HTTP debug endpoint. The RADIUS client only ever receives generic `Access-Accept /
Access-Reject / Access-Challenge` responses.

| # | Area | Finding | Severity |
|---|------|---------|----------|
| 1 | Deps/toolchain | 4 reachable stdlib CVEs (go1.26.5, fixed in 1.26.6); CI pins 1.25.5 | Medium |
| 2 | Concurrency | `ChallengeStateStore` lazy init data race | Medium |
| 3 | Concurrency/OTP | `ChallengeStateStore.Get` ignores expiry (weakens TTL/single-use) | Medium |
| 4 | Keycloak TLS | `insecure_skip_tls_verify` enables credential MITM when on (no startup warning) | Medium |
| 5 | RADIUS | Message-Authenticator not mandatory for non-EAP; `--disable-message-authenticator` disables all verification | Low |
| 6 | RADIUS | No replay protection / Request-Authenticator never validated non-zero | Low |
| 7 | Keycloak | Roles JWT not signature/aud/exp verified (relies on TLS) | Low |
| 8 | Keycloak | `HasOTP` transient failure degrades to password-only attempt (availability) | Low |
| 9 | Secrets | Residual: a malformed YAML *near* the secret may surface a snippet in a parse error | Low |
| 10 | Docker | Build clones `main` + unpinned toolchain by default (supply chain) | Low |
| 11 | Compose | Secrets in `environment` visible via `docker inspect`/`/proc` (standard; ops caveat) | Info |
| 12 | Memory | Plaintext password cached in challenge sessions up to TTL | Info |

---

## 1. Secret handling (incl. new ENV override code)

### Verified positive
- `config.go` `logConfig()` logs `client_id`/`client_secret` only via `maskSecret()` and
  `appliedEnvVars` only contains variable **names**, never values. Same masked value used in
  both YAML and ENV paths (masking is applied after merge, so it is identical for both).
  Unit test `TestStartupLogsNeverContainPlaintextSecret` exercises the real `run()` startup
  path at debug level and asserts the plaintext never appears.
- Startup/validation errors name the **field** and the **env var name** but never the value
  (`config.go` `validate()`). The missing-required-secret failure prints e.g.
  `... client_secret is not set ... export KEYRAD_KEYCLOAK_CLIENT_SECRET` — no secret value,
  and the config path shown is the operator-supplied `-c` argument. Confirmed by
  `TestStartupFailsWhenRequiredSecretMissing` / `TestLoadConfigMissingRequiredFieldFailsClearly`.
- No HTTP server, debug endpoint, or config dump exists anywhere in production code
  (verified: no `http.ListenAndServe`, only RADIUS UDP).
- `keyrad.yaml`/`clients.conf` are never sent over the network and are only readable by the
  operator/container mount.

### Finding 9 — Low — Malformed YAML near a secret may embed a snippet in a parse error
- Affected: `config.go:28-38` (`LoadConfig` returns raw `yaml.Decode` error → `main.go`
  `log.Fatalf`).
- Detail: `gopkg.in/yaml.v3` type/syntax errors are usually content-free, but a malformed
  scalar can include the offending value in the message. If that value is the
  `client_secret`, a startup log/console line could expose it.
- Recommendation: wrap the decode error generically, e.g.
  `fmt.Errorf("failed to parse %s: %w", path, err)` is already generic at `main`; instead
  suppress the underlying snippet: return `fmt.Errorf("invalid yaml in %s (see file)", path)`
  and log the verbose error only when `-debug`. (Optional hardening; no reachable leak in the
  normal path.)

---

## 2. RADIUS protocol hardening

### Finding 5 — Low — Message-Authenticator is optional for non-EAP PAP
- Affected: `radiussrv/msgauth.go:47-67` (`VerifyMessageAuthenticator`, `case 0: return nil`
  when no EAP present), `radiussrv/server.go:117-123`, flag `--disable-message-authenticator`
  (`main.go`).
- Detail: MA is **verified when present** but MA-less PAP Access-Requests are accepted
  (RFC 2865 does not require MA for PAP; RFC 3579 requires it only for EAP, which is enforced:
  EAP without MA → rejected). `--disable-message-authenticator` removes even verification and
  MA generation on replies.
- Recommendation: keep the current RFC-compliant default, but consider a strict mode
  (e.g. env `KEYRAD_RADIUS_REQUIRE_MESSAGE_AUTHENTICATOR=1`) for networks where every NAS
  supports MA. Document clearly. Low risk today because forging an Access-Request still
  requires the shared secret (User-Password is MD5-encrypted with it).

### Finding 6 — Low — No replay protection; Request-Authenticator not validated
- Affected: `radiussrv/server.go:92-126` (worker), `radiussrv/handle.go` challenge flow.
- Detail: RADIUS/UDP has no transport freshness. A captured, valid Access-Request can be
  replayed verbatim (same Request Authenticator + ID) and will be re-authenticated. The
  challenge `State` attribute mitigates the OTP second step (random 128-bit, single use via
  `Delete`), but first-step PAP re-authentication is not rate-limited. The Request
  Authenticator is never checked for being all-zero, which would weaken password encryption
  for a misbehaving NAS.
- Recommendation (hardening): keep a small per-source-IP cache of recent
  `(Request-Authenticator, ID)` values and drop duplicates; reject all-zero Request
  Authenticators. Optionally rate-limit authentication attempts per source IP.

---

## 3. Keycloak integration

### Finding 4 — Medium (conditional High) — `insecure_skip_tls_verify` disables cert validation without a warning
- Affected: `main.go:178-189` (`getHTTPClient`), `keyrad.yaml` (`insecure_skip_tls_verify`),
  ENV `KEYRAD_KEYCLOAK_INSECURE_SKIP_TLS_VERIFY` (`config.go`).
- Detail: When enabled, the client secret and user passwords are POSTed to `token_url` over a
  TLS connection whose peer certificate is not verified → a network MITM can harvest every
  credential. This is an operator opt-in (default `false`), but the server logs nothing to
  flag it.
- Recommendation: emit a `Warn` at startup whenever it is enabled (patch proposed below);
  prefer a private CA and set `true` only for self-signed lab setups.

### Finding 7 — Low — Roles token not signature/aud/exp verified
- Affected: `keycloak/keycloak.go:129-153` (`AuthenticateUser`), `extractRolesFromJWT`
  (`keycloak.go:156-177`).
- Detail: `access_token` from the password-grant response is base64-decoded (middle segment)
  and roles/groups/scopes are trusted **without** verifying the JWT signature, `aud`, issuer,
  or `exp`. The token is obtained server-side directly from Keycloak over the (optionally
  unverified) TLS channel, so this is acceptable in the default configuration; with
  `insecure_skip_tls_verify: true` a MITM could forge roles and thereby influence
  `scope_radius_map`-driven attributes in Access-Accept.
- Recommendation: if strictness is desired, verify the JWT signature against Keycloak's JWKS
  and check `aud`/`exp` (adds a dependency). At minimum, do not enable
  `insecure_skip_tls_verify` in production.

### Finding 8 — Low — `HasOTP` failures degrade availability
- Affected: `radiussrv/handle.go:78-93`; `keycloak/keycloak.go:66-106` (admin token cache),
  `190-...` (`HasOTP`).
- Detail: on a transient admin-token/API error, `HasOTP` returns `false` + error; the handler
  then tries a plain password grant. Real OTP users are rejected by Keycloak (no bypass — the
  conditional-OTP requirement still applies at the token endpoint), but legitimate OTP
  logins fail during Keycloak API hiccups. No retry/backoff on a stale cached admin token.
- Recommendation: acceptable; optionally retry `GetAdminToken` once on 401 before failing.

### ReDoS check — Not vulnerable
- `scope_radius_map` regex keys are compiled with Go `regexp` (RE2) → linear-time matching, no
  catastrophic backtracking. Patterns come from trusted config (operator), not from users, and
  are matched against short role/group strings from Keycloak. `compileScopeRules`
  (`radiussrv/attributes.go:36-57`) compiles once at startup. No ReDoS exposure.

---

## 4. Concurrency

### Finding 2 — Medium — Data race on lazy `ChallengeStateStore` initialization
- Affected: `radiussrv/handle.go:176-184`; workers run `HandlePacket` concurrently
  (`radiussrv/server.go:66-73`).
- Detail: the store is created lazily *inside* worker goroutines:
  ```go
  if s.ChallengeStateStore == nil {
      s.ChallengeStateStore = NewChallengeStateStore()   // racy write on Server
  }
  s.ChallengeStateStore.Set(state, ChallengeSession{...})
  ```
  Two concurrent first-time OTP challenges read `nil`, both create a store, and the second
  assignment can clobber the first — the first session's `State` then cannot be found on the
  OTP reply (silent failure) and the `-race` detector flags a genuine data race on the
  `Server` field. Each `NewChallengeStateStore()` also leaks a cleanup goroutine if its store
  is orphaned.
- Recommendation: initialize the store once in `ListenAndServe` **before** workers start
  (patch proposed below); the lazy branch can then be removed or kept as a fallback.

### Finding 3 — Medium — `Get` does not enforce the session TTL
- Affected: `radiussrv/challenge.go:53-63` (`Get`), `defaultChallengeSessionTTL`,
  `evictExpired` (runs every 60s).
- Detail: `Get` returns the stored session regardless of `expires`. Because eviction runs only
  once per minute, a captured `State` value remains usable up to ~TTL+60s instead of the
  documented 5 minutes. The doc comment claims Get "deletes the entry when expired" but it
  does not. Sessions also store the plaintext password in memory for that window.
- Recommendation: check expiry inside `Get` and delete-on-access (patch proposed below).

### Verified positive
- `KeycloakAPI` admin-token cache guarded by `adminMu`; challenge store map guarded by
  `sync.RWMutex` for Set/Delete/evict; `scopeRules` compiled once before workers; `Clients`
  map is read-only after startup (`resolveClientSecret` only reads). `go test -race ./...`
  is clean for the existing test suite.

---

## 5. Input validation & packet parsing

### Verified positive
- UDP reads bounded to a 4096-byte buffer (`radiussrv/server.go:84`) — RADIUS max packet
  size. Larger/truncated datagrams are rejected by the vendored `radius.Parse`
  (`vendor/layeh.com/radius/packet.go:51` checks `len(b) < length`).
- Backpressure: `s.jobs` is a buffered channel (128); when full, the read loop blocks and the
  kernel drops packets — no unbounded queue/memory growth.
- Attribute walking in `msgauth.go` (`containsAttrType`, `messageAuthenticatorValueOffsets`)
  bounds-checks `attrLen` (`attrLen < 2 || pos+attrLen > end`) before every step — no panic.
- The server calls `radius.Parse` **before** `VerifyMessageAuthenticator`, so a spoofed length
  field cannot drive `VerifyMessageAuthenticator`'s `packet[:n]` slice past the buffer.

### Finding 13 — Low (defensive) — `radiusPacketLength` does not bound `n` by `len(packet)`
- Affected: `radiussrv/msgauth.go:230-237` (`radiusPacketLength`), used by
  `VerifyMessageAuthenticator`, `finalizeMessageAuthenticatorInPlace`.
- Detail: it enforces `20 ≤ n ≤ 4096` but not `n ≤ len(packet)`. Not reachable via the server
  (Parse runs first), but a future caller passing an untrusted, truncated buffer would panic
  on `packet[:n]`. Cheap to harden (patch proposed below).

---

## 6. Dependency security

`govulncheck` (vuln DB current as of review date) — command:
`GOFLAGS=-mod=vendor govulncheck ./...`

> "Your code is affected by 4 vulnerabilities from the Go standard library. This scan also
> found 2 vulnerabilities in packages you import and 2 vulnerabilities in modules you
> require, but your code doesn't appear to call these vulnerabilities."

### Finding 1 — Medium — Reachable Go stdlib CVEs (build toolchain)
Affected (all fixed in Go 1.26.6):
- `GO-2026-6090` crypto/tls — post-handshake message limits (reached via `http.Client.Do`
  to Keycloak).
- `GO-2026-6218` net/url — quadratic `resolvePath` (reached via URL parse on requests).
- `GO-2026-5972` encoding/asn1 — recursion depth (reached via TLS).
- `GO-2026-5026` net/http — ASCII-only Punycode rejection (reached via Keycloak requests).

Locations: `main.go:78`, `keycloak/keycloak.go:135,205,209-210`; **current local toolchain is
go1.26.5**, CI pins `go-version: '1.25.5'` (`.github/workflows/go.yml:23`), `go.mod` says
`go 1.25.5`, and the `Dockerfile` builder `apk add ... go` (unpinned, whatever wolfi ships).

Recommendation: build and test with a patched toolchain (≥ 1.26.6, or the newest patched
1.25.x). Concretely: bump CI `go-version` to a patched line, add `toolchain go1.26.6` to
`go.mod`, and pin the builder's Go (e.g. builder `FROM golang:1.26.6-alpine` or install a
specific wolfi `go` version). No third-party module reachable vulns found (zap/multierr/
yaml.v3/layeh radius findings are non-reachable per govulncheck).

---

## 7. Dockerfile / Compose

### Verified positive
- Final image runs as **non-root** `USER 65532:65532`; only `EXPOSE 1812/udp`; binary is
  `root:root` 0555. The runtime image ships **no** `keyrad.yaml`/`clients.conf` (config is
  mounted), so no secrets are baked into image layers.
- `docker-compose.example.yml` injects `KEYRAD_KEYCLOAK_CLIENT_ID/SECRET` via an
  `environment:` block (`${VAR:?}` fail-fast); the mounted `keyrad.yaml` keeps `< >`
  placeholders. `.gitignore` already ignores `.env`. Env-based secrets are **not** in image
  layers or build args.

### Finding 11 — Info — env secrets visible to `docker inspect` / container root
- Detail: any principal able to run `docker inspect`/`docker compose config`, or root inside
  the container, can read `KEYRAD_KEYCLOAK_CLIENT_SECRET` from the environment. This is
  standard for env-based secrets and is exactly the trade-off of ENV-over-YAML. In
  multi-tenant K8s, prefer a mounted `Secret` volume or a secrets manager.
- Recommendation: document; ensure `docker.sock` access and the compose `.env` file are
  restricted to trusted admins.

### Finding 10 — Low — Build-time supply chain not pinned
- Affected: `Dockerfile` — `ARG VERSION=main` then `git clone --branch ${VERSION}` from GitHub
  at build time; builder base + `go` version unpinned.
- Recommendation: default `VERSION` to the latest release tag, pin the builder base by digest,
  and pin the Go version (see Finding 1). Image signing/SBOM already exist via the
  `docker-publish.yml` workflow (good).

---

## 8. Error handling / information disclosure

### Verified positive
- The RADIUS server only ever sends `Access-Accept`, `Access-Reject`, or `Access-Challenge`
  (confirmed across `radiussrv/handle.go`). Internal errors, HTTP statuses, stack traces, and
  parse errors are logged (mostly at `Debug`) but **never** transmitted to the NAS.
- The new **missing-required-secret startup failure does not leak the expected secret value
  or internal paths**: the message contains the field name, the env var name, and the
  operator-supplied config path only. Env var *names* (e.g. `KEYRAD_KEYCLOAK_CLIENT_SECRET`)
  are identifiers, not secrets. No stack trace is printed (single `log.Fatalf("startup error:
  %v", err)`), and this happens before the UDP socket is bound, so no RADIUS client can read
  it either.

---

## Applied hardening patches (2026-09-09)

No finding is a reachable critical/high in the default config, so the following are
recommended hardening patches for the Medium items. All are small and behavior-preserving.
Patches A–D below have been **applied and validated** (`go build`, `go vet`,
`go test ./...`, `go test -race ./...` all green). Finding 2 is resolved by creating the
store in `ListenAndServe`; the lazy branch in `handle.go` remains only as a fallback for
direct (test) callers.

### Patch A — `radiussrv/server.go`: create the challenge store once, before workers start (Finding 2)
```diff
 	defer conn.Close()
 
+	// Create the challenge store once, before workers start, so concurrent OTP
+	// challenge requests can never race on lazy initialization (handle.go used to
+	// initialize it inside worker goroutines).
+	if s.ChallengeStateStore == nil {
+		s.ChallengeStateStore = NewChallengeStateStore()
+	}
+
 	for i := 0; i < workerCount; i++ {
 		go s.worker()
 	}
```

### Patch B — `radiussrv/challenge.go`: enforce TTL inside `Get` (Finding 3)
```diff
-// Get returns the session for state if present and not expired, and deletes the entry when expired.
+// Get returns the session for state if present and not expired. An expired entry is
+// deleted on access so the TTL is enforced even between cleanup ticks.
 func (s *ChallengeStateStore) Get(state string) (ChallengeSession, bool) {
-	s.mu.RLock()
-	defer s.mu.RUnlock()
+	s.mu.Lock()
+	defer s.mu.Unlock()
 	e, ok := s.m[state]
 	if !ok {
 		return ChallengeSession{}, false
 	}
+	if time.Now().After(e.expires) {
+		delete(s.m, state)
+		return ChallengeSession{}, false
+	}
 	return e.sess, true
 }
```

### Patch C — `main.go` (`run`): warn when TLS verification is disabled (Finding 4)
```diff
 	// Logs only masked credentials and env var *names* - never secret values.
 	cfg.logConfig(logger, len(radiusSecretOverrides))
 
+	// Warn loudly when TLS verification is disabled: with this on, a network MITM can
+	// read the client secret and user passwords sent to Keycloak.
+	if cfg.InsecureSkipTLSVerify {
+		logger.Warn("insecure_skip_tls_verify is enabled: TLS certificate verification to Keycloak is DISABLED",
+			zap.String("token_url", cfg.TokenURL))
+	}
+
 	return srv.ListenAndServe(listenAddr)
 }
```

### Patch D — `radiussrv/msgauth.go`: defensive length bound (Finding 13)
```diff
 	n := int(binary.BigEndian.Uint16(packet[2:4]))
-	if n < 20 || n > radius.MaxPacketLength {
+	if n < 20 || n > radius.MaxPacketLength || n > len(packet) {
 		return 0, errInvalidPacketLength
 	}
```

### Recommended (no code change required)
- Bump build toolchain to a patched Go (≥ 1.26.6) in `.github/workflows/go.yml`, `go.mod`
  (`toolchain`), and the `Dockerfile` builder (Finding 1).
- Consider an opt-in strict Message-Authenticator mode and per-source replay cache
  (Findings 5/6).

---

## How to verify

```sh
go build ./... && go vet ./... && go test ./...          # all green
go test -race ./...                                       # clean
GOFLAGS=-mod=vendor govulncheck ./...                     # stdlib findings below
go install golang.org/x/vuln/cmd/govulncheck@latest       # if not installed
```

_This report reflects a point-in-time review and should be re-run after dependency or
toolchain changes._
