# keyrad: Keycloak RADIUS Server

A Go-based RADIUS server that authenticates users against Keycloak, supporting password and OTP (TOTP) flows.

![Keyrad](/assets/keyrad.png)

Features include:
- Challenge-response for OTP
- YAML-based Keycloak and RADIUS config
- FreeRADIUS-style `clients.conf` for client secrets
- Optional Message-Authenticator
- Scope/group-to-RADIUS attribute mapping (with regexp support)
- **Vendor-Specific Attributes (VSA):** Return vendor-specific attributes (e.g. MikroTik, Cisco, Ubiquiti) in Access-Accept responses based on user roles, groups, or scopes
- **Configurable OTP mode:** Use standard challenge-response or <password><otp> style
- **Configurable OTP challenge message** via `otp_challenge_message` in config
- **Asynchronous/multi-request support:** Multiple RADIUS requests are handled concurrently for high performance

## Requirements
- Go 1.18+
- A running Keycloak instance (tested with Keycloak 21+)

## Compilation
```bash
git clone https://github.com/gpappsoft/keyrad.git
cd keyrad
go build -o keyrad main.go
```

### FreeBSD / OPNsense

OPNsense is based on FreeBSD, so the binary is built the same way. You have two options:

**Option A — Build natively on FreeBSD (or an OPNsense box):**
```sh
# Install Go and git (FreeBSD pkg)
pkg install -y go git

git clone https://github.com/gpappsoft/keyrad.git
cd keyrad
go build -o keyrad main.go
```

> On OPNsense the package repository is locked down by default. Either build on a
> separate FreeBSD machine matching your OPNsense major version (recommended for
> appliances), or temporarily enable the FreeBSD repo to install `go`/`git`.

**Option B — Cross-compile from Linux/macOS** (no Go toolchain needed on the firewall):
```sh
# Match the OPNsense architecture: amd64 for most x86 deployments, arm64 for ARM
GOOS=freebsd GOARCH=amd64 go build -o keyrad-freebsd-amd64 main.go
```

Then copy the binary to the firewall and make it executable:
```sh
scp keyrad-freebsd-amd64 root@opnsense:/usr/local/bin/keyrad
ssh root@opnsense chmod +x /usr/local/bin/keyrad
```

Place `keyrad.yaml` and `clients.conf` alongside the binary (e.g. `/usr/local/etc/keyrad/`)
and start it with `keyrad -c /usr/local/etc/keyrad/keyrad.yaml -r /usr/local/etc/keyrad/clients.conf`.
To run it persistently, add an rc.d service or a cron `@reboot` entry. The produced binary is
statically linked and has no runtime dependencies.

## Configuration

### 1. Keycloak Setup
- **Create a confidential client** (e.g. `radius-client`) in your realm.
  - Enable `Service Accounts Enabled`.
  - Enable `Direct Access Grants`.
  - Set `Valid Redirect URIs` to `*` (or as needed).
- **Assign roles to the client service account**:
  - Go to `Service Account Roles` for your client.
  - Assign at least:
    - `view-users`
    - `query-users`
    - `view-realm`
    - `view-authorization`
- **User setup**:
  - Users must have credentials set for password or OTP (TOTP) as desired.
  - To use OTP, users must enroll an OTP device in Keycloak.

### 2. keyrad.yaml
See `keyrad.yaml` for a full example.

- To customize the OTP challenge message, add `otp_challenge_message: "Your custom message"` to `keyrad.yaml`.
- The server supports multiple concurrent RADIUS requests (async worker pool, default 8 workers).

### 3. clients.conf
FreeRADIUS-style client definitions. See `clients.conf` for the format.

### 4. Scope-to-RADIUS Attribute Mapping

Map Keycloak realm roles, groups, or OAuth2 scopes to RADIUS attributes returned in Access-Accept responses. Supports both standard RADIUS attributes and Vendor-Specific Attributes (VSA).

After successful authentication, keyrad extracts the user's roles, groups, and scopes from the Keycloak JWT access token and matches them against the `scope_radius_map` keys.

#### Configuration format

```yaml
scope_radius_map:
  # Exact match against role/group/scope name
  admin:
    - attribute: 6        # Service-Type
      value: "6"          # Administrative-User
      value_type: integer

  # Multiple attributes per scope
  vpn:
    - attribute: 8        # Framed-IP-Address
      value: "10.0.0.1"
      value_type: ipaddr
    - vendor: 14988       # MikroTik Vendor ID
      attribute: 3        # Mikrotik-Group
      value: "full"

  # Vendor-Specific Attributes (VSA)
  wifi:
    - vendor: 14988       # MikroTik
      attribute: 8        # Mikrotik-Rate-Limit
      value: "10M/10M"

  # Regex matching with "re:" prefix
  re:^group_.*:
    - attribute: 11       # Filter-Id
      value: "group-member"
```

#### Attribute fields

| Field        | Required | Description                                                        |
|--------------|----------|--------------------------------------------------------------------|
| `vendor`     | No       | IANA vendor ID. Omit or set to `0` for standard RADIUS attributes. |
| `attribute`  | Yes      | Attribute type number.                                             |
| `value`      | Yes      | Attribute value.                                                   |
| `value_type` | No       | Encoding type: `string` (default), `integer`, or `ipaddr`.        |

#### Common vendor IDs

| Vendor   | ID    | Reference                                                    |
|----------|-------|--------------------------------------------------------------|
| Cisco    | 9     | [Cisco VSA documentation](https://www.cisco.com)             |
| Microsoft| 311   | RFC 2548                                                     |
| MikroTik | 14988 | [MikroTik RADIUS dictionary](https://help.mikrotik.com/docs/spaces/ROS/pages/328097/RADIUS) |
| Ubiquiti | 41112 | Ubiquiti RADIUS dictionary                                   |

#### Keycloak setup for scope/group matching

For roles and scopes, no extra Keycloak configuration is needed -- they are included in the JWT by default.

For **group-based matching**, add a "groups" protocol mapper to your Keycloak client:
1. Go to your client's **Client Scopes** > **Dedicated scope** > **Add mapper** > **By configuration** > **Group Membership**.
2. Set **Token Claim Name** to `groups`.
3. Disable **Full group path** if you want short group names.

### 5. Secrets via Environment Variables

For Docker/Kubernetes deployments you can keep `keyrad.yaml` and `clients.conf` free of plaintext
credentials by supplying security-sensitive values through environment variables instead. Values
are merged at startup with **ENV taking precedence over YAML** (`KEYRAD_` prefix, followed by
section and field in SCREAMING_SNAKE_CASE). If `client_id` or `client_secret` is set in neither
YAML nor ENV (empty, or the `<>` placeholder shipped in the sample), **keyrad refuses to start**
with a clear error instead of running with an empty credential.

| YAML key (or file)              | Environment variable                        | Description                                                        |
|---------------------------------|---------------------------------------------|--------------------------------------------------------------------|
| `client_id`                     | `KEYRAD_KEYCLOAK_CLIENT_ID`                 | Keycloak confidential client ID (required).                       |
| `client_secret`                 | `KEYRAD_KEYCLOAK_CLIENT_SECRET`             | Keycloak client secret (required).                                 |
| `token_url`                     | `KEYRAD_KEYCLOAK_TOKEN_URL`                 | OIDC token endpoint URL.                                           |
| `realm`                         | `KEYRAD_KEYCLOAK_REALM`                     | Keycloak realm name.                                               |
| `api_url`                       | `KEYRAD_KEYCLOAK_API_URL`                   | Keycloak Admin REST API base URL.                                  |
| `insecure_skip_tls_verify`      | `KEYRAD_KEYCLOAK_INSECURE_SKIP_TLS_VERIFY`  | Set to `true`/`false` to skip TLS verification.                    |
| `clients.conf` per-client secret | `KEYRAD_RADIUS_CLIENT_SECRET_<CLIENT_KEY>`  | Overrides the shared secret of one RADIUS client (see below).      |

**RADIUS client shared secrets** (`clients.conf`) can also be injected per client. `<CLIENT_KEY>`
is the client block's `ipaddr` (or its name when `ipaddr` is absent) with `.`, `:`, `/`, `-` and
spaces replaced by `_`. Clients can only be *defined* in `clients.conf`; the environment only
*overrides* their secret. For example a `client 10.0.0.1` block is overridden by
`KEYRAD_RADIUS_CLIENT_SECRET_10_0_0_1`, and `client nas-1` by `KEYRAD_RADIUS_CLIENT_SECRET_NAS_1`.

```bash
# keyrad.yaml can keep client_id/client_secret empty or as "<>"; ENV wins.
export KEYRAD_KEYCLOAK_CLIENT_ID=radius-client
export KEYRAD_KEYCLOAK_CLIENT_SECRET=my-very-long-client-secret
./keyrad -c keyrad.yaml -r clients.conf
```

> **Security note**: secrets are never logged. At startup keyrad logs only the **masked** form
> (first/last two characters, e.g. `ab****yz`) and the **names** of the environment variables
> that were applied — never the plaintext value, not even at debug level.

See `docker-compose.example.yml` for a compose file that injects the credentials via an
`environment:` block rather than a plaintext secret in the mounted YAML.

## Usage

### Start the server
```bash
./keyrad -c keyrad.yaml -r clients.conf
```
- Use `--disable-message-authenticator` to disable Message-Authenticator checks (for legacy clients).
- Use `--disable-challenge-response` to allow OTP users to authenticate with `<password><otp>` in the User-Password field (no challenge-response).
- Use `--version` to print version and author.

### Test with radtest
```bash
radtest testuser password 127.0.0.1 0 test
```
- For OTP (default): Enter password first, then respond to challenge with OTP code (customizable message).
- For OTP with `--disable-challenge-response`: Enter `<password><otp>` as the password (e.g. `mypassword123456`).

## Advanced Features
- **Challenge-response**: Standard RADIUS Access-Challenge for OTP, or disable for legacy OTP style.
- **Configurable OTP challenge message**: Set `otp_challenge_message` in your config for custom challenge text.
- **Scope/group mapping**: Map Keycloak realm roles, groups, or OAuth2 scopes to RADIUS attributes. Supports regexp keys (e.g. `re:^group_.*`).
- **Vendor-Specific Attributes (VSA)**: Return vendor-specific attributes in Access-Accept based on user roles/groups. Supports any vendor by IANA vendor ID (e.g. MikroTik 14988, Cisco 9, Microsoft 311).
- **TLS verification**: Set `insecure_skip_tls_verify: true` for self-signed Keycloak certs.
- **Asynchronous/multi-request support**: Multiple RADIUS requests are handled concurrently for high performance.

## Testing

Three layers of automated tests are included, all runnable with `go test ./...`:

1. **Unit tests** (no external dependencies):
   - `config_test.go` — `keyrad.yaml` parsing, ENV-override precedence (ENV > YAML),
     missing-required-field startup failure, `scope_radius_map` value validation,
     secret masking.
   - `radiussrv/*_test.go` — `clients.conf` parsing, attribute encoding, VSA encoding
     for MikroTik/Cisco/Microsoft/Ubiquiti, `scope_radius_map` matching (exact, `re:`
     regex, multiple matching rules), challenge-state store (TTL/eviction).
   - `keycloak/keycloak_test.go` — admin-token cache, password grant, `HasOTP`
     (OTP detection against the Admin API).
2. **Integration tests** (`server_test.go`) — the real server is started on a local
   UDP port via `run()` and backed by a **mocked Keycloak** (`httptest.Server`). They
   exercise the full auth flow with real RADIUS packets: successful password auth
   (with credentials supplied **via YAML and via ENV** to prove both behave the same),
   OTP challenge-response (`Access-Challenge` → second request with the OTP), the
   `<password><otp>` combined flow (`--disable-challenge-response`), and failure cases
   (wrong password, unreachable Keycloak, expired service-account token, invalid
   client secret).
3. **Smoke tests** (`server_test.go`) — start the server with the secret provided only
   through the environment, confirm an unknown RADIUS client is dropped, verify
   Message-Authenticator handling (valid accepted, tampered dropped, disabled via
   flag), and assert that **no plaintext secret appears in the server logs**.

```bash
# Everything (unit + integration + smoke) with the race detector and coverage:
go test ./... -race -cover

# Fast end-to-end run only (integration + smoke, ~5 s):
go test -run 'TestIntegration_|TestSmoke_' -count=1 -v .

# Or via make:
make test
make test-race
make smoke-test
```

> The integration/smoke tests bind loopback UDP ports and start real servers; the
> "dropped packet" assertions intentionally wait ~1.2 s to confirm the absence of a
> reply. CI (`.github/workflows/ci.yml`) runs `go vet`, `go test ./... -race -cover`
> and `govulncheck` on every push/PR.

## Docker and Compose (UDP)

- Set **`listen_addr: "0.0.0.0:1812"`** in `keyrad.yaml`. Binding to **`127.0.0.1`** only listens inside the container, so traffic published with **`ports: - "1812:1812/udp"`** never reaches the process.
- Publish UDP explicitly, e.g. **`ports: ["1812:1812/udp"]`**.
- **`clients.conf` matches the UDP source address keyrad sees.** With bridge networking that is often the **Docker gateway** (e.g. `172.17.0.1`) or another **RFC1918** address, **not** your NAS IP and **not** `127.0.0.1`. If nothing matches, keyrad logs at **Info**: `RADIUS: datagram received but no clients.conf match` with `remote_ip` — use that value to add a `client { }` block or a CIDR (see example `clients.conf` with `172.16.0.0/12` for lab; tighten in production).
- On **Linux**, **`network_mode: host`** makes the original NAS source visible and avoids Docker UDP port mapping quirks; then do not rely on `ports:` for 1812. On **Docker Desktop (Mac/Windows)** host mode behaves differently; test from another container on the same user-defined network, or from the LAN to the host’s IP with a matching `clients.conf` entry for the observed `remote_ip`.
- See **`docker-compose.example.yml`** for a minimal compose file.

## Troubleshooting
- **403 errors**: Ensure your Keycloak client has the correct service account roles.
- **Invalid Message-Authenticator**: Check shared secrets in `clients.conf` and your RADIUS client.
- **OTP not working**: Ensure user has the credential enrolled in Keycloak.
- **Legacy OTP**: If your client cannot handle RADIUS challenge-response, use `--disable-challenge-response`.

## Known issues
- The password is more than 16 characters. 
Some devices use RADIUS 1.0 (RFC 2138), which limits passwords to 16 characters. For example: Checkpoint version < R81.10.00 - https://support.checkpoint.com/results/sk/sk13740

## Professional Support

keyrad is open-source and free to use under the Apache 2.0 license.
For production deployments, commercial support subscriptions with SLA are available.

→ See [SUPPORT.md](SUPPORT.md) or contact [info@sec73.io](mailto:info@sec73.io)

## Disclaimer
This project is provided as-is, without warranty of any kind. Use at your own risk. The maintainers are not responsible for any damage, data loss, or security issues resulting from the use or misuse of this software. Always review and test in a safe environment before deploying to production.

## License
Apache-2.0
