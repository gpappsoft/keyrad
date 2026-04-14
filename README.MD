# keyrad: Keycloak RADIUS Server

A Go-based RADIUS server that authenticates users against Keycloak, supporting password and OTP (TOTP) flows.

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

## Support
If you need professional support, please write to

[info@sec73.io](mailto:info@sec73.io)

## Disclaimer
This project is provided as-is, without warranty of any kind. Use at your own risk. The maintainers are not responsible for any damage, data loss, or security issues resulting from the use or misuse of this software. Always review and test in a safe environment before deploying to production.

## License
Apache-2.0
