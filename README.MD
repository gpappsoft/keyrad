# keyrad: Keycloak RADIUS Server

A Go-based RADIUS server that authenticates users against Keycloak, supporting password and OTP (TOTP) flows. 

Features include:
- Challenge-response for OTP
- YAML-based Keycloak and RADIUS config
- FreeRADIUS-style `clients.conf` for client secrets
- Optional Message-Authenticator
- Scope/group-to-RADIUS attribute mapping (with regexp support)
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

### Configuration
See `clients.conf` and `keyrad.yaml`.

- To customize the OTP challenge message, add `otp_challenge_message: "Your custom message"` to `keyrad.yaml`.
- The server now supports multiple concurrent RADIUS requests for high performance (async worker pool, default 8 workers).

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
- **Scope/group mapping**: Map Keycloak OAuth2 scopes or group memberships to RADIUS attributes. Supports regexp keys (e.g. `re:^group_.*`).
- **TLS verification**: Set `insecure_skip_tls_verify: true` for self-signed Keycloak certs.
- **Asynchronous/multi-request support**: Multiple RADIUS requests are handled concurrently for high performance.

## Troubleshooting
- **403 errors**: Ensure your Keycloak client has the correct service account roles.
- **Invalid Message-Authenticator**: Check shared secrets in `clients.conf` and your RADIUS client.
- **OTP not working**: Ensure user has the credential enrolled in Keycloak.
- **Legacy OTP**: If your client cannot handle RADIUS challenge-response, use `--disable-challenge-response`.

## Support
If you need professional support, please write to

[info@sec73.io](mailto:info@sec73.io)

## Disclaimer
This project is provided as-is, without warranty of any kind. Use at your own risk. The maintainers are not responsible for any damage, data loss, or security issues resulting from the use or misuse of this software. Always review and test in a safe environment before deploying to production.

## License
Apache-2.0
