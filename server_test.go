/*
 * Copyright 2026 Marco Moenig <marco@sec73.io>, Oleg Ermoshkin <o@ermoshkin.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Integration + smoke tests. These start the real keyrad server (package main run())
 * on a local UDP port, back it with a mocked Keycloak (httptest.Server), and talk to it
 * with real RADIUS packets built with the vendored layeh.com/radius library.
 *
 * Run just the end-to-end tests:
 *   go test -run 'TestIntegration_|TestSmoke_' -count=1 -v .
 */
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// ---------------------------------------------------------------------------
// Mocked Keycloak
// ---------------------------------------------------------------------------

type mockUser struct {
	username string
	password string
	hasOTP   bool
	otp      string
	roles    []string
}

// keycloakMock simulates the Keycloak token + admin REST endpoints used by keyrad.
type keycloakMock struct {
	clientID     string
	clientSecret string // the secret the mock accepts; if keyrad sends another -> 401
	adminToken   string // bearer token the mock issues for client_credentials
	adminDenyAll bool   // if true the admin API rejects every request (expired SA token)
	users        map[string]*mockUser

	ts       *httptest.Server
	tokenURL string
	apiURL   string
}

func newKeycloakMock(clientID, clientSecret string, users ...*mockUser) *keycloakMock {
	m := &keycloakMock{
		clientID:     clientID,
		clientSecret: clientSecret,
		adminToken:   "mock-admin-token",
		users:        map[string]*mockUser{},
	}
	for _, u := range users {
		m.users[u.username] = u
	}
	m.ts = httptest.NewServer(m)
	m.tokenURL = m.ts.URL + "/realms/master/protocol/openid-connect/token"
	m.apiURL = m.ts.URL + "/admin/realms/master"
	return m
}

func (m *keycloakMock) close() {
	if m.ts != nil {
		m.ts.Close()
	}
}

func (m *keycloakMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(r.URL.Path, "/token") {
		m.handleToken(w, r)
		return
	}
	m.handleAdmin(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (m *keycloakMock) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_form"})
		return
	}
	if r.Form.Get("client_id") != m.clientID || r.Form.Get("client_secret") != m.clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.Form.Get("grant_type") {
	case "client_credentials":
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": m.adminToken,
			"expires_in":   300,
			"token_type":   "Bearer",
		})
	case "password":
		u := m.users[r.Form.Get("username")]
		if u == nil || u.password != r.Form.Get("password") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant"})
			return
		}
		if u.hasOTP && r.Form.Get("totp") != u.otp {
			// Simulates Keycloak conditional OTP: the grant requires the totp value.
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant", "error_description": "OTP required or wrong"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": fakeAccessToken(u.roles),
			"expires_in":   300,
			"token_type":   "Bearer",
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (m *keycloakMock) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if m.adminDenyAll || r.Header.Get("Authorization") != "Bearer "+m.adminToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	// GET /admin/realms/master/users/{id}/credentials
	if strings.HasSuffix(r.URL.Path, "/credentials") {
		id := r.URL.Path
		id = strings.TrimSuffix(id, "/credentials")
		id = id[strings.LastIndex(id, "/")+1:]
		if u := m.users[id]; u != nil && u.hasOTP {
			writeJSON(w, http.StatusOK, []map[string]string{{"type": "otp", "id": "otp-id"}})
			return
		}
		writeJSON(w, http.StatusOK, []map[string]string{})
		return
	}
	// GET /admin/realms/master/users?username=...
	if u := m.users[r.URL.Query().Get("username")]; u != nil {
		writeJSON(w, http.StatusOK, []map[string]string{{"id": u.username, "username": u.username}})
		return
	}
	writeJSON(w, http.StatusOK, []map[string]string{})
}

// fakeAccessToken builds a base64url JWT-shaped token whose payload carries realm roles,
// groups and scopes, matching what keyrad's extractRolesFromJWT reads.
func fakeAccessToken(roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"realm_access": map[string]any{"roles": roles},
		"groups":       []string{},
		"scope":        "",
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// ---------------------------------------------------------------------------
// RADIUS test client (real wire packets via the vendored radius library)
// ---------------------------------------------------------------------------

const (
	nasSharedSecret = "testing123"
	attrState       = radius.Type(24)
	attrMA          = radius.Type(80)
)

var errResponseTimeout = errors.New("radius test client: timed out waiting for a response")

// syncLogBuf is a concurrency-safe log sink: the RADIUS server logs from up to 8 worker
// goroutines at once, so the underlying buffer must be mutex-protected.
type syncLogBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newDebugJSONLogger returns a debug-level JSON logger writing to w (zapcore.Lock serializes
// concurrent writes from the worker goroutines on top of the syncLogBuf lock).
func newDebugJSONLogger(w io.Writer) *zap.Logger {
	encCfg := zapcore.EncoderConfig{
		TimeKey:     zapcore.OmitKey,
		LevelKey:    "level",
		MessageKey:  "msg",
		EncodeLevel: zapcore.LowercaseLevelEncoder,
	}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.Lock(zapcore.AddSync(w)), zapcore.DebugLevel)
	return zap.New(core)
}

// testServer is a running keyrad instance plus the loopback NAS credentials used to talk
// to it and the captured log output (for the "no plaintext secrets in logs" assertions).
type testServer struct {
	addr   string
	secret []byte
	logs   *syncLogBuf
	done   chan error
}

// loopbackClientsConf authorizes the loopback NAS used by the tests.
func loopbackClientsConf() string {
	return fmt.Sprintf("client 127.0.0.1 {\n\tsecret = %s\n\tipaddr = 127.0.0.1\n}\n", nasSharedSecret)
}

// startTestServer writes a keyrad.yaml + clients.conf into a temp dir, injects a free
// loopback listen_addr, and starts the real server via run().
func startTestServer(t *testing.T, yamlContent, clientsContent string, env map[string]string, opts runOptions) *testServer {
	t.Helper()
	dir := t.TempDir()

	addr := freeUDPAddr(t)
	if !strings.Contains(yamlContent, "listen_addr:") {
		yamlContent += fmt.Sprintf("\nlisten_addr: %q\n", addr)
	}
	yamlPath := writeTemp(t, dir, "keyrad.yaml", yamlContent)
	clientsPath := writeTemp(t, dir, "clients.conf", clientsContent)

	opts.configPath = yamlPath
	opts.clientsPath = clientsPath
	opts.pap = true
	opts.debug = true // capture debug logs so tests can assert secrets never appear

	buf := &syncLogBuf{}
	done := make(chan error, 1)
	go func() { done <- run(opts, newDebugJSONLogger(buf), envMapLookup(env)) }()

	// Surface early startup/bind failures instead of timing out later.
	select {
	case err := <-done:
		t.Fatalf("server exited during startup: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	ts := &testServer{addr: addr, secret: []byte(nasSharedSecret), logs: buf, done: done}
	t.Cleanup(func() {
		select {
		case err := <-done:
			_ = err // server exited; ignore
		default:
			// server intentionally left running until the test binary exits
		}
	})
	return ts
}

// freeUDPAddr returns a free loopback UDP address (bind to pick a port, then close).
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("free udp addr: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// buildAccessRequest constructs a real Access-Request wire packet for the given NAS secret.
// When includeMA is true a valid RFC 2869 Message-Authenticator is computed. corruptMA
// (only meaningful with includeMA) flips a byte so verification must fail server-side.
func buildAccessRequest(secret []byte, username, password string, includeMA, corruptMA bool, attrs map[radius.Type][]byte) ([]byte, error) {
	p := radius.New(radius.CodeAccessRequest, secret)
	p.Add(radius.Type(1), []byte(username)) // User-Name
	enc, err := radius.NewUserPassword([]byte(password), secret, p.Authenticator[:])
	if err != nil {
		return nil, err
	}
	p.Add(radius.Type(2), enc) // User-Password
	for typ, val := range attrs {
		p.Add(typ, val)
	}
	if includeMA {
		if err := rfc2869.MessageAuthenticator_Add(p, make([]byte, 16)); err != nil {
			return nil, err
		}
	}
	wire, err := p.Encode()
	if err != nil {
		return nil, err
	}
	if includeMA {
		off, err := messageAuthenticatorValueOffset(wire)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(md5.New, secret)
		_, _ = mac.Write(wire) // MA bytes are still zero here
		copy(wire[off:off+16], mac.Sum(nil)[:16])
		if corruptMA {
			wire[off] ^= 0xff
		}
	}
	return wire, nil
}

func messageAuthenticatorValueOffset(wire []byte) (int, error) {
	end := int(binary.BigEndian.Uint16(wire[2:4]))
	if end > len(wire) {
		return 0, fmt.Errorf("packet shorter than length field")
	}
	for pos := 20; pos+2 <= end; {
		typ := wire[pos]
		l := int(wire[pos+1])
		if l < 2 || pos+l > end {
			return 0, fmt.Errorf("malformed attribute list")
		}
		if typ == byte(attrMA) {
			if l != 18 {
				return 0, fmt.Errorf("Message-Authenticator length != 18")
			}
			return pos + 2, nil
		}
		pos += l
	}
	return 0, fmt.Errorf("Message-Authenticator not found")
}

// roundTrip sends reqWire to the server (retrying while the server comes up) and returns
// the first authentic, parseable response. It fails with errResponseTimeout when the
// server intentionally drops the request (unknown client, bad Message-Authenticator).
func (ts *testServer) roundTrip(reqWire []byte, total time.Duration) (*radius.Packet, error) {
	deadline := time.Now().Add(total)
	buf := make([]byte, 4096)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("udp", ts.addr)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
		if _, err := conn.Write(reqWire); err != nil {
			_ = conn.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for {
			n, err := conn.Read(buf)
			if err == nil {
				resp, perr := radius.Parse(buf[:n], ts.secret)
				if perr != nil {
					continue
				}
				if !radius.IsAuthenticResponse(buf[:n], reqWire, ts.secret) {
					_ = conn.Close()
					return nil, errors.New("radius test client: non-authentic response")
				}
				_ = conn.Close()
				return resp, nil
			}
			_ = conn.Close()
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break // try again (still within deadline)
			}
			break // connection refused etc. while server is starting: retry
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errResponseTimeout
}

// accessRequest performs one request/response round.
func (ts *testServer) accessRequest(t *testing.T, username, password string, includeMA bool, attrs map[radius.Type][]byte) (*radius.Packet, error) {
	t.Helper()
	reqWire, err := buildAccessRequest(ts.secret, username, password, includeMA, false, attrs)
	if err != nil {
		t.Fatalf("build Access-Request: %v", err)
	}
	return ts.roundTrip(reqWire, 5*time.Second)
}

func expectCode(t *testing.T, resp *radius.Packet, err error, want radius.Code) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected %s, got error: %v", want, err)
	}
	if resp.Code != want {
		t.Fatalf("expected %s, got %s", want, resp.Code)
	}
}

func expectDropped(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected request to be dropped (no response), but got a response")
	}
}

// ---------------------------------------------------------------------------
// Test fixtures / helpers
// ---------------------------------------------------------------------------

func radiusUsers() []*mockUser {
	return []*mockUser{
		{username: "alice", password: "alice-pw", roles: []string{"vpn", "wifi"}},
		{username: "bob", password: "bob-pw", hasOTP: true, otp: "123456", roles: []string{"vpn"}},
	}
}

// testYAML returns keyrad.yaml content for the given client secret + Keycloak endpoints.
// scopeBlock, when non-empty, is appended verbatim (must already be YAML-indented).
func testYAML(clientID, clientSecret, tokenURL, apiURL, scopeBlock string) string {
	return fmt.Sprintf(`
token_url: %q
client_id: %q
client_secret: %q
realm: "master"
api_url: %q
insecure_skip_tls_verify: false
%s
`, tokenURL, clientID, clientSecret, apiURL, scopeBlock)
}

const scopeMapBlock = `
scope_radius_map:
  vpn:
    - attribute: 8
      value: "10.0.0.5"
      value_type: ipaddr
`

// startYAMLServer starts a full server against mock for the given effective client secret
// (supplied either via YAML or via the KEYRAD_KEYCLOAK_CLIENT_SECRET env var).
func startYAMLServer(t *testing.T, mock *keycloakMock, envSecret bool, secret string) *testServer {
	t.Helper()
	var env map[string]string
	yamlSecret := secret
	if envSecret {
		yamlSecret = "<>"
		env = map[string]string{envKeycloakClientSecret: secret}
	}
	yamlContent := testYAML(mock.clientID, yamlSecret, mock.tokenURL, mock.apiURL, scopeMapBlock)
	opts := runOptions{}
	return startTestServer(t, yamlContent, loopbackClientsConf(), env, opts)
}

// ---------------------------------------------------------------------------
// Integration tests: full auth flows against a mocked Keycloak
// ---------------------------------------------------------------------------

func TestIntegration_PasswordAuth_YAMLSecret(t *testing.T) {
	mock := newKeycloakMock("radius-client", "s3cr3t-yaml-secret", radiusUsers()...)
	defer mock.close()

	ts := startYAMLServer(t, mock, false, "s3cr3t-yaml-secret")

	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessAccept)

	// Roles from the mocked Keycloak JWT should have driven scope_radius_map: vpn -> Framed-IP.
	if got := resp.Get(8); !bytes.Equal(got, []byte{10, 0, 0, 5}) {
		t.Fatalf("expected Framed-IP-Address 10.0.0.5 from role mapping, got %#v", got)
	}
}

func TestIntegration_PasswordAuth_ENVSecret(t *testing.T) {
	// Same effective secret as the YAML test, but injected via the environment while the
	// YAML file carries the "<>" placeholder. Behaviour must be identical.
	mock := newKeycloakMock("radius-client", "s3cr3t-env-secret", radiusUsers()...)
	defer mock.close()

	ts := startYAMLServer(t, mock, true, "s3cr3t-env-secret")

	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessAccept)
	if got := resp.Get(8); !bytes.Equal(got, []byte{10, 0, 0, 5}) {
		t.Fatalf("expected Framed-IP-Address 10.0.0.5 from role mapping, got %#v", got)
	}
}

func TestIntegration_OTPChallengeResponse(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	defer mock.close()

	ts := startYAMLServer(t, mock, false, "secret")

	// Step 1: password only -> server answers Access-Challenge with a State attribute.
	challenge, err := ts.accessRequest(t, "bob", "bob-pw", true, nil)
	expectCode(t, challenge, err, radius.CodeAccessChallenge)

	state := challenge.Get(attrState)
	if state == nil {
		t.Fatal("Access-Challenge did not carry a State attribute")
	}

	// Step 2: submit the OTP in the User-Password field together with State.
	resp, err := ts.accessRequest(t, "bob", "123456", true, map[radius.Type][]byte{attrState: state})
	expectCode(t, resp, err, radius.CodeAccessAccept)
}

func TestIntegration_OTPCombinedDisableChallenge(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	defer mock.close()

	// Disable challenge-response: OTP users present <password><otp> in a single request.
	opts := runOptions{disableChallenge: true}
	yamlContent := testYAML("radius-client", "secret", mock.tokenURL, mock.apiURL, "")
	ts := startTestServer(t, yamlContent, loopbackClientsConf(), nil, opts)

	// password "bob-pw" + OTP "123456"
	resp, err := ts.accessRequest(t, "bob", "bob-pw123456", true, nil)
	expectCode(t, resp, err, radius.CodeAccessAccept)
}

func TestIntegration_WrongPasswordRejected(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	defer mock.close()
	ts := startYAMLServer(t, mock, false, "secret")

	resp, err := ts.accessRequest(t, "alice", "wrong-password", true, nil)
	expectCode(t, resp, err, radius.CodeAccessReject)
}

func TestIntegration_InvalidClientSecretRejected(t *testing.T) {
	// The mock only accepts "right-secret"; keyrad is configured with a different secret
	// (supplied via ENV) so the mocked Keycloak rejects the client on every grant.
	mock := newKeycloakMock("radius-client", "right-secret", radiusUsers()...)
	defer mock.close()

	env := map[string]string{envKeycloakClientSecret: "wrong-secret"}
	yamlContent := testYAML("radius-client", "<>", mock.tokenURL, mock.apiURL, "")
	ts := startTestServer(t, yamlContent, loopbackClientsConf(), env, runOptions{})

	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessReject)
}

func TestIntegration_KeycloakUnreachable(t *testing.T) {
	// Point keyrad at a server that has been closed so connections are refused.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	yamlContent := testYAML("radius-client", "secret", deadURL+"/token", deadURL+"/admin", "")
	ts := startTestServer(t, yamlContent, loopbackClientsConf(), nil, runOptions{})

	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessReject)
}

func TestIntegration_ExpiredServiceAccountToken(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	mock.adminDenyAll = true // admin API always rejects (expired/invalid SA token)
	defer mock.close()

	yamlContent := testYAML("radius-client", "secret", mock.tokenURL, mock.apiURL, "")
	ts := startTestServer(t, yamlContent, loopbackClientsConf(), nil, runOptions{})

	// Password-only users must still authenticate (HasOTP degrades gracefully).
	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessAccept)

	// OTP users must NOT get in via a password-only grant when OTP detection is down.
	resp, err = ts.accessRequest(t, "bob", "bob-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessReject)
}

// ---------------------------------------------------------------------------
// Smoke tests: real server startup semantics
// ---------------------------------------------------------------------------

func TestSmoke_StartsWithEnvSecretAndLogsNoPlaintext(t *testing.T) {
	const envSecret = "s3cr3t-env-smoke-secret-77"
	mock := newKeycloakMock("radius-client", envSecret, radiusUsers()...)
	defer mock.close()

	// keyrad.yaml contains placeholders only; the secret arrives exclusively via ENV.
	yamlContent := testYAML("radius-client", "<>", mock.tokenURL, mock.apiURL, "")
	ts := startTestServer(t, yamlContent, loopbackClientsConf(),
		map[string]string{envKeycloakClientSecret: envSecret}, runOptions{})

	resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
	expectCode(t, resp, err, radius.CodeAccessAccept)

	logs := ts.logs.String()
	if strings.Contains(logs, envSecret) {
		t.Fatalf("client secret leaked in plaintext into server logs:\n%s", logs)
	}
	if strings.Contains(logs, "alice-pw") {
		t.Fatalf("user password leaked in plaintext into server logs:\n%s", logs)
	}
	if strings.Contains(logs, nasSharedSecret) {
		t.Fatalf("RADIUS shared secret leaked in plaintext into server logs:\n%s", logs)
	}
	// The startup log should show the masked credential (first/last two chars) instead.
	if !strings.Contains(logs, "s3****77") {
		t.Fatalf("expected masked client_secret s3****77 in server logs:\n%s", logs)
	}
}

func TestSmoke_UnknownClientIsDropped(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	defer mock.close()

	// clients.conf only authorizes a remote RFC1918 network, never 127.0.0.1.
	clients := "client 10.0.0.0/8 {\n\tsecret = " + nasSharedSecret + "\n\tipaddr = 10.0.0.0/8\n}\n"
	yamlContent := testYAML("radius-client", "secret", mock.tokenURL, mock.apiURL, "")
	ts := startTestServer(t, yamlContent, clients, nil, runOptions{})

	reqWire, err := buildAccessRequest(ts.secret, "alice", "alice-pw", true, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ts.roundTrip(reqWire, 1200*time.Millisecond)
	expectDropped(t, err)
}

func TestSmoke_MessageAuthenticatorHandling(t *testing.T) {
	mock := newKeycloakMock("radius-client", "secret", radiusUsers()...)
	defer mock.close()

	t.Run("valid MA accepted", func(t *testing.T) {
		ts := startYAMLServer(t, mock, false, "secret")
		resp, err := ts.accessRequest(t, "alice", "alice-pw", true, nil)
		expectCode(t, resp, err, radius.CodeAccessAccept)
	})
	t.Run("tampered MA dropped by default", func(t *testing.T) {
		ts := startYAMLServer(t, mock, false, "secret")
		reqWire, err := buildAccessRequest(ts.secret, "alice", "alice-pw", true, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ts.roundTrip(reqWire, 1200*time.Millisecond)
		expectDropped(t, err)
	})
	t.Run("MA-less PAP accepted by default", func(t *testing.T) {
		ts := startYAMLServer(t, mock, false, "secret")
		resp, err := ts.accessRequest(t, "alice", "alice-pw", false, nil)
		expectCode(t, resp, err, radius.CodeAccessAccept)
	})
	t.Run("tampered MA accepted when verification disabled", func(t *testing.T) {
		opts := runOptions{disableMsgAuth: true}
		yamlContent := testYAML("radius-client", "secret", mock.tokenURL, mock.apiURL, "")
		ts := startTestServer(t, yamlContent, loopbackClientsConf(), nil, opts)

		reqWire, err := buildAccessRequest(ts.secret, "alice", "alice-pw", true, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := ts.roundTrip(reqWire, 5*time.Second)
		expectCode(t, resp, err, radius.CodeAccessAccept)
	})
}

// ---------------------------------------------------------------------------
// (end of file)
