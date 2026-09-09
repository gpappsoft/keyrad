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
 */

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"keyrad/radiussrv"
)

// envMapLookup adapts a map to the func(string) (string, bool) signature of os.LookupEnv.
func envMapLookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

// writeTemp writes content to a file inside dir and returns its absolute path.
func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestLoadConfigUsesYAMLWhenNoEnv(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", `
client_id: "radius-client"
client_secret: "yaml-secret"
token_url: "https://keycloak.example/realms/master/protocol/openid-connect/token"
realm: "master"
api_url: "https://keycloak.example/admin/realms/master"
`)
	cfg, err := LoadConfig(yamlPath, envMapLookup(nil))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ClientID != "radius-client" {
		t.Errorf("client_id: got %q want %q", cfg.ClientID, "radius-client")
	}
	if cfg.ClientSecret != "yaml-secret" {
		t.Errorf("client_secret: got %q want %q", cfg.ClientSecret, "yaml-secret")
	}
	if len(cfg.appliedEnvVars) != 0 {
		t.Errorf("expected no env overrides, got %v", cfg.appliedEnvVars)
	}
}

func TestLoadConfigEnvOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	// The YAML ships with a placeholder for the secret, so it is safe to commit.
	yamlPath := writeTemp(t, dir, "keyrad.yaml", `
client_id: "from-yaml"
client_secret: "<>"
token_url: "https://yaml.example/realms/master/protocol/openid-connect/token"
realm: "master"
api_url: "https://yaml.example/admin/realms/master"
insecure_skip_tls_verify: false
`)
	env := map[string]string{
		envKeycloakClientID:              "from-env-client",
		envKeycloakClientSecret:          "from-env-secret",
		envKeycloakTokenURL:              "https://env.example/realms/master/protocol/openid-connect/token",
		envKeycloakInsecureSkipTLSVerify: "true",
	}
	cfg, err := LoadConfig(yamlPath, envMapLookup(env))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ClientID != "from-env-client" {
		t.Errorf("client_id: got %q want %q (ENV must win over YAML)", cfg.ClientID, "from-env-client")
	}
	if cfg.ClientSecret != "from-env-secret" {
		t.Errorf("client_secret: got %q want %q (ENV must win over placeholder)", cfg.ClientSecret, "from-env-secret")
	}
	if cfg.TokenURL != "https://env.example/realms/master/protocol/openid-connect/token" {
		t.Errorf("token_url: got %q, ENV must win", cfg.TokenURL)
	}
	if !cfg.InsecureSkipTLSVerify {
		t.Error("insecure_skip_tls_verify: want true from ENV")
	}
	// realm is not overridden, so it must keep the YAML value.
	if cfg.Realm != "master" {
		t.Errorf("realm: got %q want %q", cfg.Realm, "master")
	}
	want := []string{
		envKeycloakClientID,
		envKeycloakClientSecret,
		envKeycloakTokenURL,
		envKeycloakInsecureSkipTLSVerify,
	}
	if got := cfg.appliedEnvVars; len(got) != len(want) {
		t.Fatalf("applied env vars: got %v want %v", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range cfg.appliedEnvVars {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("applied env vars missing %q (got %v)", w, cfg.appliedEnvVars)
		}
	}
}

func TestLoadConfigMissingRequiredFieldFailsClearly(t *testing.T) {
	// base holds a fully-valid configuration; each case then empties, placeholders, or
	// drops one key so validate() fails on exactly that field.
	base := map[string]string{
		"token_url":     "https://keycloak.example/realms/master/protocol/openid-connect/token",
		"realm":         "master",
		"api_url":       "https://keycloak.example/admin/realms/master",
		"client_id":     "radius-client",
		"client_secret": "very-long-client-secret",
	}
	fieldOrder := []string{"token_url", "realm", "api_url", "client_id", "client_secret"}
	cases := []struct {
		name     string
		key      string // config key under test
		value    string // value to set ("" + omit=false means an empty string)
		omit     bool   // drop the key entirely instead of writing it
		wantVar  string
		wantFrag string
	}{
		{name: "client_secret omitted", key: "client_secret", omit: true, wantVar: envKeycloakClientSecret, wantFrag: "client_secret"},
		{name: "client_secret empty", key: "client_secret", value: "", wantVar: envKeycloakClientSecret, wantFrag: "client_secret"},
		{name: "client_secret placeholder", key: "client_secret", value: "<>", wantVar: envKeycloakClientSecret, wantFrag: "client_secret"},
		{name: "client_id placeholder", key: "client_id", value: "<>", wantVar: envKeycloakClientID, wantFrag: "client_id"},
		{name: "token_url empty", key: "token_url", value: "", wantVar: envKeycloakTokenURL, wantFrag: "token_url"},
		{name: "token_url half-filled placeholder", key: "token_url", value: "https://keycloak.example/realms/<>/protocol/openid-connect/token", wantVar: envKeycloakTokenURL, wantFrag: "token_url"},
		{name: "realm empty", key: "realm", value: "", wantVar: envKeycloakRealm, wantFrag: "realm"},
		{name: "realm placeholder", key: "realm", value: "<>", wantVar: envKeycloakRealm, wantFrag: "realm"},
		{name: "api_url empty", key: "api_url", value: "", wantVar: envKeycloakAPIURL, wantFrag: "api_url"},
		{name: "api_url half-filled placeholder", key: "api_url", value: "https://keycloak.example/admin/realms/<>", wantVar: envKeycloakAPIURL, wantFrag: "api_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := make(map[string]string, len(base))
			for k, v := range base {
				fields[k] = v
			}
			if tc.omit {
				delete(fields, tc.key)
			} else {
				fields[tc.key] = tc.value
			}
			var b strings.Builder
			for _, k := range fieldOrder {
				if v, ok := fields[k]; ok {
					b.WriteString(k + ": \"" + v + "\"\n")
				}
			}
			dir := t.TempDir()
			yamlPath := writeTemp(t, dir, "keyrad.yaml", b.String())
			_, err := LoadConfig(yamlPath, envMapLookup(nil))
			if err == nil {
				t.Fatal("expected an error for missing required field, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantFrag) {
				t.Errorf("error should mention %q, got: %v", tc.wantFrag, err)
			}
			if !strings.Contains(err.Error(), tc.wantVar) {
				t.Errorf("error should mention env var %q, got: %v", tc.wantVar, err)
			}
		})
	}
}

func TestLoadConfigInvalidBoolEnvFailsClearly(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", `
client_id: "radius-client"
client_secret: "secret"
realm: "master"
`)
	env := map[string]string{envKeycloakInsecureSkipTLSVerify: "not-a-bool"}
	_, err := LoadConfig(yamlPath, envMapLookup(env))
	if err == nil {
		t.Fatal("expected an error for invalid boolean env value, got nil")
	}
	if !strings.Contains(err.Error(), envKeycloakInsecureSkipTLSVerify) {
		t.Errorf("error should name env var %q, got: %v", envKeycloakInsecureSkipTLSVerify, err)
	}
}

func TestStartupFailsWhenRequiredSecretMissing(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", `
client_id: "radius-client"
client_secret: ""
realm: "master"
`)
	clientsPath := writeTemp(t, dir, "clients.conf", `
client 127.0.0.1 {
    secret = testing123
    ipaddr = 127.0.0.1
}
`)
	err := run(runOptions{
		configPath:  yamlPath,
		clientsPath: clientsPath,
		pap:         true,
	}, zap.NewNop(), envMapLookup(nil))
	if err == nil {
		t.Fatal("startup should fail when client_secret is missing, got nil error")
	}
	if !strings.Contains(err.Error(), "client_secret") || !strings.Contains(err.Error(), envKeycloakClientSecret) {
		t.Fatalf("startup error must be a clear message naming the field and env var, got: %v", err)
	}
}

// zapBufferLogger builds a logger that writes JSON to buf at debug level.
func zapBufferLogger(buf *bytes.Buffer) *zap.Logger {
	encCfg := zapcore.EncoderConfig{
		TimeKey:     zapcore.OmitKey,
		LevelKey:    "level",
		MessageKey:  "msg",
		EncodeLevel: zapcore.LowercaseLevelEncoder,
	}
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encCfg), zapcore.AddSync(buf), zapcore.DebugLevel)
	return zap.New(core)
}

// TestStartupLogsNeverContainPlaintextSecret drives the real run() startup path (it logs
// before ListenAndServe fails on an invalid listen_addr) and asserts the secret value is
// never written in plaintext - only its masked form - even at debug level.
func TestStartupLogsNeverContainPlaintextSecret(t *testing.T) {
	const secret = "s3cr3t-Keycloak-Secret-42"
	const clientID = "very-secret-radius-client"

	dir := t.TempDir()
	// listen_addr is intentionally invalid so run() logs and then returns without binding.
	yamlPath := writeTemp(t, dir, "keyrad.yaml", `
client_id: "`+clientID+`"
client_secret: "`+secret+`"
token_url: "https://keycloak.example/realms/master/protocol/openid-connect/token"
realm: "master"
api_url: "https://keycloak.example/admin/realms/master"
listen_addr: "not-an-address"
`)
	clientsPath := writeTemp(t, dir, "clients.conf", `
client 127.0.0.1 {
    secret = testing123
    ipaddr = 127.0.0.1
}
`)
	buf := &bytes.Buffer{}
	logger := zapBufferLogger(buf)

	err := run(runOptions{
		configPath:  yamlPath,
		clientsPath: clientsPath,
		pap:         true,
		debug:       true, // even debug logs must not leak secrets
	}, logger, envMapLookup(nil))
	if err == nil {
		t.Fatal("expected ListenAndServe to fail on the invalid listen_addr")
	}

	out := buf.String()
	if !strings.Contains(out, "keycloak configuration") {
		t.Fatalf("expected startup to log the (masked) configuration, got:\n%s", out)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("client_secret leaked in plaintext in log output:\n%s", out)
	}
	if strings.Contains(out, clientID) {
		t.Fatalf("client_id leaked in plaintext in log output:\n%s", out)
	}
	// The masked form (first 2 + last 2 chars) should be present so operators can
	// confirm which credential is loaded without exposing it.
	if !strings.Contains(out, "s3****42") {
		t.Fatalf("expected masked client_secret s3****42 in log output:\n%s", out)
	}
}

func TestApplyRadiusClientSecretEnv(t *testing.T) {
	dir := t.TempDir()
	clientsPath := writeTemp(t, dir, "clients.conf", `
client 10.0.0.1 {
    secret = from-file-ip
    ipaddr = 10.0.0.1
}
client 10.0.0.2 {
    secret = keep-from-file
    ipaddr = 10.0.0.2
}
client nas-1 {
    secret = from-file-name
    shortname = nas-1
}
`)
	clients, err := radiussrv.ParseClientsConf(clientsPath)
	if err != nil {
		t.Fatalf("ParseClientsConf: %v", err)
	}
	env := map[string]string{
		"KEYRAD_RADIUS_CLIENT_SECRET_10_0_0_1": "env-ip-secret",
		"KEYRAD_RADIUS_CLIENT_SECRET_NAS_1":    "env-name-secret",
	}
	overridden, err := ApplyRadiusClientSecretEnv(clients, envMapLookup(env))
	if err != nil {
		t.Fatalf("ApplyRadiusClientSecretEnv: %v", err)
	}
	if clients["10.0.0.1"].Secret != "env-ip-secret" {
		t.Errorf("client 10.0.0.1 secret: got %q want %q", clients["10.0.0.1"].Secret, "env-ip-secret")
	}
	if clients["nas-1"].Secret != "env-name-secret" {
		t.Errorf("client nas-1 secret: got %q want %q", clients["nas-1"].Secret, "env-name-secret")
	}
	// Client without an env override keeps the value from clients.conf.
	if clients["10.0.0.2"].Secret != "keep-from-file" {
		t.Errorf("client 10.0.0.2 secret: got %q want %q (no env -> file value)", clients["10.0.0.2"].Secret, "keep-from-file")
	}
	if len(overridden) != 2 {
		t.Errorf("overridden clients: got %v want 2 entries", overridden)
	}
}

func TestEnvKeyForClient(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":      "127_0_0_1",
		"192.168.1.0/24": "192_168_1_0_24",
		"nas-1":          "NAS_1",
		"fe80::1":        "FE80__1",
	}
	for in, want := range cases {
		if got := envKeyForClient(in); got != want {
			t.Errorf("envKeyForClient(%q): got %q want %q", in, got, want)
		}
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "(unset)"},
		{"a", "****"},
		{"abcd", "****"},
		{"abcde", "ab****de"},
		{"abcdefgh", "ab****gh"},
		{"  ", "(unset)"},
	}
	for _, tc := range cases {
		if got := maskSecret(tc.in); got != tc.want {
			t.Errorf("maskSecret(%q): got %q want %q", tc.in, got, tc.want)
		}
	}
}

func scopeYAML(scopeMap string) string {
	return `
client_id: "radius-client"
client_secret: "secret"
token_url: "https://kc.example/realms/master/protocol/openid-connect/token"
realm: "master"
api_url: "https://kc.example/admin/realms/master"
` + scopeMap
}

func TestLoadConfig_ScopeMapValid(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", scopeYAML(`
scope_radius_map:
  admin:
    - attribute: 6
      value: "6"
      value_type: integer
  vpn:
    - attribute: 8
      value: "10.0.0.1"
      value_type: ipaddr
  wifi:
    - attribute: 11
      value: "group-member"
`))
	if _, err := LoadConfig(yamlPath, envMapLookup(nil)); err != nil {
		t.Fatalf("valid scope map rejected: %v", err)
	}
}

func TestLoadConfig_ScopeMapInvalidValueType(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", scopeYAML(`
scope_radius_map:
  vpn:
    - attribute: 8
      value: "10.0.0.1"
      value_type: bogus
`))
	_, err := LoadConfig(yamlPath, envMapLookup(nil))
	if err == nil {
		t.Fatal("expected error for invalid value_type, got nil")
	}
	if !strings.Contains(err.Error(), `value_type "bogus"`) {
		t.Fatalf("error should name the bad value_type, got: %v", err)
	}
}

func TestLoadConfig_ScopeMapInvalidInteger(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", scopeYAML(`
scope_radius_map:
  vpn:
    - attribute: 8
      value: "not-a-number"
      value_type: integer
`))
	_, err := LoadConfig(yamlPath, envMapLookup(nil))
	if err == nil {
		t.Fatal("expected error for non-numeric integer value, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid 32-bit integer") {
		t.Fatalf("error should mention integer parse failure, got: %v", err)
	}
}

func TestLoadConfig_ScopeMapInvalidIP(t *testing.T) {
	dir := t.TempDir()
	yamlPath := writeTemp(t, dir, "keyrad.yaml", scopeYAML(`
scope_radius_map:
  vpn:
    - attribute: 8
      value: "999.0.0.1"
      value_type: ipaddr
`))
	_, err := LoadConfig(yamlPath, envMapLookup(nil))
	if err == nil {
		t.Fatal("expected error for invalid ipaddr value, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid IP address") {
		t.Fatalf("error should mention invalid IP, got: %v", err)
	}
}
