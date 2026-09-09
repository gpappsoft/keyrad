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
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"keyrad/radiussrv"
)

// Environment-variable override names. Naming scheme: KEYRAD_ + section + field, all in
// SCREAMING_SNAKE_CASE. A value exported for one of these variables takes precedence over
// the matching key in keyrad.yaml, so the YAML file can be committed or baked into an
// image without plaintext credentials (leave the value empty or as the "<>" placeholder).
const (
	envKeycloakTokenURL              = "KEYRAD_KEYCLOAK_TOKEN_URL"
	envKeycloakClientID              = "KEYRAD_KEYCLOAK_CLIENT_ID"
	envKeycloakClientSecret          = "KEYRAD_KEYCLOAK_CLIENT_SECRET"
	envKeycloakRealm                 = "KEYRAD_KEYCLOAK_REALM"
	envKeycloakAPIURL                = "KEYRAD_KEYCLOAK_API_URL"
	envKeycloakInsecureSkipTLSVerify = "KEYRAD_KEYCLOAK_INSECURE_SKIP_TLS_VERIFY"
	// Radius client shared secrets are overridden per client via
	// KEYRAD_RADIUS_CLIENT_SECRET_<key>, where <key> is the client block's ipaddr (or its
	// name when ipaddr is absent) with ".", ":", "/", "-" and spaces replaced by "_".
	envRadiusClientSecretPrefix = "KEYRAD_RADIUS_CLIENT_SECRET_"
)

// Config mirrors the flat keyrad.yaml plus any KEYRAD_* environment overrides merged on
// top (ENV wins over YAML). ScopeRadiusMap and ListenAddr are not environment-overridable.
type Config struct {
	TokenURL              string                       `yaml:"token_url"`
	ClientID              string                       `yaml:"client_id"`
	ClientSecret          string                       `yaml:"client_secret"`
	Realm                 string                       `yaml:"realm"`
	APIURL                string                       `yaml:"api_url"`
	InsecureSkipTLSVerify bool                         `yaml:"insecure_skip_tls_verify"`
	ScopeRadiusMap        radiussrv.ScopeRadiusMapping `yaml:"scope_radius_map"`
	OTPChallengeMessage   string                       `yaml:"otp_challenge_message"`
	ListenAddr            string                       `yaml:"listen_addr"`

	// appliedEnvVars records which KEYRAD_* variables actually overrode the YAML so the
	// startup log can name them without ever logging their values.
	appliedEnvVars []string
}

// LoadConfig reads path, applies KEYRAD_* environment variable overrides on top of the
// YAML values (ENV > YAML), and validates that required credentials resolve to a real
// value. lookupEnv is os.LookupEnv in production; tests inject a map-backed function.
func LoadConfig(path string, lookupEnv func(string) (string, bool)) (*Config, error) {
	c := &Config{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(c); err != nil {
		return nil, err
	}
	if err := c.applyEnvOverrides(lookupEnv); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// applyEnvOverrides overlays each configured KEYRAD_* variable on its YAML field.
// A variable that is set - even to an empty string - overrides the YAML value.
func (c *Config) applyEnvOverrides(lookupEnv func(string) (string, bool)) error {
	setString := func(envName string, dst *string) {
		if v, ok := lookupEnv(envName); ok {
			*dst = v
			c.appliedEnvVars = append(c.appliedEnvVars, envName)
		}
	}
	setBool := func(envName string, dst *bool) error {
		v, ok := lookupEnv(envName)
		if !ok {
			return nil
		}
		b, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			return fmt.Errorf("%s: invalid boolean value %q (expected true/false/1/0)", envName, v)
		}
		*dst = b
		c.appliedEnvVars = append(c.appliedEnvVars, envName)
		return nil
	}

	setString(envKeycloakTokenURL, &c.TokenURL)
	setString(envKeycloakClientID, &c.ClientID)
	setString(envKeycloakClientSecret, &c.ClientSecret)
	setString(envKeycloakRealm, &c.Realm)
	setString(envKeycloakAPIURL, &c.APIURL)
	if err := setBool(envKeycloakInsecureSkipTLSVerify, &c.InsecureSkipTLSVerify); err != nil {
		return err
	}
	return nil
}

// validate makes sure the server never starts with empty or placeholder credentials.
// Non-credential fields are intentionally not validated so partial YAML stays valid.
func (c *Config) validate() error {
	if isMissing(c.ClientID) {
		return fmt.Errorf("missing required configuration: client_id is not set (it is empty or a placeholder) - set it in keyrad.yaml or export %s", envKeycloakClientID)
	}
	if isMissing(c.ClientSecret) {
		return fmt.Errorf("missing required configuration: client_secret is not set (it is empty or a placeholder) - set it in keyrad.yaml or export %s", envKeycloakClientSecret)
	}
	return nil
}

// isMissing reports whether a required value is effectively unset: empty after trimming
// or the sample "<>" placeholder shipped in keyrad.yaml.
func isMissing(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || v == "<>"
}

// ApplyRadiusClientSecretEnv overrides the shared secret of each RADIUS client whose
// matching KEYRAD_RADIUS_CLIENT_SECRET_<key> variable is set. ENV wins over clients.conf;
// clients can only be defined in clients.conf, never created from the environment. It
// returns the list of overridden client keys (used for logging only).
func ApplyRadiusClientSecretEnv(clients map[string]radiussrv.ClientConfig, lookupEnv func(string) (string, bool)) ([]string, error) {
	var overridden []string
	for key := range clients {
		envName := envRadiusClientSecretPrefix + envKeyForClient(key)
		v, ok := lookupEnv(envName)
		if !ok {
			continue
		}
		cfg := clients[key]
		cfg.Secret = v
		clients[key] = cfg
		overridden = append(overridden, key)
	}
	return overridden, nil
}

// envKeyForClient converts a clients.conf map key (IP address, CIDR or block name) into
// the uppercase, punctuation-free suffix used to build the env var name.
func envKeyForClient(key string) string {
	replacer := strings.NewReplacer(".", "_", ":", "_", "/", "_", "-", "_", " ", "_")
	return strings.ToUpper(replacer.Replace(key))
}

// maskSecret renders a secret for log output so operators can tell which credential was
// loaded (first and last two characters) without exposing it. Empty input becomes
// "(unset)" and very short values are fully hidden.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(unset)"
	}
	r := []rune(s)
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:2]) + "****" + string(r[len(r)-2:])
}

// logConfig writes the effective configuration to the logger. Credentials are always
// masked: plaintext secrets are never logged, at any level.
func (c *Config) logConfig(logger *zap.Logger, radiusClientSecretOverrides int) {
	logger.Info("keycloak configuration",
		zap.String("token_url", c.TokenURL),
		zap.String("realm", c.Realm),
		zap.String("api_url", c.APIURL),
		zap.Bool("insecure_skip_tls_verify", c.InsecureSkipTLSVerify),
		zap.String("client_id", maskSecret(c.ClientID)),
		zap.String("client_secret", maskSecret(c.ClientSecret)),
		zap.Int("env_overrides", len(c.appliedEnvVars)),
		zap.Int("radius_client_secret_env_overrides", radiusClientSecretOverrides),
	)
	if len(c.appliedEnvVars) > 0 {
		// Variable names only - never their values.
		logger.Info("keyrad configuration overrides applied from environment",
			zap.Strings("variables", c.appliedEnvVars))
	}
}
