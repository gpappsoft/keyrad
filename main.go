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

// Keyrad is the RADIUS authentication daemon entrypoint: YAML and clients.conf loading,
// Keycloak client construction, and UDP RADIUS listener startup.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"keyrad/keycloak"
	"keyrad/radiussrv"
)

const Version = "2.0.1"
const Author = "Marco Moenig <marco@sec73.io>, Oleg Ermoshkin <o@ermoshkin.com>"

func main() {
	var zapcfg zap.Config
	zapcfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	zapcfg.Encoding = "json"
	zapcfg.OutputPaths = []string{"stdout"}
	zapcfg.ErrorOutputPaths = []string{"stderr"}
	zapcfg.EncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var keycloakConfigPath string
	var clientsConfPath string
	var showVersion bool
	var disableMessageAuthenticator bool
	var disableChallengeResponse bool
	var debug bool
	var papEnabled bool

	flag.StringVar(&keycloakConfigPath, "c", "keyrad.yaml", "Path to keyrad.yaml config file")
	flag.StringVar(&clientsConfPath, "r", "clients.conf", "Path to clients.conf file")
	flag.BoolVar(&disableMessageAuthenticator, "disable-message-authenticator", false, "Disable Message-Authenticator verification and generation")
	flag.BoolVar(&disableChallengeResponse, "disable-challenge-response", false, "Disable RADIUS challenge-response and use <password><otp> style for OTP users")
	flag.BoolVar(&debug, "debug", false, "Enable debug output for RADIUS and Keycloak communication")
	flag.BoolVar(&showVersion, "version", false, "Show version and author information")
	flag.BoolVar(&papEnabled, "pap", true, "Enable PAP authentication")
	flag.Parse()
	if showVersion {
		fmt.Printf("keyrad version %s\nAuthor: %s\n", Version, Author)
		os.Exit(0)
	}

	if debug {
		zapcfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	logger, err := zapcfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}
	defer logger.Sync()

	if err := run(runOptions{
		configPath:       keycloakConfigPath,
		clientsPath:      clientsConfPath,
		disableMsgAuth:   disableMessageAuthenticator,
		disableChallenge: disableChallengeResponse,
		pap:              papEnabled,
		debug:            debug,
	}, logger, os.LookupEnv); err != nil {
		log.Fatalf("startup error: %v", err)
	}
}

// runOptions carries the resolved command-line settings into run.
type runOptions struct {
	configPath       string
	clientsPath      string
	disableMsgAuth   bool
	disableChallenge bool
	pap              bool
	debug            bool
}

// run loads the Keycloak configuration and RADIUS clients, applies environment overrides,
// and starts the UDP listener. It returns an error instead of exiting so startup failures
// are easy to test.
func run(opts runOptions, logger *zap.Logger, lookupEnv func(string) (string, bool)) error {
	// Load and validate Keycloak config: YAML values first, then KEYRAD_* env overrides
	// (ENV wins). Missing required credentials fail here with a clear error.
	cfg, err := LoadConfig(opts.configPath, lookupEnv)
	if err != nil {
		return fmt.Errorf("invalid configuration in %s: %w", opts.configPath, err)
	}

	// Load clients.conf, then let KEYRAD_RADIUS_CLIENT_SECRET_* override shared secrets.
	clients, err := radiussrv.ParseClientsConf(opts.clientsPath)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", opts.clientsPath, err)
	}
	radiusSecretOverrides, err := ApplyRadiusClientSecretEnv(clients, lookupEnv)
	if err != nil {
		return err
	}

	// Create Keycloak API client
	kc := &keycloak.KeycloakAPI{
		TokenURL:     cfg.TokenURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Realm:        cfg.Realm,
		APIURL:       cfg.APIURL,
		HTTPClient:   getHTTPClient(cfg.InsecureSkipTLSVerify),
		Logger:       logger,
	}

	// Create RADIUS server
	srv := &radiussrv.Server{
		Keycloak:         kc,
		Clients:          clients,
		ScopeRadiusMap:   cfg.ScopeRadiusMap,
		OTPChallengeMsg:  cfg.OTPChallengeMessage,
		DisableMsgAuth:   opts.disableMsgAuth,
		DisableChallenge: opts.disableChallenge,
		PAPEnabled:       opts.pap,
		Logger:           logger,
	}
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0:1812"
	}

	// Info (not Debug): visible under default log level in Docker/Kubernetes without -debug.
	logger.Info("keyrad starting",
		zap.String("version", Version),
		zap.String("listen_addr", listenAddr),
		zap.String("config", opts.configPath),
		zap.String("clients_conf", opts.clientsPath),
		zap.Bool("pap", opts.pap),
		zap.Bool("debug_flag", opts.debug),
	)
	// Logs only masked credentials and env var *names* - never secret values.
	cfg.logConfig(logger, len(radiusSecretOverrides))

	// Warn loudly when TLS verification is disabled: with this on, a network MITM can
	// read the client secret and user passwords sent to Keycloak.
	if cfg.InsecureSkipTLSVerify {
		logger.Warn("insecure_skip_tls_verify is enabled: TLS certificate verification to Keycloak is DISABLED",
			zap.String("token_url", cfg.TokenURL))
	}

	return srv.ListenAndServe(listenAddr)
}

// getHTTPClient returns an HTTP client with a 30s timeout and optional TLS certificate verification skip.
func getHTTPClient(insecureSkipTLSVerify bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecureSkipTLSVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}
