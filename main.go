/*
 * Copyright 2026 Marco Moenig <marco@sec73.io>
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

// main.go for keyrad: only config, flag parsing, and server startup
package main

import (
	"flag"
	"fmt"
	"keyrad/auth"
	"keyrad/keycloak"
	"keyrad/radiussrv"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

const Version = "1.0.0"
const Author = "Marco Moenig <marco@sec73.io>"

func main() {
	var keycloakConfigPath string
	var clientsConfPath string
	var showVersion bool
	var disableMessageAuthenticator bool
	var disableChallengeResponse bool
	var debug bool
	var mschapEnabled bool
	var papEnabled bool

	flag.StringVar(&keycloakConfigPath, "c", "keyrad.yaml", "Path to keyrad.yaml config file")
	flag.StringVar(&clientsConfPath, "r", "clients.conf", "Path to clients.conf file")
	flag.BoolVar(&disableMessageAuthenticator, "disable-message-authenticator", false, "Disable Message-Authenticator verification and generation")
	flag.BoolVar(&disableChallengeResponse, "disable-challenge-response", false, "Disable RADIUS challenge-response and use <password><otp> style for OTP users")
	flag.BoolVar(&debug, "debug", false, "Enable debug output for RADIUS and Keycloak communication")
	flag.BoolVar(&showVersion, "version", false, "Show version and author information")
	flag.BoolVar(&mschapEnabled, "mschap", true, "Enable MS-CHAPv2 authentication")
	flag.BoolVar(&papEnabled, "pap", true, "Enable PAP authentication")
	flag.Parse()
	if showVersion {
		fmt.Printf("keyrad version %s\nAuthor: %s\n", Version, Author)
		os.Exit(0)
	}

	// Load Keycloak config from YAML
	var keycloakConfig struct {
		TokenURL              string                  `yaml:"token_url"`
		ClientID              string                  `yaml:"client_id"`
		ClientSecret          string                  `yaml:"client_secret"`
		Realm                 string                  `yaml:"realm"`
		APIURL                string                  `yaml:"api_url"`
		InsecureSkipTLSVerify bool                    `yaml:"insecure_skip_tls_verify"`
		ScopeRadiusMap        auth.ScopeRadiusMapping `yaml:"scope_radius_map"`
		OTPChallengeMessage   string                  `yaml:"otp_challenge_message"`
		ListenAddr            string                  `yaml:"listen_addr"`
	}
	f, err := os.Open(keycloakConfigPath)
	if err != nil {
		log.Fatalf("Failed to load %s: %v", keycloakConfigPath, err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&keycloakConfig); err != nil {
		log.Fatalf("Failed to parse %s: %v", keycloakConfigPath, err)
	}

	// Load clients.conf
	clients, err := auth.ParseClientsConf(clientsConfPath)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", clientsConfPath, err)
	}

	// Create Keycloak API client
	kc := &keycloak.KeycloakAPI{
		TokenURL:     keycloakConfig.TokenURL,
		ClientID:     keycloakConfig.ClientID,
		ClientSecret: keycloakConfig.ClientSecret,
		Realm:        keycloakConfig.Realm,
		APIURL:       keycloakConfig.APIURL,
		HTTPClient:   radiussrv.GetHTTPClient(keycloakConfig.InsecureSkipTLSVerify),
	}

	// Create and start RADIUS server
	srv := &radiussrv.Server{
		Keycloak:         kc,
		Clients:          clients,
		ScopeRadiusMap:   keycloakConfig.ScopeRadiusMap,
		OTPChallengeMsg:  keycloakConfig.OTPChallengeMessage,
		DisableMsgAuth:   disableMessageAuthenticator,
		DisableChallenge: disableChallengeResponse,
		Debug:            debug,
		MSCHAPEnabled:    mschapEnabled,
		PAPEnabled:       papEnabled,
	}
	listenAddr := keycloakConfig.ListenAddr
	if listenAddr == "" {
		listenAddr = "0.0.0.0:1812"
	}
	if debug {
		log.Printf("[DEBUG] Listening on %s", listenAddr)
	}
	if err := srv.ListenAndServe(listenAddr); err != nil {
		log.Fatalf("RADIUS server error: %v", err)
	}
}
