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

package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	auth "keyrad/auth"
)

const Version = "1.0.0"
const Author = "Marco Moenig <marco@sec73.io>"

const MessageAuthenticatorType = 80

var keycloakConfig KeycloakConfig
var insecureSkipTLSVerify bool
var disableMessageAuthenticator bool // New global flag
var disableChallengeResponse bool    // New global flag
var scopeRadiusMap ScopeRadiusMapping
var otpChallengeMessage string // global

type KeycloakConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Realm        string
	APIURL       string // Base URL for Keycloak REST API
}

type KeycloakConfigYAML struct {
	TokenURL              string             `yaml:"token_url"`
	ClientID              string             `yaml:"client_id"`
	ClientSecret          string             `yaml:"client_secret"`
	Realm                 string             `yaml:"realm"`
	APIURL                string             `yaml:"api_url"`
	InsecureSkipTLSVerify bool               `yaml:"insecure_skip_tls_verify"`
	ScopeRadiusMap        ScopeRadiusMapping `yaml:"scope_radius_map"`
	OTPChallengeMessage   string             `yaml:"otp_challenge_message"` // New: configurable OTP message
}

type ClientConfig struct {
	Secret    string
	ShortName string
	IPAddr    string // New: explicit ipaddr field
}

type ScopeRadiusMapping map[string]struct {
	Attribute int    `yaml:"attribute"`
	Value     string `yaml:"value"`
}

type keycloakAPI struct{}

func (k *keycloakAPI) GetAdminToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", keycloakConfig.ClientID)
	data.Set("client_secret", keycloakConfig.ClientSecret)
	client := getHTTPClient()
	resp, err := client.PostForm(keycloakConfig.TokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("keycloak admin token error: %s", string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token in admin token response: %s", string(body))
	}
	return token, nil
}

func (k *keycloakAPI) AuthenticateWithKeycloak(username, password, otp string) (bool, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", keycloakConfig.ClientID)
	data.Set("client_secret", keycloakConfig.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if otp != "" {
		data.Set("totp", otp)
	}
	client := getHTTPClient()
	resp, err := client.PostForm(keycloakConfig.TokenURL, data)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("keycloak token error: %s", string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}
	_, ok := result["access_token"]
	return ok, nil
}

func (k *keycloakAPI) GetConfig() auth.KeycloakConfig {
	return auth.KeycloakConfig{
		TokenURL:     keycloakConfig.TokenURL,
		ClientID:     keycloakConfig.ClientID,
		ClientSecret: keycloakConfig.ClientSecret,
		Realm:        keycloakConfig.Realm,
		APIURL:       keycloakConfig.APIURL,
	}
}

func (k *keycloakAPI) GetHTTPClient() *http.Client {
	return getHTTPClient()
}

func (k *keycloakAPI) GetUserScopes(username string) ([]string, error) {
	// Get a user token with password grant (simulate as in AuthenticateWithKeycloak, but just get scopes)
	// For demo, just return []string{"example"} or parse from token if needed
	return []string{}, nil // TODO: implement real scope extraction from token
}

// Load KeycloakConfig from a YAML file
func loadKeycloakConfigFromYAML(path string) (KeycloakConfig, error) {
	var cfg KeycloakConfigYAML
	f, err := os.Open(path)
	if err != nil {
		return KeycloakConfig{}, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return KeycloakConfig{}, err
	}
	insecureSkipTLSVerify = cfg.InsecureSkipTLSVerify
	scopeRadiusMap = cfg.ScopeRadiusMap
	otpChallengeMessage = cfg.OTPChallengeMessage
	if otpChallengeMessage == "" {
		otpChallengeMessage = "Enter OTP code" // default
	}
	return KeycloakConfig{
		TokenURL:     cfg.TokenURL,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Realm:        cfg.Realm,
		APIURL:       cfg.APIURL,
	}, nil
}

// Helper to get an http.Client with optional TLS verification
func getHTTPClient() *http.Client {
	if insecureSkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{Transport: tr}
	}
	return http.DefaultClient
}

// Parse clients.conf and return a map of allowed client IPs/CIDRs to ClientConfig
func parseClientsConf(path string) (map[string]ClientConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	clients := make(map[string]ClientConfig)
	var currentClient string
	var currentConfig ClientConfig
	inClient := false
	scanner := bufio.NewScanner(file)
	clientRe := regexp.MustCompile(`^client\s+([^\s{]+)\s*{`)
	secretRe := regexp.MustCompile(`^\s*secret\s*=\s*(\S+)`)
	shortnameRe := regexp.MustCompile(`^\s*shortname\s*=\s*(\S+)`)
	ipaddrRe := regexp.MustCompile(`^\s*ipaddr\s*=\s*(\S+)`)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !inClient {
			if m := clientRe.FindStringSubmatch(line); m != nil {
				currentClient = m[1]
				currentConfig = ClientConfig{}
				inClient = true
			}
			continue
		}
		if line == "}" {
			// Use ipaddr if set, else use block name
			key := currentConfig.IPAddr
			if key == "" {
				key = currentClient
			}
			clients[key] = currentConfig
			inClient = false
			continue
		}
		if m := secretRe.FindStringSubmatch(line); m != nil {
			currentConfig.Secret = m[1]
		}
		if m := shortnameRe.FindStringSubmatch(line); m != nil {
			currentConfig.ShortName = m[1]
		}
		if m := ipaddrRe.FindStringSubmatch(line); m != nil {
			currentConfig.IPAddr = m[1]
		}
	}
	return clients, scanner.Err()
}

// Find the matching client config for a given remote address
func getClientSecretForAddr(clients map[string]ClientConfig, addr net.Addr) (string, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return "", false
	}
	for key, cfg := range clients {
		match := key
		if cfg.IPAddr != "" {
			match = cfg.IPAddr
		}
		// Try as CIDR
		_, ipnet, err := net.ParseCIDR(match)
		if err == nil {
			if ipnet.Contains(udpAddr.IP) {
				return cfg.Secret, true
			}
			continue
		}
		// Try as single IP
		if net.ParseIP(match) != nil && net.ParseIP(match).Equal(udpAddr.IP) {
			return cfg.Secret, true
		}
	}
	return "", false
}

func handleRadiusPacket(packet *radius.Packet, addr net.Addr, conn *net.UDPConn, secret []byte) {
	keycloak := &keycloakAPI{}
	otpAuth := &auth.OTPAuthenticator{Keycloak: keycloak}

	// Check for Message-Authenticator (RFC 3579)
	if !disableMessageAuthenticator {
		ma := packet.Attributes.Get(MessageAuthenticatorType)
		if ma != nil {
			if !verifyMessageAuthenticator(packet, secret) {
				log.Printf("Invalid Message-Authenticator from %v", addr)
				resp := packet.Response(radius.CodeAccessReject)
				addMessageAuthenticator(resp, secret)
				if b, err := resp.Encode(); err == nil {
					conn.WriteTo(b, addr)
				}
				return
			}
		}
	}

	// --- Challenge-response state tracking ---
	// Use a map to store state -> (username, password) for OTP challenge
	// (in production, use a time-limited cache)
	var (
		challengeStateStore = getChallengeStateStore()
	)

	username := rfc2865.UserName_GetString(packet)
	password := rfc2865.UserPassword_GetString(packet)
	state := packet.Attributes.Get(24) // State attribute (type 24)

	if username == "" {
		resp := packet.Response(radius.CodeAccessReject)
		addMessageAuthenticator(resp, secret)
		if b, err := resp.Encode(); err == nil {
			conn.WriteTo(b, addr)
		}
		return
	}

	hasOTP, _ := otpAuth.UserHasOTP(username)

	if disableChallengeResponse && hasOTP {
		// Accept password+otp in User-Password, authenticate in one step
		// Split last 6 digits as OTP, rest as password
		pass := password
		otp := ""
		if len(password) > 6 && regexp.MustCompile(`^[0-9]{6}$`).MatchString(password[len(password)-6:]) {
			pass = password[:len(password)-6]
			otp = password[len(password)-6:]
		}
		ok, err := otpAuth.Authenticate(username, pass, otp)
		resp := packet.Response(radius.CodeAccessReject)
		if ok && err == nil {
			resp = packet.Response(radius.CodeAccessAccept)
			if tokenScopes, err := keycloak.GetUserScopes(username); err == nil {
				addScopeRadiusAttributes(resp, tokenScopes)
			}
		}
		addMessageAuthenticator(resp, secret)
		if b, err := resp.Encode(); err == nil {
			conn.WriteTo(b, addr)
		}
		return
	}

	if state != nil && len(state) > 0 {
		// This is a response to a previous challenge
		// Look up the original username/password for this state
		orig, ok := challengeStateStore.Get(string(state))
		if !ok || orig.Username != username {
			log.Printf("Invalid or expired challenge state for user %s", username)
			resp := packet.Response(radius.CodeAccessReject)
			addMessageAuthenticator(resp, secret)
			if b, err := resp.Encode(); err == nil {
				conn.WriteTo(b, addr)
			}
			return
		}
		// Now treat password as OTP
		otp := password
		pass := orig.Password
		ok, err := otpAuth.Authenticate(username, pass, otp)
		challengeStateStore.Delete(string(state)) // Always delete after attempt
		if err != nil {
			log.Printf("Auth error (challenge): %v", err)
			resp := packet.Response(radius.CodeAccessReject)
			addMessageAuthenticator(resp, secret)
			if b, err := resp.Encode(); err == nil {
				conn.WriteTo(b, addr)
			}
			return
		}
		resp := packet.Response(radius.CodeAccessReject)
		if ok {
			resp = packet.Response(radius.CodeAccessAccept)
		}
		addMessageAuthenticator(resp, secret)
		if b, err := resp.Encode(); err == nil {
			conn.WriteTo(b, addr)
		}
		return
	}

	hasOTP, _ = otpAuth.UserHasOTP(username)
	if hasOTP {
		// First step: send Access-Challenge, ask for OTP
		challengeState := generateRandomState()
		challengeStateStore.Set(challengeState, challengeSession{Username: username, Password: password})
		resp := packet.Response(radius.CodeAccessChallenge)
		resp.Attributes.Set(18, []byte(otpChallengeMessage)) // Reply-Message (type 18)
		resp.Attributes.Set(24, []byte(challengeState))      // State (type 24)
		addMessageAuthenticator(resp, secret)
		if b, err := resp.Encode(); err == nil {
			conn.WriteTo(b, addr)
		}
		return
	}
	// Fallback: try OTP, then password
	ok, err := otpAuth.Authenticate(username, password, "")
	if !ok && err == nil {
		ok, err = keycloak.AuthenticateWithKeycloak(username, password, "")
	}
	if err != nil {
		log.Printf("Auth error: %v", err)
		resp := packet.Response(radius.CodeAccessReject)
		addMessageAuthenticator(resp, secret)
		if b, err := resp.Encode(); err == nil {
			conn.WriteTo(b, addr)
		}
		return
	}
	resp := packet.Response(radius.CodeAccessReject)
	if ok {
		resp = packet.Response(radius.CodeAccessAccept)
		// --- Scope to RADIUS attribute mapping ---
		if tokenScopes, err := keycloak.GetUserScopes(username); err == nil {
			addScopeRadiusAttributes(resp, tokenScopes)
		}
	}
	addMessageAuthenticator(resp, secret)
	if b, err := resp.Encode(); err == nil {
		conn.WriteTo(b, addr)
	}
}

// --- Challenge state store (simple in-memory, not persistent) ---
type challengeSession struct {
	Username string
	Password string
}

type challengeStateStoreType struct {
	m map[string]challengeSession
}

var globalChallengeStateStore *challengeStateStoreType

func getChallengeStateStore() *challengeStateStoreType {
	if globalChallengeStateStore == nil {
		globalChallengeStateStore = &challengeStateStoreType{m: make(map[string]challengeSession)}
	}
	return globalChallengeStateStore
}

func (s *challengeStateStoreType) Get(state string) (challengeSession, bool) {
	sess, ok := s.m[state]
	return sess, ok
}

func (s *challengeStateStoreType) Set(state string, sess challengeSession) {
	s.m[state] = sess
}

func (s *challengeStateStoreType) Delete(state string) {
	delete(s.m, state)
}

// Generate a random state string (16 bytes hex)
func generateRandomState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback to pseudo-random
		for i := range b {
			b[i] = byte(65 + i)
		}
	}
	return fmt.Sprintf("%x", b)
}

// Add Message-Authenticator attribute to a response packet
func addMessageAuthenticator(pkt *radius.Packet, secret []byte) {
	if disableMessageAuthenticator {
		return
	}
	// Add a placeholder 16-byte zero value
	pkt.Attributes.Set(MessageAuthenticatorType, make([]byte, 16))
	// Calculate HMAC-MD5 over the packet with the secret
	hash := computeMessageAuthenticator(pkt, secret)
	pkt.Attributes.Set(MessageAuthenticatorType, hash)
}

// Verify Message-Authenticator attribute in a request packet
func verifyMessageAuthenticator(pkt *radius.Packet, secret []byte) bool {
	ma := pkt.Attributes.Get(MessageAuthenticatorType)
	if ma == nil || len(ma) != 16 {
		return false
	}
	// Save original value
	orig := make([]byte, 16)
	copy(orig, ma)
	// Set to zero for calculation
	for i := range ma {
		ma[i] = 0
	}
	hash := computeMessageAuthenticator(pkt, secret)
	// Restore original value
	copy(ma, orig)
	return hmac.Equal(hash, orig)
}

// Compute HMAC-MD5 for Message-Authenticator
func computeMessageAuthenticator(pkt *radius.Packet, secret []byte) []byte {
	b, _ := pkt.Encode()
	h := hmac.New(md5.New, secret)
	h.Write(b)
	return h.Sum(nil)
}

func addScopeRadiusAttributes(pkt *radius.Packet, scopes []string) {
	for _, scope := range scopes {
		if mapping, ok := scopeRadiusMap[scope]; ok {
			pkt.Attributes.Set(radius.Type(mapping.Attribute), []byte(mapping.Value))
			continue
		}
		// Regexp support: keys starting with 're:'
		for k, mapping := range scopeRadiusMap {
			if strings.HasPrefix(k, "re:") {
				pattern := k[3:]
				if matched, err := regexp.MatchString(pattern, scope); err == nil && matched {
					pkt.Attributes.Set(radius.Type(mapping.Attribute), []byte(mapping.Value))
				}
			}
		}
	}
}

func main() {
	var keycloakConfigPath string
	var clientsConfPath string
	var showVersion bool
	flag.StringVar(&keycloakConfigPath, "c", "keyrad.yaml", "Path to keyrad.yaml config file")
	flag.StringVar(&clientsConfPath, "r", "clients.conf", "Path to clients.conf file")
	flag.BoolVar(&disableMessageAuthenticator, "disable-message-authenticator", false, "Disable Message-Authenticator verification and generation")
	flag.BoolVar(&disableChallengeResponse, "disable-challenge-response", false, "Disable RADIUS challenge-response and use <password><otp> style for OTP users")
	flag.BoolVar(&showVersion, "version", false, "Show version and author information")
	flag.Parse()
	if showVersion {
		fmt.Printf("keyrad version %s\nAuthor: %s\n", Version, Author)
		os.Exit(0)
	}
	// Load Keycloak config from YAML file
	cfg, err := loadKeycloakConfigFromYAML(keycloakConfigPath)
	if err != nil {
		log.Fatalf("Failed to load %s: %v", keycloakConfigPath, err)
	}
	keycloakConfig = cfg

	clients, err := parseClientsConf(clientsConfPath)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", clientsConfPath, err)
	}
	addr := ":1812" // Default RADIUS port
	log.Printf("Starting RADIUS server on %s", addr)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer conn.Close()

	// --- Async RADIUS request handling ---
	const workerCount = 8 // Number of concurrent workers, can be made configurable
	type radiusJob struct {
		packetData []byte
		remoteAddr net.Addr
	}
	jobs := make(chan radiusJob, 128)

	// Worker pool
	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobs {
				secret, ok := getClientSecretForAddr(clients, job.remoteAddr)
				if !ok {
					log.Printf("Rejected packet from unauthorized client: %v", job.remoteAddr)
					continue
				}
				packet, err := radius.Parse(job.packetData, []byte(secret))
				if err != nil {
					log.Printf("Failed to parse RADIUS packet: %v", err)
					continue
				}
				go handleRadiusPacket(packet, job.remoteAddr, conn, []byte(secret))
			}
		}()
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}
		// Copy packet data to avoid race
		packetCopy := make([]byte, n)
		copy(packetCopy, buf[:n])
		jobs <- radiusJob{packetData: packetCopy, remoteAddr: remoteAddr}
	}
}
