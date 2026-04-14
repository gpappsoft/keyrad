// Package keycloak implements an HTTP client for Keycloak token and Admin API
// endpoints used by the RADIUS server (password grant, admin token cache, OTP discovery).
package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// KeycloakAPI holds OAuth2/OpenID settings and an HTTP client for Keycloak.
// Admin access tokens are cached in memory until shortly before expiry.
type KeycloakAPI struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Realm        string
	APIURL       string
	HTTPClient   *http.Client
	Logger       *zap.Logger

	adminMu          sync.Mutex
	adminToken       string
	adminTokenExpiry time.Time
}

type token struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type jwtClaims struct {
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	Groups []string `json:"groups"`
	Scope  string   `json:"scope"`
}

// GetAdminToken requests an access token using the client_credentials grant.
// It returns a cached token when still valid, based on expires_in from Keycloak.
func (k *KeycloakAPI) GetAdminToken() (string, error) {
	k.adminMu.Lock()
	defer k.adminMu.Unlock()
	if k.adminToken != "" && time.Now().Before(k.adminTokenExpiry) {
		return k.adminToken, nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	resp, err := k.HTTPClient.PostForm(k.TokenURL, data)
	if err != nil {
		return "", fmt.Errorf("error send keycloak post from: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak admin token error: status %d", resp.StatusCode)
	}

	var admin token
	err = json.NewDecoder(resp.Body).Decode(&admin)
	if err != nil {
		return "", fmt.Errorf("error decoding keycloak response: %w", err)
	}
	if admin.AccessToken == "" {
		return "", fmt.Errorf("keycloak admin token response missing access_token")
	}

	ttl := 4 * time.Minute
	if admin.ExpiresIn > 0 {
		ttl = time.Duration(admin.ExpiresIn)*time.Second - 60*time.Second
		if ttl < 30*time.Second {
			ttl = 30 * time.Second
		}
	}
	k.adminToken = admin.AccessToken
	k.adminTokenExpiry = time.Now().Add(ttl)
	return k.adminToken, nil
}

func (k *KeycloakAPI) logger(ctx context.Context) *zap.Logger {
	l := k.Logger
	if l == nil {
		l = zap.NewNop()
	}
	if rid := requestIDFromContext(ctx); rid != "" {
		return l.With(zap.String("request_id", rid))
	}
	return l
}

// AuthenticateUser performs the OAuth2 resource-owner password grant against TokenURL.
// On HTTP 200 it returns ok=true and roles from the JWT payload (realm roles, groups, scopes).
// Signature of the JWT is not verified. otp, when non-empty, is sent as the totp form field.
// ctx may carry a request_id (see WithRequestID) for debug log correlation.
func (k *KeycloakAPI) AuthenticateUser(ctx context.Context, username, password string, otp ...string) (bool, []string, error) {
	log := k.logger(ctx)
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if len(otp) > 0 && otp[0] != "" {
		data.Set("totp", otp[0])
	}
	log.Debug("keycloak password grant request", zap.String("username", username))
	resp, err := k.HTTPClient.PostForm(k.TokenURL, data)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	log.Debug("keycloak password grant response", zap.String("username", username), zap.Int("status", resp.StatusCode))

	if resp.StatusCode == http.StatusOK {
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return false, nil, fmt.Errorf("failed to parse keycloak response: %w", err)
		}
		accessToken, _ := result["access_token"].(string)
		roles := extractRolesFromJWT(accessToken)
		return true, roles, nil
	}
	return false, nil, fmt.Errorf("keycloak auth failed: status %d", resp.StatusCode)
}

// extractRolesFromJWT decodes the JWT access token payload (middle segment) without
// signature verification and returns realm roles, groups, and space-separated scopes.
func extractRolesFromJWT(token string) []string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload := parts[1]
	// Add base64 padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil
	}

	var claims jwtClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil
	}
	var roles []string
	roles = append(roles, claims.RealmAccess.Roles...)
	roles = append(roles, claims.Groups...)
	if claims.Scope != "" {
		roles = append(roles, strings.Split(claims.Scope, " ")...)
	}
	return roles
}

// HasOTP reports whether Keycloak lists an OTP-type credential for the user.
// It uses a cached admin token from GetAdminToken and the Admin REST API.
// ctx may carry a request_id (see WithRequestID) for warn log correlation.
func (k *KeycloakAPI) HasOTP(ctx context.Context, username string) (bool, error) {
	log := k.logger(ctx)
	token, err := k.GetAdminToken()
	if err != nil {
		return false, err
	}

	reqURL := fmt.Sprintf("%s/users?username=%s", k.APIURL, url.QueryEscape(username))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create user lookup request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := k.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var users []map[string]interface{}
	err = json.Unmarshal(respBody, &users)
	if err != nil {
		log.Warn("failed to decode user lookup response", zap.String("url", reqURL), zap.Int("status code", resp.StatusCode), zap.Error(err))
		return false, fmt.Errorf("decode error: %w", err)
	}
	if len(users) == 0 {
		return false, fmt.Errorf("user not found")
	}
	userID, _ := users[0]["id"].(string)
	// Get credentials for user
	credURL := fmt.Sprintf("%s/users/%s/credentials", k.APIURL, userID)
	req, err = http.NewRequest("GET", credURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create credentials request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = k.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var creds []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return false, err
	}
	for _, c := range creds {
		typeStr, _ := c["type"].(string)
		if typeStr == "otp" {
			return true, nil
		}
	}
	return false, nil
}
