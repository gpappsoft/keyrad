package keycloak

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type KeycloakAPI struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Realm        string
	APIURL       string
	HTTPClient   *http.Client
}

func (k *KeycloakAPI) GetAdminToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	resp, err := k.HTTPClient.PostForm(k.TokenURL, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("keycloak admin token error: status %d", resp.StatusCode)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("no access_token in admin token response")
	}
	return token, nil
}

// AuthenticateUser checks username/password (and optional OTP) against Keycloak.
// Returns (ok, userRoles, error) where userRoles are extracted from the JWT access token
// and include realm roles, groups, and OAuth2 scopes.
func (k *KeycloakAPI) AuthenticateUser(username, password string, otp ...string) (bool, []string, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if len(otp) > 0 && otp[0] != "" {
		data.Set("totp", otp[0])
	}
	fmt.Printf("[DEBUG] Keycloak Auth Request for user: %s\n", username)
	fmt.Printf("[DEBUG] Keycloak Token URL: %s\n", k.TokenURL)
	resp, err := k.HTTPClient.PostForm(k.TokenURL, data)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("[DEBUG] Keycloak Response Status: %d\n", resp.StatusCode)
	if resp.StatusCode == 200 {
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

// extractRolesFromJWT decodes the JWT payload and extracts realm roles, groups, and scopes.
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
	var claims struct {
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		Groups []string `json:"groups"`
		Scope  string   `json:"scope"`
	}
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

// HasOTP returns true if the user has an OTP authenticator assigned in Keycloak
func (k *KeycloakAPI) HasOTP(username string) (bool, error) {
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
	var users []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil || len(users) == 0 {
		return false, fmt.Errorf("user not found or decode error")
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

// ...other Keycloak methods...
