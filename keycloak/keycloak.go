package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// AuthenticateUser checks username/password (and optional OTP) against Keycloak
func (k *KeycloakAPI) AuthenticateUser(username, password string, otp ...string) (bool, error) {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", k.ClientID)
	data.Set("client_secret", k.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if len(otp) > 0 && otp[0] != "" {
		data.Set("totp", otp[0])
	}
	fmt.Printf("[DEBUG] Keycloak Auth Request: %s\n", data.Encode())
	fmt.Printf("[DEBUG] Keycloak Token URL: %s\n", k.TokenURL)
	resp, err := k.HTTPClient.PostForm(k.TokenURL, data)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("[DEBUG] Keycloak Response Status: %d\n", resp.StatusCode)
	fmt.Printf("[DEBUG] Keycloak Response Body: %s\n", string(body))
	if resp.StatusCode == 200 {
		return true, nil
	}
	return false, fmt.Errorf("keycloak auth failed: %s", string(body))
}

// HasOTP returns true if the user has an OTP authenticator assigned in Keycloak
func (k *KeycloakAPI) HasOTP(username string) (bool, error) {
	token, err := k.GetAdminToken()
	if err != nil {
		return false, err
	}
	url := fmt.Sprintf("%s/users?username=%s", k.APIURL, url.QueryEscape(username))
	req, _ := http.NewRequest("GET", url, nil)
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
	req, _ = http.NewRequest("GET", credURL, nil)
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
