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

package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type KeycloakAPI interface {
	GetAdminToken() (string, error)
	GetConfig() KeycloakConfig
	GetHTTPClient() *http.Client
}

type KeycloakConfig struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Realm        string
	APIURL       string
}

type OTPAuthenticator struct {
	Keycloak KeycloakAPI
}

func (a *OTPAuthenticator) UserHasOTP(username string) (bool, error) {
	if a.Keycloak == nil {
		return false, fmt.Errorf("Keycloak API not set")
	}
	adminToken, err := a.Keycloak.GetAdminToken()
	if err != nil {
		return false, err
	}
	cfg := a.Keycloak.GetConfig()
	client := a.Keycloak.GetHTTPClient()
	userReq, err := http.NewRequest("GET", fmt.Sprintf("%s/users?username=%s", cfg.APIURL, url.QueryEscape(username)), nil)
	if err != nil {
		return false, err
	}
	userReq.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := client.Do(userReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var users []map[string]interface{}
	if err := json.Unmarshal(body, &users); err != nil || len(users) == 0 {
		return false, fmt.Errorf("user not found or bad response: %v", err)
	}
	userID := users[0]["id"].(string)
	credReq, err := http.NewRequest("GET", fmt.Sprintf("%s/users/%s/credentials", cfg.APIURL, userID), nil)
	if err != nil {
		return false, err
	}
	credReq.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = client.Do(credReq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	var creds []map[string]interface{}
	if err := json.Unmarshal(body, &creds); err != nil {
		return false, err
	}
	for _, cred := range creds {
		if cred["type"] == "otp" {
			return true, nil
		}
	}
	return false, nil
}

func (a *OTPAuthenticator) Authenticate(username, password, otp string) (bool, error) {
	if a.Keycloak == nil {
		return false, fmt.Errorf("Keycloak API not set")
	}
	cfg := a.Keycloak.GetConfig()
	client := a.Keycloak.GetHTTPClient()
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("username", username)
	data.Set("password", password)
	if otp != "" {
		data.Set("totp", otp)
	}
	resp, err := client.PostForm(cfg.TokenURL, data)
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
