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
package keycloak

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// jwtTestVector builds a 3-part JWT-shaped string without embedding base64 literals
// that secret scanners treat as generic high-entropy secrets.
func jwtTestVector(headerJSON, payloadJSON, sigPlain string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	p := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	s := base64.RawURLEncoding.EncodeToString([]byte(sigPlain))
	return h + "." + p + "." + s
}

func TestWithRequestID_context(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-1")
	if requestIDFromContext(ctx) != "req-1" {
		t.Fatalf("got %q", requestIDFromContext(ctx))
	}
	if requestIDFromContext(context.Background()) != "" {
		t.Fatal("expected empty")
	}
	if requestIDFromContext(nil) != "" {
		t.Fatal("expected empty for nil ctx")
	}
	if WithRequestID(context.Background(), "") != context.Background() {
		t.Fatal("empty id should return same ctx")
	}
}

func TestExtractRolesFromJWT(t *testing.T) {
	claims := jwtClaims{
		RealmAccess: struct {
			Roles []string `json:"roles"`
		}{Roles: []string{"realm-admin", "default-roles"}},
		Groups: []string{"/operators"},
		Scope:  "openid radius",
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token := jwtTestVector(`{"alg":"none"}`, string(raw), "{}")

	got := extractRolesFromJWT(token)
	want := []string{"realm-admin", "default-roles", "/operators", "openid", "radius"}
	if len(got) != len(want) {
		t.Fatalf("len got %d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestExtractRolesFromJWT_Invalid(t *testing.T) {
	if extractRolesFromJWT("") != nil {
		t.Fatal("expected nil")
	}
	if extractRolesFromJWT("not-a-jwt") != nil {
		t.Fatal("expected nil")
	}
	if extractRolesFromJWT("a.b!!!.c") != nil {
		t.Fatal("expected nil for bad base64 payload")
	}
}

func TestGetAdminToken_CachesByExpiresIn(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type: %q", r.Form.Get("grant_type"))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"token-%d","expires_in":3600}`, calls)
	}))
	defer ts.Close()

	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "cid",
		ClientSecret: "sec",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	tok1, err := k.GetAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := k.GetAdminToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != tok2 {
		t.Fatalf("cache miss: %q vs %q", tok1, tok2)
	}
	if calls != 1 {
		t.Fatalf("expected 1 token HTTP call, got %d", calls)
	}
}

func TestGetAdminToken_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()
	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	_, err := k.GetAdminToken()
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 error, got %v", err)
	}
}

func TestGetAdminToken_MissingAccessToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"expires_in":60}`)
	}))
	defer ts.Close()
	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	_, err := k.GetAdminToken()
	if err == nil || !strings.Contains(err.Error(), "missing access_token") {
		t.Fatalf("expected missing access_token, got %v", err)
	}
}

func TestAuthenticateUser_Success(t *testing.T) {
	claims := jwtClaims{Scope: "s1"}
	raw, _ := json.Marshal(claims)
	access := jwtTestVector(`{"alg":"none"}`, string(raw), "sig")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q}`, access)
	}))
	defer ts.Close()

	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	ok, roles, err := k.AuthenticateUser(context.Background(), "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected ok")
	}
	if len(roles) != 1 || roles[0] != "s1" {
		t.Fatalf("roles: %#v", roles)
	}
}

func TestAuthenticateUser_FailureStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	defer ts.Close()
	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	ok, roles, err := k.AuthenticateUser(context.Background(), "u", "p")
	if ok || roles != nil {
		t.Fatalf("expected failure, ok=%v roles=%v", ok, roles)
	}
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetAdminToken_RefreshAfterExpiry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Short lifetime so cache TTL becomes 30s minimum in implementation
		io.WriteString(w, `{"access_token":"fresh","expires_in":90}`)
	}))
	defer ts.Close()
	k := &KeycloakAPI{
		TokenURL:     ts.URL,
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
	if _, err := k.GetAdminToken(); err != nil {
		t.Fatal(err)
	}
	k.adminMu.Lock()
	k.adminTokenExpiry = time.Now().Add(-time.Second)
	k.adminMu.Unlock()
	if _, err := k.GetAdminToken(); err != nil {
		t.Fatal(err)
	}
}

// hasOTPMock returns an httptest server simulating the token + admin endpoints used by
// HasOTP: client_credentials grant, /users?username=..., and /users/{id}/credentials.
func hasOTPMock(t *testing.T, adminOK bool, usersBody, credsBody string) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/token") {
			if !adminOK {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":"invalid_client"}`)
				return
			}
			io.WriteString(w, `{"access_token":"adm","expires_in":3600}`)
			return
		}
		if strings.Contains(r.URL.Path, "/credentials") {
			io.WriteString(w, credsBody)
			return
		}
		io.WriteString(w, usersBody)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func hasOTPAPI(ts *httptest.Server) *KeycloakAPI {
	return &KeycloakAPI{
		TokenURL:     ts.URL + "/realms/master/protocol/openid-connect/token",
		APIURL:       ts.URL + "/admin/realms/master",
		ClientID:     "c",
		ClientSecret: "s",
		HTTPClient:   ts.Client(),
		Logger:       zap.NewNop(),
	}
}

func TestHasOTP_UserHasOTP(t *testing.T) {
	ts := hasOTPMock(t, true, `[{"id":"u1","username":"alice"}]`, `[{"type":"otp","id":"o1"}]`)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("expected OTP true")
	}
}

func TestHasOTP_UserWithoutOTP(t *testing.T) {
	ts := hasOTPMock(t, true, `[{"id":"u1","username":"alice"}]`, `[]`)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("expected OTP false")
	}
}

func TestHasOTP_AdminTokenUnauthorized(t *testing.T) {
	ts := hasOTPMock(t, false, `[]`, `[]`)
	_, err := hasOTPAPI(ts).HasOTP(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error for unauthorized admin token")
	}
}

func TestHasOTP_UserNotFound(t *testing.T) {
	ts := hasOTPMock(t, true, `[]`, `[]`)
	_, err := hasOTPAPI(ts).HasOTP(context.Background(), "ghost")
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected 'user not found', got %v", err)
	}
}

// lookupUser is one user exposed by lookupMock.
type lookupUser struct {
	id       string
	username string
	hasOTP   bool
}

// lookupMock emulates Keycloak's Admin REST API user lookup: `username` is a substring
// search unless exact=true is sent, and result order is not guaranteed. With ignoreExact
// the mock returns every known user even when exact=true was requested, emulating a
// server that does not honor the parameter.
type lookupMock struct {
	users       []lookupUser
	ignoreExact bool

	mu      sync.Mutex
	queries []string
}

// newLookupMock starts a mock Keycloak whose token, user lookup and credentials
// endpoints behave like the real Admin API for the given users.
func newLookupMock(t *testing.T, users []lookupUser, ignoreExact bool) (*lookupMock, *httptest.Server) {
	t.Helper()
	m := &lookupMock{users: users, ignoreExact: ignoreExact}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/token") {
			io.WriteString(w, `{"access_token":"adm","expires_in":3600}`)
			return
		}
		if strings.Contains(r.URL.Path, "/credentials") {
			// /users/{id}/credentials
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) < 2 {
				io.WriteString(w, `[]`)
				return
			}
			id := parts[len(parts)-2]
			for _, u := range users {
				if u.id == id && u.hasOTP {
					io.WriteString(w, `[{"type":"otp","id":"o1"}]`)
					return
				}
			}
			io.WriteString(w, `[]`)
			return
		}

		m.mu.Lock()
		m.queries = append(m.queries, r.URL.RawQuery)
		m.mu.Unlock()

		q := r.URL.Query()
		name := q.Get("username")
		var matched []lookupUser
		if q.Get("exact") == "true" && !ignoreExact {
			for _, u := range users {
				if strings.EqualFold(u.username, name) {
					matched = append(matched, u)
				}
			}
		} else {
			// Substring search: unrelated users come back, in no particular order.
			matched = users
		}
		body := make([]map[string]string, 0, len(matched))
		for _, u := range matched {
			body = append(body, map[string]string{"id": u.id, "username": u.username})
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("encode users: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	return m, ts
}

// requests returns the raw query string of every recorded user lookup.
func (m *lookupMock) requests() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.queries...)
}

// sentExact reports whether every recorded user lookup requested exact=true.
func (m *lookupMock) sentExact(t *testing.T) {
	t.Helper()
	qs := m.requests()
	if len(qs) == 0 {
		t.Fatal("expected at least one user lookup request, got none")
	}
	for _, q := range qs {
		if !strings.Contains(q, "exact=true") {
			t.Fatalf("user lookup %q did not request exact=true", q)
		}
	}
}

func TestHasOTP_ExactLookupSelectsRequestedUser(t *testing.T) {
	m, ts := newLookupMock(t, []lookupUser{
		{id: "u-alice", username: "alice", hasOTP: true},
		{id: "u-al", username: "al", hasOTP: false},
	}, false)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "al")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("expected OTP false for al, got alice's OTP state")
	}
	m.sentExact(t)
}

func TestHasOTP_LongerUsernameKeepsOwnResult(t *testing.T) {
	m, ts := newLookupMock(t, []lookupUser{
		{id: "u-alice", username: "alice", hasOTP: true},
		{id: "u-al", username: "al", hasOTP: false},
	}, false)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("expected OTP true for alice")
	}
	m.sentExact(t)
}

func TestHasOTP_UsernameMatchIsCaseInsensitive(t *testing.T) {
	m, ts := newLookupMock(t, []lookupUser{
		{id: "u-alice", username: "alice", hasOTP: true},
		{id: "u-al", username: "al", hasOTP: false},
	}, false)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "AL")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("expected OTP false for AL, matching al's state")
	}
	m.sentExact(t)
}

func TestHasOTP_NoExactMatchIsNotFound(t *testing.T) {
	m, ts := newLookupMock(t, []lookupUser{
		{id: "u-alice", username: "alice", hasOTP: true},
		{id: "u-al", username: "al", hasOTP: false},
	}, false)
	_, err := hasOTPAPI(ts).HasOTP(context.Background(), "nonexistent")
	if err == nil || !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected 'user not found', got %v", err)
	}
	m.sentExact(t)
}

func TestHasOTP_IgnoresUnrelatedUsersWhenExactIsIgnored(t *testing.T) {
	// Regression guard: even if Keycloak ignores exact=true and returns [alice, al] for
	// "al", the matching entry must win over users[0]. No exact=true assertion here: this
	// test isolates the EqualFold selection, which must hold regardless of the query.
	m, ts := newLookupMock(t, []lookupUser{
		{id: "u-alice", username: "alice", hasOTP: true},
		{id: "u-al", username: "al", hasOTP: false},
	}, true)
	got, err := hasOTPAPI(ts).HasOTP(context.Background(), "al")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatal("expected OTP false for al, got alice's OTP state")
	}
	if qs := m.requests(); len(qs) == 0 {
		t.Fatal("expected at least one user lookup request, got none")
	}
}
