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
package radiussrv

import (
	"bytes"
	"net"
	"testing"

	"go.uber.org/zap"
	"layeh.com/radius"
)

func TestEncodeAttributeValue(t *testing.T) {
	if got := string(encodeAttributeValue("hello", "")); got != "hello" {
		t.Fatalf("string: %q", got)
	}
	if got := encodeAttributeValue("42", "integer"); !bytes.Equal(got, []byte{0, 0, 0, 42}) {
		t.Fatalf("integer: %#v", got)
	}
	if got := encodeAttributeValue("badint", "integer"); string(got) != "badint" {
		t.Fatalf("integer fallback: %q", got)
	}
	if got := encodeAttributeValue("192.0.2.1", "ipaddr"); !net.IPv4(192, 0, 2, 1).Equal(net.IP(got)) {
		t.Fatalf("ipaddr: %#v", got)
	}
}

func TestCompileScopeRules_InvalidRegexSkipped(t *testing.T) {
	s := &Server{
		ScopeRadiusMap: ScopeRadiusMapping{
			"re:[(": {{Attribute: 18, Value: "x"}},
			"good":  {{Attribute: 18, Value: "y"}},
		},
		Logger: zap.NewNop(),
	}
	s.compileScopeRules()
	if len(s.scopeRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(s.scopeRules))
	}
	if s.scopeRules[0].literal != "good" {
		t.Fatalf("expected literal rule good, got %#v", s.scopeRules[0])
	}
}

func TestAddScopeAttributes_LiteralMatch(t *testing.T) {
	secret := []byte("secret")
	s := &Server{
		ScopeRadiusMap: ScopeRadiusMapping{
			"vpn": {{Attribute: 18, Value: "ok", ValueType: "string"}},
		},
		Logger: zap.NewNop(),
	}
	s.compileScopeRules()
	resp := radius.New(radius.CodeAccessAccept, secret)
	s.addScopeAttributes(resp, []string{"other", "vpn"}, "")
	val := resp.Get(18)
	if string(val) != "ok" {
		t.Fatalf("Reply-Message: %q", val)
	}
}

func TestAddScopeAttributes_RegexMatch(t *testing.T) {
	secret := []byte("secret")
	s := &Server{
		ScopeRadiusMap: ScopeRadiusMapping{
			"re:^radius-": {{Attribute: 18, Value: "hit"}},
		},
		Logger: zap.NewNop(),
	}
	s.compileScopeRules()
	resp := radius.New(radius.CodeAccessAccept, secret)
	s.addScopeAttributes(resp, []string{"radius-user"}, "")
	val := resp.Get(18)
	if string(val) != "hit" {
		t.Fatalf("got %q", val)
	}
}

// TestAddScopeAttributes_VendorSpecific verifies the wire encoding of VSAs for common
// IANA vendor IDs (MikroTik, Cisco, Microsoft, Ubiquiti) and value types.
func TestAddScopeAttributes_VendorSpecific(t *testing.T) {
	cases := []struct {
		name     string
		vendor   uint32
		attr     int
		value    string
		valueTyp string
		wantData []byte
	}{
		{"mikrotik-group", 14988, 3, "full", "string", []byte("full")},
		{"mikrotik-rate-limit", 14988, 8, "10M/10M", "string", []byte("10M/10M")},
		{"cisco-avpair", 9, 1, "ip:pool=vpnpool", "string", []byte("ip:pool=vpnpool")},
		{"microsoft-mppe", 311, 12, "secretkey", "string", []byte("secretkey")},
		{"ubiquiti-default", 41112, 1, "default", "string", []byte("default")},
		{"integer-value", 14988, 99, "42", "integer", []byte{0, 0, 0, 42}},
		{"ipaddr-value", 9, 8, "192.0.2.7", "ipaddr", []byte{192, 0, 2, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret := []byte("secret")
			s := &Server{
				ScopeRadiusMap: ScopeRadiusMapping{
					"g": {{Vendor: tc.vendor, Attribute: tc.attr, Value: tc.value, ValueType: tc.valueTyp}},
				},
				Logger: zap.NewNop(),
			}
			s.compileScopeRules()
			resp := radius.New(radius.CodeAccessAccept, secret)
			s.addScopeAttributes(resp, []string{"g"}, "")

			raw := resp.Get(26) // Vendor-Specific
			if raw == nil {
				t.Fatalf("no VSA (type 26) returned")
			}
			vendorID, val, err := radius.VendorSpecific(raw)
			if err != nil {
				t.Fatalf("VendorSpecific decode: %v", err)
			}
			if vendorID != tc.vendor {
				t.Fatalf("vendor id: got %d want %d", vendorID, tc.vendor)
			}
			inner := []byte(val) // sub-attribute: [type][len][value]
			if len(inner) != 2+len(tc.wantData) {
				t.Fatalf("inner length: got %d want %d (%#v)", len(inner), 2+len(tc.wantData), inner)
			}
			if inner[0] != byte(tc.attr) {
				t.Fatalf("inner type: got %d want %d", inner[0], tc.attr)
			}
			if inner[1] != byte(2+len(tc.wantData)) {
				t.Fatalf("inner length field: got %d want %d", inner[1], 2+len(tc.wantData))
			}
			if !bytes.Equal(inner[2:], tc.wantData) {
				t.Fatalf("inner value: got %#v want %#v", inner[2:], tc.wantData)
			}
		})
	}
}

// TestAddScopeAttributes_MultipleMatchingRules verifies every matching rule contributes its
// attributes (literal + regex + no-match), independent of map iteration order.
func TestAddScopeAttributes_MultipleMatchingRules(t *testing.T) {
	secret := []byte("secret")
	s := &Server{
		ScopeRadiusMap: ScopeRadiusMapping{
			"vpn":     {{Attribute: 18, Value: "reply-vpn"}},   // Reply-Message
			"re:^vpn": {{Attribute: 11, Value: "fid-vpn"}},     // Filter-Id
			"other":   {{Attribute: 18, Value: "reply-other"}}, // must NOT match
		},
		Logger: zap.NewNop(),
	}
	s.compileScopeRules()
	resp := radius.New(radius.CodeAccessAccept, secret)
	// "vpn" matches the literal rule; "vpn-user" matches the regex rule; "other" rule stays out.
	s.addScopeAttributes(resp, []string{"vpn-user", "vpn"}, "")
	if got := string(resp.Get(18)); got != "reply-vpn" {
		t.Fatalf("Reply-Message from literal rule: got %q", got)
	}
	if got := string(resp.Get(11)); got != "fid-vpn" {
		t.Fatalf("Filter-Id from regex rule: got %q", got)
	}
	// No attributes for the "other" rule should appear: attr 18 must only carry "reply-vpn".
	count18 := 0
	for _, avp := range resp.Attributes {
		if avp.Type == 18 && string(avp.Attribute) == "reply-other" {
			count18++
		}
	}
	if count18 != 0 {
		t.Fatal("non-matching 'other' rule contributed an attribute")
	}
}

// TestAddScopeAttributes_LiteralNoPrefixMatch confirms literal rules require an exact match.
func TestAddScopeAttributes_LiteralNoPrefixMatch(t *testing.T) {
	secret := []byte("secret")
	s := &Server{
		ScopeRadiusMap: ScopeRadiusMapping{
			"vpn": {{Attribute: 18, Value: "hit"}},
		},
		Logger: zap.NewNop(),
	}
	s.compileScopeRules()
	resp := radius.New(radius.CodeAccessAccept, secret)
	s.addScopeAttributes(resp, []string{"vpn-user", "myvpn"}, "")
	if val := resp.Get(18); val != nil {
		t.Fatalf("literal rule matched a prefix/suffix role, got %q", val)
	}
}

// TestEncodeAttributeValue_ValueTypeFallbacks locks in the fallback behaviour for malformed
// integer/ipaddr values and unknown value types (invalid value_type is rejected earlier by
// Config validation, but the encoder must not panic or emit wrong-typed bytes).
func TestEncodeAttributeValue_ValueTypeFallbacks(t *testing.T) {
	// integer overflow beyond uint32 falls back to the raw string.
	if got := string(encodeAttributeValue("4294967296", "integer")); got != "4294967296" {
		t.Fatalf("integer overflow fallback: %q", got)
	}
	// malformed IP falls back to the raw string.
	if got := string(encodeAttributeValue("not-an-ip", "ipaddr")); got != "not-an-ip" {
		t.Fatalf("ipaddr fallback: %q", got)
	}
	// unknown value types are treated as plain strings.
	if got := string(encodeAttributeValue("hello", "bogus")); got != "hello" {
		t.Fatalf("unknown value_type fallback: %q", got)
	}
	// empty value type behaves as string.
	if got := string(encodeAttributeValue("hello", "")); got != "hello" {
		t.Fatalf("empty value_type fallback: %q", got)
	}
}
