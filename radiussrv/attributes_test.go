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
