package radiussrv

import (
	"bytes"
	"net"
	"testing"

	"go.uber.org/zap"
	"layeh.com/radius"
)

func TestNewPacket_RequestID(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	p.Identifier = 7
	p.Authenticator = [16]byte(bytes.Repeat([]byte{1}, 16))
	p.Add(CallingStationIDType, []byte("AA-BB-CC-DD-EE-FF"))
	pkt := newPacket(p, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1812}, nil, []byte("secret"))
	if len(pkt.requestID) != 16 {
		t.Fatalf("request_id hex length: got %d want 16", len(pkt.requestID))
	}
	if pkt.callingStationID != "AA-BB-CC-DD-EE-FF" {
		t.Fatalf("calling_station_id: got %q", pkt.callingStationID)
	}
}

func TestWithRequest(t *testing.T) {
	s := &Server{Logger: zap.NewExample()}
	p := &packet{requestID: "abc123"}
	s.withRequest(p).Info("x")
	s.withRequest(nil).Info("y")

	s2 := &Server{Logger: nil}
	if s2.withRequest(p) == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestUserPassword_InvalidLength(t *testing.T) {
	_, err := radius.UserPassword([]byte{1, 2, 3}, []byte("s"), bytes.Repeat([]byte{1}, 16))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveClientSecret_ExactIPWinsOverBroadCIDR(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	clients := map[string]ClientConfig{
		"10.0.0.0/8":  {Secret: "broad"},
		"10.0.0.5":    {Secret: "exact"},
		"10.0.0.0/24": {Secret: "medium"},
	}
	if got := resolveClientSecret(clients, ip); got != "exact" {
		t.Fatalf("got %q want exact", got)
	}
}

func TestResolveClientSecret_MostSpecificCIDR(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	clients := map[string]ClientConfig{
		"10.0.0.0/8":  {Secret: "broad"},
		"10.0.0.0/24": {Secret: "narrow"},
	}
	if got := resolveClientSecret(clients, ip); got != "narrow" {
		t.Fatalf("got %q want narrow", got)
	}
}
