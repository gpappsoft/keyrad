package radiussrv

import (
	"errors"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
)

func TestVerifyMessageAuthenticator_requestSignedRoundTrip(t *testing.T) {
	secret := []byte("xyzzy5461")
	p := radius.New(radius.CodeAccessRequest, secret)
	if err := rfc2865.UserName_AddString(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := rfc2869.MessageAuthenticator_Add(p, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeMessageAuthenticatorInPlace(wire, secret, p.Authenticator); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessageAuthenticator(wire, secret); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyMessageAuthenticator_EAPWithoutMA(t *testing.T) {
	secret := []byte("secret")
	p := radius.New(radius.CodeAccessRequest, secret)
	if err := rfc2865.UserName_AddString(p, "u"); err != nil {
		t.Fatal(err)
	}
	p.Add(eapMessageAttrType, []byte{1, 2, 3})
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyMessageAuthenticator(wire, secret)
	if !errors.Is(err, errEAPWithoutMsgAuth) {
		t.Fatalf("got %v want %v", err, errEAPWithoutMsgAuth)
	}
}

func TestVerifyMessageAuthenticator_wrongSecret(t *testing.T) {
	secret := []byte("correctsecret!!")
	p := radius.New(radius.CodeAccessRequest, secret)
	if err := rfc2869.MessageAuthenticator_Add(p, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeMessageAuthenticatorInPlace(wire, secret, p.Authenticator); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMessageAuthenticator(wire, []byte("wrongsecret!!!!")); err == nil {
		t.Fatal("expected mismatch error")
	}
}

func TestEncodeAccessReplyWithMessageAuthenticator_accessAccept(t *testing.T) {
	secret := []byte("testsecret12!!")
	req := radius.New(radius.CodeAccessRequest, secret)
	reqWire, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	reqAuth := req.Authenticator

	resp := radius.New(radius.CodeAccessAccept, secret)
	resp.Identifier = req.Identifier
	resp.Authenticator = reqAuth
	if err := rfc2869.MessageAuthenticator_Add(resp, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	wire, err := encodeAccessReplyWithMessageAuthenticator(resp, reqAuth)
	if err != nil {
		t.Fatal(err)
	}
	n := len(wire)
	offsets, err := messageAuthenticatorValueOffsets(wire, 20, n)
	if err != nil || len(offsets) != 1 {
		t.Fatalf("offsets: %v err %v", offsets, err)
	}
	if err := verifyMessageAuthenticatorHMAC(n, wire[:n], secret, reqAuth, offsets[0]); err != nil {
		t.Fatal(err)
	}
	if !radius.IsAuthenticResponse(wire, reqWire, secret) {
		t.Fatal("IsAuthenticResponse failed")
	}
}

func TestVerifyMessageAuthenticator_tampered(t *testing.T) {
	secret := []byte("xyzzy5461")
	p := radius.New(radius.CodeAccessRequest, secret)
	if err := rfc2869.MessageAuthenticator_Add(p, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeMessageAuthenticatorInPlace(wire, secret, p.Authenticator); err != nil {
		t.Fatal(err)
	}
	n, err := radiusPacketLength(wire)
	if err != nil {
		t.Fatal(err)
	}
	offsets, err := messageAuthenticatorValueOffsets(wire, 20, n)
	if err != nil || len(offsets) != 1 {
		t.Fatalf("offsets: %v err %v", offsets, err)
	}
	wire[offsets[0]] ^= 0xff
	if err := VerifyMessageAuthenticator(wire, secret); err == nil {
		t.Fatal("expected verify error")
	}
}
