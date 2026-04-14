package radiussrv

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

const eapMessageAttrType = 79

var (
	errPacketTooShort      = errors.New("radius: packet shorter than header")
	errInvalidPacketLength = errors.New("radius: invalid packet length field")
	errMalformedAttributes = errors.New("radius: malformed attribute list")
	errMultipleMsgAuth     = errors.New("radius: multiple Message-Authenticator attributes")
	errMsgAuthLength       = errors.New("radius: Message-Authenticator must be 18 octets (16 value)")
	errMsgAuthNotFound     = errors.New("radius: Message-Authenticator not found in response")
	errEAPWithoutMsgAuth   = errors.New("radius: EAP-Message present without Message-Authenticator (RFC 3579)")
)

// VerifyMessageAuthenticator checks HMAC-MD5 integrity when attribute 80 is present, and enforces
// RFC 3579: any EAP-Message (79) requires Message-Authenticator. When absent and there is no EAP,
// verification succeeds (PAP-only clients often omit MA).
func VerifyMessageAuthenticator(packet []byte, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("radius: empty shared secret")
	}
	n, err := radiusPacketLength(packet)
	if err != nil {
		return err
	}
	body := packet[:n]

	hasEAP, err := containsAttrType(body, 20, n, eapMessageAttrType)
	if err != nil {
		return err
	}
	offsets, err := messageAuthenticatorValueOffsets(body, 20, n)
	if err != nil {
		return err
	}
	switch len(offsets) {
	case 0:
		if hasEAP {
			return errEAPWithoutMsgAuth
		}
		return nil
	case 1:
		off := offsets[0]
		if off < 2 || body[off-2] != MessageAuthenticatorType || body[off-1] != 18 {
			return errMsgAuthLength
		}
		var authForHMAC [16]byte
		copy(authForHMAC[:], body[4:20])
		return verifyMessageAuthenticatorHMAC(n, body, secret, authForHMAC, off)
	default:
		return errMultipleMsgAuth
	}
}

// verifyMessageAuthenticatorHMAC checks RFC 2869 Message-Authenticator using the given
// 16-octet authenticator value that must appear at bytes 4–19 in the HMAC input (for
// Access-Request this is the on-wire Request Authenticator; for replies it is the Request
// Authenticator from the pending request, not the Response Authenticator on the wire).
func verifyMessageAuthenticatorHMAC(n int, body []byte, secret []byte, authenticatorForHMAC [16]byte, maValueOff int) error {
	clone := make([]byte, n)
	copy(clone, body[:n])
	copy(clone[4:20], authenticatorForHMAC[:])
	for i := 0; i < 16; i++ {
		clone[maValueOff+i] = 0
	}
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(clone)
	sum := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sum[:16], body[maValueOff:maValueOff+16]) != 1 {
		return fmt.Errorf("radius: Message-Authenticator mismatch")
	}
	return nil
}

// finalizeMessageAuthenticatorInPlace sets Message-Authenticator on an **Access-Request** (or
// any packet where Encode does not overwrite the authenticator field). Do not use this for
// Access-Accept/Reject/Challenge: RFC 2869 §5.14 requires Message-Authenticator to be present
// before the Response Authenticator is calculated, so use encodeAccessReplyWithMessageAuthenticator.
func finalizeMessageAuthenticatorInPlace(wire []byte, secret []byte, requestAuthenticator [16]byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("radius: empty shared secret")
	}
	n, err := radiusPacketLength(wire)
	if err != nil {
		return err
	}
	if n > len(wire) {
		return errInvalidPacketLength
	}
	offsets, err := messageAuthenticatorValueOffsets(wire, 20, n)
	if err != nil {
		return err
	}
	if len(offsets) != 1 {
		return errMsgAuthNotFound
	}
	off := offsets[0]
	if off < 2 || wire[off-2] != MessageAuthenticatorType || wire[off-1] != 18 {
		return errMsgAuthLength
	}
	for i := 0; i < 16; i++ {
		if wire[off+i] != 0 {
			return fmt.Errorf("radius: Message-Authenticator must be zero before finalize")
		}
	}
	sum := messageAuthenticatorHMACSum(wire[:n], secret, requestAuthenticator, off)
	copy(wire[off:off+16], sum)
	return nil
}

// encodeAccessReplyWithMessageAuthenticator marshals Access-Accept, Access-Reject, or
// Access-Challenge, fills Message-Authenticator (RFC 2869: HMAC uses Request Authenticator in
// bytes 4–19 of the HMAC input), then computes the Response Authenticator (RFC 2865) over
// attributes **including** the final Message-Authenticator. This order matches RFC 2869
// (“inserted … before the Response Authenticator is calculated”) and FreeRADIUS/radtest.
func encodeAccessReplyWithMessageAuthenticator(resp *radius.Packet, requestAuthenticator [16]byte) ([]byte, error) {
	if len(resp.Secret) == 0 {
		return nil, fmt.Errorf("radius: empty secret")
	}
	switch resp.Code {
	case radius.CodeAccessAccept, radius.CodeAccessReject, radius.CodeAccessChallenge:
	default:
		return nil, fmt.Errorf("radius: unsupported code %v for Message-Authenticator reply", resp.Code)
	}
	b, err := resp.MarshalBinary()
	if err != nil {
		return nil, err
	}
	n := len(b)
	offsets, err := messageAuthenticatorValueOffsets(b, 20, n)
	if err != nil {
		return nil, err
	}
	if len(offsets) != 1 {
		return nil, errMsgAuthNotFound
	}
	off := offsets[0]
	if off < 2 || b[off-2] != MessageAuthenticatorType || b[off-1] != 18 {
		return nil, errMsgAuthLength
	}
	for i := 0; i < 16; i++ {
		if b[off+i] != 0 {
			return nil, fmt.Errorf("radius: Message-Authenticator must be zero before signing")
		}
	}
	sum := messageAuthenticatorHMACSum(b, resp.Secret, requestAuthenticator, off)
	copy(b[off:off+16], sum)

	hash := md5.New()
	hash.Write(b[:4])
	hash.Write(requestAuthenticator[:])
	hash.Write(b[20:])
	hash.Write(resp.Secret)
	hash.Sum(b[4:4:20])
	return b, nil
}

func messageAuthenticatorHMACSum(body []byte, secret []byte, requestAuthenticator [16]byte, maValueOff int) []byte {
	n := len(body)
	clone := make([]byte, n)
	copy(clone, body)
	copy(clone[4:20], requestAuthenticator[:])
	for i := 0; i < 16; i++ {
		clone[maValueOff+i] = 0
	}
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(clone)
	return mac.Sum(nil)[:16]
}

func radiusPacketLength(packet []byte) (int, error) {
	if len(packet) < 20 {
		return 0, errPacketTooShort
	}
	n := int(binary.BigEndian.Uint16(packet[2:4]))
	if n < 20 || n > radius.MaxPacketLength {
		return 0, errInvalidPacketLength
	}
	return n, nil
}

func containsAttrType(packet []byte, start, end int, want byte) (bool, error) {
	for pos := start; pos < end; {
		if pos+2 > end {
			return false, errMalformedAttributes
		}
		typ := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 || pos+attrLen > end {
			return false, errMalformedAttributes
		}
		if typ == want {
			return true, nil
		}
		pos += attrLen
	}
	return false, nil
}

// messageAuthenticatorValueOffsets returns the start index of the 16-byte Message-Authenticator
// value within each matching AVP (type 80, length 18).
func messageAuthenticatorValueOffsets(packet []byte, start, end int) ([]int, error) {
	var out []int
	for pos := start; pos < end; {
		if pos+2 > end {
			return nil, errMalformedAttributes
		}
		typ := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 || pos+attrLen > end {
			return nil, errMalformedAttributes
		}
		if typ == MessageAuthenticatorType {
			if attrLen != 18 {
				return nil, errMsgAuthLength
			}
			out = append(out, pos+2)
		}
		pos += attrLen
	}
	return out, nil
}

func (s *Server) writePAPResponse(p *packet, resp *radius.Packet) {
	log := s.withRequest(p)
	resp.Identifier = p.packet.Identifier
	resp.Authenticator = p.packet.Authenticator

	if !s.DisableMsgAuth {
		if err := rfc2869.MessageAuthenticator_Add(resp, make([]byte, 16)); err != nil {
			log.Debug("message-authenticator add failed", zap.Error(err))
			return
		}
	}

	var b []byte
	var err error
	if s.DisableMsgAuth {
		b, err = resp.Encode()
	} else {
		b, err = encodeAccessReplyWithMessageAuthenticator(resp, p.packet.Authenticator)
	}
	if err != nil {
		log.Debug("radius response encode failed", zap.Error(err))
		return
	}
	_, _ = p.conn.WriteTo(b, p.addr)
}
