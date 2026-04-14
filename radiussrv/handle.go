package radiussrv

import (
	"context"
	"net"

	"go.uber.org/zap"
	"layeh.com/radius"

	"keyrad/keycloak"
)

// packet carries a parsed RADIUS request, peer address, UDP socket, secret, decrypted PAP fields,
// and a per-request correlation id for logging.
type packet struct {
	packet           *radius.Packet
	addr             net.Addr
	conn             *net.UDPConn
	secret           []byte
	username         string
	password         string
	requestID        string
	callingStationID string
}

// newPacket wraps a parsed RADIUS packet with connection context, shared secret bytes,
// and a new random request_id used for structured logging across the handler pipeline.
func newPacket(p *radius.Packet, addr net.Addr, conn *net.UDPConn, secret []byte) *packet {
	return &packet{
		packet:           p,
		addr:             addr,
		conn:             conn,
		secret:           secret,
		requestID:        newRequestID(),
		callingStationID: string(p.Get(CallingStationIDType)),
	}
}

// HandlePacket runs PAP handling: optional OTP discovery, Keycloak authentication, and replies.
func (s *Server) HandlePacket(p *packet) {
	if s.PAPEnabled {
		log := s.withRequest(p)
		kcCtx := keycloak.WithRequestID(context.Background(), p.requestID)
		log.Debug("handling PAP", zap.String("address", p.addr.String()))
		usernameRaw := p.packet.Get(1) // User-Name
		passwordRaw := p.packet.Get(2) // User-Password
		username := string(usernameRaw)
		p.username = username
		if len(passwordRaw) > 0 {
			decrypted, err := radius.UserPassword(passwordRaw, p.secret, p.packet.Authenticator[:])
			if err != nil {
				log.Debug("decrypt User-Password failed", zap.String("username", username), zap.Error(err))
				return
			}
			p.password = string(decrypted)
		}
		if len(username) == 0 && len(p.password) == 0 {
			log.Debug("no username or password", zap.String("address", p.addr.String()))
			return
		}

		// Check if user has OTP assigned
		hasOTP := false
		if s.Keycloak != nil {
			var err error
			hasOTP, err = s.Keycloak.HasOTP(kcCtx, username)
			log.Debug("user has OTP", zap.String("username", username), zap.Error(err))
		}

		if hasOTP {
			if s.DisableChallenge {
				s.handleDisableChallenge(p, kcCtx)
				return
			}
			s.handleUserOTP(p, kcCtx)
		} else {
			s.handleUser(p, kcCtx)
		}
	}
}

// handleDisableChallenge authenticates when challenge-response is disabled (password ends with 6-digit OTP).
func (s *Server) handleDisableChallenge(p *packet, kcCtx context.Context) {
	log := s.withRequest(p)
	if len(p.password) <= 6 {
		log.Debug("password too short for OTP split", zap.String("username", p.username))
		resp := radius.New(radius.CodeAccessReject, p.secret)
		s.writePAPResponse(p, resp)
		return
	}

	otp := p.password[len(p.password)-6:]
	userPassword := p.password[:len(p.password)-6]
	log.Debug("split password", zap.Int("len_password", len(userPassword)), zap.Int("len_otp", len(otp)))
	ok, roles, err := s.Keycloak.AuthenticateUser(kcCtx, p.username, userPassword, otp)
	otpOk := ok && err == nil
	var resp *radius.Packet
	if ok && otpOk {
		log.Debug("PAP+OTP success", zap.String("username", p.username), zap.Any("roles", roles))
		resp = radius.New(radius.CodeAccessAccept, p.secret)
		s.addScopeAttributes(resp, roles, p.requestID)
	} else {
		log.Debug("PAP+OTP failed", zap.String("username", p.username), zap.Error(err))
		resp = radius.New(radius.CodeAccessReject, p.secret)
	}
	s.writePAPResponse(p, resp)
}

// handleUser performs a single-step password grant against Keycloak (no OTP path).
func (s *Server) handleUser(p *packet, kcCtx context.Context) {
	log := s.withRequest(p)
	ok, roles, err := s.Keycloak.AuthenticateUser(kcCtx, p.username, p.password)
	var resp *radius.Packet
	if ok {
		log.Debug("PAP success", zap.String("username", p.username), zap.Any("roles", roles))
		resp = radius.New(radius.CodeAccessAccept, p.secret)
		s.addScopeAttributes(resp, roles, p.requestID)
	} else {
		log.Debug("PAP failed", zap.String("username", p.username), zap.Error(err))
		resp = radius.New(radius.CodeAccessReject, p.secret)
	}
	s.writePAPResponse(p, resp)
}

// handleUserOTP implements OTP via Access-Challenge or completes the second step using State.
func (s *Server) handleUserOTP(p *packet, kcCtx context.Context) {
	log := s.withRequest(p)
	otp := ""
	stateRaw := p.packet.Get(24) // State attribute
	log.Debug("state attribute", zap.String("state", string(stateRaw)))
	if len(stateRaw) > 0 {
		// Second step: validate OTP using stored state
		state := string(stateRaw)
		if s.ChallengeStateStore != nil {
			sess, ok := s.ChallengeStateStore.Get(state)
			if !ok {
				log.Debug("not found challenge state, close", zap.String("state", state))
				return
			}
			log.Debug("found challenge state", zap.String("username", sess.Username))

			otp = p.password // In challenge-response, password field contains OTP
			ok, roles, err := s.Keycloak.AuthenticateUser(kcCtx, sess.Username, sess.Password, otp)
			var resp *radius.Packet
			if ok && err == nil {
				resp = radius.New(radius.CodeAccessAccept, p.secret)
				s.addScopeAttributes(resp, roles, p.requestID)
				log.Debug("OTP challenge success", zap.String("username", sess.Username), zap.Any("roles", roles))
			} else {
				resp = radius.New(radius.CodeAccessReject, p.secret)
				log.Debug("OTP challenge failed", zap.String("username", sess.Username), zap.Error(err))
			}
			s.writePAPResponse(p, resp)
			s.ChallengeStateStore.Delete(state)
			return
		}
	} else {
		// Challenge-Response mode: send Access-Challenge for OTP
		log.Debug("sending Access-Challenge", zap.String("username", p.username))
		// Store challenge state for this session
		if s.ChallengeStateStore == nil {
			s.ChallengeStateStore = NewChallengeStateStore()
		}
		state, err := GenerateRandomState()
		if err != nil {
			log.Warn("generate challenge state fail", zap.Error(err))
			return
		}
		s.ChallengeStateStore.Set(state, ChallengeSession{Username: p.username, Password: p.password})
		resp := radius.New(radius.CodeAccessChallenge, p.secret)
		resp.Identifier = p.packet.Identifier
		resp.Authenticator = p.packet.Authenticator
		resp.Add(18, []byte(s.OTPChallengeMsg))
		resp.Add(24, []byte(state)) // State attribute
		s.writePAPResponse(p, resp)
	}
}
