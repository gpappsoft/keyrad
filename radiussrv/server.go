// Package radiussrv implements a UDP RADIUS authentication server with PAP, optional OTP
// challenge flow, and Keycloak-backed credential checks.
package radiussrv

import (
	"net"

	"go.uber.org/zap"
	"layeh.com/radius"

	"keyrad/keycloak"
)

const (
	// MessageAuthenticatorType is the RADIUS attribute type for Message-Authenticator (RFC 3579).
	MessageAuthenticatorType = 80
	// CallingStationIDType is Calling-Station-Id (RFC 2865).
	CallingStationIDType = 31
	workerCount          = 8
)

// Server wires Keycloak, RADIUS clients, scope-to-attribute mapping, and OTP challenge state.
type Server struct {
	Keycloak            *keycloak.KeycloakAPI
	Clients             map[string]ClientConfig
	ScopeRadiusMap      ScopeRadiusMapping
	scopeRules          []compiledScopeRule
	OTPChallengeMsg     string
	DisableMsgAuth      bool
	DisableChallenge    bool
	PAPEnabled          bool
	ChallengeStateStore *ChallengeStateStore
	Logger              *zap.Logger

	jobs chan request
}

type request struct {
	packetData []byte
	remoteAddr net.Addr
	conn       *net.UDPConn
}

// ListenAndServe binds a UDP socket on listenAddr, compiles scope rules, and blocks
// serving RADIUS Access-Request packets until the listener returns an error.
func (s *Server) ListenAndServe(listenAddr string) error {
	s.compileScopeRules()
	s.jobs = make(chan request, 128)
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for i := 0; i < workerCount; i++ {
		go s.worker()
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			s.Logger.Debug("error reading from UDP connection", zap.Error(err))
			continue
		}
		packetCopy := make([]byte, n)
		copy(packetCopy, buf[:n])
		s.jobs <- request{packetData: packetCopy, remoteAddr: remoteAddr, conn: conn}
	}
}

// worker pulls UDP jobs from the queue, resolves the client secret, parses the packet, and dispatches HandlePacket.
func (s *Server) worker() {
	for job := range s.jobs {
		// Find the correct secret for the remote address
		var secret string
		udpAddr, ok := job.remoteAddr.(*net.UDPAddr)
		if !ok {
			continue
		}

		secret = resolveClientSecret(s.Clients, udpAddr.IP)
		if secret != "" {
			s.Logger.Debug("matched client", zap.String("ip", udpAddr.IP.String()))
		}

		if secret == "" {
			s.Logger.Debug("no secret found", zap.String("ip", job.remoteAddr.String()))
			continue
		}

		reqPacket, err := radius.Parse(job.packetData, []byte(secret))
		if err != nil {
			s.Logger.Debug("error parsing packet", zap.Error(err))
			continue
		}

		if !s.DisableMsgAuth {
			if err := VerifyMessageAuthenticator(job.packetData, []byte(secret)); err != nil {
				s.Logger.Debug("message-authenticator verification failed",
					zap.String("ip", udpAddr.IP.String()),
					zap.Error(err))
				continue
			}
		}

		pkt := newPacket(reqPacket, job.remoteAddr, job.conn, []byte(secret))
		s.withRequest(pkt).Debug("RADIUS packet parsed, dispatching")
		s.HandlePacket(pkt)
	}
}
