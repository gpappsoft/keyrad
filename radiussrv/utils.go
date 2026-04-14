package radiussrv

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"go.uber.org/zap"
)

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// withRequest returns a logger that includes the packet's request_id field, or the server logger if absent.
func (s *Server) withRequest(p *packet) *zap.Logger {
	if s.Logger == nil {
		return zap.NewNop()
	}
	if p == nil || p.requestID == "" {
		return s.Logger
	}
	log := s.Logger.With(zap.String("request_id", p.requestID))
	if p.callingStationID != "" {
		log = log.With(zap.String("calling_station_id", p.callingStationID))
	}
	return log
}

// resolveClientSecret picks the shared secret for ip: an exact ipaddr key wins; otherwise
// the most specific matching CIDR (longest prefix) is used so map iteration order cannot
// pick a wrong secret when several clients overlap.
func resolveClientSecret(clients map[string]ClientConfig, ip net.IP) string {
	for key, cfg := range clients {
		if host := net.ParseIP(key); host != nil && host.Equal(ip) {
			return cfg.Secret
		}
	}
	var bestSecret string
	bestOnes := -1
	for key, cfg := range clients {
		_, ipnet, err := net.ParseCIDR(key)
		if err != nil || !ipnet.Contains(ip) {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			bestSecret = cfg.Secret
		}
	}
	return bestSecret
}
