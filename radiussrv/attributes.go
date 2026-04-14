package radiussrv

import (
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"layeh.com/radius"
)

// compiledScopeRule is one scope_radius_map entry after optional regex compilation.
type compiledScopeRule struct {
	literal string
	re      *regexp.Regexp
	attrs   []RadiusAttribute
}

// compileScopeRules builds scopeRules from ScopeRadiusMap; keys prefixed with "re:" are compiled as regex.
func (s *Server) compileScopeRules() {
	if s.ScopeRadiusMap == nil {
		s.scopeRules = nil
		return
	}
	var rules []compiledScopeRule
	for scopeKey, attrs := range s.ScopeRadiusMap {
		if strings.HasPrefix(scopeKey, "re:") {
			pattern := strings.TrimPrefix(scopeKey, "re:")
			re, err := regexp.Compile(pattern)
			if err != nil {
				s.Logger.Warn("invalid regex in scope_radius_map, skipping", zap.String("pattern", pattern), zap.Error(err))
				continue
			}
			rules = append(rules, compiledScopeRule{re: re, attrs: attrs})
			continue
		}
		rules = append(rules, compiledScopeRule{literal: scopeKey, attrs: attrs})
	}
	s.scopeRules = rules
}

// addScopeAttributes appends standard or vendor-specific attributes to resp for each compiled
// rule that matches any string in userRoles (literal or regex). requestID is attached to debug logs when non-empty.
func (s *Server) addScopeAttributes(resp *radius.Packet, userRoles []string, requestID string) {
	if len(s.scopeRules) == 0 || len(userRoles) == 0 {
		return
	}
	log := s.Logger
	if log == nil {
		log = zap.NewNop()
	}
	if requestID != "" {
		log = log.With(zap.String("request_id", requestID))
	}
	for _, rule := range s.scopeRules {
		matched := false
		if rule.re != nil {
			for _, role := range userRoles {
				if rule.re.MatchString(role) {
					matched = true
					break
				}
			}
		} else {
			for _, role := range userRoles {
				if role == rule.literal {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}

		for _, attr := range rule.attrs {
			value := encodeAttributeValue(attr.Value, attr.ValueType)
			if attr.Vendor > 0 {
				subAttr := make([]byte, 2+len(value))
				subAttr[0] = byte(attr.Attribute)
				subAttr[1] = byte(2 + len(value))
				copy(subAttr[2:], value)
				vsa, err := radius.NewVendorSpecific(attr.Vendor, radius.Attribute(subAttr))
				if err != nil {
					log.Debug("failed to encode VSA", zap.Uint32("vendor", attr.Vendor), zap.Int("attribute", attr.Attribute), zap.Error(err))
					continue
				}
				resp.Add(26, vsa)
				log.Debug("added vsa", zap.Uint32("vendor", attr.Vendor), zap.Int("attribute", attr.Attribute), zap.String("value", attr.Value))
				continue
			}

			resp.Add(radius.Type(attr.Attribute), value)
			log.Debug("added attribute", zap.Int("attribute", attr.Attribute), zap.String("value", attr.Value))
		}
	}
}

// encodeAttributeValue encodes a config string as RADIUS attribute bytes per valueType
// ("integer", "ipaddr", or default UTF-8 string).
func encodeAttributeValue(value, valueType string) []byte {
	switch valueType {
	case "integer":
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return []byte(value)
		}
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(n))
		return b
	case "ipaddr":
		ip := net.ParseIP(value)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return []byte(ip4)
			}
		}
		return []byte(value)
	default:
		return []byte(value)
	}
}
