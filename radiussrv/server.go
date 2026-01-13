package radiussrv

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"layeh.com/radius"

	"keyrad/auth"
	"keyrad/keycloak"
)

const (
	MessageAuthenticatorType = 80
	MSCHAPChallengeType      = 11
	MSCHAP2ResponseType      = 25
	MSCHAP2SuccessType       = 26
)

type Server struct {
	Keycloak            *keycloak.KeycloakAPI
	Clients             map[string]auth.ClientConfig
	ScopeRadiusMap      auth.ScopeRadiusMapping
	OTPChallengeMsg     string
	DisableMsgAuth      bool
	DisableChallenge    bool
	Debug               bool
	MSCHAPEnabled       bool
	PAPEnabled          bool
	ChallengeStateStore *ChallengeStateStore
}

func (s *Server) HandlePacket(packet *radius.Packet, addr net.Addr, conn *net.UDPConn, secret []byte) {
	if s.MSCHAPEnabled {
		if s.Debug {
			log.Printf("[DEBUG] Handling MS-CHAPv2 for %v", addr)
		}
		usernameRaw := packet.Get(1) // User-Name
		challenge := packet.Get(MSCHAPChallengeType)
		response := packet.Get(MSCHAP2ResponseType)
		username := string(usernameRaw)
		if len(challenge) > 0 && len(response) > 0 {
			ok, _, _, errMsg := ValidateMSCHAPv2(challenge, response, username, "testpass") // Replace with real password lookup
			var resp *radius.Packet
			if ok {
				if s.Debug {
					log.Printf("[DEBUG] MS-CHAPv2 success for %s", username)
				}
				resp = radius.New(radius.CodeAccessAccept, secret)
			} else {
				if s.Debug {
					log.Printf("[DEBUG] MS-CHAPv2 failed for %s: %s", username, errMsg)
				}
				resp = radius.New(radius.CodeAccessReject, secret)
			}
			resp.Identifier = packet.Identifier
			resp.Authenticator = packet.Authenticator // Set authenticator for response
			b, err := resp.Encode()
			if err == nil {
				conn.WriteTo(b, addr)
			}
			return
		}
	}
	if s.PAPEnabled {
		if s.Debug {
			log.Printf("[DEBUG] Handling PAP for %v", addr)
		}
		usernameRaw := packet.Get(1) // User-Name
		passwordRaw := packet.Get(2) // User-Password
		username := string(usernameRaw)
		var password string
		if len(passwordRaw) > 0 {
			decrypted, err := decryptUserPassword(passwordRaw, packet.Authenticator[:], secret)
			if err != nil {
				if s.Debug {
					log.Printf("[DEBUG] Failed to decrypt User-Password for %s: %v", username, err)
				}
				return
			}
			password = string(decrypted)
		}
		if len(username) > 0 && len(password) > 0 {
			// Check if user has OTP assigned
			hasOTP := false
			if s.Keycloak != nil {
				var err error
				hasOTP, err = s.Keycloak.HasOTP(username)
				if s.Debug {
					log.Printf("[DEBUG] User %s has OTP: %v (err: %v)", username, hasOTP, err)
				}
			}
			if hasOTP {
				otp := ""
				userPassword := password
				stateRaw := packet.Get(24) // State attribute
				if s.Debug {
					log.Printf("[DEBUG] State attribute: %s", string(stateRaw))
				}
				if !s.DisableChallenge && len(stateRaw) > 0 {
					// Second step: validate OTP using stored state
					state := string(stateRaw)
					if s.ChallengeStateStore != nil {
						sess, ok := s.ChallengeStateStore.Get(state)
						if ok {
							if s.Debug {
								log.Printf("[DEBUG] Found challenge state for %s", sess.Username)
							}
							otp = password // In challenge-response, password field contains OTP
							ok, err := s.Keycloak.AuthenticateUser(sess.Username, sess.Password, otp)
							var resp *radius.Packet
							if ok && err == nil {
								resp = radius.New(radius.CodeAccessAccept, secret)
								if s.Debug {
									log.Printf("[DEBUG] OTP challenge success for %s", sess.Username)
								}
							} else {
								resp = radius.New(radius.CodeAccessReject, secret)
								if s.Debug {
									log.Printf("[DEBUG] OTP challenge failed for %s: %v", sess.Username, err)
								}
							}
							resp.Identifier = packet.Identifier
							resp.Authenticator = packet.Authenticator
							b, err := resp.Encode()
							if err == nil {
								conn.WriteTo(b, addr)
							}
							s.ChallengeStateStore.Delete(state)
							return
						}
					}
				}
				if s.Debug {
					log.Printf("[DEBUG] DisableChallenge: %v", s.DisableChallenge)
				}
				if s.DisableChallenge {
					if len(password) > 6 {
						otp = password[len(password)-6:]
						userPassword = password[:len(password)-6]
					}
					if s.Debug {
						log.Printf("[DEBUG] Split password: '%s', otp: '%s'", userPassword, otp)
					}
					ok, err := s.Keycloak.AuthenticateUser(username, userPassword, otp)
					otpOk := ok && err == nil
					var resp *radius.Packet
					if ok && otpOk {
						if s.Debug {
							log.Printf("[DEBUG] PAP+OTP success for %s (Keycloak)", username)
						}
						resp = radius.New(radius.CodeAccessAccept, secret)
					} else {
						if s.Debug {
							log.Printf("[DEBUG] PAP+OTP failed for %s: %v", username, err)
						}
						resp = radius.New(radius.CodeAccessReject, secret)
					}
					resp.Identifier = packet.Identifier
					resp.Authenticator = packet.Authenticator
					b, err := resp.Encode()
					if err == nil {
						conn.WriteTo(b, addr)
					}
					return
				} else {
					// Challenge-Response mode: send Access-Challenge for OTP
					if s.Debug {
						log.Printf("[DEBUG] Sending Access-Challenge for OTP to %s", username)
					}
					// Store challenge state for this session
					if s.ChallengeStateStore == nil {
						s.ChallengeStateStore = NewChallengeStateStore()
					}
					state := GenerateRandomState()
					s.ChallengeStateStore.Set(state, ChallengeSession{Username: username, Password: password})
					resp := radius.New(radius.CodeAccessChallenge, secret)
					resp.Identifier = packet.Identifier
					resp.Authenticator = packet.Authenticator
					resp.Add(18, []byte(s.OTPChallengeMsg))
					resp.Add(24, []byte(state)) // State attribute
					b, err := resp.Encode()
					if err == nil {
						conn.WriteTo(b, addr)
					}
					return
				}
			} else {
				// Standard PAP (no OTP)
				ok, err := s.Keycloak.AuthenticateUser(username, password)
				var resp *radius.Packet
				if ok {
					if s.Debug {
						log.Printf("[DEBUG] PAP success for %s (Keycloak)", username)
					}
					resp = radius.New(radius.CodeAccessAccept, secret)
				} else {
					if s.Debug {
						log.Printf("[DEBUG] PAP failed for %s: %v", username, err)
					}
					resp = radius.New(radius.CodeAccessReject, secret)
				}
				resp.Identifier = packet.Identifier
				resp.Authenticator = packet.Authenticator
				b, err := resp.Encode()
				if err == nil {
					conn.WriteTo(b, addr)
				}
				return
			}
		}
	}
}

func (s *Server) ListenAndServe(listenAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	const workerCount = 8
	type radiusJob struct {
		packetData []byte
		remoteAddr net.Addr
	}
	jobs := make(chan radiusJob, 128)

	for i := 0; i < workerCount; i++ {
		go func() {
			for job := range jobs {
				// Find the correct secret for the remote address
				var secret string
				udpAddr, ok := job.remoteAddr.(*net.UDPAddr)
				if !ok {
					continue
				}
				for key, cfg := range s.Clients {
					if s.Debug {
						log.Printf("[DEBUG] Checking client key: %s, secret: %s", key, cfg.Secret)
					}
					// Try as CIDR
					_, ipnet, err := net.ParseCIDR(key)
					if err == nil && ipnet.Contains(udpAddr.IP) {
						secret = cfg.Secret
						if s.Debug {
							log.Printf("[DEBUG] Matched CIDR %s for %s, using secret: %s", key, udpAddr.IP, secret)
						}
						break
					}
					// Try as single IP
					if net.ParseIP(key) != nil && net.ParseIP(key).Equal(udpAddr.IP) {
						secret = cfg.Secret
						if s.Debug {
							log.Printf("[DEBUG] Matched IP %s for %s, using secret: %s", key, udpAddr.IP, secret)
						}
						break
					}
				}
				if secret == "" {
					if s.Debug {
						log.Printf("Rejected packet from unauthorized client: %v", job.remoteAddr)
					}
					continue
				}
				packet, err := radius.Parse(job.packetData, []byte(secret))
				if err != nil {
					if s.Debug {
						log.Printf("Failed to parse RADIUS packet: %v", err)
					}
					continue
				}
				s.HandlePacket(packet, job.remoteAddr, conn, []byte(secret))
			}
		}()
	}

	buf := make([]byte, 4096)
	for {
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if s.Debug {
				log.Printf("Error reading from UDP: %v", err)
			}
			continue
		}
		packetCopy := make([]byte, n)
		copy(packetCopy, buf[:n])
		jobs <- radiusJob{packetData: packetCopy, remoteAddr: remoteAddr}
	}
}

func GetHTTPClient(insecureSkipTLSVerify bool) *http.Client {
	if insecureSkipTLSVerify {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return &http.Client{Transport: tr}
	}
	return http.DefaultClient
}

func decryptUserPassword(encrypted, authenticator, secret []byte) ([]byte, error) {
	if len(encrypted)%16 != 0 {
		return nil, fmt.Errorf("invalid encrypted User-Password length")
	}
	b := make([]byte, len(encrypted))
	last := authenticator
	for i := 0; i < len(encrypted); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(last)
		xor := h.Sum(nil)
		for j := 0; j < 16; j++ {
			b[i+j] = encrypted[i+j] ^ xor[j]
		}
		last = encrypted[i : i+16]
	}
	// Remove padding
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			b = b[:i]
		} else {
			break
		}
	}
	return b, nil
}

// ValidateOTP now calls Keycloak with the 'totp' parameter
func ValidateOTP(username, otp string, kc *keycloak.KeycloakAPI) bool {
	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", kc.ClientID)
	data.Set("client_secret", kc.ClientSecret)
	data.Set("username", username)
	data.Set("password", "dummy") // password is not used, but must be present
	data.Set("totp", otp)
	resp, err := kc.HTTPClient.PostForm(kc.TokenURL, data)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return true
	}
	return false
}

// ...move MS-CHAPv2, challenge state, and utility functions here...
