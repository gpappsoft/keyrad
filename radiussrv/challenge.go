package radiussrv

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

const (
	defaultChallengeSessionTTL = 5 * time.Minute
	challengeCleanupInterval   = time.Minute
)

// ChallengeSession stores username and password between Access-Challenge and the OTP reply.
type ChallengeSession struct {
	Username string
	Password string
}

type challengeEntry struct {
	sess    ChallengeSession
	expires time.Time
}

// ChallengeStateStore maps opaque State attribute values to sessions with a fixed TTL.
type ChallengeStateStore struct {
	mu  sync.RWMutex
	m   map[string]challengeEntry
	ttl time.Duration
}

// NewChallengeStateStore creates an empty store with default TTL and a periodic eviction goroutine.
func NewChallengeStateStore() *ChallengeStateStore {
	s := &ChallengeStateStore{
		m:   make(map[string]challengeEntry),
		ttl: defaultChallengeSessionTTL,
	}
	go s.cleanupLoop()
	return s
}

// Get returns the session for state if present and not expired, and deletes the entry when expired.
func (s *ChallengeStateStore) Get(state string) (ChallengeSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.m[state]
	if !ok {
		return ChallengeSession{}, false
	}
	return e.sess, true
}

// Set records a challenge session; it expires after the store's configured TTL from the time of Set.
func (s *ChallengeStateStore) Set(state string, sess ChallengeSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[state] = challengeEntry{
		sess:    sess,
		expires: time.Now().Add(s.ttl),
	}
}

// Delete removes a challenge entry after successful or final handling.
func (s *ChallengeStateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, state)
}

func (s *ChallengeStateStore) evictExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.m {
		if now.After(e.expires) {
			delete(s.m, k)
		}
	}
}

func (s *ChallengeStateStore) cleanupLoop() {
	t := time.NewTicker(challengeCleanupInterval)
	defer t.Stop()
	for range t.C {
		s.evictExpired()
	}
}

// GenerateRandomState returns 32 lowercase hex characters suitable for RADIUS State.
func GenerateRandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
