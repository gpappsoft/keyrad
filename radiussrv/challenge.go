package radiussrv

import (
	"crypto/rand"
	"fmt"
	"sync"
)

type ChallengeSession struct {
	Username string
	Password string
}

type ChallengeStateStore struct {
	mu sync.RWMutex
	m  map[string]ChallengeSession
}

func NewChallengeStateStore() *ChallengeStateStore {
	return &ChallengeStateStore{m: make(map[string]ChallengeSession)}
}

func (s *ChallengeStateStore) Get(state string) (ChallengeSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.m[state]
	return sess, ok
}

func (s *ChallengeStateStore) Set(state string, sess ChallengeSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[state] = sess
}

func (s *ChallengeStateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, state)
}

func GenerateRandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}
