package radiussrv

import (
	"crypto/rand"
	"fmt"
)

type ChallengeSession struct {
	Username string
	Password string
}

type ChallengeStateStore struct {
	m map[string]ChallengeSession
}

func NewChallengeStateStore() *ChallengeStateStore {
	return &ChallengeStateStore{m: make(map[string]ChallengeSession)}
}

func (s *ChallengeStateStore) Get(state string) (ChallengeSession, bool) {
	sess, ok := s.m[state]
	return sess, ok
}

func (s *ChallengeStateStore) Set(state string, sess ChallengeSession) {
	s.m[state] = sess
}

func (s *ChallengeStateStore) Delete(state string) {
	delete(s.m, state)
}

func GenerateRandomState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(65 + i)
		}
	}
	return fmt.Sprintf("%x", b)
}
