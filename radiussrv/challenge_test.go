package radiussrv

import (
	"testing"
	"time"
)

func testChallengeStore(ttl time.Duration) *ChallengeStateStore {
	return &ChallengeStateStore{
		m:   make(map[string]challengeEntry),
		ttl: ttl,
	}
}

func TestChallengeStateStore_SetGetDelete(t *testing.T) {
	s := testChallengeStore(time.Hour)
	sess := ChallengeSession{Username: "u", Password: "p"}
	s.Set("state1", sess)
	got, ok := s.Get("state1")
	if !ok {
		t.Fatal("expected ok")
	}
	if got.Username != "u" || got.Password != "p" {
		t.Fatalf("session: %+v", got)
	}
	s.Delete("state1")
	_, ok = s.Get("state1")
	if ok {
		t.Fatal("expected miss after delete")
	}
}

func TestChallengeStateStore_EvictExpired(t *testing.T) {
	s := testChallengeStore(time.Hour)
	s.mu.Lock()
	s.m["old"] = challengeEntry{
		sess:    ChallengeSession{Username: "gone"},
		expires: time.Now().Add(-time.Minute),
	}
	s.mu.Unlock()
	s.evictExpired()
	s.mu.Lock()
	_, exists := s.m["old"]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected eviction")
	}
}

func TestGenerateRandomState(t *testing.T) {
	a, err := GenerateRandomState()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 {
		t.Fatalf("len %d", len(a))
	}
	for _, c := range a {
		if c < '0' || c > 'f' || (c > '9' && c < 'a') {
			t.Fatalf("non-hex rune %q in %q", c, a)
		}
	}
}
