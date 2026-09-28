package auth

import (
	"crypto/subtle"
	"math"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/ids"
)

// Session is an authenticated dashboard session.
type Session struct {
	ID        string
	CSRF      string
	ExpiresAt time.Time

	mu    sync.Mutex
	flash []Flash
}

// Flash is a one-shot message shown on the next page render.
type Flash struct {
	Kind    string // ok | error
	Message string
}

// AddFlash queues a message for the next page.
func (s *Session) AddFlash(kind, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flash = append(s.flash, Flash{Kind: kind, Message: msg})
}

// PopFlash returns and clears queued messages.
func (s *Session) PopFlash() []Flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.flash
	s.flash = nil
	return f
}

// ValidCSRF compares a submitted CSRF token in constant time.
func (s *Session) ValidCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

// Sessions is an in-memory session store; sessions are lost on restart.
type Sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*Session
	now func() time.Time
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]*Session{}, now: time.Now}
}

func (s *Sessions) Create() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	sess := &Session{ID: ids.Random(52), CSRF: ids.Random(52), ExpiresAt: s.now().Add(s.ttl)}
	s.m[sess.ID] = sess
	return sess
}

func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, false
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.m, id)
		return nil, false
	}
	return sess, true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

func (s *Sessions) gc() {
	now := s.now()
	for id, sess := range s.m {
		if now.After(sess.ExpiresAt) {
			delete(s.m, id)
		}
	}
}

// LoginThrottle applies per-IP exponential backoff after repeated failures.
type LoginThrottle struct {
	mu   sync.Mutex
	m    map[string]*throttleEntry
	now  func() time.Time
	free int
	max  time.Duration
}

type throttleEntry struct {
	failures    int
	lockedUntil time.Time
	last        time.Time
}

// NewLoginThrottle allows `free` failed attempts, then locks the IP out for
// 1s, 2s, 4s… (up to max) after each further failure.
func NewLoginThrottle(free int, max time.Duration) *LoginThrottle {
	return &LoginThrottle{m: map[string]*throttleEntry{}, now: time.Now, free: free, max: max}
}

// Allowed reports whether ip may attempt a login, and if not, for how long it must wait.
func (t *LoginThrottle) Allowed(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.allowedLocked(ip)
}

func (t *LoginThrottle) allowedLocked(ip string) (bool, time.Duration) {
	e, ok := t.m[ip]
	if !ok {
		return true, 0
	}
	if wait := e.lockedUntil.Sub(t.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Begin atomically checks the throttle and, if allowed, records the attempt
// as a failure up front; call Success if the password turns out correct.
// Counting before verification stops parallel guesses from all passing the
// check while the slow password hash runs.
func (t *LoginThrottle) Begin(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if ok, wait := t.allowedLocked(ip); !ok {
		return false, wait
	}
	t.failureLocked(ip)
	return true, 0
}

// Failure records a failed attempt.
func (t *LoginThrottle) Failure(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failureLocked(ip)
}

func (t *LoginThrottle) failureLocked(ip string) {
	now := t.now()
	for k, e := range t.m { // forget stale entries
		if now.Sub(e.last) > 24*time.Hour {
			delete(t.m, k)
		}
	}
	e := t.m[ip]
	if e == nil {
		e = &throttleEntry{}
		t.m[ip] = e
	}
	e.failures++
	e.last = now
	if over := e.failures - t.free + 1; over > 0 {
		d := time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(over-1)), float64(t.max)))
		e.lockedUntil = now.Add(d)
	}
}

// Success clears the failure history for ip.
func (t *LoginThrottle) Success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, ip)
}
