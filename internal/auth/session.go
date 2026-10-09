package auth

import (
	"crypto/subtle"
	"sync"

	"github.com/tut1vog/email-me/internal/ids"
)

// Session is an authenticated dashboard session. It lasts until the
// console that opened the dashboard closes.
type Session struct {
	ID   string
	CSRF string

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

// Sessions is an in-memory session store with the console's one-time login
// links. Clear ends everything when the console closes.
type Sessions struct {
	mu    sync.Mutex
	m     map[string]*Session
	links map[string]bool // unspent login link tokens
}

func NewSessions() *Sessions {
	return &Sessions{m: map[string]*Session{}, links: map[string]bool{}}
}

// NewLink mints a one-time login link token.
func (s *Sessions) NewLink() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	tok := ids.Random(52)
	s.links[tok] = true
	return tok
}

// Redeem spends a login link token and starts a session, or returns false
// for a spent or unknown token.
func (s *Sessions) Redeem(token string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.links[token] {
		return nil, false
	}
	delete(s.links, token)
	sess := &Session{ID: ids.Random(52), CSRF: ids.Random(52)}
	s.m[sess.ID] = sess
	return sess, true
}

func (s *Sessions) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	return sess, ok
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// Clear ends every session and voids every unspent link.
func (s *Sessions) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[string]*Session{}
	s.links = map[string]bool{}
}
