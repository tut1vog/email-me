// Package ratelimit enforces per-agent hourly and daily send limits. Counts
// come from audit rows (so limits survive restarts) plus in-flight sends.
package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
)

type Limiter struct {
	st       *store.Store
	mu       sync.Mutex
	inflight map[string]int
	now      func() time.Time
}

func New(st *store.Store) *Limiter {
	return &Limiter{st: st, inflight: map[string]int{}, now: time.Now}
}

// Remaining returns how many sends are left this rolling hour and day.
func (l *Limiter) Remaining(ctx context.Context, agentID string, rl policy.RateLimit) (hour, day int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, d, err := l.usedLocked(ctx, agentID)
	if err != nil {
		return 0, 0, err
	}
	return max(rl.PerHour-h, 0), max(rl.PerDay-d, 0), nil
}

func (l *Limiter) usedLocked(ctx context.Context, agentID string) (hour, day int, err error) {
	now := l.now()
	h, _, err := l.st.SentSince(ctx, agentID, now.Add(-time.Hour))
	if err != nil {
		return 0, 0, err
	}
	d, _, err := l.st.SentSince(ctx, agentID, now.Add(-24*time.Hour))
	if err != nil {
		return 0, 0, err
	}
	in := l.inflight[agentID]
	return h + in, d + in, nil
}

// Reserve claims a send slot. If the agent is over a limit it returns ok=false
// and how long until a slot frees up. Otherwise the caller must call release
// once the outcome has been recorded in the audit log.
func (l *Limiter) Reserve(ctx context.Context, agentID string, rl policy.RateLimit) (release func(), ok bool, retryAfter time.Duration, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h, d, err := l.usedLocked(ctx, agentID)
	if err != nil {
		return nil, false, 0, err
	}
	if h >= rl.PerHour || d >= rl.PerDay {
		var wait time.Duration
		if h >= rl.PerHour {
			wait = max(wait, l.waitFor(ctx, agentID, time.Hour, h-rl.PerHour+1))
		}
		if d >= rl.PerDay {
			wait = max(wait, l.waitFor(ctx, agentID, 24*time.Hour, d-rl.PerDay+1))
		}
		return nil, false, wait, nil
	}
	l.inflight[agentID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.inflight[agentID]--; l.inflight[agentID] <= 0 {
				delete(l.inflight, agentID)
			}
		})
	}, true, 0, nil
}

// waitFor returns when the n-th oldest send in the window ages out.
func (l *Limiter) waitFor(ctx context.Context, agentID string, window time.Duration, n int) time.Duration {
	now := l.now()
	ts, err := l.st.NthOldestSent(ctx, agentID, now.Add(-window), n)
	if err != nil {
		// Slots are held by in-flight sends; they resolve quickly.
		return 5 * time.Second
	}
	return max(ts.Add(window).Sub(now), time.Second)
}
