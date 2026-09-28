// Package idempotency caches send results per (token, idempotency key) in
// memory so retried requests are not delivered twice. Only a hash of the key
// and the (content-free) response are kept.
package idempotency

import (
	"crypto/sha256"
	"sync"
	"time"
)

// Result is a cached HTTP response.
type Result struct {
	Status int
	Body   []byte
}

type entry struct {
	done    chan struct{}
	result  *Result
	expires time.Time
}

type Cache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[[32]byte]*entry
	now func() time.Time
}

func New(ttl time.Duration) *Cache {
	return &Cache{ttl: ttl, m: map[[32]byte]*entry{}, now: time.Now}
}

func key(tokenID, k string) [32]byte { return sha256.Sum256([]byte(tokenID + "\x00" + k)) }

// Begin claims a key. If the key already completed, it returns the cached
// result. If another request holds it, Begin waits for that request.
// Otherwise it returns a finish function the caller must call exactly once:
// finish(result) caches it; finish(nil) releases the key without caching
// (so the request can be retried).
func (c *Cache) Begin(tokenID, k string) (cached *Result, finish func(*Result)) {
	h := key(tokenID, k)
	for {
		c.mu.Lock()
		c.gcLocked()
		e, ok := c.m[h]
		if !ok {
			e = &entry{done: make(chan struct{})}
			c.m[h] = e
			c.mu.Unlock()
			var once sync.Once
			return nil, func(r *Result) {
				once.Do(func() {
					c.mu.Lock()
					if r == nil {
						delete(c.m, h)
					} else {
						e.result = r
						e.expires = c.now().Add(c.ttl)
					}
					c.mu.Unlock()
					close(e.done)
				})
			}
		}
		c.mu.Unlock()
		<-e.done
		c.mu.Lock()
		r := e.result
		c.mu.Unlock()
		if r != nil {
			return r, nil
		}
		// The holder released without a result; try to claim it ourselves.
	}
}

func (c *Cache) gcLocked() {
	now := c.now()
	for h, e := range c.m {
		if e.result != nil && now.After(e.expires) {
			delete(c.m, h)
		}
	}
}
