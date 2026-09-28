package keys

import "time"

// SetNow overrides the clock (tests only).
func SetNow(m *Manager, now func() time.Time) { m.now = now }
