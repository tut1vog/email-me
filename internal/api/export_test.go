package api

import "time"

// SetNow overrides the server clock (tests only).
func SetNow(s *Server, now func() time.Time) { s.now = now }
