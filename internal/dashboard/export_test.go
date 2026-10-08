package dashboard

import (
	"time"

	"github.com/tut1vog/email-me/internal/auth"
)

// FreezeThrottle gives the login throttle a fixed clock so a lockout cannot
// expire while the slow password hash runs under test load.
func FreezeThrottle(s *Server, now time.Time) {
	s.throttle = auth.NewLoginThrottleAt(5, time.Minute, func() time.Time { return now })
}
