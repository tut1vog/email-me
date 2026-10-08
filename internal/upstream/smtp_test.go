package upstream_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/units"
	"github.com/tut1vog/email-me/internal/upstream"
)

func TestNotConfiguredFailsFast(t *testing.T) {
	s := upstream.NewSMTP(config.SMTP{Port: 587, Security: "starttls", Timeout: units.Duration(time.Minute)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for name, err := range map[string]error{
		"check": s.Check(ctx),
		"send":  s.Send(ctx, "gateway@example.com", []string{"me@example.com"}, []byte("x")),
	} {
		var ue *upstream.Error
		if !errors.As(err, &ue) || !errors.Is(err, upstream.ErrNotConfigured) || err.Error() != "upstream SMTP: not configured; set it on the dashboard's Settings page" {
			t.Errorf("%s: %v", name, err)
		}
	}
	configured := upstream.NewSMTP(config.SMTP{Host: "127.0.0.1", Port: 1, Security: "none", Timeout: units.Duration(time.Second)})
	if err := configured.Send(ctx, "", []string{"me@example.com"}, []byte("x")); !errors.Is(err, upstream.ErrNotConfigured) {
		t.Errorf("empty From must not be sent as the null sender: %v", err)
	}
}
