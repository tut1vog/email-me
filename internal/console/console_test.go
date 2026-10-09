package console_test

import (
	"net"
	"testing"

	"github.com/tut1vog/email-me/internal/console"
)

func TestLinkURL(t *testing.T) {
	bound := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 49152}
	for listen, want := range map[string]string{
		"127.0.0.1:8026":       "http://email-me.localhost:8026",
		"localhost:8026":       "http://email-me.localhost:8026",
		"[::1]:8026":           "http://email-me.localhost:8026",
		"0.0.0.0:8026":         "http://email-me.localhost:8026",
		":8026":                "http://email-me.localhost:8026",
		"127.0.0.1:0":          "http://email-me.localhost:49152",
		"10.0.0.5:8026":        "http://10.0.0.5:8026",
		"[2001:db8::1]:8026":   "http://[2001:db8::1]:8026",
		"gateway.example:8026": "http://gateway.example:8026",
	} {
		if got := console.LinkURL(listen, bound); got != want {
			t.Errorf("LinkURL(%q) = %q, want %q", listen, got, want)
		}
	}
}
