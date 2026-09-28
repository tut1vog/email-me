package api

import (
	"crypto/tls"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestTransportClassification(t *testing.T) {
	proxy := netip.MustParsePrefix("10.0.0.2/32")
	cases := []struct {
		name     string
		remote   string
		host     string
		hdr      map[string]string
		tls      bool
		trusted  bool
		external bool
		want     string
	}{
		{name: "direct TLS", remote: "203.0.113.5:1", host: "gw.example.com", tls: true, want: TransportTLS},
		{name: "localhost", remote: "172.17.0.1:1", host: "localhost:8025", want: TransportLocal},
		{name: "loopback v4", remote: "172.17.0.1:1", host: "127.0.0.1:8025", want: TransportLocal},
		{name: "loopback v6", remote: "172.17.0.1:1", host: "[::1]:8025", want: TransportLocal},
		{name: "remote plain", remote: "203.0.113.5:1", host: "gw.example.com:8025", want: TransportInsecure},
		{name: "remote plain, tunnel asserted", remote: "100.64.0.9:1", host: "gw:8025", external: true, want: TransportTunnel},
		{name: "trusted proxy https", remote: "10.0.0.2:1", host: "gw.example.com", trusted: true, hdr: map[string]string{"X-Forwarded-Proto": "https"}, want: TransportTLS},
		{name: "trusted proxy http", remote: "10.0.0.2:1", host: "gw.example.com", trusted: true, hdr: map[string]string{"X-Forwarded-Proto": "http"}, want: TransportInsecure},
		{name: "untrusted peer spoofs https", remote: "203.0.113.5:1", host: "gw.example.com", trusted: true, hdr: map[string]string{"X-Forwarded-Proto": "https"}, want: TransportInsecure},
		{name: "untrusted peer spoofs localhost host", remote: "203.0.113.5:1", host: "gw.example.com", trusted: true, hdr: map[string]string{"X-Forwarded-Host": "localhost"}, want: TransportInsecure},
		{name: "trusted proxy forwards localhost host", remote: "10.0.0.2:1", host: "gw", trusted: true, hdr: map[string]string{"X-Forwarded-Host": "localhost:8025"}, want: TransportLocal},
	}
	for _, c := range cases {
		n := &netInfo{external: c.external}
		if c.trusted {
			n.trusted = []netip.Prefix{proxy}
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr, r.Host = c.remote, c.host
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := n.Transport(r); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestClientIP(t *testing.T) {
	n := &netInfo{trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.2:5555"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.7, 10.0.0.3")
	if got := n.ClientIP(r).String(); got != "198.51.100.7" {
		t.Fatalf("rightmost untrusted hop expected, got %s", got)
	}
	r.RemoteAddr = "203.0.113.9:1"
	if got := n.ClientIP(r).String(); got != "203.0.113.9" {
		t.Fatalf("untrusted peer's XFF must be ignored, got %s", got)
	}
	r.RemoteAddr = "10.0.0.2:1"
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := n.ClientIP(r).String(); got != "10.0.0.2" {
		t.Fatalf("malformed XFF falls back to the proxy, got %s", got)
	}
}

func TestBaseURL(t *testing.T) {
	n := &netInfo{}
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "gw.example.com:8025"
	if got := n.BaseURL(r, ""); got != "http://gw.example.com:8025" {
		t.Fatal(got)
	}
	if got := n.BaseURL(r, "https://pub.example.com"); got != "https://pub.example.com" {
		t.Fatal(got)
	}
	r.Host = "evil.example.com/<script>"
	if got := n.BaseURL(r, ""); got != "http://localhost" {
		t.Fatalf("hostile Host header must not be reflected: %s", got)
	}
}
