package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/tut1vog/email-me/internal/config"
)

// Transport classes: how a request reached the gateway. Signing needs the
// gateway to read content, so anything but tls, local or tunnel means message
// content crossed the network unencrypted; it is reported, never blocked.
const (
	TransportTLS      = "tls"
	TransportLocal    = "local"
	TransportTunnel   = "tunnel"
	TransportInsecure = "insecure"
)

// netInfo derives client IP, transport class and base URL from a request,
// honoring X-Forwarded-* only from trusted proxies.
type netInfo struct {
	trusted  []netip.Prefix
	external bool
}

// newNetInfo returns the netInfo for a configuration. It is cheap: build
// one per request from the current configuration.
func newNetInfo(cfg *config.Config) netInfo {
	return netInfo{trusted: cfg.API.TrustedNets, external: cfg.API.ExternalTransportEncryption}
}

func (n *netInfo) peer(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func (n *netInfo) isTrusted(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range n.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (n *netInfo) fromTrustedProxy(r *http.Request) bool { return n.isTrusted(n.peer(r)) }

// ClientIP is the TCP peer, or the rightmost untrusted X-Forwarded-For hop
// when the peer is a trusted proxy.
func (n *netInfo) ClientIP(r *http.Request) netip.Addr {
	peer := n.peer(r)
	if !n.isTrusted(peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(hops[i])
		if err != nil {
			return peer // malformed chain: fall back to the proxy itself
		}
		a = a.Unmap()
		if !n.isTrusted(a) {
			return a
		}
	}
	return peer
}

func lastForwarded(r *http.Request, name string) string {
	vals := r.Header.Values(name)
	if len(vals) == 0 {
		return ""
	}
	parts := strings.Split(vals[len(vals)-1], ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

// host is the Host the client addressed (X-Forwarded-Host from trusted proxies).
func (n *netInfo) host(r *http.Request) string {
	if n.fromTrustedProxy(r) {
		if h := lastForwarded(r, "X-Forwarded-Host"); h != "" {
			return h
		}
	}
	return r.Host
}

// Transport classifies how the request reached the gateway. The Host header,
// not the source IP, decides "local": Docker port publishing rewrites
// loopback clients to the bridge gateway address.
func (n *netInfo) Transport(r *http.Request) string {
	if r.TLS != nil {
		return TransportTLS
	}
	if n.fromTrustedProxy(r) && strings.EqualFold(lastForwarded(r, "X-Forwarded-Proto"), "https") {
		return TransportTLS
	}
	h := n.host(r)
	if hn, _, err := net.SplitHostPort(h); err == nil {
		h = hn
	}
	if config.IsLoopbackHost(h) {
		return TransportLocal
	}
	if n.external {
		return TransportTunnel
	}
	return TransportInsecure
}

// BaseURL is the public URL if configured, else derived from the request.
func (n *netInfo) BaseURL(r *http.Request, publicURL string) string {
	if publicURL != "" {
		return publicURL
	}
	scheme := "http"
	if n.Transport(r) == TransportTLS {
		scheme = "https"
	}
	h := n.host(r)
	if h == "" || strings.ContainsAny(h, "/\\ \"'<>`") {
		h = "localhost"
	}
	return scheme + "://" + h
}
