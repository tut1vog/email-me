// Package console opens the dashboard on demand. The gateway listens on a
// Unix socket in its data directory (Server); `email-me console` connects
// to it (Attach), and the gateway opens the dashboard listener and answers
// with a one-time login link. The connection is the console's lifetime:
// when it drops, the gateway closes the listener and ends every session.
package console

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/config"
)

// SocketName is the control socket's name in the data directory.
const SocketName = "console.sock"

// Dashboard is what the console opens.
type Dashboard interface {
	Handler() http.Handler
	// NewLink mints a one-time login token for GET /login?token=.
	NewLink() string
	// EndSessions ends every session and voids unspent links.
	EndSessions()
}

// reply is the gateway's one message to a console.
type reply struct {
	URL   string `json:"url,omitempty"`
	Error string `json:"error,omitempty"`
}

// Server serves consoles on the control socket.
type Server struct {
	Dash Dashboard
	// Listen is dashboard.listen, the host's address: the login link names
	// it. Bind is where the listener binds, Listen itself unless the
	// gateway runs in a container (all interfaces, same port).
	Listen, Bind string
	Log          *slog.Logger
	// Opened, if set, is called with the bound address each time the
	// dashboard opens.
	Opened func(addr string)

	mu   sync.Mutex
	open bool
}

// Listen creates the control socket at path, replacing a stale one, and
// makes it reachable by its owner only.
func Listen(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("console socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve accepts consoles on ln until ctx ends, then closes any open
// dashboard and returns.
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

// handle serves one console: it opens the dashboard, sends the link and
// keeps the dashboard open until the console disconnects or ctx ends.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	send := func(r reply) {
		_ = json.NewEncoder(conn).Encode(r)
	}
	s.mu.Lock()
	busy := s.open
	s.open = true
	s.mu.Unlock()
	if busy {
		send(reply{Error: "a console is already open; close it first"})
		return
	}
	defer func() {
		s.mu.Lock()
		s.open = false
		s.mu.Unlock()
	}()

	ln, err := net.Listen("tcp", s.Bind)
	if err != nil {
		send(reply{Error: fmt.Sprintf("opening the dashboard on %s: %v", s.Bind, err)})
		return
	}
	srv := &http.Server{
		Handler:           s.Dash.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln)
	}()
	s.Log.Info("console opened the dashboard", "addr", ln.Addr().String())
	if s.Opened != nil {
		s.Opened(ln.Addr().String())
	}
	send(reply{URL: LinkURL(s.Listen, ln.Addr()) + "/login?token=" + s.Dash.NewLink()})

	// The console never writes: a read returns when it disconnects.
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		_, _ = io.Copy(io.Discard, conn)
	}()
	select {
	case <-gone:
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		srv.Close()
	}
	<-served
	s.Dash.EndSessions()
	s.Log.Info("console closed the dashboard")
}

// LinkURL is the dashboard's base URL for a login link: the host of
// dashboard.listen, with email-me.localhost for loopback and unspecified
// addresses (browsers scope cookies by host, so a dedicated name keeps the
// session cookie from web servers on other local ports), and the bound
// port when the configured one is 0.
func LinkURL(listen string, bound net.Addr) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "", "0"
	}
	if port == "0" {
		if a, ok := bound.(*net.TCPAddr); ok {
			port = strconv.Itoa(a.Port)
		}
	}
	if host == "" || config.IsLoopbackHost(host) || net.ParseIP(host).IsUnspecified() {
		host = "email-me.localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// Attach opens the dashboard through the gateway's control socket at path,
// prints the login link to out and keeps the dashboard open until ctx ends
// or, if stdin is not nil, stdin reaches end of file. It returns an error
// if the gateway refuses or stops.
func Attach(ctx context.Context, path string, stdin io.Reader, out io.Writer) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return fmt.Errorf("email-me is not running here (no console socket at %s)", filepath.Clean(path))
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("the gateway did not answer: %w", err)
	}
	var r reply
	if err := json.Unmarshal(line, &r); err != nil {
		return fmt.Errorf("the gateway's answer is not understood: %w", err)
	}
	if r.Error != "" {
		return errors.New(r.Error)
	}
	fmt.Fprintf(out, "Dashboard: %s\n\nOpen the link to sign in; it works once. The dashboard stays open until you press Ctrl-C.\n", r.URL)

	gone := make(chan struct{})
	go func() {
		defer close(gone)
		_, _ = io.Copy(io.Discard, conn)
	}()
	eof := make(chan struct{})
	if stdin != nil {
		go func() {
			defer close(eof)
			_, _ = io.Copy(io.Discard, stdin)
		}()
	}
	select {
	case <-ctx.Done():
	case <-eof:
	case <-gone:
		return errors.New("email-me stopped; the dashboard is closed")
	}
	fmt.Fprintln(out, "Dashboard closed.")
	return nil
}
