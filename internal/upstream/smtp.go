// Package upstream delivers messages to the configured SMTP server,
// synchronously and without any queue or spool.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/tut1vog/email-me/internal/config"
)

// Sender delivers a message.
type Sender interface {
	Send(ctx context.Context, from string, to []string, msg []byte) error
	Check(ctx context.Context) error
}

// ErrNotConfigured means no upstream server or From address is set yet (a
// fresh install); sends fail with it until the operator sets them.
var ErrNotConfigured = errors.New("not configured; set it on the dashboard's Settings page")

// Error is a delivery failure with the upstream SMTP reply code, if any.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("upstream SMTP %d: %v", e.Code, e.Err)
	}
	return "upstream SMTP: " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

type SMTP struct {
	cfg       config.SMTP
	tlsConfig *tls.Config
}

func NewSMTP(cfg config.SMTP) *SMTP {
	return &SMTP{cfg: cfg, tlsConfig: &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}}
}

func (s *SMTP) dial(ctx context.Context) (*smtp.Client, error) {
	if s.cfg.Host == "" {
		return nil, &Error{Err: ErrNotConfigured}
	}
	timeout := s.cfg.Timeout.D()
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if s.cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: d, Config: s.tlsConfig}).DialContext(ctx, "tcp", s.cfg.Addr())
	} else {
		conn, err = d.DialContext(ctx, "tcp", s.cfg.Addr())
	}
	if err != nil {
		return nil, &Error{Err: err}
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	var c *smtp.Client
	if s.cfg.Security == "starttls" {
		c, err = smtp.NewClientStartTLS(conn, s.tlsConfig)
	} else {
		c = smtp.NewClient(conn)
	}
	if err != nil {
		conn.Close()
		return nil, wrap(err)
	}
	if s.cfg.Username != "" {
		if err := c.Auth(sasl.NewPlainClient("", s.cfg.Username, s.cfg.Password)); err != nil {
			c.Close()
			return nil, wrap(err)
		}
	}
	return c, nil
}

// Send delivers msg; it returns only after the server accepted the data.
func (s *SMTP) Send(ctx context.Context, from string, to []string, msg []byte) error {
	if from == "" {
		// An empty MAIL FROM is the null sender reserved for bounces.
		return &Error{Err: ErrNotConfigured}
	}
	c, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SendMail(from, to, bytes.NewReader(msg)); err != nil {
		return wrap(err)
	}
	if err := c.Quit(); err != nil {
		// Data was accepted; a failed QUIT does not undo delivery.
		return nil
	}
	return nil
}

// Check connects, authenticates and quits.
func (s *SMTP) Check(ctx context.Context) error {
	c, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Noop(); err != nil {
		return wrap(err)
	}
	return wrap(c.Quit())
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return &Error{Code: se.Code, Err: err}
	}
	return &Error{Err: err}
}
