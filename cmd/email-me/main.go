// Command email-me runs the email gateway.
//
//	email-me serve [--config /config/config.yaml]   (default command)
//	email-me healthcheck [--config ...]             (for Docker HEALTHCHECK)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/api"
	"github.com/tut1vog/email-me/internal/audit"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/dashboard"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/ratelimit"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/upstream"
)

func main() {
	cmd, args := "serve", os.Args[1:]
	if len(args) > 0 && (args[0] == "serve" || args[0] == "healthcheck") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	defaultCfg := os.Getenv("EMAIL_ME_CONFIG")
	if defaultCfg == "" {
		defaultCfg = "/config/config.yaml"
	}
	cfgPath := fs.String("config", defaultCfg, "path to config.yaml (env EMAIL_ME_CONFIG)")
	fs.Parse(args)

	switch cmd {
	case "healthcheck":
		os.Exit(healthcheck(*cfgPath))
	default:
		if err := serve(*cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "email-me:", err)
			os.Exit(1)
		}
	}
}

func newLogger(c config.Log) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(c.Level))
	opts := &slog.HandlerOptions{Level: level}
	if c.Format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func serve(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		return fmt.Errorf("opening state database in %s: %w", cfg.DataDir, err)
	}
	defer st.Close()

	// Settings first: they complete cfg (upstream, default policy, ...).
	sm, _, err := settings.Bootstrap(ctx, st, cfg, log)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}

	reg, seeded, err := recipients.Bootstrap(ctx, st, cfg)
	if err != nil {
		return err
	}
	if len(seeded) > 0 {
		log.Info("imported recipients from config.yaml into the state database; manage them in the dashboard from now on", "aliases", seeded)
	}
	if reg.Len() == 0 {
		log.Warn("no recipients: agents cannot send until you add one in the dashboard")
	}
	if u := reg.UnknownAliases(cfg.Defaults.Policy); len(u) > 0 {
		log.Warn("defaults.policy.recipients names recipients that do not exist; they are ignored", "aliases", u)
	}

	km := keys.NewManager(st, keysOptions(cfg))
	if km.Enabled() {
		n, err := km.EnsureAll(ctx)
		switch {
		case errors.Is(err, keys.ErrNoFrom):
			log.Warn("some agents have no signing key; they get one once upstream.from is set on the Settings page and the gateway restarted")
		case err != nil:
			return fmt.Errorf("checking signing keys: %w", err)
		}
		if n > 0 {
			log.Info("generated signing keys for existing agents", "count", n)
		}
	}

	sender := upstream.NewSMTP(cfg.Upstream.SMTP)
	auditW := audit.NewWriter(st, cfg.Audit.LogSubject, log)
	apiSrv := api.New(api.Deps{
		Config: cfg, Store: st, Recipients: reg, Keys: km, Sender: sender,
		Limiter: ratelimit.New(st), Audit: auditW, Log: log.With("component", "api"),
	})
	dash, err := dashboard.New(dashboard.Deps{Config: cfg, Store: st, Recipients: reg, Settings: sm, Keys: km, Sender: sender, Log: log.With("component", "dashboard")})
	if err != nil {
		return err
	}

	go audit.RunRetention(ctx, st, time.Duration(cfg.Audit.RetentionDays)*24*time.Hour, log)

	apiHTTP := &http.Server{
		Addr:              cfg.API.Listen,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      cfg.Upstream.SMTP.Timeout.D() + 2*time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.API.Certificate != nil {
		apiHTTP.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cfg.API.Certificate}, MinVersion: tls.VersionTLS12}
	}
	dashHTTP := &http.Server{
		Addr:              cfg.Dashboard.Listen,
		Handler:           dash.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      cfg.Upstream.SMTP.Timeout.D() + time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 2)
	go func() {
		log.Info("API listening", "addr", cfg.API.Listen, "tls", apiHTTP.TLSConfig != nil, "docs", cfg.API.Docs)
		var err error
		if apiHTTP.TLSConfig != nil {
			err = apiHTTP.ListenAndServeTLS("", "")
		} else {
			err = apiHTTP.ListenAndServe()
		}
		errc <- fmt.Errorf("API server: %w", err)
	}()
	go func() {
		log.Info("dashboard listening", "addr", cfg.Dashboard.Listen)
		errc <- fmt.Errorf("dashboard server: %w", dashHTTP.ListenAndServe())
	}()
	upstreamAddr := "not configured"
	if cfg.Upstream.SMTP.Host != "" {
		upstreamAddr = cfg.Upstream.SMTP.Addr()
	}
	log.Info("email-me started", "signing", km.Enabled(), "recipients", reg.Len(), "upstream", upstreamAddr)

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Upstream.SMTP.Timeout.D()+10*time.Second)
	defer cancel()
	apiHTTP.Shutdown(shutdownCtx) // lets in-flight sends finish
	dashHTTP.Shutdown(shutdownCtx)
	return nil
}

func keysOptions(cfg *config.Config) keys.Options {
	o := keys.Options{Email: cfg.Upstream.From}
	if cfg.Signing != nil {
		o.KEK, o.Validity, o.Master = cfg.Signing.KEK, cfg.Signing.KeyValidity.D(), cfg.Signing.Master
	}
	return o
}

// healthcheck GETs /healthz on the local API. It reads only api.listen and
// api.tls from the config so it works without access to secrets.
func healthcheck(cfgPath string) int {
	var c struct {
		API struct {
			Listen string `yaml:"listen"`
			TLS    struct {
				CertFile string `yaml:"cert_file"`
			} `yaml:"tls"`
		} `yaml:"api"`
	}
	if data, err := os.ReadFile(cfgPath); err == nil {
		_ = yaml.Unmarshal(data, &c)
	}
	port := "8025"
	if _, p, err := net.SplitHostPort(c.API.Listen); err == nil {
		port = p
	}
	scheme := "http"
	if c.API.TLS.CertFile != "" {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Loopback check of our own listener; the certificate names a public host.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(scheme + "://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", resp.StatusCode)
		return 1
	}
	return 0
}
