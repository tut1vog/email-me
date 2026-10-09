// Command email-me runs the email gateway.
//
//	email-me serve [--config /config/config.yaml]   (default command)
//	email-me healthcheck [--config ...]             (for Docker HEALTHCHECK)
//
// Settings saved on the dashboard apply at once. serve restarts in place on
// SIGHUP or from the dashboard, to apply edits to config.yaml.
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
	"github.com/tut1vog/email-me/internal/policy"
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
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// errRestart ends a run that should be followed by the next one.
var errRestart = errors.New("restart requested")

// runHooks lets tests observe and drive the serve loop.
type runHooks struct {
	// started is called with the bound addresses once both listeners are up.
	started func(apiAddr, dashAddr string)
	// hup delivers SIGHUP. serve subscribes once, for the process lifetime,
	// so a SIGHUP between two runs is not fatal.
	hup <-chan os.Signal
	// grace is how long a dashboard-requested restart waits before it stops
	// the listeners, so the restarting page's assets still load.
	grace time.Duration
}

// serve runs the gateway until SIGINT or SIGTERM. A restart (the
// dashboard's Restart button or SIGHUP) ends one run and starts the next in
// the same process, reloading config.yaml; if the next run cannot start,
// serve returns its error.
func serve(cfgPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	return loop(ctx, cfgPath, runHooks{hup: hup, grace: time.Second})
}

func loop(ctx context.Context, cfgPath string, hooks runHooks) error {
	for {
		if err := run(ctx, cfgPath, hooks); !errors.Is(err, errRestart) {
			return err
		}
	}
}

// run is one start of the gateway. It returns nil when ctx ends,
// errRestart when a restart was requested, or the error that stopped it.
func run(ctx context.Context, cfgPath string, hooks runHooks) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)

	// runCtx ends with this run: it stops the retention job.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		return fmt.Errorf("opening state database in %s: %w", cfg.DataDir, err)
	}
	defer st.Close()

	// Settings first: they complete cfg (upstream, default policy, ...).
	// From here on, everything reads the current configuration through sm,
	// so a saved setting applies at once; cfg itself is used only for the
	// bootstrap keys, which need a restart.
	sm, _, err := settings.Bootstrap(runCtx, st, cfg, log)
	if err != nil {
		return err
	}
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}

	reg, seeded, err := recipients.Bootstrap(runCtx, st, cfg, func() policy.Effective { return sm.Current().DefaultPolicy })
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

	km := keys.NewManager(st, keysOptions(cfg, sm))
	if km.Enabled() {
		n, err := km.EnsureAll(runCtx)
		switch {
		case errors.Is(err, keys.ErrNoFrom):
			log.Warn("some agents have no signing key; they get one once upstream.from is set on the Settings page")
		case err != nil:
			return fmt.Errorf("checking signing keys: %w", err)
		}
		if n > 0 {
			log.Info("generated signing keys for existing agents", "count", n)
		}
	}

	// A restart is refused while config.yaml does not load, so a typo in
	// the file cannot take the gateway down.
	restart := make(chan struct{}, 1)
	requestRestart := func() error {
		if _, err := config.Load(cfgPath); err != nil {
			return err
		}
		select {
		case restart <- struct{}{}:
		default: // one is already on its way
		}
		return nil
	}

	// configChanged re-hashes config.yaml when a dashboard page renders:
	// the file is small, and an unreadable one counts as changed.
	configChanged := func() bool {
		fp, err := config.FileFingerprint(cfgPath)
		return err != nil || fp != cfg.Fingerprint
	}

	sender := upstream.NewDynamic(func() config.SMTP { return sm.Current().Upstream.SMTP })
	auditW := audit.NewWriter(st, func() bool { return sm.Current().Audit.LogSubject }, log)
	apiSrv := api.New(api.Deps{
		Config: sm.Current, Store: st, Recipients: reg, Keys: km, Sender: sender,
		Limiter: ratelimit.New(st), Audit: auditW, Log: log.With("component", "api"),
	})
	dash, err := dashboard.New(dashboard.Deps{Config: sm.Current, Store: st, Recipients: reg, Settings: sm, Keys: km, Sender: sender,
		Log: log.With("component", "dashboard"), Restart: requestRestart, ConfigChanged: configChanged})
	if err != nil {
		return err
	}

	// Write timeouts are fixed: the handlers that wait on the upstream
	// server extend their own deadline by the current upstream timeout.
	apiHTTP := &http.Server{
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	if cfg.API.Certificate != nil {
		apiHTTP.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cfg.API.Certificate}, MinVersion: tls.VersionTLS12}
	}
	dashHTTP := &http.Server{
		Handler:           dash.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	// Bind both before serving, so a port that cannot be (re)bound fails
	// the run at once.
	apiLn, err := net.Listen("tcp", cfg.API.Listen)
	if err != nil {
		return fmt.Errorf("API server: %w", err)
	}
	dashLn, err := net.Listen("tcp", cfg.Dashboard.Listen)
	if err != nil {
		apiLn.Close()
		return fmt.Errorf("dashboard server: %w", err)
	}

	retention := make(chan struct{})
	go func() {
		defer close(retention)
		audit.RunRetention(runCtx, st, func() time.Duration {
			return time.Duration(sm.Current().Audit.RetentionDays) * 24 * time.Hour
		}, log)
	}()

	errc := make(chan error, 2)
	go func() {
		log.Info("API listening", "addr", apiLn.Addr().String(), "tls", apiHTTP.TLSConfig != nil, "docs", cfg.API.Docs)
		var err error
		if apiHTTP.TLSConfig != nil {
			err = apiHTTP.ServeTLS(apiLn, "", "")
		} else {
			err = apiHTTP.Serve(apiLn)
		}
		errc <- fmt.Errorf("API server: %w", err)
	}()
	go func() {
		log.Info("dashboard listening", "addr", dashLn.Addr().String())
		errc <- fmt.Errorf("dashboard server: %w", dashHTTP.Serve(dashLn))
	}()
	upstreamAddr := "not configured"
	if cfg.Upstream.SMTP.Host != "" {
		upstreamAddr = cfg.Upstream.SMTP.Addr()
	}
	log.Info("email-me started", "signing", km.Enabled(), "recipients", reg.Len(), "upstream", upstreamAddr)
	if hooks.started != nil {
		hooks.started(apiLn.Addr().String(), dashLn.Addr().String())
	}

	var result error
wait:
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			break wait
		case <-restart:
			log.Info("restarting to re-read config.yaml")
			// Let the restarting page load its stylesheet and script first.
			time.Sleep(hooks.grace)
			result = errRestart
			break wait
		case <-hooks.hup:
			if _, err := config.Load(cfgPath); err != nil {
				log.Error("SIGHUP: not restarting: config.yaml no longer loads", "err", err)
				continue
			}
			log.Info("SIGHUP: restarting to re-read config.yaml")
			result = errRestart
			break wait
		case err := <-errc: // a listener failed: stop the other and exit
			result = err
			break wait
		}
	}
	// API first, so in-flight sends finish; then the dashboard, then the
	// retention job; the store closes last (deferred).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), sm.Current().Upstream.SMTP.Timeout.D()+10*time.Second)
	defer cancel()
	if err := apiHTTP.Shutdown(shutdownCtx); err != nil {
		apiHTTP.Close()
	}
	if err := dashHTTP.Shutdown(shutdownCtx); err != nil {
		dashHTTP.Close()
	}
	cancelRun()
	<-retention
	return result
}

// keysOptions configures signing from config.yaml's bootstrap keys; the
// From address and key validity of new keys follow the saved settings.
func keysOptions(cfg *config.Config, sm *settings.Manager) keys.Options {
	o := keys.Options{From: func() (string, time.Duration) {
		c := sm.Current()
		var validity time.Duration
		if c.Signing != nil {
			validity = c.Signing.KeyValidity.D()
		}
		return c.Upstream.From, validity
	}}
	if cfg.Signing != nil {
		o.KEK, o.Master = cfg.Signing.KEK, cfg.Signing.Master
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
