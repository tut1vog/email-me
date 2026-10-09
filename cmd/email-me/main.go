// Command email-me runs the email gateway.
//
//	email-me serve [--config /config/config.yaml]   (default command)
//	email-me healthcheck [--config ...]             (for Docker HEALTHCHECK)
//	email-me version
//	email-me reset-admin-password [--config ...]    (forgotten admin password)
//	email-me reset-keyring --yes [--config ...]     (lost key-encryption key)
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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/admin"
	"github.com/tut1vog/email-me/internal/api"
	"github.com/tut1vog/email-me/internal/audit"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/dashboard"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/ratelimit"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/upstream"
)

// version is the release tag, set at build time with
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	cmd, args := "serve", os.Args[1:]
	switch {
	case len(args) == 0:
	case args[0] == "serve", args[0] == "healthcheck", args[0] == "version", args[0] == "reset-admin-password", args[0] == "reset-keyring":
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println(version)
		return
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	defaultCfg := os.Getenv("EMAIL_ME_CONFIG")
	if defaultCfg == "" {
		defaultCfg = "/config/config.yaml"
	}
	cfgPath := fs.String("config", defaultCfg, "path to config.yaml (env EMAIL_ME_CONFIG)")
	yes := false
	if cmd == "reset-keyring" {
		fs.BoolVar(&yes, "yes", false, "discard the credentials (without it, only say what would be discarded)")
	}
	fs.Parse(args)

	switch cmd {
	case "healthcheck":
		os.Exit(healthcheck(*cfgPath))
	case "reset-admin-password":
		if err := resetAdminPassword(*cfgPath, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "email-me:", err)
			os.Exit(1)
		}
	case "reset-keyring":
		if err := resetKeyring(*cfgPath, yes, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "email-me:", err)
			os.Exit(1)
		}
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

	// The keyring before anything that reads a credential. A KEK that does
	// not open it is fatal, like any other bootstrap problem.
	kr, ev, err := keyring.Open(runCtx, st, cfg.KEK.Key, cfg.KEK.Previous)
	if err != nil {
		return err
	}
	switch {
	case ev == keyring.Created:
		log.Info("created the keyring: stored credentials are encrypted under kek.file from now on")
	case ev == keyring.Rewrapped:
		log.Info("rotated the key-encryption key: the keyring is now encrypted under kek.file; remove kek.previous_file and restart")
	case cfg.KEK.Previous != nil:
		log.Info("kek.previous_file is no longer needed: the keyring opens with kek.file; remove it")
	case kr == nil:
		log.Warn("no key-encryption key (kek.file): signing is off and the SMTP password is stored unencrypted")
	}
	setup, err := admin.Ensure(runCtx, st)
	if err != nil {
		return err
	}
	if setup != "" {
		// The one secret ever logged: it works once, to choose a password.
		log.Warn("dashboard setup password: log in with it and choose your own; every start prints a new one until you do", "password", setup)
	}

	// Settings first: they complete cfg (upstream, default policy, ...).
	// From here on, everything reads the current configuration through sm,
	// so a saved setting applies at once; cfg itself is used only for the
	// bootstrap keys, which need a restart.
	sm, _, err := settings.Bootstrap(runCtx, st, cfg, kr, log)
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
	for _, rc := range reg.All() {
		if rc.KeyErr != nil {
			log.Warn("recipient's stored PGP key cannot be read: replace or remove it in the dashboard", "alias", rc.Alias, "err", rc.KeyErr)
		}
	}
	if u := reg.UnknownAliases(cfg.Defaults.Policy); len(u) > 0 {
		log.Warn("defaults.policy.recipients names recipients that do not exist; they are ignored", "aliases", u)
	}

	km := keys.NewManager(st, keysOptions(sm, kr))
	if err := km.LoadMaster(runCtx); err != nil {
		log.Error("the certification key cannot be loaded; new agent keys are not certified until it is set again on the Settings page", "err", err)
	}
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

	// A restart is refused while config.yaml does not load or its KEK does
	// not open the keyring, so a typo cannot take the gateway down.
	preflight := func() error {
		c, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("config.yaml no longer loads: %w", err)
		}
		return keyring.Verify(runCtx, st, c.KEK.Key, c.KEK.Previous)
	}
	restart := make(chan struct{}, 1)
	requestRestart := func() error {
		if err := preflight(); err != nil {
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
			if err := preflight(); err != nil {
				log.Error("SIGHUP: not restarting", "err", err)
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

// keysOptions configures signing: keys are sealed under the keyring (nil:
// signing is off), and the From address and key validity of new keys
// follow the saved settings.
func keysOptions(sm *settings.Manager, kr *keyring.Keyring) keys.Options {
	return keys.Options{Keyring: kr, From: func() (string, time.Duration) {
		c := sm.Current()
		return c.Upstream.From, c.Signing.KeyValidity.D()
	}}
}

// openStateDB opens state.db for a recovery command. It reads only
// data_dir from config.yaml, so it works when the rest of the file does
// not load.
func openStateDB(cfgPath string) (*store.Store, error) {
	var c struct {
		DataDir string `yaml:"data_dir"`
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	path := filepath.Join(c.DataDir, "state.db")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no state database at %s: %w", path, err)
	}
	return store.Open(path)
}

// resetAdminPassword replaces the admin password with a setup password
// that the next login must change, and prints it.
func resetAdminPassword(cfgPath string, out io.Writer) error {
	st, err := openStateDB(cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	pw, err := admin.Reset(context.Background(), st)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Setup password: %s\n\nLog in to the dashboard with it; you will choose a new password next.\nSessions already open stay valid until they expire or email-me restarts.\n", pw)
	return nil
}

// resetKeyring discards the keyring and every credential sealed under it,
// for a lost key-encryption key. Without yes it only says what it would do.
func resetKeyring(cfgPath string, yes bool, out io.Writer) error {
	st, err := openStateDB(cfgPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if !yes {
		fmt.Fprint(out, `reset-keyring discards every credential encrypted with the key-encryption key:
  - the upstream SMTP password (enter it again on the Settings page),
  - the certification master key (set it again on the Settings page),
  - every agent's signing private key (the keys are retired; their public keys
    and revocation certificates stay, and agents get new keys at the next start).
Agents, tokens, recipients, settings and the audit log are kept.
Stop email-me (or restart it right after), then run again with --yes.
`)
		return nil
	}
	d, err := st.ResetKeyring(context.Background())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Discarded the keyring: SMTP password %s, certification key %s, %d agent signing key(s) retired.\n",
		yesNo(d.SMTPPassword, "removed", "none stored"), yesNo(d.CertifyKey, "removed", "none set"), d.AgentKeys)
	fmt.Fprintln(out, "Start email-me with the new kek.file: it creates a new keyring and new agent keys.")
	return nil
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
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
