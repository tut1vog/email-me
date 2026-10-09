// Command email-me is the email gateway, and the host commands that run it
// in a Docker container.
//
// On the host:
//
//	email-me start                  create and start the container (the first run writes a starter config)
//	email-me stop                   stop it
//	email-me restart                stop, then start: applies config.yaml and a new version
//	email-me console                open the dashboard until Ctrl-C
//	email-me reset-keyring [--yes]  lost key-encryption key: discard the sealed credentials
//	email-me update [--version V]   replace this binary with the latest release, then restart a running gateway
//	email-me version
//
// In the container, or directly on a host without Docker:
//
//	email-me run [--config F] [--data-dir D] [--listen-all]   the gateway, in the foreground
//	email-me healthcheck [--config F]                         GET /healthz, for Docker's HEALTHCHECK
//	email-me console [--data-dir D] [--stdin]
//	email-me reset-keyring [--yes] [--data-dir D]
//
// The configuration lives in config.yaml in the configuration directory
// (~/.config/email-me, mounted at /config in the container); the state
// database in the data directory (/data in the container).
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
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/api"
	"github.com/tut1vog/email-me/internal/audit"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/console"
	"github.com/tut1vog/email-me/internal/dashboard"
	"github.com/tut1vog/email-me/internal/host"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/ratelimit"
	"github.com/tut1vog/email-me/internal/selfupdate"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/upstream"
)

// version is the release tag, set at build time with
// -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `Usage: email-me <command>

Commands:
  start           create and start the gateway's container
  stop            stop it
  restart         stop, then start: applies config.yaml and a new version
  console         open the dashboard and print a login link; Ctrl-C closes it
  reset-keyring   lost key-encryption key: discard the credentials sealed with it
  update          install the latest release and restart a running gateway on it
  version         print the version

  run             run the gateway in the foreground (the container's command)
  healthcheck     check the gateway answers (Docker's HEALTHCHECK)

Configuration: ~/.config/email-me/config.yaml (or $EMAIL_ME_CONFIG_DIR).
`

// errUsage exits with status 2 after the usage was shown.
var errUsage = errors.New("usage")

// inContainer reports whether this process runs in the image, which sets
// EMAIL_ME_CONTAINER: there console and reset-keyring act on the local
// gateway, and the host commands do not exist.
func inContainer() bool { return os.Getenv("EMAIL_ME_CONTAINER") != "" }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := dispatch(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, errUsage):
		os.Exit(2)
	case errors.As(err, &exit):
		os.Exit(exit.ExitCode()) // docker's command already said why
	case errors.Is(err, errUnhealthy):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "email-me:", err)
		os.Exit(1)
	}
}

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errUsage
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("email-me "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir, _ := host.ConfigDir()
	dataDir, _ := host.DataDir()
	switch cmd {
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil

	case "run":
		cfgPath := fs.String("config", filepath.Join(configDir, "config.yaml"), "config file")
		data := fs.String("data-dir", dataDir, "state directory")
		listenAll := fs.Bool("listen-all", false, "listen on all interfaces at the configured ports (in a container, whose ports are published on the configured host addresses)")
		if err := parse(fs, args); err != nil {
			return err
		}
		return run(ctx, options{config: *cfgPath, dataDir: *data, listenAll: *listenAll})

	case "healthcheck":
		cfgPath := fs.String("config", filepath.Join(configDir, "config.yaml"), "config file")
		if err := parse(fs, args); err != nil {
			return err
		}
		return healthcheck(*cfgPath, stderr)

	case "console":
		data := fs.String("data-dir", dataDir, "the gateway's state directory, when it runs on this host without Docker")
		stdin := fs.Bool("stdin", false, "also close the dashboard when standard input ends")
		if err := parse(fs, args); err != nil {
			return err
		}
		if inContainer() || flagSet(fs, "data-dir") {
			var in io.Reader
			if *stdin {
				in = os.Stdin
			}
			return console.Attach(ctx, filepath.Join(*data, console.SocketName), in, stdout)
		}
		return newHost(configDir, dataDir, stdout, stderr).Console(ctx)

	case "reset-keyring":
		yes := fs.Bool("yes", false, "discard the credentials (without it, only say what would be discarded)")
		data := fs.String("data-dir", dataDir, "the gateway's state directory, when it runs on this host without Docker")
		if err := parse(fs, args); err != nil {
			return err
		}
		if inContainer() || flagSet(fs, "data-dir") {
			return resetKeyring(*data, *yes, stdout)
		}
		return newHost(configDir, dataDir, stdout, stderr).ResetKeyring(ctx, *yes)

	case "update":
		want := fs.String("version", "", "release tag to install, e.g. v1.2.3 (default: the latest release)")
		if err := parse(fs, args); err != nil {
			return err
		}
		if inContainer() {
			return errors.New("update runs on the host, not in the container")
		}
		return update(ctx, selfupdate.New(), *want, newHost(configDir, dataDir, stdout, stderr), stdout, stderr)

	case "start", "stop", "restart":
		if err := parse(fs, args); err != nil {
			return err
		}
		if inContainer() {
			return fmt.Errorf("%s runs on the host, not in the container", cmd)
		}
		h := newHost(configDir, dataDir, stdout, stderr)
		switch cmd {
		case "start":
			return h.Start(ctx)
		case "stop":
			return h.Stop(ctx)
		}
		return h.Restart(ctx)
	}
	fmt.Fprintf(stderr, "email-me: unknown command %q\n\n%s", cmd, usage)
	return errUsage
}

// update replaces this binary with the release want (default: the
// latest), then restarts a running gateway with the new binary, whose
// version picks the new image.
func update(ctx context.Context, u *selfupdate.Updater, want string, h *host.Host, stdout, stderr io.Writer) error {
	if want == "" {
		if version == "dev" {
			return errors.New("this is a development build; pass --version to replace it with a release")
		}
		latest, err := u.Latest(ctx)
		if err != nil {
			return err
		}
		want = latest
	}
	if want == version {
		fmt.Fprintf(stdout, "email-me %s is the latest release.\n", version)
		return nil
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return fmt.Errorf("finding this binary: %w", err)
	}
	fmt.Fprintf(stderr, "Downloading email-me %s for %s/%s...\n", want, u.OS, u.Arch)
	if err := u.Install(ctx, want, exe); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Updated %s from %s to %s.\n  Release notes: https://github.com/%s/releases/tag/%s\n",
		exe, version, want, selfupdate.Repo, want)
	if running, err := h.Running(ctx); err != nil || !running {
		fmt.Fprintln(stdout, "Run email-me start to run it.")
		return nil
	}
	fmt.Fprintln(stdout, "Restarting the gateway on the new version.")
	cmd := exec.CommandContext(ctx, exe, "restart")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return cmd.Run()
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
		return errUsage
	}
	return nil
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func newHost(configDir, dataDir string, stdout, stderr io.Writer) *host.Host {
	image := os.Getenv("EMAIL_ME_IMAGE")
	if image == "" {
		image = host.ImageFor(version)
	}
	return &host.Host{Dir: configDir, DataDir: dataDir, Image: image, UID: os.Getuid(), GID: os.Getgid(),
		Docker: host.CLI{}, Out: stdout, Err: stderr}
}

func newLogger(c config.Log) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(c.Level))
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// options configure run.
type options struct {
	config, dataDir string
	// listenAll binds each listener on all interfaces at its configured
	// port: in a container, whose ports Docker publishes on the configured
	// host addresses.
	listenAll bool
	// started, for tests, is called with the API's bound address once it
	// listens; consoleOpened with the dashboard's each time a console
	// opens it.
	started       func(apiAddr string)
	consoleOpened func(dashAddr string)
}

// bindAddr is where a listener binds: listen itself, or all interfaces at
// its port with listenAll.
func (o options) bindAddr(listen string) string {
	if !o.listenAll {
		return listen
	}
	_, port, _ := net.SplitHostPort(listen)
	return ":" + port
}

// run runs the gateway until ctx ends: the agent API, the console's
// control socket (which opens the dashboard on demand) and the retention
// job.
func run(ctx context.Context, o options) error {
	cfg, err := config.Load(o.config)
	if err != nil {
		return err
	}
	log := newLogger(cfg.Log)

	// runCtx stops the retention job and the console socket.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(o.dataDir, "state.db"))
	if err != nil {
		return fmt.Errorf("opening state database in %s: %w", o.dataDir, err)
	}
	defer st.Close()

	// The keyring before anything that reads a credential. A KEK that does
	// not open it is fatal, like any other configuration problem.
	kr, ev, err := keyring.Open(runCtx, st, cfg.KEK.Key, cfg.KEK.Previous)
	if err != nil {
		return err
	}
	switch {
	case ev == keyring.Created:
		log.Info("created the keyring: stored credentials are encrypted under kek.file from now on")
	case ev == keyring.Rewrapped:
		log.Info("rotated the key-encryption key: the keyring is now encrypted under kek.file; delete the previous key")
	case cfg.KEK.Previous != nil:
		log.Info("the previous key-encryption key is no longer needed: the keyring opens with kek.file; delete it")
	case kr == nil:
		log.Warn("no key-encryption key (kek.file): signing is off and the SMTP password is stored unencrypted")
	}

	// From here on, everything reads the current configuration through sm,
	// so a change saved on the dashboard applies at once; cfg itself is used
	// only for the bootstrap keys.
	sm, err := settings.Open(runCtx, o.config, cfg, st, kr, log)
	if err != nil {
		return err
	}
	cur := sm.Current()
	for _, w := range cur.Warnings {
		log.Warn(w)
	}
	if len(cur.Recipients) == 0 {
		log.Warn("no recipients: agents cannot send until you add one on the dashboard")
	}
	if orphans, err := st.AgentsWithData(runCtx); err == nil {
		for _, name := range orphans {
			if _, ok := cur.Agent(name); !ok {
				log.Info("the state database holds tokens and keys of an agent that is not in config.yaml; they are inert", "agent", name)
			}
		}
	}

	km := keys.NewManager(st, keysOptions(sm, kr))
	if err := km.LoadMaster(runCtx); err != nil {
		log.Error("the certification key cannot be loaded; new agent keys are not certified until it is set again on the Settings page", "err", err)
	}
	if km.Enabled() {
		n, err := km.EnsureAll(runCtx, cur.AgentNames())
		switch {
		case errors.Is(err, keys.ErrNoFrom):
			log.Warn("some agents have no signing key; they get one once upstream.from is set on the Settings page")
		case err != nil:
			return fmt.Errorf("checking signing keys: %w", err)
		}
		if n > 0 {
			log.Info("generated signing keys for agents without one", "count", n)
		}
	}

	sender := upstream.NewDynamic(func() config.SMTP { return sm.Current().Upstream.SMTP })
	auditW := audit.NewWriter(st, func() bool { return sm.Current().Audit.LogSubject }, log)
	apiSrv := api.New(api.Deps{
		Config: sm.Current, Store: st, Keys: km, Sender: sender,
		Limiter: ratelimit.New(st), Audit: auditW, Log: log.With("component", "api"),
	})
	dash, err := dashboard.New(dashboard.Deps{Store: st, Settings: sm, Keys: km, Sender: sender,
		Log: log.With("component", "dashboard")})
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
	apiLn, err := net.Listen("tcp", o.bindAddr(cfg.API.Listen))
	if err != nil {
		return fmt.Errorf("API server: %w", err)
	}
	ctlLn, err := console.Listen(filepath.Join(o.dataDir, console.SocketName))
	if err != nil {
		apiLn.Close()
		return err
	}
	consoles := &console.Server{Dash: dash, Listen: cfg.Dashboard.Listen, Bind: o.bindAddr(cfg.Dashboard.Listen),
		Log: log.With("component", "console"), Opened: o.consoleOpened}

	var bg group
	bg.Go(func() {
		audit.RunRetention(runCtx, st, func() time.Duration {
			return time.Duration(sm.Current().Audit.RetentionDays) * 24 * time.Hour
		}, log)
	})
	bg.Go(func() { consoles.Serve(runCtx, ctlLn) })

	errc := make(chan error, 1)
	go func() {
		log.Info("API listening", "addr", apiLn.Addr().String(), "tls", apiHTTP.TLSConfig != nil, "docs", cur.API.Docs)
		var err error
		if apiHTTP.TLSConfig != nil {
			err = apiHTTP.ServeTLS(apiLn, "", "")
		} else {
			err = apiHTTP.Serve(apiLn)
		}
		errc <- fmt.Errorf("API server: %w", err)
	}()
	upstreamAddr := "not configured"
	if cur.Upstream.SMTP.Host != "" {
		upstreamAddr = cur.Upstream.SMTP.Addr()
	}
	log.Info("email-me started; run email-me console to open the dashboard", "version", version,
		"signing", km.Enabled(), "recipients", len(cur.Recipients), "agents", len(cur.Agents), "upstream", upstreamAddr)
	if o.started != nil {
		o.started(apiLn.Addr().String())
	}

	var result error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case result = <-errc: // the listener failed
	}
	// API first, so in-flight sends finish; then the console (and with it
	// the dashboard) and the retention job; the store closes last
	// (deferred).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), sm.Current().Upstream.SMTP.Timeout.D()+10*time.Second)
	defer cancel()
	if err := apiHTTP.Shutdown(shutdownCtx); err != nil {
		apiHTTP.Close()
	}
	cancelRun()
	bg.Wait()
	return result
}

// group runs functions and waits for them.
type group struct{ done []chan struct{} }

func (g *group) Go(f func()) {
	c := make(chan struct{})
	g.done = append(g.done, c)
	go func() {
		defer close(c)
		f()
	}()
}

func (g *group) Wait() {
	for _, c := range g.done {
		<-c
	}
}

// keysOptions configures signing: keys are sealed under the keyring (nil:
// signing is off), and the From address and key validity of new keys
// follow the configuration.
func keysOptions(sm *settings.Manager, kr *keyring.Keyring) keys.Options {
	return keys.Options{Keyring: kr, From: func() (string, time.Duration) {
		c := sm.Current()
		return c.Upstream.From, c.Signing.KeyValidity.D()
	}}
}

// resetKeyring discards the keyring and every credential sealed under it,
// for a lost key-encryption key. Without yes it only says what it would do.
// It needs nothing but the state database, so it works when the gateway
// cannot start.
func resetKeyring(dataDir string, yes bool, out io.Writer) error {
	path := filepath.Join(dataDir, "state.db")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no state database at %s: %w", path, err)
	}
	st, err := store.Open(path)
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
Tokens, the audit log and config.yaml are kept.
Run again with --yes, then email-me restart.
`)
		return nil
	}
	d, err := st.ResetKeyring(context.Background())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Discarded the keyring: SMTP password %s, certification key %s, %d agent signing key(s) retired.\n",
		yesNo(d.SMTPPassword, "removed", "none stored"), yesNo(d.CertifyKey, "removed", "none set"), d.AgentKeys)
	fmt.Fprintln(out, "Run email-me restart with the new kek: it creates a new keyring and new agent keys.")
	return nil
}

func yesNo(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

// errUnhealthy fails healthcheck after it said why.
var errUnhealthy = errors.New("unhealthy")

// healthcheck GETs /healthz on the local API. It reads only api.listen and
// api.tls from the config, so it works without access to secrets.
func healthcheck(cfgPath string, stderr io.Writer) error {
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
		fmt.Fprintln(stderr, "unhealthy:", err)
		return errUnhealthy
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(stderr, "unhealthy: status", resp.StatusCode)
		return errUnhealthy
	}
	return nil
}
