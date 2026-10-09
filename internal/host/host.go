// Package host implements the commands that run on the operator's machine
// and drive the gateway's Docker container through the docker CLI: start,
// stop, restart, console and reset-keyring. The container is disposable:
// everything durable is in the configuration directory, mounted at
// /config, and the named volume at /data, so start always creates a fresh
// container from the current configuration.
package host

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	emailme "github.com/tut1vog/email-me"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/console"
)

const (
	// Container is the gateway container's name.
	Container = "email-me"
	// Volume is the named volume holding state.db.
	Volume = "email-me-data"
	// ImageRepo is where release images are published.
	ImageRepo = "ghcr.io/tut1vog/email-me"
)

// Host runs the host commands.
type Host struct {
	// Dir is the configuration directory, mounted at /config.
	Dir string
	// DataDir is where a gateway run directly on this host (without
	// Docker) keeps state.db; console attaches to it when no container
	// runs.
	DataDir  string
	Image    string
	UID, GID int
	Docker   Docker
	Out, Err io.Writer
	// Healthy checks that the gateway answers; nil checks GET /healthz on
	// the API's host address.
	Healthy func(ctx context.Context, cfg *config.Config) error
	// StartTimeout bounds how long start waits for the gateway (default 60s).
	StartTimeout time.Duration
}

// ConfigDir returns the configuration directory: $EMAIL_ME_CONFIG_DIR, else
// email-me under $XDG_CONFIG_HOME, else ~/.config/email-me.
func ConfigDir() (string, error) {
	if d := os.Getenv("EMAIL_ME_CONFIG_DIR"); d != "" {
		return filepath.Abs(d)
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "email-me"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "email-me"), nil
}

// DataDir returns where a gateway run without Docker keeps its state:
// $EMAIL_ME_DATA_DIR, else email-me under $XDG_DATA_HOME, else
// ~/.local/share/email-me.
func DataDir() (string, error) {
	if d := os.Getenv("EMAIL_ME_DATA_DIR"); d != "" {
		return filepath.Abs(d)
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "email-me"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "email-me"), nil
}

// ImageFor returns the image for a binary version: the release's tag for
// a release build (v1.2.3 → 1.2.3), latest otherwise.
func ImageFor(version string) string {
	tag := "latest"
	if v, ok := strings.CutPrefix(version, "v"); ok && v != "" {
		tag = v
	}
	return ImageRepo + ":" + tag
}

func (h *Host) configPath() string { return filepath.Join(h.Dir, "config.yaml") }

// Init creates the configuration directory on the first run: a starter
// config.yaml and a fresh KEK. It reports whether it did; an existing
// config.yaml is never touched.
func (h *Host) Init() (bool, error) {
	if _, err := os.Stat(h.configPath()); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(h.Dir, 0o700); err != nil {
		return false, err
	}
	kek := filepath.Join(h.Dir, "kek")
	if _, err := os.Stat(kek); errors.Is(err, os.ErrNotExist) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return false, err
		}
		if err := os.WriteFile(kek, []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			return false, err
		}
	}
	if err := os.WriteFile(h.configPath(), emailme.ExampleConfig, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// Load loads and validates config.yaml as the gateway will. Files it
// names must be inside the configuration directory, the only part of the
// host the container sees.
func (h *Host) Load() (*config.Config, error) {
	var paths struct {
		API struct {
			TLS struct {
				CertFile string `yaml:"cert_file"`
				KeyFile  string `yaml:"key_file"`
			} `yaml:"tls"`
		} `yaml:"api"`
		KEK struct {
			File         string `yaml:"file"`
			PreviousFile string `yaml:"previous_file"`
		} `yaml:"kek"`
	}
	var problems []string
	if data, err := os.ReadFile(h.configPath()); err == nil && yaml.Unmarshal(data, &paths) == nil {
		for _, p := range []struct{ key, path string }{
			{"api.tls.cert_file", paths.API.TLS.CertFile}, {"api.tls.key_file", paths.API.TLS.KeyFile},
			{"kek.file", paths.KEK.File}, {"kek.previous_file", paths.KEK.PreviousFile},
		} {
			if p.path != "" && !filepath.IsLocal(p.path) {
				problems = append(problems, fmt.Sprintf("%s must be a path inside %s, relative to it: the container sees nothing else", p.key, h.Dir))
			}
		}
	}
	cfg, err := config.Load(h.configPath())
	var ve *config.ValidationError
	switch {
	case errors.As(err, &ve):
		ve.Problems = append(problems, ve.Problems...)
		return nil, ve
	case err != nil:
		return nil, err
	case len(problems) > 0:
		return nil, &config.ValidationError{Problems: problems}
	}
	return cfg, nil
}

// state returns the container's status ("running", "exited", ...) or ""
// if there is none.
func (h *Host) state(ctx context.Context) (string, error) {
	out, err := h.Docker.Output(ctx, "container", "inspect", "--format", "{{.State.Status}}", Container)
	if errors.Is(err, ErrNoContainer) {
		return "", nil
	}
	return strings.TrimSpace(out), err
}

// Start creates and starts the container from the current configuration
// and waits until the gateway answers. A running container is left alone.
func (h *Host) Start(ctx context.Context) error {
	created, err := h.Init()
	if err != nil {
		return fmt.Errorf("creating %s: %w", h.Dir, err)
	}
	if created {
		fmt.Fprintf(h.Out, "Created %s with a starter config.yaml and a key-encryption key (kek).\nBack the directory up: without kek, the credentials email-me stores are lost.\n\n", h.Dir)
	}
	cfg, err := h.Load()
	if err != nil {
		return err
	}
	st, err := h.state(ctx)
	if err != nil {
		return err
	}
	if st == "running" {
		fmt.Fprintf(h.Out, "email-me is already running (run email-me restart to apply changes).\n  API: %s\n", apiURL(cfg))
		return nil
	}
	if st != "" {
		if _, err := h.Docker.Output(ctx, "container", "rm", "--force", Container); err != nil {
			return err
		}
	}
	if _, err := h.Docker.Output(ctx, RunArgs(RunOptions{
		Image: h.Image, ConfigDir: h.Dir, UID: h.UID, GID: h.GID,
		APIListen: cfg.API.Listen, DashboardListen: cfg.Dashboard.Listen,
	})...); err != nil {
		return err
	}
	if err := h.waitHealthy(ctx, cfg); err != nil {
		return err
	}
	fmt.Fprintf(h.Out, "email-me is running.\n  API: %s\n  Configuration: %s\nRun email-me console to open the dashboard.\n", apiURL(cfg), h.configPath())
	return nil
}

// waitHealthy waits until the gateway answers. If the container stops or
// keeps restarting instead, it shows the container's last log lines,
// stops it and fails.
func (h *Host) waitHealthy(ctx context.Context, cfg *config.Config) error {
	healthy := h.Healthy
	if healthy == nil {
		healthy = checkHealth
	}
	timeout := h.StartTimeout
	if timeout == 0 {
		timeout = time.Minute
	}
	deadline := time.Now().Add(timeout)
	for {
		st, err := h.state(ctx)
		if err != nil {
			return err
		}
		if st != "running" && st != "created" {
			return h.failed(ctx, "email-me did not start")
		}
		if healthy(ctx, cfg) == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return h.failed(ctx, fmt.Sprintf("email-me did not answer within %s", timeout))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (h *Host) failed(ctx context.Context, what string) error {
	// The gateway logs to stderr, which docker logs replays on stderr.
	var logs strings.Builder
	_ = h.Docker.Run(nil, &logs, &logs, "container", "logs", "--tail", "30", Container)
	_, _ = h.Docker.Output(ctx, "container", "stop", Container)
	if l := strings.TrimSpace(logs.String()); l != "" {
		fmt.Fprintf(h.Err, "Its last log lines:\n%s\n\n", l)
	}
	return fmt.Errorf("%s; fix the problem, then run email-me start", what)
}

// Stop stops the container, giving sends in flight the SMTP timeout to
// finish.
func (h *Host) Stop(ctx context.Context) error {
	st, err := h.state(ctx)
	if err != nil {
		return err
	}
	if st != "running" && st != "restarting" {
		fmt.Fprintln(h.Out, "email-me is not running.")
		return nil
	}
	grace := 40 * time.Second
	if cfg, err := config.Load(h.configPath()); err == nil {
		grace = cfg.Upstream.SMTP.Timeout.D() + 10*time.Second
	}
	if _, err := h.Docker.Output(ctx, "container", "stop", "--time", fmt.Sprint(int(grace.Seconds())), Container); err != nil {
		return err
	}
	fmt.Fprintln(h.Out, "email-me stopped.")
	return nil
}

// Restart stops and starts the container, applying config.yaml and a new
// image. The file is checked first, so a broken one never stops a running
// gateway.
func (h *Host) Restart(ctx context.Context) error {
	if _, err := h.Load(); err != nil {
		return fmt.Errorf("not restarted: %w", err)
	}
	if err := h.Stop(ctx); err != nil {
		return err
	}
	return h.Start(ctx)
}

// Console opens the dashboard in the running gateway and keeps it open
// until ctx ends (Ctrl-C). Inside the container, `console --stdin` holds
// the dashboard open until its standard input closes; this process holds
// the other end, so the dashboard closes however this process ends.
func (h *Host) Console(ctx context.Context) error {
	st, err := h.state(ctx)
	if err != nil {
		return err
	}
	if st != "running" {
		// A gateway run directly on this host, without Docker.
		sock := filepath.Join(h.DataDir, console.SocketName)
		if _, err := os.Stat(sock); err == nil {
			return console.Attach(ctx, sock, nil, h.Out)
		}
		return errors.New("email-me is not running; run email-me start")
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- h.Docker.Run(pr, h.Out, h.Err, "container", "exec", "--interactive", Container, "email-me", "console", "--stdin")
	}()
	select {
	case err := <-done:
		pw.Close()
		return err
	case <-ctx.Done():
		pw.Close()
		return <-done
	}
}

// ResetKeyring runs reset-keyring in the gateway's container, or in a
// one-off container on the same volume when the gateway is not running
// (which a lost KEK prevents).
func (h *Host) ResetKeyring(ctx context.Context, yes bool) error {
	st, err := h.state(ctx)
	if err != nil {
		return err
	}
	cmd := []string{"reset-keyring"}
	if yes {
		cmd = append(cmd, "--yes")
	}
	var args []string
	if st == "running" {
		args = append([]string{"container", "exec", Container, "email-me"}, cmd...)
	} else {
		args = append([]string{"container", "run", "--rm", "--user", fmt.Sprintf("%d:%d", h.UID, h.GID),
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
			"--volume", h.Dir + ":/config", "--volume", Volume + ":/data", h.Image}, cmd...)
	}
	return h.Docker.Run(nil, h.Out, h.Err, args...)
}

// RunOptions are what RunArgs needs.
type RunOptions struct {
	Image, ConfigDir           string
	UID, GID                   int
	APIListen, DashboardListen string
}

// RunArgs returns the docker arguments that create the gateway's
// container: hardened (read-only root, no capabilities, no new
// privileges), running as the operator's user so it can write the
// configuration directory, and publishing each listener on its configured
// host address. Inside, the gateway listens on all interfaces at the same
// ports.
func RunArgs(o RunOptions) []string {
	return []string{"container", "run", "--detach", "--name", Container, "--restart", "unless-stopped",
		"--user", fmt.Sprintf("%d:%d", o.UID, o.GID),
		"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
		"--publish", publish(o.APIListen), "--publish", publish(o.DashboardListen),
		"--volume", o.ConfigDir + ":/config", "--volume", Volume + ":/data",
		o.Image, "run", "--listen-all"}
}

// publish turns a listen address into a docker port mapping.
func publish(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	if host == "" {
		return port + ":" + port
	}
	return net.JoinHostPort(host, port) + ":" + port
}

// apiURL is the API's base URL from the host.
func apiURL(cfg *config.Config) string {
	if cfg.API.PublicURL != "" {
		return cfg.API.PublicURL
	}
	scheme := "http"
	if cfg.API.TLS.Enabled() {
		scheme = "https"
	}
	return scheme + "://" + dialAddr(cfg.API.Listen)
}

// dialAddr is where the host reaches a listen address: loopback for an
// unspecified host.
func dialAddr(listen string) string {
	host, port, _ := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// checkHealth GETs /healthz on the API's published address.
func checkHealth(ctx context.Context, cfg *config.Config) error {
	scheme := "http"
	if cfg.API.TLS.Enabled() {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Our own listener; the certificate names a public host.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+dialAddr(cfg.API.Listen)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}
