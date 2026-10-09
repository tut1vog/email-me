package host_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	emailme "github.com/tut1vog/email-me"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/host"
)

// fakeDocker records docker commands and plays a container's states.
type fakeDocker struct {
	mu    sync.Mutex
	calls [][]string
	// states are what successive inspects return; the last one repeats.
	// "" is no container.
	states []string
	logs   string
	// run, if set, plays Run (the console and reset-keyring).
	run func(stdin io.Reader, stdout io.Writer, args []string) error
}

func (f *fakeDocker) Output(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	switch args[1] {
	case "inspect":
		st := ""
		if len(f.states) > 0 {
			st = f.states[0]
			if len(f.states) > 1 {
				f.states = f.states[1:]
			}
		}
		if st == "" {
			return "", host.ErrNoContainer
		}
		return st + "\n", nil
	}
	return "", nil
}

func (f *fakeDocker) Run(stdin io.Reader, stdout, stderr io.Writer, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, args)
	run, logs := f.run, f.logs
	f.mu.Unlock()
	if args[1] == "logs" {
		io.WriteString(stderr, logs)
		return nil
	}
	if run != nil {
		return run(stdin, stdout, args)
	}
	return nil
}

// commands returns the docker subcommands run, inspects left out.
func (f *fakeDocker) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if c[1] != "inspect" {
			out = append(out, strings.Join(c[:2], " "))
		}
	}
	return out
}

func (f *fakeDocker) find(sub string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Join(c[:2], " ") == sub {
			return c
		}
	}
	return nil
}

func newHost(t *testing.T, d *fakeDocker) (*host.Host, *strings.Builder, *strings.Builder) {
	t.Helper()
	var out, errOut strings.Builder
	return &host.Host{Dir: filepath.Join(t.TempDir(), "email-me"), DataDir: t.TempDir(), Image: "ghcr.io/tut1vog/email-me:1.2.3",
		UID: 501, GID: 20, Docker: d, Out: &out, Err: &errOut,
		Healthy: func(context.Context, *config.Config) error { return nil }}, &out, &errOut
}

func TestFirstStart(t *testing.T) {
	d := &fakeDocker{states: []string{"", "running"}}
	h, out, _ := newHost(t, d)
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The directory is created with the starter config and a fresh KEK.
	if fi, err := os.Stat(h.Dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.Dir, "config.yaml")); string(b) != string(emailme.ExampleConfig) {
		t.Fatal("config.yaml must be the starter file")
	}
	kek, _ := os.ReadFile(filepath.Join(h.Dir, "kek"))
	if k, err := config.ParseKEK(kek); err != nil || len(k) != 32 {
		t.Fatalf("kek: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(h.Dir, "kek")); fi.Mode().Perm() != 0o600 {
		t.Fatal("the KEK is the owner's only")
	}
	for _, want := range []string{"Created " + h.Dir, "Back the directory up", "email-me is running", "http://127.0.0.1:8025", "email-me console"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if got := d.commands(); !slices.Equal(got, []string{"container run"}) {
		t.Fatalf("docker: %v", got)
	}
	run := d.find("container run")
	want := host.RunArgs(host.RunOptions{Image: h.Image, ConfigDir: h.Dir, UID: 501, GID: 20,
		APIListen: "127.0.0.1:8025", DashboardListen: "127.0.0.1:8026"})
	if !slices.Equal(run, want) {
		t.Fatalf("run args:\n%v\nwant\n%v", run, want)
	}

	// Started again: the files are kept, and a running container left alone.
	kekBefore := string(kek)
	os.WriteFile(filepath.Join(h.Dir, "config.yaml"), []byte(string(emailme.ExampleConfig)+"# mine\n"), 0o600)
	d2 := &fakeDocker{states: []string{"running"}}
	h.Docker = d2
	out.Reset()
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(h.Dir, "kek")); string(b) != kekBefore {
		t.Fatal("the KEK must never be replaced")
	}
	if b, _ := os.ReadFile(filepath.Join(h.Dir, "config.yaml")); !strings.HasSuffix(string(b), "# mine\n") {
		t.Fatal("config.yaml must never be replaced")
	}
	if !strings.Contains(out.String(), "already running") || len(d2.commands()) != 0 {
		t.Fatalf("a running container: %v %s", d2.commands(), out)
	}
}

func TestRunArgs(t *testing.T) {
	args := strings.Join(host.RunArgs(host.RunOptions{Image: "img", ConfigDir: "/home/me/.config/email-me", UID: 1000, GID: 1000,
		APIListen: "0.0.0.0:9025", DashboardListen: "[::1]:9026"}), " ")
	for _, want := range []string{
		"--name email-me", "--restart unless-stopped", "--user 1000:1000",
		"--read-only", "--tmpfs /tmp", "--cap-drop ALL", "--security-opt no-new-privileges:true",
		"--publish 0.0.0.0:9025:9025", "--publish [::1]:9026:9026",
		"--volume /home/me/.config/email-me:/config", "--volume email-me-data:/data",
		"img run --listen-all",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("run args lack %q: %s", want, args)
		}
	}
	if !strings.HasSuffix(args, "img run --listen-all") {
		t.Fatal("the image and its command come last")
	}
	if got := host.ImageFor("v1.2.3"); got != "ghcr.io/tut1vog/email-me:1.2.3" {
		t.Fatal(got)
	}
	if got := host.ImageFor("dev"); got != "ghcr.io/tut1vog/email-me:latest" {
		t.Fatal(got)
	}
}

func TestStartReplacesAStoppedContainer(t *testing.T) {
	d := &fakeDocker{states: []string{"exited", "running"}}
	h, _, _ := newHost(t, d)
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := d.commands(); !slices.Equal(got, []string{"container rm", "container run"}) {
		t.Fatalf("docker: %v", got)
	}
}

func TestStartShowsWhyTheGatewayDidNotStart(t *testing.T) {
	d := &fakeDocker{states: []string{"", "running", "restarting"}, logs: "email-me: the KEK does not open the state database's keyring\n"}
	h, _, errOut := newHost(t, d)
	h.Healthy = func(context.Context, *config.Config) error { return errors.New("connection refused") }
	err := h.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("start: %v", err)
	}
	if !strings.Contains(errOut.String(), "does not open the state database's keyring") {
		t.Fatalf("the container's log must be shown: %s", errOut)
	}
	if got := d.commands(); !slices.Equal(got, []string{"container run", "container logs", "container stop"}) {
		t.Fatalf("a failing container is stopped, not left restarting: %v", got)
	}
}

func TestBrokenConfigTouchesNothing(t *testing.T) {
	d := &fakeDocker{states: []string{"running"}}
	h, _, _ := newHost(t, d)
	if _, err := h.Init(); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(h.Dir, "config.yaml"), []byte("log:\n  level: loud\n"), 0o600)
	for name, cmd := range map[string]func(context.Context) error{"start": h.Start, "restart": h.Restart} {
		if err := cmd(context.Background()); err == nil || !strings.Contains(err.Error(), "log.level") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := d.commands(); len(got) != 0 {
		t.Fatalf("a broken config.yaml must not touch the container: %v", got)
	}

	// Files outside the directory are invisible to the container.
	os.WriteFile(filepath.Join(h.Dir, "config.yaml"), []byte("kek:\n  file: /etc/kek\n"), 0o600)
	if _, err := h.Load(); err == nil || !strings.Contains(err.Error(), "kek.file must be a path inside") {
		t.Fatalf("an absolute KEK path: %v", err)
	}
	os.WriteFile(filepath.Join(h.Dir, "config.yaml"), []byte("kek:\n  previous_file: ../old\n"), 0o600)
	if _, err := h.Load(); err == nil || !strings.Contains(err.Error(), "kek.previous_file must be a path inside") {
		t.Fatalf("a path out of the directory: %v", err)
	}
}

func TestStopAndRestart(t *testing.T) {
	d := &fakeDocker{states: []string{"running", "exited", "running"}}
	h, out, _ := newHost(t, d)
	if _, err := h.Init(); err != nil {
		t.Fatal(err)
	}
	if err := h.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Stop waits for the SMTP timeout plus a margin; start replaces the container.
	if stop := d.find("container stop"); !slices.Equal(stop, []string{"container", "stop", "--time", "40", host.Container}) {
		t.Fatalf("stop: %v", stop)
	}
	if got := d.commands(); !slices.Equal(got, []string{"container stop", "container rm", "container run"}) {
		t.Fatalf("restart: %v", got)
	}
	if !strings.Contains(out.String(), "email-me stopped.") || !strings.Contains(out.String(), "email-me is running.") {
		t.Fatal(out.String())
	}

	d = &fakeDocker{}
	h.Docker = d
	out.Reset()
	if err := h.Stop(context.Background()); err != nil || !strings.Contains(out.String(), "not running") || len(d.commands()) != 0 {
		t.Fatalf("stop without a container: %v %s", err, out)
	}
}

func TestConsole(t *testing.T) {
	d := &fakeDocker{states: []string{"running"}}
	released := make(chan struct{})
	d.run = func(stdin io.Reader, stdout io.Writer, args []string) error {
		io.WriteString(stdout, "Dashboard: http://email-me.localhost:8026/login?token=x\n")
		io.Copy(io.Discard, stdin) // until the host command lets go
		close(released)
		return nil
	}
	h, out, _ := newHost(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Console(ctx) }()
	cancel() // Ctrl-C
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-released
	if exec := d.find("container exec"); !slices.Equal(exec, []string{"container", "exec", "--interactive", host.Container, "email-me", "console", "--stdin"}) {
		t.Fatalf("exec: %v", exec)
	}
	if !strings.Contains(out.String(), "Dashboard: ") {
		t.Fatal("the link is shown")
	}

	// Nothing running, here or in Docker.
	h.Docker = &fakeDocker{}
	if err := h.Console(context.Background()); err == nil || !strings.Contains(err.Error(), "email-me start") {
		t.Fatalf("not running: %v", err)
	}
}

func TestResetKeyring(t *testing.T) {
	d := &fakeDocker{states: []string{"running"}}
	h, _, _ := newHost(t, d)
	if err := h.ResetKeyring(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if exec := d.find("container exec"); !slices.Equal(exec, []string{"container", "exec", host.Container, "email-me", "reset-keyring", "--yes"}) {
		t.Fatalf("beside a running gateway: %v", exec)
	}
	// A lost KEK keeps the gateway from starting: a one-off container works
	// on the same volume.
	d = &fakeDocker{states: []string{"exited"}}
	h.Docker = d
	if err := h.ResetKeyring(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	run := strings.Join(d.find("container run"), " ")
	for _, want := range []string{"--rm", "--user 501:20", "--volume " + h.Dir + ":/config", "--volume email-me-data:/data", h.Image + " reset-keyring"} {
		if !strings.Contains(run, want) {
			t.Errorf("one-off run lacks %q: %s", want, run)
		}
	}
	if strings.HasSuffix(run, "--yes") {
		t.Fatal("--yes only when given")
	}
}

func TestDirs(t *testing.T) {
	t.Setenv("EMAIL_ME_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if d, _ := host.ConfigDir(); d != "/xdg/email-me" {
		t.Fatal(d)
	}
	t.Setenv("EMAIL_ME_CONFIG_DIR", "/custom")
	if d, _ := host.ConfigDir(); d != "/custom" {
		t.Fatal(d)
	}
	t.Setenv("EMAIL_ME_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/home/me")
	if d, _ := host.DataDir(); d != "/home/me/.local/share/email-me" {
		t.Fatal(d)
	}
}
