package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/console"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// gateway is run in the test process on ephemeral ports.
type gateway struct {
	t      *testing.T
	env    *testutil.Env
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	api    string       // the API's base URL
	opened chan string  // the dashboard's address, each time a console opens it
	c      *http.Client // the operator's browser
	dash   string       // the dashboard's base URL while a console is open
	close  func()       // closes the console
	closed <-chan error // the console's result
}

// startGateway runs the gateway on env, with the SMTP password an operator
// would have entered.
func startGateway(t *testing.T, env *testutil.Env) *gateway {
	t.Helper()
	testutil.SeedState(t, env)
	return startFresh(t, env)
}

// startFresh runs the gateway on env's state database as it is.
func startFresh(t *testing.T, env *testutil.Env) *gateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	jar, _ := cookiejar.New(nil)
	g := &gateway{t: t, env: env, cancel: cancel, done: make(chan struct{}), opened: make(chan string, 4),
		c: &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	started := make(chan string, 1)
	go func() {
		defer close(g.done)
		g.err = run(ctx, options{config: env.Path, dataDir: env.DataDir,
			started: func(api string) { started <- api }, consoleOpened: func(dash string) { g.opened <- dash }})
	}()
	t.Cleanup(g.stop)
	select {
	case api := <-started:
		g.api = "http://" + api
	case <-g.done:
		t.Fatalf("the gateway did not start: %v", g.err)
	case <-time.After(30 * time.Second):
		t.Fatal("the gateway did not start")
	}
	return g
}

// stop stops the gateway as SIGTERM does and waits for it.
func (g *gateway) stop() {
	g.cancel()
	select {
	case <-g.done:
	case <-time.After(30 * time.Second):
		g.t.Fatal("the gateway did not stop")
	}
}

var linkRe = regexp.MustCompile(`Dashboard: (http://\S+)`)

// openConsole runs `email-me console` against the gateway and signs the
// browser in with its link.
func (g *gateway) openConsole() {
	g.t.Helper()
	link := g.openConsoleOnly()
	// The link names email-me.localhost; the test reaches it by address.
	if status, _ := g.get(g.dash + link.RequestURI()); status != http.StatusSeeOther {
		g.t.Fatalf("login link: %d", status)
	}
}

// openConsoleOnly runs `email-me console` and returns its login link.
func (g *gateway) openConsoleOnly() *url.URL {
	g.t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	closed := make(chan error, 1)
	out := &syncBuilder{}
	go func() { closed <- console.Attach(ctx, filepath.Join(g.env.DataDir, console.SocketName), pr, out) }()
	var addr string
	select {
	case addr = <-g.opened:
	case err := <-closed:
		g.t.Fatalf("console: %v", err)
	case <-time.After(10 * time.Second):
		g.t.Fatal("the console did not open the dashboard")
	}
	g.dash, g.closed = "http://"+addr, closed
	g.close = func() {
		pw.Close()
		cancel()
	}
	var link string
	for deadline := time.Now().Add(5 * time.Second); link == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if m := linkRe.FindStringSubmatch(out.String()); m != nil {
			link = m[1]
		}
	}
	u, err := url.Parse(link)
	if err != nil || u.Hostname() != "email-me.localhost" || u.Path != "/login" || u.Port() != strings.Split(addr, ":")[1] {
		g.t.Fatalf("login link %q: %v", link, err)
	}
	return u
}

// closeConsole ends the console as Ctrl-C does and waits for the
// dashboard to close.
func (g *gateway) closeConsole() {
	g.t.Helper()
	g.close()
	if err := <-g.closed; err != nil {
		g.t.Fatalf("console: %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", strings.TrimPrefix(g.dash, "http://"))
		if err != nil {
			return
		}
		c.Close()
		if time.Now().After(deadline) {
			g.t.Fatal("the dashboard is still open")
		}
	}
}

// syncBuilder collects what a console prints while the test reads it.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuilder) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuilder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (g *gateway) do(req *http.Request) (int, string) {
	g.t.Helper()
	res, err := g.c.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (g *gateway) get(url string) (int, string) {
	g.t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	return g.do(req)
}

func (g *gateway) post(path string, form url.Values) (int, string) {
	g.t.Helper()
	req, _ := http.NewRequest("POST", g.dash+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", g.dash)
	return g.do(req)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (g *gateway) form(kv ...string) url.Values {
	g.t.Helper()
	_, body := g.get(g.dash + "/settings")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		g.t.Fatal("no CSRF token")
	}
	v := url.Values{"csrf": {m[1]}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConsoleOpensTheDashboard(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	if status, _ := g.get(g.api + "/healthz"); status != 200 {
		t.Fatalf("the API runs without a console: %d", status)
	}

	g.openConsole()
	if status, body := g.get(g.dash + "/"); status != 200 || !strings.Contains(body, "Overview") {
		t.Fatalf("signed in: %d", status)
	}
	// One console at a time.
	if err := console.Attach(context.Background(), filepath.Join(env.DataDir, console.SocketName), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "already open") {
		t.Fatalf("a second console: %v", err)
	}

	// Closing the console closes the dashboard and ends the session: the
	// next console's dashboard needs its own link.
	g.closeConsole()
	link := g.openConsoleOnly()
	if status, _ := g.get(g.dash + "/"); status != http.StatusSeeOther {
		t.Fatalf("the old session must be gone: %d", status)
	}
	if status, _ := g.get(g.dash + link.RequestURI()); status != http.StatusSeeOther {
		t.Fatal("the new link signs in")
	}
	if status, _ := g.get(g.dash + "/"); status != 200 {
		t.Fatal("signed in again")
	}
	g.closeConsole()

	// A console whose gateway stops is told so.
	g.openConsole()
	g.stop()
	if err := <-g.closed; err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("the console of a stopped gateway: %v", err)
	}
	if g.err != nil {
		t.Fatalf("a clean stop: %v", g.err)
	}
}

func TestChangesApplyAtOnceAndLandInConfigFile(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	g.openConsole()
	if status, _ := g.get(g.api + "/"); status != 200 {
		t.Fatalf("docs are public: %d", status)
	}
	if status, _ := g.post("/settings/api", g.form("docs", "authenticated")); status != http.StatusSeeOther {
		t.Fatalf("save: %d", status)
	}
	if status, _ := g.get(g.api + "/"); status != http.StatusUnauthorized {
		t.Fatalf("a saved setting applies to the next request: %d", status)
	}
	if status, _ := g.post("/agents", g.form("name", "bench", "recipients", "me")); status != http.StatusSeeOther {
		t.Fatalf("creating an agent: %d", status)
	}
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if a, ok := c.Agent("bench"); c.API.Docs != "authenticated" || !ok || (*a.Policy.Recipients)[0] != "me" {
		t.Fatalf("config.yaml holds the changes:\n%s", read(t, env.Path))
	}

	// The configuration survives the state database: a fresh one starts
	// with the same agents and settings.
	g.stop()
	if err := os.RemoveAll(env.DataDir); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(env.DataDir, 0o700)
	g = startFresh(t, env)
	g.openConsole()
	if _, body := g.get(g.dash + "/agents"); !strings.Contains(body, "bench") {
		t.Fatal("the agent survives losing state.db")
	}
	if status, _ := g.get(g.api + "/"); status != http.StatusUnauthorized {
		t.Fatal("so do the settings")
	}
}

func TestHandEditAppliesOnRestart(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	g.openConsole()
	if _, body := g.get(g.dash + "/agents"); strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("no banner while config.yaml is unchanged")
	}
	edited := strings.Replace(read(t, env.Path), "  docs: public\n", "  docs: authenticated\n", 1)
	os.WriteFile(env.Path, []byte(edited), 0o600)
	if _, body := g.get(g.dash + "/agents"); !strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("a hand edit raises the banner")
	}
	if status, _ := g.get(g.api + "/"); status != 200 {
		t.Fatal("a hand edit is not applied before a restart")
	}
	if status, body := g.post("/settings/audit", g.form("retention_days", "7")); status != http.StatusUnprocessableEntity || !strings.Contains(body, "email-me restart") {
		t.Fatalf("saves are refused meanwhile: %d", status)
	}
	g.stop()
	g = startFresh(t, env)
	if status, _ := g.get(g.api + "/"); status != http.StatusUnauthorized {
		t.Fatal("the restart applies the edit")
	}
	if read(t, env.Path) != edited {
		t.Fatal("the edit is kept as written")
	}
}

func TestBrokenConfigIsFatal(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	os.WriteFile(env.Path, []byte(env.YAML+"agents:\n  Bad_Name: {}\n"), 0o600)
	err := run(context.Background(), options{config: env.Path, dataDir: env.DataDir})
	if err == nil || !strings.Contains(err.Error(), `agents: name "Bad_Name"`) {
		t.Fatalf("a broken config.yaml must be fatal: %v", err)
	}
}

// writeKEK replaces the file name in env's directory with a new random KEK
// and returns it.
func writeKEK(t *testing.T, env *testutil.Env, name string) []byte {
	t.Helper()
	kek := make([]byte, 32)
	rand.Read(kek)
	if err := os.WriteFile(filepath.Join(env.Dir, name), []byte(hex.EncodeToString(kek)), 0o600); err != nil {
		t.Fatal(err)
	}
	return kek
}

func TestKEKRotation(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	g := startGateway(t, env)
	g.openConsole()
	if status, _ := g.post("/agents", g.form("name", "bench")); status != http.StatusSeeOther {
		t.Fatalf("creating an agent: %d", status)
	}
	g.stop()
	old := read(t, filepath.Join(env.Dir, "kek"))

	// A new KEK alone does not open the keyring.
	writeKEK(t, env, "kek")
	if err := run(context.Background(), options{config: env.Path, dataDir: env.DataDir}); err == nil || !strings.Contains(err.Error(), "does not open the state database") {
		t.Fatalf("a wrong KEK must be fatal: %v", err)
	}

	// With the previous KEK beside it, the start rewraps the keyring.
	os.WriteFile(filepath.Join(env.Dir, "previous_kek"), []byte(old), 0o600)
	g = startFresh(t, env)
	g.openConsole()
	if _, body := g.get(g.dash + "/"); !strings.Contains(body, "previous key-encryption key is still there") {
		t.Fatal("the overview asks to delete the previous KEK")
	}
	if status, _ := g.post("/recipients/me/test", g.form()); status != http.StatusSeeOther || env.SMTP.Count() != 1 {
		t.Fatal("the SMTP password still decrypts")
	}
	g.stop()

	// The next start needs only the new KEK; the agent's key still opens
	// (run checks every key at start).
	os.Remove(filepath.Join(env.Dir, "previous_kek"))
	g = startFresh(t, env)
	g.openConsole()
	if _, body := g.get(g.dash + "/"); strings.Contains(body, "previous key-encryption key") {
		t.Fatal("no previous KEK any more")
	}
	if status, _ := g.post("/recipients/me/test", g.form()); status != http.StatusSeeOther || env.SMTP.Count() != 2 {
		t.Fatal("the SMTP password decrypts with the new KEK alone")
	}
}

func TestWrongKEKIsFatalAndResetKeyring(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true, Agents: "bench: {}\n"})
	testutil.SeedState(t, env)
	ctx := context.Background()
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := testutil.Keys(t, env, st, testutil.Settings(t, env, st)).Create(ctx, "bench"); err != nil {
		t.Fatal(err)
	}
	before, _ := st.ActiveKey(ctx, "bench")

	// The KEK is lost: a start with another one fails.
	writeKEK(t, env, "kek")
	if err := run(ctx, options{config: env.Path, dataDir: env.DataDir}); err == nil || !strings.Contains(err.Error(), "does not open the state database's keyring") {
		t.Fatalf("a wrong KEK must be fatal: %v", err)
	}

	var out strings.Builder
	if err := resetKeyring(env.DataDir, false, &out); err != nil || !strings.Contains(out.String(), "--yes") {
		t.Fatalf("without --yes: %v %s", err, out.String())
	}
	if _, err := st.GetKeyring(ctx); err != nil {
		t.Fatal("without --yes nothing is discarded")
	}
	out.Reset()
	if err := resetKeyring(env.DataDir, true, &out); err != nil || !strings.Contains(out.String(), "SMTP password removed") || !strings.Contains(out.String(), "1 agent signing key(s) retired") {
		t.Fatalf("reset: %v %s", err, out.String())
	}
	if err := resetKeyring(t.TempDir(), true, &out); err == nil || !strings.Contains(err.Error(), "no state database") {
		t.Fatalf("no database: %v", err)
	}

	// The next start creates a new keyring and a new key for the agent.
	g := startFresh(t, env)
	g.openConsole()
	after, err := st.ActiveKey(ctx, "bench")
	if err != nil || after.Fingerprint == before.Fingerprint {
		t.Fatalf("a new agent key: %v", err)
	}
	if _, body := g.get(g.dash + "/settings"); !strings.Contains(body, "No password is stored.") {
		t.Fatal("the SMTP password was discarded")
	}
}

func TestSendThroughTheGateway(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	g.openConsole()
	if status, _ := g.post("/agents", g.form("name", "bench", "recipients", "me")); status != http.StatusSeeOther {
		t.Fatalf("creating an agent: %d", status)
	}
	_, body := g.post("/agents/bench/tokens", g.form("label", "ci"))
	tok := regexp.MustCompile(`em_[a-z2-7]{12}_[a-z2-7]{52}`).FindString(body)
	if tok == "" {
		t.Fatal("no token")
	}
	req, _ := http.NewRequest("POST", g.api+"/v1/messages", strings.NewReader(`{"to":["me"],"subject":"hi","body":{"text":"hello"}}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	if status, body := g.do(req); status != 200 || env.SMTP.Count() != 1 {
		t.Fatalf("send: %d %s", status, body)
	}
}

func TestDispatch(t *testing.T) {
	run := func(args ...string) (string, string, error) {
		var out, errOut strings.Builder
		err := dispatch(context.Background(), args, &out, &errOut)
		return out.String(), errOut.String(), err
	}
	if out, _, err := run("version"); err != nil || out != version+"\n" {
		t.Fatalf("version: %q %v", out, err)
	}
	if _, errOut, err := run(); err != errUsage || !strings.Contains(errOut, "Usage: email-me") {
		t.Fatalf("no command: %v", err)
	}
	if _, errOut, err := run("serve"); err != errUsage || !strings.Contains(errOut, `unknown command "serve"`) {
		t.Fatalf("unknown command: %v %s", err, errOut)
	}
	if _, _, err := run("start", "extra"); err != errUsage {
		t.Fatalf("stray argument: %v", err)
	}
	if _, _, err := run("update"); err == nil || !strings.Contains(err.Error(), "development build") {
		t.Fatalf("update of a development build: %v", err)
	}
	t.Setenv("EMAIL_ME_CONTAINER", "1")
	if _, _, err := run("start"); err == nil || !strings.Contains(err.Error(), "runs on the host") {
		t.Fatalf("start in the container: %v", err)
	}
	if _, _, err := run("update"); err == nil || !strings.Contains(err.Error(), "runs on the host") {
		t.Fatalf("update in the container: %v", err)
	}
	if _, _, err := run("console", "--data-dir", t.TempDir()); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("console without a gateway: %v", err)
	}
}

func TestHealthcheck(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(g.api, "http://"))
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(cfg, []byte("api:\n  listen: 127.0.0.1:"+port+"\n"), 0o600)
	var errOut strings.Builder
	if err := healthcheck(cfg, &errOut); err != nil {
		t.Fatalf("healthy: %v %s", err, errOut.String())
	}
	g.stop()
	if err := healthcheck(cfg, &errOut); err != errUnhealthy || !strings.Contains(errOut.String(), "unhealthy") {
		t.Fatalf("stopped: %v", err)
	}
}
