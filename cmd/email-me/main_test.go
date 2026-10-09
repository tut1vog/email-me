package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// gateway is serve's loop running in the test process on ephemeral ports.
type gateway struct {
	t         *testing.T
	env       *testutil.Env
	addrs     chan [2]string
	hup       chan os.Signal
	done      chan struct{}
	err       error
	api, dash string // base URLs of the current run
	c         *http.Client
}

func startGateway(t *testing.T, env *testutil.Env) *gateway {
	t.Helper()
	testutil.SeedState(t, env)
	return startFresh(t, env)
}

// startFresh starts serve on env's state database as it is: on a fresh
// one, the admin has only a setup password and no SMTP password is set.
func startFresh(t *testing.T, env *testutil.Env) *gateway {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	jar, _ := cookiejar.New(nil)
	g := &gateway{t: t, env: env, addrs: make(chan [2]string, 4), hup: make(chan os.Signal, 1), done: make(chan struct{}),
		c: &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	hooks := runHooks{hup: g.hup, started: func(api, dash string) { g.addrs <- [2]string{api, dash} }}
	go func() {
		g.err = loop(ctx, env.Path, hooks)
		close(g.done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-g.done:
			if g.err != nil {
				t.Errorf("serve: %v", g.err)
			}
		case <-time.After(30 * time.Second):
			t.Error("serve did not stop")
		}
	})
	g.waitStarted()
	return g
}

// waitStarted waits for the next run's listeners.
func (g *gateway) waitStarted() {
	g.t.Helper()
	select {
	case a := <-g.addrs:
		g.api, g.dash = "http://"+a[0], "http://"+a[1]
	case <-g.done:
		g.t.Fatalf("serve ended: %v", g.err)
	case <-time.After(30 * time.Second):
		g.t.Fatal("serve did not start")
	}
}

// noRestart checks that no new run starts for a while.
func (g *gateway) noRestart() {
	g.t.Helper()
	select {
	case <-g.addrs:
		g.t.Fatal("the gateway restarted")
	case <-g.done:
		g.t.Fatalf("serve ended: %v", g.err)
	case <-time.After(500 * time.Millisecond):
	}
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
	return g.do(req)
}

func (g *gateway) bootID() string {
	g.t.Helper()
	status, id := g.get(g.dash + "/up")
	if status != http.StatusOK || id == "" {
		g.t.Fatalf("GET /up: %d %q", status, id)
	}
	return id
}

func (g *gateway) login() {
	g.t.Helper()
	if status, _ := g.post("/login", url.Values{"password": {g.env.AdminPW}, "next": {"/settings"}}); status != http.StatusSeeOther {
		g.t.Fatalf("login: %d", status)
	}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// form returns form values with the session's CSRF token.
func (g *gateway) form(kv ...string) url.Values {
	g.t.Helper()
	_, body := g.get(g.dash + "/settings")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		g.t.Fatal("no CSRF token: not logged in?")
	}
	v := url.Values{"csrf": {m[1]}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func (g *gateway) session() string {
	u, _ := url.Parse(g.dash)
	for _, c := range g.c.Jar.Cookies(u) {
		if c.Name == "email_me_session" {
			return c.Value
		}
	}
	return ""
}

func TestSettingsApplyWithoutRestart(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	boot := g.bootID()
	if status, _ := g.get(g.api + "/"); status != http.StatusOK {
		t.Fatalf("public guide: %d", status)
	}
	g.login()
	if status, _ := g.post("/settings/api", g.form("docs", "authenticated")); status != http.StatusSeeOther {
		t.Fatalf("saving api settings: %d", status)
	}
	if status, _ := g.get(g.api + "/"); status != http.StatusUnauthorized {
		t.Fatalf("api.docs authenticated must apply at once: %d", status)
	}

	// The upstream server changes for the next send.
	other := testutil.StartSMTP(t)
	if status, _ := g.post("/settings/upstream", g.form("host", other.Host, "port", strconv.Itoa(other.Port), "security", "none",
		"username", env.SMTP.User, "timeout", "5s", "from", "gateway@example.com")); status != http.StatusSeeOther {
		t.Fatalf("saving upstream settings: %d", status)
	}
	if status, _ := g.post("/settings/test-send", g.form("alias", "me")); status != http.StatusSeeOther {
		t.Fatalf("test send: %d", status)
	}
	if other.Count() != 1 || env.SMTP.Count() != 0 {
		t.Fatalf("test send: new server %d, old server %d", other.Count(), env.SMTP.Count())
	}

	g.noRestart()
	if g.bootID() != boot {
		t.Fatal("saving settings must not restart")
	}
	if status, body := g.get(g.dash + "/settings"); status != http.StatusOK || strings.Contains(body, `id="restart-banner"`) {
		t.Fatalf("the session stays and no restart is asked for: %d", status)
	}
}

func TestRestartForConfigFile(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	boot := g.bootID()
	g.login()
	if _, body := g.get(g.dash + "/settings"); strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("no banner while config.yaml is unchanged")
	}
	edit := func(comment string) {
		t.Helper()
		data, err := os.ReadFile(env.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.Path, append(data, "# "+comment+"\n"...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edit("edited")
	if _, body := g.get(g.dash + "/agents"); !strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("a changed config.yaml must ask for a restart")
	}
	old := g.session()

	status, body := g.post("/settings/restart", g.form())
	if status != http.StatusOK || !strings.Contains(body, `data-boot="`+boot+`"`) {
		t.Fatalf("restart: %d", status)
	}
	g.waitStarted()
	if g.bootID() == boot {
		t.Fatal("a restart must change the boot id")
	}
	req, _ := http.NewRequest("GET", g.dash+"/settings", nil)
	req.AddCookie(&http.Cookie{Name: "email_me_session", Value: old})
	res, err := (&http.Client{CheckRedirect: g.c.CheckRedirect}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || !strings.HasPrefix(res.Header.Get("Location"), "/login") {
		t.Fatalf("sessions must not survive a restart: %d", res.StatusCode)
	}
	g.login()
	if _, body := g.get(g.dash + "/settings"); strings.Contains(body, `id="restart-banner"`) || !strings.Contains(body, "config.yaml is unchanged since email-me started.") {
		t.Fatal("the restart applied config.yaml: no banner")
	}

	// SIGHUP restarts the same way.
	edit("edited again")
	if _, body := g.get(g.dash + "/settings"); !strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("a changed config.yaml must ask for a restart")
	}
	boot = g.bootID()
	g.hup <- syscall.SIGHUP
	g.waitStarted()
	if g.bootID() == boot {
		t.Fatal("SIGHUP must restart")
	}
	g.login()
	if _, body := g.get(g.dash + "/settings"); strings.Contains(body, `id="restart-banner"`) {
		t.Fatal("SIGHUP applied config.yaml: no banner")
	}
}

func TestRestartRefusedWhenConfigBroken(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startGateway(t, env)
	boot := g.bootID()
	g.login()
	good := env.YAML
	if err := os.WriteFile(env.Path, []byte(good+"bogus_key: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, _ := g.post("/settings/restart", g.form())
	if status != http.StatusSeeOther {
		t.Fatalf("refused restart: %d", status)
	}
	_, body := g.get(g.dash + "/settings")
	if !strings.Contains(body, "Not restarted: config.yaml no longer loads") || !strings.Contains(body, "bogus_key") {
		t.Fatal("the refusal must say why, and keep the session")
	}
	g.hup <- syscall.SIGHUP
	g.noRestart()
	if g.bootID() != boot {
		t.Fatal("the gateway must keep running")
	}

	if err := os.WriteFile(env.Path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	g.hup <- syscall.SIGHUP
	g.waitStarted()
	if g.bootID() == boot {
		t.Fatal("SIGHUP must restart once config.yaml loads again")
	}
}

func TestFirstStartAndResetAdminPassword(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	g := startFresh(t, env)
	if status, _ := g.post("/login", url.Values{"password": {env.AdminPW}}); status != http.StatusUnauthorized {
		t.Fatal("a fresh install has only a setup password")
	}
	if _, body := g.get(g.dash + "/login"); !strings.Contains(body, "one-time setup password") {
		t.Fatal("the login page says where the setup password is")
	}

	// The recovery command works on the running gateway's database.
	var out strings.Builder
	if err := resetAdminPassword(env.Path, &out); err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`Setup password: (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("output: %s", out.String())
	}
	status, _ := g.post("/login", url.Values{"password": {m[1]}, "next": {"/settings"}})
	if status != http.StatusSeeOther {
		t.Fatalf("setup login: %d", status)
	}
	_, body := g.get(g.dash + "/password")
	tok := csrfRe.FindStringSubmatch(body)
	if tok == nil {
		t.Fatal("no CSRF token on the Password page")
	}
	if status, _ := g.post("/password", url.Values{"csrf": {tok[1]}, "password": {env.AdminPW}, "confirm": {env.AdminPW}, "next": {"/settings"}}); status != http.StatusSeeOther {
		t.Fatalf("choosing a password: %d", status)
	}
	// Seeded upstream, but no password: the operator enters it.
	_, body = g.get(g.dash + "/")
	if !strings.Contains(body, "username but no password") {
		t.Fatal("a seeded username without a password needs attention")
	}
	if status, _ := g.post("/settings/upstream", g.form("host", env.SMTP.Host, "port", strconv.Itoa(env.SMTP.Port), "security", "none",
		"username", env.SMTP.User, "password", env.SMTP.Pass, "timeout", "5s", "from", "gateway@example.com")); status != http.StatusSeeOther {
		t.Fatalf("saving the SMTP password: %d", status)
	}
	if status, _ := g.post("/settings/test-send", g.form("alias", "me")); status != http.StatusSeeOther || env.SMTP.Count() != 1 {
		t.Fatalf("test send: %d, %d messages", status, env.SMTP.Count())
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
	g.login()
	if status, _ := g.post("/agents", g.form("name", "bench")); status != http.StatusSeeOther {
		t.Fatalf("creating an agent: %d", status)
	}
	kekPath := filepath.Join(env.Dir, "kek")
	old, err := os.ReadFile(kekPath)
	if err != nil {
		t.Fatal(err)
	}

	// A new KEK alone does not open the keyring: the restart is refused.
	writeKEK(t, env, "kek")
	boot := g.bootID()
	g.hup <- syscall.SIGHUP
	g.noRestart()
	if g.bootID() != boot {
		t.Fatal("the gateway must keep running")
	}
	status, _ := g.post("/settings/restart", g.form())
	if _, body := g.get(g.dash + "/settings"); status != http.StatusSeeOther || !strings.Contains(body, "does not open the state database") {
		t.Fatal("the dashboard refuses the restart and says why")
	}

	// With the previous KEK alongside, the restart rewraps the keyring.
	if err := os.WriteFile(filepath.Join(env.Dir, "previous_kek"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	withPrevious := strings.Replace(env.YAML, "kek:\n", fmt.Sprintf("kek:\n  previous_file: %q\n", filepath.Join(env.Dir, "previous_kek")), 1)
	if err := os.WriteFile(env.Path, []byte(withPrevious), 0o600); err != nil {
		t.Fatal(err)
	}
	g.hup <- syscall.SIGHUP
	g.waitStarted()
	g.login()
	if _, body := g.get(g.dash + "/"); !strings.Contains(body, "kek.previous_file is still set") {
		t.Fatal("the overview asks to remove the previous KEK")
	}
	if status, _ := g.post("/settings/test-send", g.form("alias", "me")); status != http.StatusSeeOther || env.SMTP.Count() != 1 {
		t.Fatal("the SMTP password still decrypts")
	}

	// The next start needs only the new KEK; the agent's key still opens
	// (serve checks every key at start).
	if err := os.WriteFile(env.Path, []byte(env.YAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(env.Dir, "previous_kek")); err != nil {
		t.Fatal(err)
	}
	g.hup <- syscall.SIGHUP
	g.waitStarted()
	g.login()
	if _, body := g.get(g.dash + "/"); strings.Contains(body, "kek.previous_file is still set") {
		t.Fatal("no previous KEK any more")
	}
	if status, _ := g.post("/settings/test-send", g.form("alias", "me")); status != http.StatusSeeOther || env.SMTP.Count() != 2 {
		t.Fatal("the SMTP password decrypts with the new KEK alone")
	}
}

func TestWrongKEKIsFatalAndResetKeyring(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	testutil.SeedState(t, env)
	ctx := context.Background()
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a, err := st.CreateAgent(ctx, "bench", "", policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.Keys(t, env, st, testutil.BootstrapSettings(t, env, st)).Create(ctx, a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	before, _ := st.ActiveKey(ctx, a.ID)

	// The KEK is lost: a start with another one fails.
	writeKEK(t, env, "kek")
	if err := run(ctx, env.Path, runHooks{}); err == nil || !strings.Contains(err.Error(), "does not open the state database's keyring") {
		t.Fatalf("a wrong KEK must be fatal: %v", err)
	}

	var out strings.Builder
	if err := resetKeyring(env.Path, false, &out); err != nil || !strings.Contains(out.String(), "--yes") {
		t.Fatalf("without --yes: %v %s", err, out.String())
	}
	if _, err := st.GetKeyring(ctx); err != nil {
		t.Fatal("without --yes nothing is discarded")
	}
	out.Reset()
	if err := resetKeyring(env.Path, true, &out); err != nil || !strings.Contains(out.String(), "SMTP password removed") || !strings.Contains(out.String(), "1 agent signing key(s) retired") {
		t.Fatalf("reset: %v %s", err, out.String())
	}

	// The next start creates a new keyring and a new key for the agent.
	g := startFresh(t, env)
	g.login()
	after, err := st.ActiveKey(ctx, a.ID)
	if err != nil || after.Fingerprint == before.Fingerprint {
		t.Fatalf("a new agent key: %v", err)
	}
	if _, body := g.get(g.dash + "/settings"); !strings.Contains(body, "No password is stored.") {
		t.Fatal("the SMTP password was discarded")
	}
}
