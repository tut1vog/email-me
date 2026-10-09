package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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
