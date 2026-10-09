package dashboard_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/admin"
	"github.com/tut1vog/email-me/internal/testutil"
)

// session is another browser on the same dashboard.
func (d *dash) session() *dash {
	jar, _ := cookiejar.New(nil)
	other := *d
	other.c = &http.Client{Jar: jar, CheckRedirect: d.c.CheckRedirect}
	return &other
}

// passwordForm is a form on the Password page, which is all a session
// with a setup password can reach.
func (d *dash) passwordForm(kv ...string) url.Values {
	d.t.Helper()
	m := csrfRe.FindStringSubmatch(d.get("/password").body)
	if m == nil {
		d.t.Fatal("no CSRF token on the Password page")
	}
	v := url.Values{"csrf": {m[1]}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

func TestSetupPasswordMustBeReplaced(t *testing.T) {
	d := newDash(t, testutil.Options{})
	ctx := context.Background()
	setup, err := admin.Reset(ctx, d.st)
	if err != nil {
		t.Fatal(err)
	}
	if b := d.get("/login").body; !strings.Contains(b, "one-time setup password") || !strings.Contains(b, "docker compose logs email-me") {
		t.Fatal("the login page says where the setup password is")
	}
	if p := d.post("/login", d.loginForm(url.Values{"password": {d.env.AdminPW}})); p.status != http.StatusUnauthorized {
		t.Fatalf("the reset password applies at once: %d", p.status)
	}
	p := d.post("/login", d.loginForm(url.Values{"password": {setup}, "next": {"/agents"}}))
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/password?next=%2Fagents" {
		t.Fatalf("setup login: %d %s", p.status, p.header.Get("Location"))
	}

	// Only the Password page (and Log out) is reachable.
	for _, path := range []string{"/", "/settings", "/agents/new"} {
		if g := d.get(path); g.status != http.StatusSeeOther || !strings.HasPrefix(g.header.Get("Location"), "/password?next=") {
			t.Errorf("GET %s: %d %s", path, g.status, g.header.Get("Location"))
		}
	}
	page := d.get("/password?next=/agents")
	if page.status != 200 || !strings.Contains(page.body, "Choose your admin password") || strings.Contains(page.body, `name="current"`) ||
		strings.Contains(page.body, `class="sidebar"`) || strings.Contains(page.body, setup) {
		t.Fatal("the setup Password page: no current password, no navigation")
	}
	if p := d.post("/agents", d.passwordForm("name", "x")); p.status != http.StatusForbidden {
		t.Fatalf("POST elsewhere: %d", p.status)
	}

	for _, c := range []struct{ pw, confirm, want string }{
		{"long enough password", "a different password", "do not match"},
		{"short", "short", "at least 12 characters"},
		{setup, setup, "different from the current one"},
	} {
		p := d.post("/password", d.passwordForm("password", c.pw, "confirm", c.confirm, "next", "/agents"))
		if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, c.want) {
			t.Errorf("%q: %d, want %q", c.pw, p.status, c.want)
		}
	}
	p = d.post("/password", d.passwordForm("password", "my own long password", "confirm", "my own long password", "next", "/agents"))
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/agents" {
		t.Fatalf("set: %d %s", p.status, p.header.Get("Location"))
	}
	if g := d.get("/agents"); g.status != 200 || !strings.Contains(g.body, "Password set.") {
		t.Fatal("the session continues once the password is set")
	}
	if ok, must, _ := admin.Verify(ctx, d.st, "my own long password"); !ok || must || admin.Pending(ctx, d.st) {
		t.Fatal("the chosen password is stored")
	}
	if ok, _, _ := admin.Verify(ctx, d.st, setup); ok {
		t.Fatal("the setup password stops working")
	}
	if b := d.get("/login").body; strings.Contains(b, "one-time setup password") {
		t.Fatal("no setup hint once a password is chosen")
	}
}

func TestChangePassword(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	other := d.session()
	other.login()

	page := d.get("/password")
	if page.status != 200 || !strings.Contains(page.body, `name="current"`) || !strings.Contains(page.body, `href="/password"`) {
		t.Fatal("the Password page asks for the current password and is in the sidebar")
	}
	p := d.post("/password", d.form("current", "wrong", "password", "a brand new password", "confirm", "a brand new password"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "current password is wrong") {
		t.Fatalf("wrong current: %d", p.status)
	}
	p = d.post("/password", d.form("current", d.env.AdminPW, "password", d.env.AdminPW, "confirm", d.env.AdminPW))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "different from the current one") {
		t.Fatalf("unchanged: %d", p.status)
	}
	p = d.post("/password", d.form("current", d.env.AdminPW, "password", "a brand new password", "confirm", "a brand new password"))
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/" {
		t.Fatalf("change: %d %s", p.status, p.header.Get("Location"))
	}
	if g := d.get("/"); g.status != 200 || !strings.Contains(g.body, "Every other session was logged out") {
		t.Fatal("this session continues")
	}
	if g := other.get("/"); g.status != http.StatusSeeOther {
		t.Fatal("other sessions end")
	}
	if p := d.post("/login", d.loginForm(url.Values{"password": {d.env.AdminPW}})); p.status != http.StatusUnauthorized {
		t.Fatal("the old password stops working")
	}
	if p := other.post("/login", other.loginForm(url.Values{"password": {"a brand new password"}})); p.status != http.StatusSeeOther || p.header.Get("Location") != "/" {
		t.Fatalf("the new password logs in without a forced change: %d %s", p.status, p.header.Get("Location"))
	}
}

func TestCertifyKeyCard(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	master := testutil.NewKey(t, "email-me master", "gateway@example.com")
	armored := testutil.ArmorPrivate(t, master)

	p := d.post("/settings/certify-key", d.form("private_key", testutil.ArmorPublic(t, master)))
	if p.status != http.StatusSeeOther || !strings.Contains(d.get("/settings").body, "Certification key not set: this is a public key") {
		t.Fatal("a public key is refused")
	}
	p = d.post("/settings/certify-key", d.form("private_key", armored))
	s := d.saved(p, "signing")
	if d.keys.Master() == nil || !strings.Contains(s, "Certification key") || !strings.Contains(s, "rotate an agent") ||
		!strings.Contains(s, `action="/settings/certify-key/remove"`) || strings.Contains(s, `name="private_key"`) {
		t.Fatal("the key is set and the card offers Remove instead of the form")
	}
	if strings.Contains(s, "PRIVATE KEY") {
		t.Fatal("the private key is never shown")
	}
	d.createAgent("bench", "me")
	if bundle := d.get("/keys.asc").body; strings.Count(bundle, "BEGIN PGP PUBLIC KEY BLOCK") != 2 {
		t.Fatal("the bundle holds the master and agent public keys")
	}
	s = d.saved(d.post("/settings/certify-key/remove", d.form()), "signing")
	if d.keys.Master() != nil || !strings.Contains(s, "Certification key removed") || !strings.Contains(s, `name="private_key"`) {
		t.Fatal("remove")
	}

	off := newDash(t, testutil.Options{})
	off.login()
	off.post("/settings/certify-key", off.form("private_key", armored))
	if b := off.get("/settings").body; !strings.Contains(b, "set kek.file in config.yaml first") || off.keys.Master() != nil {
		t.Fatal("without a KEK the key is refused")
	}
}
