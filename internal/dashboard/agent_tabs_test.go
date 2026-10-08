package dashboard_test

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/testutil"
)

func TestAgentTabs(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	base := "/agents/" + d.createAgent("bench", "me").ID

	for _, tab := range []string{base, base + "/tokens", base + "/policy", base + "/signing"} {
		p := d.get(tab)
		if p.status != 200 {
			t.Fatalf("%s: %d", tab, p.status)
		}
		if !strings.Contains(p.body, `href="`+tab+`" aria-current="page"`) {
			t.Errorf("%s: its tab link is not marked current", tab)
		}
		// One for the sidebar's Agents item, one for the tab.
		if n := strings.Count(p.body, `aria-current="page"`); n != 2 {
			t.Errorf("%s: %d aria-current links, want 2", tab, n)
		}
	}
	for _, tab := range []string{"", "/tokens", "/policy", "/signing"} {
		if p := d.get("/agents/ag_nope" + tab); p.status != http.StatusNotFound {
			t.Errorf("unknown agent %q: %d", tab, p.status)
		}
	}

	f := d.form("name", "second")
	p := d.post("/agents", f)
	if loc := p.header.Get("Location"); !regexp.MustCompile(`^/agents/ag_[^/]+/tokens$`).MatchString(loc) {
		t.Errorf("create agent redirects to %q, want its tokens tab", loc)
	}
	if body := d.get(p.header.Get("Location")).body; !strings.Contains(body, "Agent second created") {
		t.Error("creation flash must land on the tokens tab")
	}

	tp := d.post(base+"/tokens", d.form("label", "x"))
	id, _, _ := auth.ParseToken(tokenRe.FindString(tp.body))
	if tp.status != 200 || id == "" || !strings.Contains(tp.body, `href="`+base+`/tokens"`) {
		t.Fatalf("token page: %d, Done must lead back to the tokens tab", tp.status)
	}
	for _, c := range []struct {
		path string
		kv   []string
		want string
	}{
		{base, []string{"description", "x", "enabled", "on"}, base},
		{base + "/policy", []string{"require_signing", "inherit"}, base + "/policy"},
		{base + "/policy", []string{"ov_rate", "on", "per_hour", "nope"}, base + "/policy"},
		{base + "/tokens", []string{"cidrs", "not-an-ip"}, base + "/tokens"},
		{base + "/tokens", []string{"expires_days", "0"}, base + "/tokens"},
		{base + "/tokens/" + id + "/revoke", nil, base + "/tokens"},
		{base + "/keys/rotate", nil, base + "/signing"},
		{base + "/keys", nil, base + "/signing"},
	} {
		p := d.post(c.path, d.form(c.kv...))
		if p.status != http.StatusSeeOther || p.header.Get("Location") != c.want {
			t.Errorf("POST %s %v: %d → %q, want %q", c.path, c.kv, p.status, p.header.Get("Location"), c.want)
		}
	}
}

func TestPolicyDefaultSwitchClearsOverride(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	a := d.createAgent("bench", "me")
	ctx := context.Background()

	d.post("/agents/"+a.ID+"/policy", d.form("ov_max_bytes", "on", "max_bytes", "2MiB"))
	got, _ := d.st.GetAgent(ctx, a.ID)
	if got.Policy.MaxMessageBytes == nil || int64(*got.Policy.MaxMessageBytes) != 2<<20 {
		t.Fatalf("override not saved: %+v", got.Policy)
	}
	page := d.get("/agents/" + a.ID + "/policy").body
	if !regexp.MustCompile(`name="ov_max_bytes" checked`).MatchString(page) || !strings.Contains(page, `name="max_bytes" value="2MiB"`) {
		t.Fatal("policy tab must show the override switched on with its value")
	}

	// Switching back to Default omits ov_max_bytes; the value field is still posted.
	d.post("/agents/"+a.ID+"/policy", d.form("max_bytes", "2MiB"))
	got, _ = d.st.GetAgent(ctx, a.ID)
	if got.Policy.MaxMessageBytes != nil {
		t.Fatalf("switch off must clear the override: %v", *got.Policy.MaxMessageBytes)
	}
	if strings.Contains(d.get("/agents/"+a.ID+"/policy").body, `name="ov_max_bytes" checked`) {
		t.Fatal("cleared override must render with the switch off")
	}
}

func TestTokensTabSplitsRevoked(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	a := d.createAgent("bench", "me")
	tab := "/agents/" + a.ID + "/tokens"

	if p := d.get(tab).body; !strings.Contains(p, "<details class=\"disclosure mt-0\" open>") || strings.Contains(p, `id="inactive-tokens"`) {
		t.Fatal("with no tokens the issue form is open and there is no inactive list")
	}
	issue := func(label string) string {
		tp := d.post(tab, d.form("label", label))
		id, _, err := auth.ParseToken(tokenRe.FindString(tp.body))
		if err != nil {
			t.Fatalf("issue %s: %v", label, err)
		}
		return id
	}
	keep, gone := issue("keep"), issue("gone")
	d.post(tab+"/"+gone+"/revoke", d.form())

	// Skip the flash ("Token … revoked.") above the tab strip.
	_, body, _ := strings.Cut(d.get(tab).body, `<nav class="tabs"`)
	active, inactive, ok := strings.Cut(body, `id="inactive-tokens"`)
	if !ok {
		t.Fatal("revoked tokens must be listed in their own disclosure")
	}
	if !strings.Contains(active, keep) || strings.Contains(active, gone) {
		t.Fatal("active table must list only the active token")
	}
	if !strings.Contains(inactive, gone) || strings.Contains(inactive, keep) {
		t.Fatal("inactive list must hold the revoked token")
	}
	if !strings.Contains(active, `Tokens <span class="count">1</span>`) {
		t.Fatal("tokens tab count must show active tokens only")
	}
	if strings.Contains(active, "<details class=\"disclosure mt-0\" open>") {
		t.Fatal("issue form collapses once a token is active")
	}
}

var inlineHandlerRe = regexp.MustCompile(` on[a-z]+="`)

func TestAgentPagesAreCSPSafe(t *testing.T) {
	for _, signing := range []bool{true, false} {
		d := newDash(t, testutil.Options{Signing: signing})
		d.login()
		a := d.createAgent("bench", "me")
		base := "/agents/" + a.ID
		pages := map[string]string{}
		for _, path := range []string{base, base + "/tokens", base + "/policy", base + "/signing", base + "/delete", "/agents/new"} {
			p := d.get(path)
			if p.status != 200 {
				t.Fatalf("%s: %d", path, p.status)
			}
			pages[path] = p.body
		}
		tp := d.post(base+"/tokens", d.form("label", "x"))
		pages["token page"] = tp.body
		d.post(base+"/keys/rotate", d.form())
		pages["signing after rotation"] = d.get(base + "/signing").body
		for name, body := range pages {
			if strings.Contains(body, ` style="`) || strings.Contains(body, "<script>") || inlineHandlerRe.MatchString(body) {
				t.Errorf("signing=%v %s: inline style, script or handler (CSP)", signing, name)
			}
		}
	}
}
