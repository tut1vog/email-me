package dashboard_test

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// statValue reads the number shown on the overview tile with the given label.
func statValue(t *testing.T, body, label string) int {
	t.Helper()
	re := regexp.MustCompile(`stat-label">` + regexp.QuoteMeta(label) + `</span>\s*<span class="stat-value[^"]*">(\d+)`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no %q tile on the overview", label)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func TestOverviewTiles(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	ctx := context.Background()
	a := d.createAgent("bench", "me")
	b := d.createAgent("idle")
	d.post("/agents/"+b.ID, d.form("description", "off")) // no "enabled" → disabled
	if tp := d.post("/agents/"+a.ID+"/tokens", d.form("label", "ci")); tp.status != 200 {
		t.Fatalf("issue token: %d", tp.status)
	}
	now := time.Now()
	for _, e := range []store.AuditEntry{
		{AgentID: a.ID, Status: store.StatusSent, TS: now},
		{AgentID: a.ID, Status: store.StatusSent, TS: now.Add(-time.Hour)},
		{AgentID: a.ID, Status: store.StatusSent, TS: now.Add(-3 * 24 * time.Hour)}, // week only
		{AgentID: a.ID, Status: store.StatusFailed, TS: now},
		{AgentID: a.ID, Status: store.StatusRejected, TS: now},
		{Status: store.StatusRejected, ErrorCode: "unauthorized", TS: now}, // no agent: still counted
	} {
		if err := d.st.InsertAudit(ctx, &e); err != nil {
			t.Fatal(err)
		}
	}

	body := d.get("/").body
	for label, want := range map[string]int{"Agents enabled": 1, "Active tokens": 1, "Sent, last 24 h": 2, "Failed, last 24 h": 1} {
		if got := statValue(t, body, label); got != want {
			t.Errorf("tile %q = %d, want %d", label, got, want)
		}
	}
	for _, want := range []string{
		`<span class="unit">/ 2</span>`, // two agents in total
		`3 in 7 days`,
		`2 rejected`, // includes the request no agent was resolved for
		`<span class="stat-value danger">1</span>`,
		`<span class="tag">not checked</span>`,
		`action="/settings/test-smtp"`,
		"Needs attention",
		"All clear",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(body, "Needs attention (") {
		t.Error("nothing is wrong, so there is no attention count")
	}
}

func TestOverviewAttentionOrderAndLinks(t *testing.T) {
	d := newDash(t, testutil.Options{PublicURL: "http://gw.example.com:8025"})
	d.login()
	body := d.get("/").body
	warn := strings.Index(body, "plain HTTP on a non-localhost host")
	info := strings.Index(body, "Signing is not configured")
	if warn < 0 || info < 0 || warn > info {
		t.Fatalf("attention list must put warnings before info (warn at %d, info at %d)", warn, info)
	}
	for _, want := range []string{"Needs attention (2)", `href="/settings"`, `href="/settings#signing"`, "Create your first agent"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(body, "All clear") {
		t.Error("no all-clear while something needs attention")
	}
}

func TestAuditColumnsAndAutosubmit(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	a := d.createAgent("bench", "me")
	fpr := strings.Repeat("AB", 20)
	d.st.InsertAudit(context.Background(), &store.AuditEntry{
		AgentID: a.ID, TokenID: "tk_one", SourceIP: "203.0.113.7", Recipients: []string{"me"}, SizeBytes: 2048,
		AttachmentCount: 2, Services: []string{"markdown"}, Encrypted: true, Signed: true, SigningKeyFpr: fpr,
		Transport: "insecure", Status: store.StatusSent, TS: time.Now(),
	})
	body := d.get("/audit").body
	for _, want := range []string{
		"data-autosubmit", `class="secondary js-hide"`,
		`<span class="tag ok">sent</span>`, `<span class="tag danger">insecure</span>`,
		`<span class="tag ok">enc</span>`, `title="` + fpr + `"`,
		"2 att", "markdown", "203.0.113.7", "tk_one", "subjects are not logged",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page lacks %q", want)
		}
	}
	thead := regexp.MustCompile(`(?s)<thead>(.*?)</thead>`).FindStringSubmatch(body)
	if thead == nil || strings.Count(thead[1], "<th") != 7 {
		t.Fatalf("audit table must have 7 columns: %v", thead)
	}
	if e := d.get("/audit?status=failed").body; !strings.Contains(e, "No matching entries") {
		t.Fatal("empty audit result needs an empty state")
	}
}

var (
	inlineStyle   = regexp.MustCompile(`(?i)<[^>]*\sstyle\s*=`)
	inlineHandler = regexp.MustCompile(`(?i)<[^>]*\son[a-z]+\s*=`)
)

func TestPagesHaveNoInlineStyleOrScript(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true, PublicURL: "http://gw.example.com:8025"})
	d.login()
	a := d.createAgent("bench", "me")
	d.st.InsertAudit(context.Background(), &store.AuditEntry{AgentID: a.ID, Status: store.StatusSent, Transport: "insecure", Signed: true, TS: time.Now()})
	for _, path := range []string{"/", "/agents", "/audit", "/settings", "/recipients", "/settings/guide"} {
		p := d.get(path)
		if p.status != 200 {
			t.Fatalf("%s: %d", path, p.status)
		}
		if strings.Contains(p.body, "<script>") || inlineStyle.MatchString(p.body) || inlineHandler.MatchString(p.body) {
			t.Errorf("%s has inline script, style or event handler (CSP)", path)
		}
	}
}
