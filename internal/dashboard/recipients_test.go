package dashboard_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

func TestRecipientsCRUD(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	if p := d.get("/recipients/new"); p.status != 200 || !strings.Contains(p.body, "export-minimal") {
		t.Fatalf("new recipient page: %d", p.status)
	}

	// Rejections keep what was typed, so a pasted key is not lost.
	k1 := testutil.NewKey(t, "Pager", "pager@example.net")
	armor1 := testutil.ArmorPublic(t, k1)
	p := d.post("/recipients", d.form("alias", "Bad Alias", "address", "pager@example.net", "pgp_public_key", armor1))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "Alias must be") ||
		!strings.Contains(p.body, `value="pager@example.net"`) || !strings.Contains(p.body, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("invalid alias: %d", p.status)
	}
	if p := d.post("/recipients", d.form("alias", "pager", "address", "pager@example.net", "require_encryption", "on")); !strings.Contains(p.body, "needs a PGP public key") {
		t.Fatal("require_encryption without a key must be refused")
	}
	if p := d.post("/recipients", d.form("alias", "me", "address", "x@example.net")); !strings.Contains(p.body, "already exists") {
		t.Fatal("duplicate alias must be refused")
	}
	if p := d.post("/recipients", d.form("alias", "pager", "address", "Pager <pager@example.net>")); !strings.Contains(p.body, "bare email address") {
		t.Fatal("display names must be refused")
	}
	if _, ok := d.settings.Current().Recipient("pager"); ok {
		t.Fatal("refused recipient must not be saved")
	}

	// Create with a key: the fingerprint is shown and the API sees it at once.
	p = d.post("/recipients", d.form("alias", "pager", "address", "pager@example.net", "description", "On-call pager", "pgp_public_key", armor1))
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/recipients/pager" {
		t.Fatalf("create: %d %s", p.status, p.header.Get("Location"))
	}
	rp := d.get("/recipients/pager")
	if rp.status != 200 || !strings.Contains(rp.body, "Recipient pager created") || !strings.Contains(rp.body, pgp.Fingerprint(k1)) {
		t.Fatalf("recipient page: %d", rp.status)
	}
	if rc, ok := d.settings.Current().Recipient("pager"); !ok || rc.Fingerprint() != pgp.Fingerprint(k1) || rc.Description != "On-call pager" {
		t.Fatalf("current configuration: %+v", rc)
	}
	if f := read(t, d.env.Path); !strings.Contains(f, "  pager:\n    address: pager@example.net\n    description: On-call pager\n    pgp_public_key: |") {
		t.Fatalf("config.yaml must hold the recipient:\n%s", f)
	}
	if l := d.get("/recipients").body; !strings.Contains(l, `href="/recipients/pager"`) || !strings.Contains(l, "On-call pager") {
		t.Fatal("list must link the new recipient")
	}
	if p := d.get("/agents/new").body; !strings.Contains(p, `value="pager"`) {
		t.Fatal("new recipients must be grantable to agents")
	}

	// Replace the key; both replacing and removing at once is refused.
	k2 := testutil.NewKey(t, "Pager 2", "pager@example.net")
	d.post("/recipients/pager", d.form("address", "pager@example.net", "description", "On-call pager", "pgp_public_key", testutil.ArmorPublic(t, k2)))
	if b := d.get("/recipients/pager").body; !strings.Contains(b, pgp.Fingerprint(k2)) || !strings.Contains(b, "new PGP key") {
		t.Fatal("replaced key must be shown")
	}
	d.post("/recipients/pager", d.form("address", "pager@example.net", "remove_key", "on", "pgp_public_key", armor1))
	if b := d.get("/recipients/pager").body; !strings.Contains(b, "not both") {
		t.Fatal("remove + replace must be refused")
	}
	// Editing other fields keeps the key.
	d.post("/recipients/pager", d.form("address", "pager2@example.net", "description", "Pager", "require_encryption", "on"))
	if rc, _ := d.settings.Current().Recipient("pager"); rc.Fingerprint() != pgp.Fingerprint(k2) || rc.Address != "pager2@example.net" || !rc.RequireEncryption {
		t.Fatalf("edit must keep the key: %+v", rc)
	}
	// Removing the key while encryption is required is refused.
	d.post("/recipients/pager", d.form("address", "pager2@example.net", "remove_key", "on", "require_encryption", "on"))
	if b := d.get("/recipients/pager").body; !strings.Contains(b, "needs a PGP public key") {
		t.Fatal("removing the key of a recipient that requires encryption must be refused")
	}
	d.post("/recipients/pager", d.form("address", "pager2@example.net", "remove_key", "on"))
	if rc, _ := d.settings.Current().Recipient("pager"); rc.Key != nil || !strings.Contains(d.get("/recipients/pager").body, "PGP key was removed") {
		t.Fatal("key must be removed")
	}

	// A key expiring soon is saved with a note.
	soon := testutil.ArmorPublic(t, testutil.NewKeyWithLifetime(t, "Soon", "soon@example.net", 10*24*time.Hour))
	d.post("/recipients", d.form("alias", "soon", "address", "soon@example.net", "pgp_public_key", soon))
	if b := d.get("/recipients/soon").body; !strings.Contains(b, "Its PGP key expires on") || !strings.Contains(b, `class="banner warn"`) {
		t.Fatal("expiring key must be flagged")
	}

	for _, path := range []string{"/recipients/ghost", "/recipients/Bad_Alias", "/recipients/ghost/delete"} {
		if p := d.get(path); p.status != http.StatusNotFound {
			t.Errorf("%s: %d", path, p.status)
		}
	}

	// Delete: the confirm page names the agents granting it; their policy
	// keeps the alias, ignored and flagged.
	a := d.createAgent("bench", "me", "pager")
	dp := d.get("/recipients/pager/delete")
	if dp.status != 200 || !strings.Contains(dp.body, `href="/agents/`+a.Name+`/policy"`) || !strings.Contains(dp.body, "recipient_not_allowed") {
		t.Fatalf("delete page: %d", dp.status)
	}
	d.post("/recipients/pager/delete", d.form("confirm", "wrong"))
	if _, ok := d.settings.Current().Recipient("pager"); !ok {
		t.Fatal("wrong confirmation must not delete")
	}
	if p := d.post("/recipients/pager/delete", d.form("confirm", "pager")); p.header.Get("Location") != "/recipients" {
		t.Fatalf("delete redirects to %q", p.header.Get("Location"))
	}
	if _, ok := d.settings.Current().Recipient("pager"); ok {
		t.Fatal("recipient must be deleted")
	}
	if b := d.get("/agents/" + a.Name + "/policy").body; !strings.Contains(b, "no longer exist") || !strings.Contains(b, "pager") {
		t.Fatal("policy tab must flag the deleted alias")
	}
	got := d.agent(a.Name)
	if len(*got.Policy.Recipients) != 2 {
		t.Fatal("deleting a recipient must not rewrite policies")
	}
	if p := d.post("/recipients/pager/test", d.form()); p.status != http.StatusNotFound {
		t.Fatalf("test send to a deleted recipient: %d", p.status)
	}
}

func TestOverviewNoRecipientsNotice(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	ctx := context.Background()
	if strings.Contains(d.get("/").body, "No recipients") {
		t.Fatal("with recipients: no notice")
	}
	for _, a := range d.settings.Current().Aliases() {
		if err := d.settings.DeleteRecipient(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	body := d.get("/").body
	for _, want := range []string{"No recipients", `href="/recipients/new"`, "Add your first recipient"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if s := d.get("/settings").body; strings.Contains(s, "/settings/test-send") || !strings.Contains(s, `<a href="/recipients">recipient's page</a>`) {
		t.Error("settings must point at the recipient pages for test messages")
	}
	if r := d.get("/recipients"); r.status != 200 || !strings.Contains(r.body, "No recipients") {
		t.Error("recipients page needs an empty state")
	}
	if n := d.get("/agents/new").body; !strings.Contains(n, `href="/recipients/new"`) {
		t.Error("new agent page must point at adding a recipient")
	}

	// defaults.policy.recipients naming a missing alias is flagged, not fatal.
	g := newDash(t, testutil.Options{DefaultsPolicy: "recipients: [me, ghost]"})
	g.login()
	if b := g.get("/").body; !strings.Contains(b, "Default policy") || !strings.Contains(b, "ghost") || !strings.Contains(b, `href="/settings#policy"`) {
		t.Error("unknown default alias must be flagged")
	}
}

func TestRecipientTestSendWithoutUpstream(t *testing.T) {
	d := newDashWith(t, testutil.Options{}, func(env *testutil.Env, _ *store.Store) { withoutUpstream(t, env) })
	d.login()
	b := d.get("/recipients/me").body
	if strings.Contains(b, `action="/recipients/me/test"`) ||
		!strings.Contains(b, "No SMTP host or From address is set") || !strings.Contains(b, `href="/settings#upstream"`) {
		t.Fatal("without upstream the recipient page must say what is missing instead of offering a test")
	}
	sent := d.env.SMTP.Count()
	if p := d.post("/recipients/me/test", d.form()); p.status != http.StatusSeeOther || p.header.Get("Location") != "/recipients/me" {
		t.Fatalf("test send without upstream: %d to %q", p.status, p.header.Get("Location"))
	}
	if d.env.SMTP.Count() != sent {
		t.Fatal("nothing may be sent without upstream")
	}
	if b := d.get("/recipients/me").body; !strings.Contains(b, "Test message not sent: No SMTP host or From address is set") {
		t.Fatal("the refusal must say what is missing")
	}
}
