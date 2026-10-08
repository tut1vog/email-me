package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/emersion/go-message"
	"github.com/emersion/go-pgpmail"

	"github.com/tut1vog/email-me/internal/api"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/units"
)

// ---- discovery -------------------------------------------------------------

func TestGuideIsGenericAndPointsToSpec(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	h.agent("secret-agent-name", policy.Policy{Recipients: ptr([]string{"me"})})
	for _, path := range []string{"/", "/llms.txt"} {
		r := h.do("GET", path, "", nil)
		if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/markdown") {
			t.Fatalf("GET %s = %d %s", path, r.status, r.header.Get("Content-Type"))
		}
		g := string(r.body)
		mustContain(t, g, h.ts.URL+"/openapi.json", h.ts.URL+"/v1/capabilities", "idempotency_key", "e2e_available", "insecure", "Retry-After")
		for _, leak := range []string{"me@example.com", "work@example.org", "Personal inbox", "secret-agent-name", "gateway@example.com"} {
			if strings.Contains(g, leak) {
				t.Errorf("guide leaks deployment data %q", leak)
			}
		}
		if len(g) > 7000 { // ≈1.5-1.75k tokens
			t.Errorf("guide is %d bytes; keep it within the ~1.5k token budget", len(g))
		}
	}
}

func TestOpenAPIServedAndValid(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	r := h.do("GET", "/openapi.json", "", nil)
	if r.status != 200 {
		t.Fatal(r.status)
	}
	var doc map[string]any
	if err := json.Unmarshal(r.body, &doc); err != nil {
		t.Fatal(err)
	}
	servers := doc["servers"].([]any)
	if servers[0].(map[string]any)["url"] != h.ts.URL {
		t.Fatalf("server URL = %v", servers)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatal(doc["openapi"])
	}
}

func TestPublicURLOverridesBase(t *testing.T) {
	h := newHarness(t, testutil.Options{PublicURL: "https://mail-gw.example.ts.net"})
	r := h.do("GET", "/", "", nil)
	mustContain(t, string(r.body), "https://mail-gw.example.ts.net/v1/capabilities")
}

func TestSpecDocumentsEveryErrorCode(t *testing.T) {
	doc := loadSpec(t)
	enum := doc.Components.Schemas["Error"].Value.Properties["error"].Value.Enum
	var inSpec []string
	for _, e := range enum {
		inSpec = append(inSpec, e.(string))
	}
	for _, c := range api.AllCodes {
		if !slices.Contains(inSpec, c) {
			t.Errorf("error code %q is returned by handlers but missing from openapi.yaml", c)
		}
	}
	for _, c := range inSpec {
		if !slices.Contains(api.AllCodes, c) {
			t.Errorf("openapi.yaml documents %q which handlers never return", c)
		}
	}
}

func TestHealthNotFoundAndMethods(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	if r := h.do("GET", "/healthz", "", nil); r.status != 200 || string(r.body) != "{\"status\":\"ok\"}\n" {
		t.Fatalf("healthz = %d %s", r.status, r.body)
	}
	r := h.do("GET", "/v2/whatever", "", nil)
	if r.status != 404 || r.code(t) != "not_found" {
		t.Fatalf("unknown path = %d %s", r.status, r.body)
	}
	r = h.do("GET", "/v1/messages", "", nil)
	if r.status != 405 || r.code(t) != "method_not_allowed" {
		t.Fatalf("wrong method = %d %s", r.status, r.body)
	}
	if r.header.Get("X-Content-Type-Options") != "nosniff" || r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("security headers missing")
	}
}

func TestDocsAuthenticated(t *testing.T) {
	h := newHarness(t, testutil.Options{Docs: "authenticated"})
	_, tok := h.agent("a", policy.Policy{})
	for _, p := range []string{"/", "/llms.txt", "/openapi.json"} {
		if r := h.do("GET", p, "", nil); r.status != 401 || bytes.Contains(r.body, []byte("capabilities")) {
			t.Fatalf("GET %s without token = %d", p, r.status)
		}
		if r := h.do("GET", p, tok, nil); r.status != 200 {
			t.Fatalf("GET %s with token = %d", p, r.status)
		}
	}
	if r := h.do("GET", "/healthz", "", nil); r.status != 200 {
		t.Fatal("healthz stays public")
	}
}

// ---- authentication ---------------------------------------------------------

func TestAuthentication(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	a, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	id, _, _ := strings.Cut(strings.TrimPrefix(tok, "em_"), "_")

	past := time.Now().Add(-time.Hour)
	expired := h.token(a, nil, &past)
	revoked := h.token(a, nil, nil)
	rid, _, _ := strings.Cut(strings.TrimPrefix(revoked, "em_"), "_")
	h.st.RevokeToken(context.Background(), a.ID, rid)

	cases := map[string]func(*http.Request){
		"missing":      func(r *http.Request) { r.Header.Del("Authorization") },
		"basic scheme": func(r *http.Request) { r.Header.Set("Authorization", "Basic "+tok) },
		"malformed":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") },
		"wrong secret": func(r *http.Request) { r.Header.Set("Authorization", "Bearer em_"+id+"_"+strings.Repeat("a", 52)) },
		"unknown id": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer em_"+strings.Repeat("b", 12)+"_"+strings.Repeat("a", 52))
		},
		"expired": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+expired) },
		"revoked": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+revoked) },
	}
	for name, mod := range cases {
		r := h.do("GET", "/v1/capabilities", tok, nil, mod)
		if r.status != 401 || r.code(t) != "unauthorized" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := h.do("GET", "/v1/capabilities", tok, nil); r.status != 200 {
		t.Fatalf("valid token: %d %s", r.status, r.body)
	}
	got, _ := h.st.GetToken(context.Background(), id)
	if got.LastUsedAt == nil || got.LastUsedIP != "127.0.0.1" {
		t.Fatalf("last use not recorded: %+v", got)
	}
	h.st.UpdateAgent(context.Background(), a.ID, "", false)
	if r := h.do("POST", "/v1/messages", tok, msg("me", "x", "y")); r.status != 403 || r.code(t) != "agent_disabled" {
		t.Fatalf("disabled agent: %d %s", r.status, r.body)
	}
	if rows := h.auditRows(a.ID); len(rows) != 1 || rows[0].ErrorCode != "agent_disabled" {
		t.Fatalf("disabled-agent attempt must be audited: %+v", rows)
	}
}

func TestSourceCIDRs(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	a, _ := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	blocked := h.token(a, []string{"10.0.0.0/8"}, nil)
	allowed := h.token(a, []string{"10.0.0.0/8", "127.0.0.1/32"}, nil)
	if r := h.do("GET", "/v1/capabilities", blocked, nil); r.status != 403 || r.code(t) != "source_ip_not_allowed" {
		t.Fatalf("blocked: %d %s", r.status, r.body)
	}
	if r := h.do("GET", "/v1/capabilities", allowed, nil); r.status != 200 {
		t.Fatalf("allowed: %d %s", r.status, r.body)
	}
}

// ---- capabilities ------------------------------------------------------------

func TestCapabilities(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	a, tok := h.agent("bench", policy.Policy{
		Recipients: ptr([]string{"me", "ops"}),
		Services:   ptr([]string{policy.SvcMarkdown, policy.SvcEncrypt, policy.SvcThread}),
	})
	r := h.do("GET", "/v1/capabilities", tok, nil)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	var c struct {
		Agent      string
		Recipients []struct {
			Alias, Description  string
			EncryptionAvailable bool `json:"encryption_available"`
		}
		Services      []string
		Limits        map[string]any
		SubjectPrefix string `json:"subject_prefix"`
		Signing       struct {
			Available, Required, Default bool
			Fingerprint                  string
		}
		E2E       bool `json:"e2e_available"`
		Transport string
	}
	json.Unmarshal(r.body, &c)
	if c.Agent != "bench" || len(c.Recipients) != 2 || c.Recipients[0].Alias != "me" || !c.Recipients[0].EncryptionAvailable || c.Recipients[1].EncryptionAvailable {
		t.Fatalf("recipients: %+v", c.Recipients)
	}
	if c.Recipients[0].Description != "Personal inbox" {
		t.Fatal("descriptions help the agent choose")
	}
	if !slices.Contains(c.Services, "sign") {
		t.Fatal("require_signing (default) implies the sign service")
	}
	k, _ := h.st.ActiveKey(context.Background(), a.ID)
	if !c.Signing.Available || !c.Signing.Required || !c.Signing.Default || c.Signing.Fingerprint != k.Fingerprint {
		t.Fatalf("signing: %+v", c.Signing)
	}
	if c.E2E || c.Transport != "local" || c.SubjectPrefix != "[bench] " || c.Limits["remaining_this_hour"].(float64) != 20 {
		t.Fatalf("caps: %+v", c)
	}
	if bytes.Contains(r.body, []byte("@example")) {
		t.Fatal("capabilities must not reveal addresses")
	}
}

// ---- sending -----------------------------------------------------------------

func agentPublicKey(t *testing.T, h *harness, agentID string) *openpgp.Entity {
	t.Helper()
	k, err := h.st.ActiveKey(context.Background(), agentID)
	if err != nil {
		t.Fatal(err)
	}
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return el[0]
}

func TestSendSignedMarkdownByDefault(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	a, tok := h.agent("bench", policy.Policy{Recipients: ptr([]string{"me"})})
	body := msg("me", "Nightly results", "## Results\n- p50: 12ms")
	body["options"] = map[string]any{"thread": "nightly"}
	r := h.do("POST", "/v1/messages", tok, body)
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	res := r.json(t)
	if res["status"] != "sent" || res["signed"] != true || res["encrypted"] != false || !strings.HasPrefix(res["id"].(string), "msg_") {
		t.Fatalf("response: %s", r.body)
	}
	c := h.env.SMTP.Last(t)
	if c.From != "gateway@example.com" || len(c.To) != 1 || c.To[0] != "me@example.com" {
		t.Fatalf("envelope: %s → %v", c.From, c.To)
	}
	outer, _ := mail.ReadMessage(bytes.NewReader(c.Data))
	if !strings.HasPrefix(outer.Header.Get("Content-Type"), "multipart/signed") {
		t.Fatalf("expected multipart/signed, got %q", outer.Header.Get("Content-Type"))
	}
	if outer.Header.Get("Subject") != "[bench] Nightly results" || outer.Header.Get("X-Email-Me-Agent") != "bench" || outer.Header.Get("In-Reply-To") == "" {
		t.Fatalf("headers: %v", outer.Header)
	}
	pr, err := pgpmail.Read(bytes.NewReader(c.Data), openpgp.EntityList{agentPublicKey(t, h, a.ID)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := message.Read(pr.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, inner.Body)
	if pr.MessageDetails.SignatureError != nil {
		t.Fatalf("signature does not verify with the agent's public key: %v", pr.MessageDetails.SignatureError)
	}
	if inner.Header.Get("X-Email-Me-Agent") != "bench" {
		t.Fatal("agent attribution must be inside the signed entity")
	}
	rows := h.auditRows(a.ID)
	if len(rows) != 1 {
		t.Fatalf("audit rows: %d", len(rows))
	}
	e := rows[0]
	k, _ := h.st.ActiveKey(context.Background(), a.ID)
	if e.Status != "sent" || !e.Signed || e.SigningKeyFpr != k.Fingerprint || e.Transport != "local" || e.Subject != "" ||
		!hasString(e.Services, "markdown") || !hasString(e.Services, "sign") || !hasString(e.Services, "thread") || e.MessageID == "" {
		t.Fatalf("audit row: %+v", e)
	}
}

func TestSendEncryptedAndSigned(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true, WorkRequiresEncryption: true})
	a, tok := h.agent("bench", policy.Policy{
		Recipients: ptr([]string{"me", "work"}),
		Services:   ptr([]string{policy.SvcMarkdown, policy.SvcEncrypt, policy.SvcAttachments}),
	})
	plain := msg("work", "Quarterly numbers", "The confidential numbers are **42**.")
	if r := h.do("POST", "/v1/messages", tok, plain); r.status != 403 || r.code(t) != "encryption_required" {
		t.Fatalf("unencrypted to work: %d %s", r.status, r.body)
	}
	plain["options"] = map[string]any{"encrypt": "pgp"}
	plain["attachments"] = []map[string]any{{"filename": "n.csv", "content_type": "text/csv", "content_base64": base64.StdEncoding.EncodeToString([]byte("q,n\n3,42\n"))}}
	r := h.do("POST", "/v1/messages", tok, plain)
	if r.status != 200 || r.json(t)["encrypted"] != true || r.json(t)["signed"] != true {
		t.Fatalf("%d %s", r.status, r.body)
	}
	c := h.env.SMTP.Last(t)
	if bytes.Contains(c.Data, []byte("Quarterly")) || bytes.Contains(c.Data, []byte("confidential")) || bytes.Contains(c.Data, []byte("3,42")) {
		t.Fatal("plaintext leaked to the mail provider")
	}
	outer, _ := mail.ReadMessage(bytes.NewReader(c.Data))
	if outer.Header.Get("Subject") != "[bench] Encrypted message" {
		t.Fatalf("outer subject = %q", outer.Header.Get("Subject"))
	}
	pr, err := pgpmail.Read(bytes.NewReader(c.Data), openpgp.EntityList{h.env.WorkKey, agentPublicKey(t, h, a.ID)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := message.Read(pr.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if all := leafText(t, inner); inner.Header.Get("Subject") != "[bench] Quarterly numbers" || !strings.Contains(all, "3,42") || !strings.Contains(all, "confidential") {
		t.Fatalf("inner: subject=%q", inner.Header.Get("Subject"))
	}
	if !pr.MessageDetails.IsSigned || pr.MessageDetails.SignatureError != nil {
		t.Fatalf("inner signature: %v", pr.MessageDetails.SignatureError)
	}
}

// leafText concatenates the decoded bodies of all leaf parts.
func leafText(t *testing.T, e *message.Entity) string {
	t.Helper()
	if mr := e.MultipartReader(); mr != nil {
		var b strings.Builder
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return b.String()
			}
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(leafText(t, p))
		}
	}
	body, _ := io.ReadAll(e.Body)
	return string(body)
}

func TestSendE2E(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	_, tok := h.agent("vault", policy.Policy{
		Recipients: ptr([]string{"me", "ops"}), Services: ptr([]string{policy.SvcE2E}), RequireSigning: ptr(false),
	})
	caps := h.do("GET", "/v1/capabilities", tok, nil).json(t)
	if caps["e2e_available"] != true {
		t.Fatalf("e2e should be available: %v", caps)
	}
	r := h.do("GET", "/v1/recipients/me/pgp-key", tok, nil)
	if r.status != 200 || r.header.Get("X-Email-Me-Key-Fingerprint") != pgp.Fingerprint(h.env.MeKey) {
		t.Fatalf("key: %d %v", r.status, r.header)
	}
	if r := h.do("GET", "/v1/recipients/ops/pgp-key", tok, nil); r.status != 404 {
		t.Fatalf("ops has no key: %d", r.status)
	}
	if r := h.do("GET", "/v1/recipients/work/pgp-key", tok, nil); r.status != 403 || r.code(t) != "recipient_not_allowed" {
		t.Fatalf("work not allowed: %d", r.status)
	}
	keyResp := h.do("GET", "/v1/recipients/me/pgp-key", tok, nil)
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyResp.body))
	if err != nil {
		t.Fatal(err)
	}
	entity := "Content-Type: text/plain; charset=utf-8\r\nSubject: Top secret\r\n\r\nOnly the operator can read this.\r\n"
	var ct bytes.Buffer
	aw, _ := armor.Encode(&ct, "PGP MESSAGE", nil)
	pw, _ := openpgp.Encrypt(aw, ring, nil, nil, nil)
	pw.Write([]byte(entity))
	pw.Close()
	aw.Close()

	send := map[string]any{"to": []string{"me"}, "body": map[string]any{"pgp_message": ct.String()}, "options": map[string]any{"encrypt": "e2e"}}
	r = h.do("POST", "/v1/messages", tok, send)
	if r.status != 200 || r.json(t)["signed"] != false || r.json(t)["encrypted"] != true {
		t.Fatalf("%d %s", r.status, r.body)
	}
	c := h.env.SMTP.Last(t)
	outer, _ := mail.ReadMessage(bytes.NewReader(c.Data))
	if outer.Header.Get("Subject") != "[vault] Encrypted message" {
		t.Fatal(outer.Header.Get("Subject"))
	}
	pr, err := pgpmail.Read(bytes.NewReader(c.Data), openpgp.EntityList{h.env.MeKey}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(pr.MessageDetails.UnverifiedBody)
	if string(got) != entity {
		t.Fatalf("decrypted = %q", got)
	}

	smuggle := map[string]any{"to": []string{"me"}, "body": map[string]any{"pgp_message": "SMUGGLED-PLAINTEXT\n\n" + ct.String() + "\nMORE-PLAINTEXT"}, "options": map[string]any{"encrypt": "e2e"}}
	if r := h.do("POST", "/v1/messages", tok, smuggle); r.status != 200 {
		t.Fatalf("armor with surrounding text: %d %s", r.status, r.body)
	}
	if d := h.env.SMTP.Last(t).Data; bytes.Contains(d, []byte("SMUGGLED-PLAINTEXT")) || bytes.Contains(d, []byte("MORE-PLAINTEXT")) {
		t.Fatal("text outside the armor must never reach the mail provider")
	}

	withSubject := map[string]any{"to": []string{"me"}, "subject": "leak", "body": map[string]any{"pgp_message": ct.String()}, "options": map[string]any{"encrypt": "e2e"}}
	if r := h.do("POST", "/v1/messages", tok, withSubject); r.status != 422 {
		t.Fatalf("subject with e2e: %d", r.status)
	}
	signed := map[string]any{"to": []string{"me"}, "body": map[string]any{"pgp_message": ct.String()}, "options": map[string]any{"encrypt": "e2e", "sign": true}}
	if r := h.do("POST", "/v1/messages", tok, signed); r.status != 422 {
		t.Fatalf("sign with e2e: %d", r.status)
	}
	bad := map[string]any{"to": []string{"me"}, "body": map[string]any{"pgp_message": "-----BEGIN PGP MESSAGE-----\n\nnope\n-----END PGP MESSAGE-----"}, "options": map[string]any{"encrypt": "e2e"}}
	if r := h.do("POST", "/v1/messages", tok, bad); r.status != 422 {
		t.Fatalf("bad ciphertext: %d", r.status)
	}
}

func TestE2EBlockedWhenSigningRequired(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	// The dashboard refuses to save this combination; set it directly to test the API guard.
	_, tok := h.agent("x", policy.Policy{Recipients: ptr([]string{"me"}), Services: ptr([]string{policy.SvcE2E})})
	send := map[string]any{"to": []string{"me"}, "body": map[string]any{"pgp_message": "x"}, "options": map[string]any{"encrypt": "e2e"}}
	r := h.do("POST", "/v1/messages", tok, send)
	if r.status != 403 || r.code(t) != "signing_required" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if caps := h.do("GET", "/v1/capabilities", tok, nil).json(t); caps["e2e_available"] != false {
		t.Fatal("e2e must not be advertised when signing is required")
	}
}

func TestSigningOptOutAndRequired(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	_, required := h.agent("strict", policy.Policy{Recipients: ptr([]string{"me"})})
	body := msg("me", "s", "b")
	body["options"] = map[string]any{"sign": false}
	if r := h.do("POST", "/v1/messages", required, body); r.status != 403 || r.code(t) != "signing_required" {
		t.Fatalf("opt-out under require_signing: %d %s", r.status, r.body)
	}
	_, relaxed := h.agent("relaxed", policy.Policy{Recipients: ptr([]string{"me"}), RequireSigning: ptr(false)})
	if r := h.do("POST", "/v1/messages", relaxed, body); r.status != 200 || r.json(t)["signed"] != false {
		t.Fatalf("opt-out allowed: %d %s", r.status, r.body)
	}
	if ct := contentType(t, h.env.SMTP.Last(t).Data); strings.HasPrefix(ct, "multipart/signed") {
		t.Fatal("opted-out message must not be signed")
	}
	if r := h.do("POST", "/v1/messages", relaxed, msg("me", "s", "b")); r.json(t)["signed"] != true {
		t.Fatal("signing is the default when available")
	}
}

func contentType(t *testing.T, raw []byte) string {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, _, _ := mime.ParseMediaType(m.Header.Get("Content-Type"))
	return mt
}

func TestSigningNotConfigured(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	if r := h.do("POST", "/v1/messages", tok, msg("me", "s", "b")); r.status != 200 || r.json(t)["signed"] != false {
		t.Fatalf("%d %s", r.status, r.body)
	}
	body := msg("me", "s", "b")
	body["options"] = map[string]any{"sign": true}
	if r := h.do("POST", "/v1/messages", tok, body); r.status != 403 || r.code(t) != "service_not_allowed" {
		t.Fatalf("sign without service: %d %s", r.status, r.body)
	}
	_, withSvc := h.agent("b", policy.Policy{Recipients: ptr([]string{"me"}), Services: ptr([]string{policy.SvcMarkdown, policy.SvcSign})})
	if r := h.do("POST", "/v1/messages", withSvc, body); r.status != 503 || r.code(t) != "signing_unavailable" {
		t.Fatalf("sign unavailable: %d %s", r.status, r.body)
	}
	_, req := h.agent("c", policy.Policy{Recipients: ptr([]string{"me"}), RequireSigning: ptr(true)})
	if r := h.do("POST", "/v1/messages", req, msg("me", "s", "b")); r.status != 503 || r.code(t) != "signing_unavailable" {
		t.Fatalf("required but unconfigured: %d %s", r.status, r.body)
	}
}

func TestExpiredSigningKey(t *testing.T) {
	h := newHarness(t, testutil.Options{Signing: true})
	a, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	short := keys.NewManager(h.st, keys.Options{KEK: h.env.Config.Signing.KEK, Validity: time.Second, Email: "gateway@example.com"})
	if _, err := short.Rotate(context.Background(), a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	r := h.do("POST", "/v1/messages", tok, msg("me", "s", "b"))
	if r.status != 503 || r.code(t) != "signing_unavailable" || !strings.Contains(r.json(t)["message"].(string), "expired") {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if caps := h.do("GET", "/v1/capabilities", tok, nil).json(t); caps["signing"].(map[string]any)["available"] != false {
		t.Fatal("expired key must not be advertised as available")
	}
}

func TestRejections(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	a, tok := h.agent("bench", policy.Policy{
		Recipients:             ptr([]string{"me", "ops"}),
		Services:               ptr([]string{policy.SvcMarkdown, policy.SvcAttachments, policy.SvcEncrypt}),
		MaxMessageBytes:        ptr(units.ByteSize(1024)),
		MaxAttachments:         ptr(1),
		AllowedAttachmentTypes: ptr([]string{"text/*"}),
	})
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	att := func(name, ct, data string) map[string]any {
		return map[string]any{"filename": name, "content_type": ct, "content_base64": data}
	}
	with := func(k string, v any) map[string]any {
		m := msg("me", "subject", "body")
		m[k] = v
		return m
	}
	cases := []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"not json", "{", 400, "invalid_request"},
		{"unknown field", with("cc", []string{"x"}), 400, "invalid_request"},
		{"two bodies", with("body", map[string]any{"text": "a", "markdown": "b"}), 400, "invalid_request"},
		{"no recipients", with("to", []string{}), 400, "invalid_request"},
		{"trailing data", `{"to":["me"],"subject":"s","body":{"text":"b"}} {}`, 400, "invalid_request"},
		{"email instead of alias", with("to", []string{"me@example.com"}), 422, "validation_failed"},
		{"missing subject", map[string]any{"to": []string{"me"}, "body": map[string]any{"text": "b"}}, 422, "validation_failed"},
		{"blank subject", with("subject", " \r\n "), 422, "validation_failed"},
		{"bad encrypt", with("options", map[string]any{"encrypt": "rot13"}), 422, "validation_failed"},
		{"bad base64", with("attachments", []any{att("a.txt", "text/plain", "!!!")}), 422, "validation_failed"},
		{"bad content type", with("attachments", []any{att("a.txt", "nonsense", b64("x"))}), 422, "validation_failed"},
		{"pgp_message without e2e", with("body", map[string]any{"pgp_message": "x"}), 422, "validation_failed"},
		{"encrypt to keyless alias", map[string]any{"to": []string{"ops"}, "subject": "s", "body": map[string]any{"text": "b"}, "options": map[string]any{"encrypt": "pgp"}}, 422, "validation_failed"},
		{"recipient not granted", with("to", []string{"work"}), 403, "recipient_not_allowed"},
		{"unknown alias", with("to", []string{"ghost"}), 403, "recipient_not_allowed"},
		{"html not granted", with("body", map[string]any{"html": "<p>x</p>"}), 403, "service_not_allowed"},
		{"thread not granted", with("options", map[string]any{"thread": "t"}), 403, "service_not_allowed"},
		{"high priority not granted", with("options", map[string]any{"priority": "high"}), 403, "service_not_allowed"},
		{"too large", with("body", map[string]any{"text": strings.Repeat("x", 2000)}), 413, "message_too_large"},
		{"way too large", with("body", map[string]any{"text": strings.Repeat("x", 200000)}), 413, "message_too_large"},
		{"too many attachments", with("attachments", []any{att("a.txt", "text/plain", b64("a")), att("b.txt", "text/plain", b64("b"))}), 413, "message_too_large"},
		{"attachment type", with("attachments", []any{att("a.exe", "application/x-msdownload", b64("MZ"))}), 415, "attachment_type_not_allowed"},
	}
	for _, c := range cases {
		r := h.do("POST", "/v1/messages", tok, c.body)
		if r.status != c.status || r.code(t) != c.code {
			t.Errorf("%s: got %d %s, want %d %s", c.name, r.status, r.body, c.status, c.code)
			continue
		}
		if msg, _ := r.json(t)["message"].(string); len(msg) < 10 {
			t.Errorf("%s: error message should explain the fix: %q", c.name, msg)
		}
	}
	if h.env.SMTP.Count() != 0 {
		t.Fatal("rejected requests must not be delivered")
	}
	rows := h.auditRows(a.ID)
	if len(rows) != len(cases) {
		t.Fatalf("every rejection must be audited: %d rows for %d cases", len(rows), len(cases))
	}
	for _, e := range rows {
		if e.Status != "rejected" || e.ErrorCode == "" {
			t.Fatalf("audit row: %+v", e)
		}
	}
	r := h.do("POST", "/v1/messages", tok, with("to", []string{"work"}))
	if d := r.json(t)["details"].(map[string]any)["allowed"].([]any); len(d) != 2 {
		t.Fatalf("details.allowed = %v", d)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"}), RateLimit: &policy.RateLimit{PerHour: 2, PerDay: 10}})
	for i := 0; i < 2; i++ {
		if r := h.do("POST", "/v1/messages", tok, msg("me", "s", "b")); r.status != 200 {
			t.Fatalf("send %d: %d", i, r.status)
		}
	}
	r := h.do("POST", "/v1/messages", tok, msg("me", "s", "b"))
	if r.status != 429 || r.code(t) != "rate_limited" {
		t.Fatalf("%d %s", r.status, r.body)
	}
	ra, _ := strconv.Atoi(r.header.Get("Retry-After"))
	if ra < 3500 || ra > 3601 {
		t.Fatalf("Retry-After = %q", r.header.Get("Retry-After"))
	}
	caps := h.do("GET", "/v1/capabilities", tok, nil).json(t)
	if caps["limits"].(map[string]any)["remaining_this_hour"].(float64) != 0 {
		t.Fatal("remaining must be 0")
	}
	if h.env.SMTP.Count() != 2 {
		t.Fatal("only two sends")
	}
}

func TestUpstreamFailureAndIdempotency(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	a, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	body := msg("me", "s", "b")
	body["idempotency_key"] = "run-1"

	h.env.SMTP.FailWith(451)
	r := h.do("POST", "/v1/messages", tok, body)
	if r.status != 502 || r.code(t) != "upstream_failed" || r.json(t)["details"].(map[string]any)["upstream_code"].(float64) != 451 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	rows := h.auditRows(a.ID)
	if rows[0].Status != "failed" || rows[0].UpstreamCode != 451 {
		t.Fatalf("audit: %+v", rows[0])
	}

	h.env.SMTP.FailWith(0)
	r = h.do("POST", "/v1/messages", tok, body)
	if r.status != 200 || r.json(t)["idempotent_replay"] != nil {
		t.Fatalf("retry after failure must really send: %d %s", r.status, r.body)
	}
	first := r.json(t)["id"]
	r = h.do("POST", "/v1/messages", tok, body)
	if r.status != 200 || r.json(t)["idempotent_replay"] != true || r.json(t)["id"] != first {
		t.Fatalf("replay: %d %s", r.status, r.body)
	}
	if h.env.SMTP.Count() != 1 {
		t.Fatalf("delivered %d times", h.env.SMTP.Count())
	}

	// Concurrent duplicates deliver once.
	body["idempotency_key"] = "run-2"
	var wg sync.WaitGroup
	var mu sync.Mutex
	replays := 0
	for i := 0; i < 4; i++ { // at most maxConcurrentSends in flight per agent
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := h.do("POST", "/v1/messages", tok, body)
			if r.status != 200 {
				t.Errorf("concurrent: %d", r.status)
				return
			}
			if r.json(t)["idempotent_replay"] == true {
				mu.Lock()
				replays++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if h.env.SMTP.Count() != 2 || replays != 3 {
		t.Fatalf("delivered %d, replays %d", h.env.SMTP.Count(), replays)
	}
	// Keys are per token: another token's same key is independent.
	other := h.token(a, nil, nil)
	if r := h.do("POST", "/v1/messages", other, body); r.json(t)["idempotent_replay"] != nil {
		t.Fatal("idempotency keys are scoped to the token")
	}
}

func TestInsecureTransportIsRecorded(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	a, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	caps := h.do("GET", "/v1/capabilities", tok, nil, withHost("gateway.example.com:8025")).json(t)
	if caps["transport"] != "insecure" {
		t.Fatalf("transport = %v", caps["transport"])
	}
	h.do("POST", "/v1/messages", tok, msg("me", "s", "b"), withHost("gateway.example.com"))
	if rows := h.auditRows(a.ID); rows[0].Transport != "insecure" {
		t.Fatal(rows[0].Transport)
	}
	ids, _ := h.st.InsecureAgents(context.Background(), time.Now().Add(-time.Hour))
	if len(ids) != 1 || ids[0] != a.ID {
		t.Fatal(ids)
	}
}

func TestTunnelAndProxyTransport(t *testing.T) {
	h := newHarness(t, testutil.Options{External: true})
	_, tok := h.agent("a", policy.Policy{})
	if c := h.do("GET", "/v1/capabilities", tok, nil, withHost("100.64.1.2:8025")).json(t); c["transport"] != "tunnel" {
		t.Fatal(c["transport"])
	}
	p := newHarness(t, testutil.Options{TrustedProxies: []string{"127.0.0.1"}})
	_, tok2 := p.agent("a", policy.Policy{})
	proxied := func(r *http.Request) {
		r.Host = "mail.example.com"
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
	}
	if c := p.do("GET", "/v1/capabilities", tok2, nil, proxied).json(t); c["transport"] != "tls" {
		t.Fatal(c["transport"])
	}
	if g := p.do("GET", "/", "", nil, proxied); !strings.Contains(string(g.body), "https://mail.example.com/openapi.json") {
		t.Fatal("base URL must follow trusted forwarded headers")
	}
}

// TestNoContentOnDisk sends, rejects and fails messages carrying markers and
// asserts no file under the data directory, and no log line, contains them.
func TestNoContentOnDisk(t *testing.T) {
	run := func(t *testing.T, logSubject bool) (dataHits, logHits []string) {
		h := newHarness(t, testutil.Options{Signing: true, LogSubject: logSubject})
		_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"}), Services: ptr([]string{policy.SvcMarkdown, policy.SvcAttachments, policy.SvcEncrypt})})
		body := msg("me", "SUBJ-MARKER-8c1f", "BODY-MARKER-77aa")
		body["attachments"] = []map[string]any{{"filename": "FILE-MARKER-3e.txt", "content_type": "text/plain", "content_base64": base64.StdEncoding.EncodeToString([]byte("ATT-MARKER-91bd"))}}
		if r := h.do("POST", "/v1/messages", tok, body); r.status != 200 {
			t.Fatalf("send: %d %s", r.status, r.body)
		}
		body["options"] = map[string]any{"encrypt": "pgp"}
		h.do("POST", "/v1/messages", tok, body)
		h.env.SMTP.FailWith(554)
		h.do("POST", "/v1/messages", tok, body)
		body["to"] = []string{"work"}
		h.do("POST", "/v1/messages", tok, body)
		h.st.Close() // checkpoint WAL into the main file

		markers := []string{"SUBJ-MARKER-8c1f", "BODY-MARKER-77aa", "ATT-MARKER-91bd", "FILE-MARKER-3e", base64.StdEncoding.EncodeToString([]byte("ATT-MARKER-91bd"))}
		filepath.Walk(h.env.DataDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			for _, m := range markers {
				if bytes.Contains(b, []byte(m)) {
					dataHits = append(dataHits, m+" in "+filepath.Base(p))
				}
			}
			return nil
		})
		for _, m := range markers {
			if strings.Contains(h.logs.String(), m) {
				logHits = append(logHits, m)
			}
		}
		return dataHits, logHits
	}
	t.Run("default", func(t *testing.T) {
		data, logs := run(t, false)
		if len(data) > 0 || len(logs) > 0 {
			t.Fatalf("content persisted: data=%v logs=%v", data, logs)
		}
	})
	t.Run("positive control: log_subject stores only the subject", func(t *testing.T) {
		data, logs := run(t, true)
		if len(data) == 0 || !strings.HasPrefix(data[0], "SUBJ-MARKER") || len(logs) > 0 {
			t.Fatalf("scan must detect the audited subject and nothing else: data=%v logs=%v", data, logs)
		}
		for _, d := range data {
			if !strings.HasPrefix(d, "SUBJ-MARKER") {
				t.Fatalf("only the subject may be stored: %v", data)
			}
		}
	})
}

func TestMessageIDsAreUnique(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		id := h.do("POST", "/v1/messages", tok, msg("me", "s", "b")).json(t)["id"].(string)
		if seen[id] {
			t.Fatal("duplicate id")
		}
		seen[id] = true
	}
}

func TestConcurrentSendCap(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"})})
	h.env.SMTP.SlowDown(400 * time.Millisecond)
	var wg sync.WaitGroup
	codes := make(chan int, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := h.do("POST", "/v1/messages", tok, msg("me", "s", "b"))
			if r.status == 429 && r.header.Get("Retry-After") != "1" {
				t.Errorf("Retry-After = %q", r.header.Get("Retry-After"))
			}
			codes <- r.status
		}()
	}
	wg.Wait()
	close(codes)
	count := map[int]int{}
	for c := range codes {
		count[c]++
	}
	if count[200] != 4 || count[429] != 2 {
		t.Fatalf("want 4 sent and 2 rejected for concurrency, got %v", count)
	}
}

func TestExpiredRecipientKey(t *testing.T) {
	h := newHarness(t, testutil.Options{MeKeyLifetime: 30 * 24 * time.Hour})
	_, tok := h.agent("a", policy.Policy{Recipients: ptr([]string{"me"}), Services: ptr([]string{policy.SvcEncrypt, policy.SvcE2E})})
	body := map[string]any{"to": []string{"me"}, "subject": "s", "body": map[string]any{"text": "b"}, "options": map[string]any{"encrypt": "pgp"}}
	if r := h.do("POST", "/v1/messages", tok, body); r.status != 200 {
		t.Fatalf("before expiry: %d %s", r.status, r.body)
	}
	api.SetNow(h.srv, func() time.Time { return time.Now().Add(31 * 24 * time.Hour) })
	r := h.do("POST", "/v1/messages", tok, body)
	if r.status != 503 || r.code(t) != "encryption_unavailable" {
		t.Fatalf("after expiry: %d %s", r.status, r.body)
	}
	caps := h.do("GET", "/v1/capabilities", tok, nil).json(t)
	if caps["recipients"].([]any)[0].(map[string]any)["encryption_available"] != false {
		t.Fatal("expired key must not be advertised")
	}
	if r := h.do("GET", "/v1/recipients/me/pgp-key", tok, nil); r.status != 503 {
		t.Fatalf("expired key must not be served for e2e: %d", r.status)
	}
}

func TestRecipientChangesApplyWithoutRestart(t *testing.T) {
	h := newHarness(t, testutil.Options{})
	ctx := context.Background()
	_, tok := h.agent("a", policy.Policy{
		Recipients: ptr([]string{"me", "ops", "pager"}), Services: ptr([]string{policy.SvcEncrypt, policy.SvcE2E}),
	})
	capsFor := func() map[string]map[string]any {
		t.Helper()
		out := map[string]map[string]any{}
		for _, r := range h.do("GET", "/v1/capabilities", tok, nil).json(t)["recipients"].([]any) {
			m := r.(map[string]any)
			out[m["alias"].(string)] = m
		}
		return out
	}
	caps := capsFor()
	if _, ok := caps["pager"]; ok || caps["ops"]["encryption_available"] != false || len(caps) != 2 {
		t.Fatalf("before: %v", caps)
	}

	// Adding a key to ops: encryption becomes available and the new key is served.
	key := testutil.NewKey(t, "Ops", "ops@example.net")
	if _, err := h.reg.Update(ctx, "ops", recipients.Input{Address: "ops@example.net", Description: "Ops pager", PublicKeyArmor: testutil.ArmorPublic(t, key)}); err != nil {
		t.Fatal(err)
	}
	if capsFor()["ops"]["encryption_available"] != true {
		t.Fatal("new key must be advertised")
	}
	if r := h.do("GET", "/v1/recipients/ops/pgp-key", tok, nil); r.status != 200 || r.header.Get("X-Email-Me-Key-Fingerprint") != pgp.Fingerprint(key) {
		t.Fatalf("new key must be served: %d %v", r.status, r.header)
	}
	enc := map[string]any{"to": []string{"ops"}, "subject": "s", "body": map[string]any{"text": "b"}, "options": map[string]any{"encrypt": "pgp"}}
	if r := h.do("POST", "/v1/messages", tok, enc); r.status != 200 {
		t.Fatalf("encrypted send to ops: %d %s", r.status, r.body)
	}

	// A recipient created while the agent's policy already names it becomes usable.
	if _, err := h.reg.Create(ctx, recipients.Input{Alias: "pager", Address: "pager@example.net", Description: "Pager"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := capsFor()["pager"]; !ok {
		t.Fatal("created recipient must be advertised")
	}
	if r := h.do("POST", "/v1/messages", tok, msgText("pager")); r.status != 200 || h.env.SMTP.Last(t).To[0] != "pager@example.net" {
		t.Fatalf("send to new recipient: %d %s", r.status, r.body)
	}

	// Deleting ops: it disappears and sends to it are refused.
	if err := h.reg.Delete(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if _, ok := capsFor()["ops"]; ok {
		t.Fatal("deleted recipient must not be advertised")
	}
	if r := h.do("POST", "/v1/messages", tok, msgText("ops")); r.status != 403 || r.code(t) != "recipient_not_allowed" {
		t.Fatalf("send to deleted recipient: %d %s", r.status, r.body)
	}
	if r := h.do("GET", "/v1/recipients/ops/pgp-key", tok, nil); r.status != 403 || r.code(t) != "recipient_not_allowed" {
		t.Fatalf("key of deleted recipient: %d", r.status)
	}
}

func msgText(to string) map[string]any {
	return map[string]any{"to": []string{to}, "subject": "s", "body": map[string]any{"text": "b"}}
}
