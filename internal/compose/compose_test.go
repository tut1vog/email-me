package compose

import (
	"bytes"
	"io"
	"mime"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-pgpmail"

	"github.com/tut1vog/email-me/internal/testutil"
)

func baseMessage() *Message {
	return &Message{
		FromName: "bench via email-me", FromAddr: "gateway@example.com",
		To: []string{"me@example.com"}, Subject: "[bench] Results ✓", OuterSubject: "[bench] Encrypted message",
		Agent: "bench", AgentID: "ag_1", TokenID: "tok1", MessageID: NewMessageID(),
		Date: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), Text: "Hello\nworld",
	}
}

func parse(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not a valid RFC 5322 message: %v\n%s", err, raw)
	}
	return m
}

func checkLines(t *testing.T, raw []byte) {
	t.Helper()
	for i, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatalf("line %d exceeds 998 octets", i)
		}
		if bytes.ContainsAny(line, "\r\n") {
			t.Fatalf("bare CR or LF in line %d", i)
		}
	}
}

func TestPlainTextMessage(t *testing.T) {
	m := baseMessage()
	m.Thread = "nightly"
	m.Priority = "high"
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	checkLines(t, raw)
	msg := parse(t, raw)
	h := msg.Header
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(h.Get("Subject"))
	if subj != "[bench] Results ✓" {
		t.Fatalf("subject = %q", subj)
	}
	from, err := mail.ParseAddress(h.Get("From"))
	if err != nil || from.Name != "bench via email-me" || from.Address != "gateway@example.com" {
		t.Fatalf("from = %v %v", from, err)
	}
	for k, want := range map[string]string{
		"To": "me@example.com", "X-Email-Me-Agent": "bench", "X-Email-Me-Token-Id": "tok1",
		"Auto-Submitted": "auto-generated", "Importance": "high", "X-Priority": "1", "MIME-Version": "1.0",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	root := "<" + ThreadRoot("ag_1", "nightly") + ">"
	if h.Get("In-Reply-To") != root || h.Get("References") != root {
		t.Fatal("threading headers missing")
	}
	if h.Get("Reply-To") != "" {
		t.Fatal("no Reply-To")
	}
	e, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(e.Body)
	if strings.ReplaceAll(string(body), "\r\n", "\n") != "Hello\nworld\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestMarkdownWithAttachments(t *testing.T) {
	m := baseMessage()
	html, err := RenderMarkdown("## Results\n\n| a | b |\n|---|--:|\n| 1 | 2 |\n\n<script>alert(1)</script>\n\n![x](https://tracker.example/p.png)\n\n[link](https://example.com)")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script", "<img", "tracker.example"} {
		if strings.Contains(html, bad) {
			t.Fatalf("sanitizer let %q through: %s", bad, html)
		}
	}
	for _, good := range []string{"<h2>", "<table>", `align="right"`, `href="https://example.com"`, `noreferrer`} {
		if !strings.Contains(html, good) {
			t.Errorf("expected %q in %s", good, html)
		}
	}
	m.Text, m.HTML = "## Results", html
	m.Attachments = []Attachment{
		{Filename: "results.csv", ContentType: "text/csv", Data: []byte("a,b\n1,2\n")},
		{Filename: "résumé.bin", ContentType: "application/octet-stream", Data: bytes.Repeat([]byte{0xff, 0x00}, 200)},
	}
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	checkLines(t, raw)
	mr, err := gomail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var sawText, sawHTML bool
	var files []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch h := p.Header.(type) {
		case *gomail.InlineHeader:
			ct, _, _ := h.ContentType()
			b, _ := io.ReadAll(p.Body)
			if ct == "text/plain" {
				sawText = strings.Contains(string(b), "## Results")
			}
			if ct == "text/html" {
				sawHTML = strings.Contains(string(b), "<h2>Results</h2>") && strings.Contains(string(b), "<style>")
			}
		case *gomail.AttachmentHeader:
			name, _ := h.Filename()
			b, _ := io.ReadAll(p.Body)
			files = append(files, name)
			if name == "results.csv" && string(b) != "a,b\n1,2\n" {
				t.Fatalf("attachment corrupted: %q", b)
			}
			if name == "résumé.bin" && len(b) != 400 {
				t.Fatalf("binary attachment corrupted: %d bytes", len(b))
			}
		}
	}
	if !sawText || !sawHTML || strings.Join(files, ",") != "results.csv,résumé.bin" {
		t.Fatalf("text=%v html=%v files=%v", sawText, sawHTML, files)
	}
}

func TestHeaderInjectionIsImpossible(t *testing.T) {
	m := baseMessage()
	m.Subject = CleanHeaderText("hi\r\nBcc: victim@example.com\r\n\r\nbody", 255)
	m.Agent = "bench\r\nX-Evil: 1" // defense in depth: writer strips CR/LF too
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	msg := parse(t, raw)
	if msg.Header.Get("Bcc") != "" || msg.Header.Get("X-Evil") != "" {
		t.Fatalf("header injection succeeded:\n%s", raw)
	}
}

func TestCleaners(t *testing.T) {
	if got := CleanHeaderText("  a\tb\x00c\x1b  ", 255); got != "a bc" {
		t.Fatalf("%q", got)
	}
	if got := CleanHeaderText(strings.Repeat("é", 300), 255); len([]rune(got)) != 255 {
		t.Fatal("must cap runes")
	}
	for in, want := range map[string]string{"../../etc/passwd": "passwd", `C:\x\y.txt`: "y.txt", "": "attachment", "..": "attachment", "a\r\nb.txt": "ab.txt"} {
		if got := CleanFilename(in); got != want {
			t.Errorf("CleanFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLongHeadersFold(t *testing.T) {
	m := baseMessage()
	m.Subject = strings.Repeat("長い件名 ", 60)
	m.To = []string{"a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com", "f@example.com"}
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	checkLines(t, raw)
	msg := parse(t, raw)
	dec := new(mime.WordDecoder)
	subj, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || strings.TrimSpace(subj) != strings.TrimSpace(m.Subject) {
		t.Fatalf("folded subject does not round-trip: %q %v", subj, err)
	}
	addrs, err := msg.Header.AddressList("To")
	if err != nil || len(addrs) != 6 {
		t.Fatalf("To round trip: %v %v", addrs, err)
	}
}

func TestSignedMessageHasProtectedHeaders(t *testing.T) {
	signer := testutil.NewKey(t, "bench via email-me", "gateway@example.com")
	m := baseMessage()
	m.Signer = signer
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	checkLines(t, raw)
	r, err := pgpmail.Read(bytes.NewReader(raw), openpgp.EntityList{signer}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := message.Read(r.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, e.Body)
	if r.MessageDetails.SignatureError != nil {
		t.Fatalf("signature: %v", r.MessageDetails.SignatureError)
	}
	if e.Header.Get("X-Email-Me-Agent") != "bench" || e.Header.Get("From") == "" || e.Header.Get("Message-Id") == "" {
		t.Fatalf("protected headers missing: %v", e.Header.Map())
	}
	if ct := e.Header.Get("Content-Type"); !strings.Contains(ct, `protected-headers="v1"`) && !strings.Contains(ct, "protected-headers=v1") {
		t.Fatalf("content type %q lacks protected-headers", ct)
	}
	outer := parse(t, raw)
	dec := new(mime.WordDecoder)
	subj, _ := dec.DecodeHeader(outer.Header.Get("Subject"))
	if subj != m.Subject {
		t.Fatal("signed-only messages keep the real outer subject")
	}
}

func TestEncryptedMessageHidesSubject(t *testing.T) {
	signer := testutil.NewKey(t, "bench via email-me", "gateway@example.com")
	rcpt := testutil.NewKey(t, "me", "me@example.com")
	m := baseMessage()
	m.Subject = "[bench] Secret quarterly numbers"
	m.Text = "the numbers are 42"
	m.Signer, m.EncryptTo = signer, []*openpgp.Entity{rcpt}
	raw, err := Build(m)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Secret quarterly")) || bytes.Contains(raw, []byte("numbers are 42")) {
		t.Fatal("plaintext subject or body leaked")
	}
	outer := parse(t, raw)
	if outer.Header.Get("Subject") != "[bench] Encrypted message" {
		t.Fatalf("outer subject = %q", outer.Header.Get("Subject"))
	}
	r, err := pgpmail.Read(bytes.NewReader(raw), openpgp.EntityList{rcpt, signer}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := message.Read(r.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(e.Body)
	if e.Header.Get("Subject") != "[bench] Secret quarterly numbers" || !strings.Contains(string(b), "numbers are 42") {
		t.Fatalf("inner entity wrong: %v %q", e.Header.Map(), b)
	}
	if !r.MessageDetails.IsSigned || r.MessageDetails.SignatureError != nil {
		t.Fatalf("inner signature: %v", r.MessageDetails.SignatureError)
	}
}

func TestThreadRootDeterministic(t *testing.T) {
	a := ThreadRoot("ag_1", "nightly")
	if a != ThreadRoot("ag_1", "nightly") || a == ThreadRoot("ag_2", "nightly") || a == ThreadRoot("ag_1", "weekly") {
		t.Fatal("thread root must be deterministic per agent and key")
	}
	if !strings.HasSuffix(a, "@"+MessageIDDomain) || !strings.HasPrefix(a, "thread-") {
		t.Fatal(a)
	}
}

func TestHTMLToText(t *testing.T) {
	got := HTMLToText(`<h1>Title</h1><p>Hello <b>world</b> <a href="https://x.example">link</a></p><ul><li>one</li><li>two</li></ul><pre>  keep   spaces</pre><style>.x{}</style>`)
	for _, want := range []string{"Title", "Hello world link <https://x.example>", "- one", "- two", "  keep   spaces"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, ".x{}") {
		t.Error("style content leaked")
	}
}
