// Package compose turns a validated send request into an RFC 5322 message,
// optionally signed and/or encrypted as PGP/MIME. Everything happens in memory.
package compose

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/tut1vog/email-me/internal/ids"
	"github.com/tut1vog/email-me/internal/pgp"
)

// MessageIDDomain is the right-hand side of generated Message-IDs.
const MessageIDDomain = "email-me"

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Message is a fully authorized message ready to build.
type Message struct {
	FromName string
	FromAddr string
	To       []string // real addresses
	Subject  string   // final subject, prefix included
	// OuterSubject replaces Subject in the visible header when the message is
	// encrypted (the real subject travels in the protected headers).
	OuterSubject string
	Agent        string
	AgentID      string
	TokenID      string
	MessageID    string // without angle brackets
	Date         time.Time
	Thread       string // optional thread key
	Priority     string // low | normal | high

	Text        string // plain text (for markdown: the markdown source)
	HTML        string // sanitized body HTML (optional)
	Attachments []Attachment

	E2E string // ciphertext re-armored by pgp.NormalizeCiphertext (mutually exclusive with Text/HTML)

	Signer    *openpgp.Entity
	EncryptTo []*openpgp.Entity
}

// NewMessageID returns a fresh message ID (without brackets).
func NewMessageID() string { return "msg_" + ids.Random(20) + "@" + MessageIDDomain }

// ThreadRoot returns the deterministic root Message-ID for an agent's thread key.
func ThreadRoot(agentID, key string) string {
	sum := sha256.Sum256([]byte(agentID + ":" + key))
	return "thread-" + hex.EncodeToString(sum[:])[:20] + "@" + MessageIDDomain
}

// CleanHeaderText strips control characters (including CR/LF) and caps length.
func CleanHeaderText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

// CleanFilename removes path components and control characters.
func CleanFilename(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	if i := strings.LastIndex(s, "/"); i >= 0 {
		s = s[i+1:]
	}
	s = CleanHeaderText(s, 200)
	s = strings.Trim(s, ". ")
	if s == "" {
		s = "attachment"
	}
	return s
}

// Build renders the message.
func Build(m *Message) ([]byte, error) {
	if len(m.To) == 0 {
		return nil, errors.New("compose: no recipients")
	}
	outer, err := m.outerHeader()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer

	switch {
	case m.E2E != "":
		mp := pgp.WrapCiphertext(m.E2E)
		outer.add("Content-Type", mp.ContentType)
		outer.write(&out)
		out.Write(mp.Body)
		return out.Bytes(), nil

	case m.Signer != nil || len(m.EncryptTo) > 0:
		content, err := m.content(true)
		if err != nil {
			return nil, err
		}
		// Protected headers (draft-autocrypt-lamps-protected-headers): copied
		// into the signed/encrypted entity so they are covered by the signature
		// and the real subject is hidden when encrypted.
		var inner hdr
		inner.add("From", m.from())
		inner.add("To", strings.Join(m.To, ", "))
		inner.add("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
		inner.add("Date", m.Date.Format(time.RFC1123Z))
		inner.add("Message-ID", "<"+m.MessageID+">")
		inner.add("X-Email-Me-Agent", m.Agent)
		inner = append(inner, content.h...)
		var innerBytes bytes.Buffer
		inner.write(&innerBytes)
		innerBytes.Write(content.body)

		var mp *pgp.Multipart
		if len(m.EncryptTo) > 0 {
			mp, err = pgp.Encrypt(innerBytes.Bytes(), m.EncryptTo, m.Signer)
		} else {
			mp, err = pgp.Sign(innerBytes.Bytes(), m.Signer)
		}
		if err != nil {
			return nil, err
		}
		outer.add("Content-Type", mp.ContentType)
		outer.write(&out)
		out.Write(mp.Body)
		return out.Bytes(), nil

	default:
		content, err := m.content(false)
		if err != nil {
			return nil, err
		}
		outer = append(outer, content.h...)
		outer.write(&out)
		out.Write(content.body)
		return out.Bytes(), nil
	}
}

func (m *Message) from() string {
	return (&mail.Address{Name: m.FromName, Address: m.FromAddr}).String()
}

func (m *Message) outerHeader() (hdr, error) {
	var h hdr
	h.add("From", m.from())
	h.add("To", strings.Join(m.To, ", "))
	subject := m.Subject
	if (len(m.EncryptTo) > 0 || m.E2E != "") && m.OuterSubject != "" {
		subject = m.OuterSubject
	}
	h.add("Subject", mime.QEncoding.Encode("utf-8", subject))
	h.add("Date", m.Date.Format(time.RFC1123Z))
	h.add("Message-ID", "<"+m.MessageID+">")
	if m.Thread != "" {
		root := "<" + ThreadRoot(m.AgentID, m.Thread) + ">"
		h.add("In-Reply-To", root)
		h.add("References", root)
	}
	switch m.Priority {
	case "high":
		h.add("Importance", "high")
		h.add("X-Priority", "1")
	case "low":
		h.add("Importance", "low")
		h.add("X-Priority", "5")
	}
	h.add("Auto-Submitted", "auto-generated")
	h.add("X-Email-Me-Agent", m.Agent)
	if m.TokenID != "" {
		h.add("X-Email-Me-Token-Id", m.TokenID)
	}
	h.add("MIME-Version", "1.0")
	return h, nil
}

// entity is a MIME entity: header fields (without the terminating blank
// line) and an encoded body.
type entity struct {
	h    hdr
	body []byte
}

func (e entity) bytes() []byte {
	var b bytes.Buffer
	e.h.write(&b)
	b.Write(e.body)
	return b.Bytes()
}

func (m *Message) content(protected bool) (entity, error) {
	var body entity
	if m.HTML != "" {
		body = multipart("alternative", []entity{
			textPart("text/plain", m.Text),
			textPart("text/html", Document(m.HTML)),
		})
	} else {
		body = textPart("text/plain", m.Text)
	}
	if len(m.Attachments) > 0 {
		parts := []entity{body}
		for _, a := range m.Attachments {
			parts = append(parts, attachmentPart(a))
		}
		body = multipart("mixed", parts)
	}
	if protected {
		ct := body.h.get("Content-Type")
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil {
			return entity{}, err
		}
		params["protected-headers"] = "v1"
		body.h.set("Content-Type", mime.FormatMediaType(mt, params))
	}
	return body, nil
}

func textPart(mediaType, s string) entity {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write([]byte(s))
	w.Close()
	body := buf.Bytes()
	if !bytes.HasSuffix(body, []byte("\r\n")) {
		body = append(body, '\r', '\n')
	}
	var h hdr
	h.add("Content-Type", mime.FormatMediaType(mediaType, map[string]string{"charset": "utf-8"}))
	h.add("Content-Transfer-Encoding", "quoted-printable")
	return entity{h: h, body: body}
}

func attachmentPart(a Attachment) entity {
	mt, params, err := mime.ParseMediaType(a.ContentType)
	if err != nil {
		mt, params = "application/octet-stream", map[string]string{}
	}
	params["name"] = a.Filename
	var h hdr
	h.add("Content-Type", mime.FormatMediaType(mt, params))
	h.add("Content-Transfer-Encoding", "base64")
	h.add("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))

	enc := base64.StdEncoding.EncodeToString(a.Data)
	var body bytes.Buffer
	for len(enc) > 76 {
		body.WriteString(enc[:76])
		body.WriteString("\r\n")
		enc = enc[76:]
	}
	body.WriteString(enc)
	body.WriteString("\r\n")
	return entity{h: h, body: body.Bytes()}
}

func multipart(subtype string, parts []entity) entity {
	b := "=_email-me_" + ids.Random(24)
	var body bytes.Buffer
	for _, p := range parts {
		fmt.Fprintf(&body, "--%s\r\n", b)
		body.Write(p.bytes())
		body.WriteString("\r\n")
	}
	fmt.Fprintf(&body, "--%s--\r\n", b)
	var h hdr
	h.add("Content-Type", mime.FormatMediaType("multipart/"+subtype, map[string]string{"boundary": b}))
	return entity{h: h, body: body.Bytes()}
}

// hdr is an ordered list of header fields.
type hdr []field

type field struct{ k, v string }

func (h *hdr) add(k, v string) { *h = append(*h, field{k, v}) }

func (h hdr) get(k string) string {
	for _, f := range h {
		if strings.EqualFold(f.k, k) {
			return f.v
		}
	}
	return ""
}

func (h hdr) set(k, v string) {
	for i := range h {
		if strings.EqualFold(h[i].k, k) {
			h[i].v = v
			return
		}
	}
}

// write emits the fields folded at whitespace to ≤76 columns where possible,
// followed by the blank line that ends a header block.
func (h hdr) write(b *bytes.Buffer) {
	for _, f := range h {
		v := strings.NewReplacer("\r", "", "\n", "").Replace(f.v) // defense in depth against header injection
		b.WriteString(fold(f.k + ": " + v))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
}

func fold(line string) string {
	const limit = 76
	if len(line) <= limit {
		return line
	}
	var out strings.Builder
	for len(line) > limit {
		// Fold at the last space within the limit (not in the field name).
		cut := strings.LastIndexByte(line[:limit], ' ')
		if cut <= 0 {
			// No space before the limit: fold at the next space, if any.
			next := strings.IndexByte(line[limit:], ' ')
			if next < 0 {
				break
			}
			cut = limit + next
		}
		out.WriteString(line[:cut])
		out.WriteString("\r\n")
		line = line[cut:] // keep the space as folding whitespace
	}
	out.WriteString(line)
	return out.String()
}
