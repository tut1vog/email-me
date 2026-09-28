package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/tut1vog/email-me/internal/compose"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/idempotency"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/upstream"
)

type sendRequest struct {
	To             []string          `json:"to"`
	Subject        *string           `json:"subject"`
	Body           sendBody          `json:"body"`
	Attachments    []attachmentInput `json:"attachments"`
	Options        sendOptions       `json:"options"`
	IdempotencyKey string            `json:"idempotency_key"`
}

type sendBody struct {
	Text       *string `json:"text"`
	Markdown   *string `json:"markdown"`
	HTML       *string `json:"html"`
	PGPMessage *string `json:"pgp_message"`
}

type attachmentInput struct {
	Filename      string `json:"filename"`
	ContentType   string `json:"content_type"`
	ContentBase64 string `json:"content_base64"`
}

type sendOptions struct {
	Encrypt  string `json:"encrypt"`
	Sign     *bool  `json:"sign"`
	Thread   string `json:"thread"`
	Priority string `json:"priority"`
}

type sendResponse struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	Encrypted        bool   `json:"encrypted"`
	Signed           bool   `json:"signed"`
	IdempotentReplay bool   `json:"idempotent_replay,omitempty"`
}

const (
	encNone = "none"
	encPGP  = "pgp"
	encE2E  = "e2e"

	maxSubjectRunes = 255
	maxKeyLen       = 200
)

// prepared is a fully authorized message plus its audit metadata.
type prepared struct {
	msg        *compose.Message
	aliases    []string
	services   []string
	size       int64
	nAttach    int
	encrypted  bool
	signed     bool
	fpr        string
	subject    string
	recipients []string
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	entry := &store.AuditEntry{
		AgentID: c.agent.ID, TokenID: c.token.ID, SourceIP: c.ip.String(), Transport: c.transport,
	}
	fail := func(e *apiError) {
		entry.Status = store.StatusRejected
		if e.Code == CodeUpstreamFailed || e.Code == CodeInternal {
			entry.Status = store.StatusFailed
		}
		entry.ErrorCode = e.Code
		entry.UpstreamCode = e.UpstreamCode
		s.Audit.Record(r.Context(), entry)
		writeError(w, e)
	}

	done, ok := s.acquireSend(c.agent.ID)
	if !ok {
		e := newErr(http.StatusTooManyRequests, CodeRateLimited,
			"Too many concurrent send requests from this agent (at most %d at a time). Wait for your other sends to finish, then retry after 1 second.", maxConcurrentSends).
			with("retry_after_seconds", 1)
		e.RetryAfter = 1
		fail(e)
		return
	}
	defer done()

	limit := c.policy.MaxMessageBytes*4/3 + 64<<10
	req, e := decodeSend(http.MaxBytesReader(w, r.Body, limit), c.policy.MaxMessageBytes)
	if e != nil {
		fail(e)
		return
	}

	var finish func(*idempotency.Result)
	if req.IdempotencyKey != "" {
		if len(req.IdempotencyKey) > maxKeyLen {
			fail(newErr(http.StatusUnprocessableEntity, CodeValidation, "idempotency_key must be at most %d characters.", maxKeyLen))
			return
		}
		var cached *idempotency.Result
		cached, finish = s.idem.Begin(c.token.ID, req.IdempotencyKey)
		if cached != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(cached.Status)
			w.Write(cached.Body)
			return
		}
		defer finish(nil) // released unless a success was cached below
	}

	p, e := s.prepare(r.Context(), c, req)
	if p != nil {
		entry.Recipients, entry.Services, entry.SizeBytes, entry.AttachmentCount = p.aliases, p.services, p.size, p.nAttach
		entry.Encrypted, entry.Signed, entry.SigningKeyFpr, entry.Subject = p.encrypted, p.signed, p.fpr, p.subject
	}
	if e != nil {
		fail(e)
		return
	}

	release, ok, wait, err := s.Limiter.Reserve(r.Context(), c.agent.ID, c.policy.RateLimit)
	if err != nil {
		fail(s.internalErr("rate limit check", err))
		return
	}
	if !ok {
		secs := int((wait + time.Second - 1) / time.Second)
		e := newErr(http.StatusTooManyRequests, CodeRateLimited,
			"Rate limit reached (%d per hour, %d per day). Retry after %d seconds.", c.policy.RateLimit.PerHour, c.policy.RateLimit.PerDay, secs).
			with("retry_after_seconds", secs)
		e.RetryAfter = secs
		fail(e)
		return
	}
	defer release() // after the audit row is written, so counts stay exact

	raw, err := compose.Build(p.msg)
	if err != nil {
		fail(s.internalErr("composing message", err))
		return
	}
	entry.MessageID = p.msg.MessageID

	// Delivery is not tied to the client connection: if the agent disconnects
	// mid-send, the outcome is still recorded (and cached for idempotent retries).
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.Config.Upstream.SMTP.Timeout.D()+5*time.Second)
	defer cancel()
	if err := s.Sender.Send(sendCtx, s.Config.Upstream.From, p.recipients, raw); err != nil {
		code := 0
		var ue *upstream.Error
		if errors.As(err, &ue) {
			code = ue.Code
		}
		s.Log.Warn("upstream delivery failed", "agent", c.agent.Name, "err", err)
		e := newErr(http.StatusBadGateway, CodeUpstreamFailed,
			"The upstream mail server did not accept the message. Retry later with the same idempotency_key.")
		if code != 0 {
			e = e.with("upstream_code", code)
		}
		e.UpstreamCode = code
		fail(e)
		return
	}

	entry.Status = store.StatusSent
	s.Audit.Record(r.Context(), entry)

	resp := sendResponse{ID: strings.TrimSuffix(p.msg.MessageID, "@"+compose.MessageIDDomain), Status: "sent", Encrypted: p.encrypted, Signed: p.signed}
	if finish != nil {
		replay := resp
		replay.IdempotentReplay = true
		body, _ := json.Marshal(replay)
		finish(&idempotency.Result{Status: http.StatusOK, Body: append(body, '\n')})
	}
	writeJSON(w, http.StatusOK, resp)
}

func decodeSend(body io.Reader, maxBytes int64) (*sendRequest, *apiError) {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var req sendRequest
	if err := dec.Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, newErr(http.StatusRequestEntityTooLarge, CodeTooLarge,
				"Request body is too large; the message limit is %d bytes (body plus decoded attachments).", maxBytes).with("limit", maxBytes)
		}
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, "Request body is not valid JSON for this endpoint: %s. See /openapi.json for the schema.", jsonErrText(err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, "Request body must contain a single JSON object.")
	}
	if len(req.To) == 0 {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, "\"to\" must list at least one recipient alias (see GET /v1/capabilities).")
	}
	n := 0
	for _, f := range []*string{req.Body.Text, req.Body.Markdown, req.Body.HTML, req.Body.PGPMessage} {
		if f != nil {
			n++
		}
	}
	if n != 1 {
		return nil, newErr(http.StatusBadRequest, CodeInvalidRequest, "\"body\" must contain exactly one of text, markdown, html, pgp_message.")
	}
	return &req, nil
}

func jsonErrText(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return fmt.Sprintf("syntax error at byte %d", se.Offset)
	case errors.As(err, &te):
		return fmt.Sprintf("field %q must be %s", te.Field, te.Type)
	case errors.Is(err, io.EOF):
		return "empty body"
	}
	return strings.TrimPrefix(err.Error(), "json: ")
}

func (s *Server) internalErr(what string, err error) *apiError {
	s.Log.Error(what, "err", err)
	return newErr(http.StatusInternalServerError, CodeInternal, "Internal error. Retry later; if it persists, tell your operator.")
}

// prepare validates the request, applies the agent's policy in the order
// recipients → services → size/type → encryption → signing, and builds the
// message. It returns partial audit metadata even on failure.
func (s *Server) prepare(ctx context.Context, c *caller, req *sendRequest) (*prepared, *apiError) {
	pol := c.policy
	p := &prepared{}

	// --- syntax ---------------------------------------------------------
	for _, a := range req.To {
		if !config.AliasPattern.MatchString(a) {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "Recipient %q is not a valid alias. Use an alias from GET /v1/capabilities, not an email address.", a)
		}
		if !slices.Contains(p.aliases, a) {
			p.aliases = append(p.aliases, a)
		}
	}
	enc := req.Options.Encrypt
	if enc == "" {
		enc = encNone
	}
	if enc != encNone && enc != encPGP && enc != encE2E {
		return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "options.encrypt must be none, pgp or e2e.")
	}
	prio := req.Options.Priority
	if prio == "" {
		prio = "normal"
	}
	if prio != "low" && prio != "normal" && prio != "high" {
		return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "options.priority must be low, normal or high.")
	}
	thread := ""
	if req.Options.Thread != "" {
		if len(req.Options.Thread) > 200 {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "options.thread must be at most 200 characters.")
		}
		thread = req.Options.Thread
	}

	var subject string
	if enc == encE2E {
		if req.Subject != nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation,
				"Omit \"subject\" with e2e encryption: the visible subject would leak to the mail provider. Put the subject inside your encrypted MIME entity.")
		}
		if req.Body.PGPMessage == nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "options.encrypt e2e requires body.pgp_message (your ASCII-armored ciphertext).")
		}
		if len(req.Attachments) > 0 {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "Attachments are not allowed with e2e encryption; put them inside your encrypted MIME entity.")
		}
		if req.Options.Sign != nil && *req.Options.Sign {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation,
				"e2e messages cannot be signed by the gateway (it cannot read the content). Omit options.sign, or use encrypt \"pgp\" to get a signed, encrypted message.")
		}
	} else {
		if req.Body.PGPMessage != nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "body.pgp_message is only valid with options.encrypt \"e2e\".")
		}
		if req.Subject == nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "\"subject\" is required.")
		}
		subject = compose.CleanHeaderText(*req.Subject, maxSubjectRunes)
		if subject == "" {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "\"subject\" must not be empty.")
		}
	}

	var atts []compose.Attachment
	for i, a := range req.Attachments {
		if strings.TrimSpace(a.Filename) == "" {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "attachments[%d].filename is required.", i)
		}
		mt, _, err := mime.ParseMediaType(a.ContentType)
		if err != nil || !strings.Contains(mt, "/") {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "attachments[%d].content_type %q is not a valid media type (e.g. text/csv).", i, a.ContentType)
		}
		data, err := decodeBase64(a.ContentBase64)
		if err != nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "attachments[%d].content_base64 is not valid standard base64.", i)
		}
		atts = append(atts, compose.Attachment{Filename: compose.CleanFilename(a.Filename), ContentType: mt, Data: data})
	}
	p.nAttach = len(atts)

	// --- recipients -----------------------------------------------------
	for _, a := range p.aliases {
		if _, ok := s.Config.Recipients[a]; !ok || !pol.AllowsRecipient(a) {
			return p, newErr(http.StatusForbidden, CodeRecipientNotAllow,
				"Recipient alias %q is not permitted for this agent. Allowed: %s.", a, listOrNone(pol.Recipients)).
				with("allowed", nonNil(pol.Recipients))
		}
	}

	// --- services -------------------------------------------------------
	need := []string{}
	switch {
	case req.Body.Markdown != nil:
		need = append(need, policy.SvcMarkdown)
	case req.Body.HTML != nil:
		need = append(need, policy.SvcHTML)
	}
	if len(atts) > 0 {
		need = append(need, policy.SvcAttachments)
	}
	if thread != "" {
		need = append(need, policy.SvcThread)
	}
	if prio == "high" {
		need = append(need, policy.SvcPriority)
	}
	switch enc {
	case encPGP:
		need = append(need, policy.SvcEncrypt)
	case encE2E:
		need = append(need, policy.SvcE2E)
	}
	if req.Options.Sign != nil && *req.Options.Sign {
		need = append(need, policy.SvcSign)
	}
	for _, svc := range need {
		if !pol.HasService(svc) {
			return p, newErr(http.StatusForbidden, CodeServiceNotAllowed,
				"This agent is not allowed to use the %q service. Allowed services: %s.", svc, listOrNone(pol.Services)).
				with("service", svc).with("allowed", nonNil(pol.Services))
		}
	}
	p.services = need
	if enc == encE2E && pol.RequireSigning {
		return p, newErr(http.StatusForbidden, CodeSigningRequired,
			"This agent's policy requires every message to be signed, and e2e messages cannot be signed (the gateway cannot read them). Use options.encrypt \"pgp\" instead, or ask your operator to set require_signing to false for this agent.")
	}

	// --- size and type --------------------------------------------------
	var size int64
	for _, f := range []*string{req.Body.Text, req.Body.Markdown, req.Body.HTML, req.Body.PGPMessage} {
		if f != nil {
			size += int64(len(*f))
		}
	}
	for _, a := range atts {
		size += int64(len(a.Data))
	}
	p.size = size
	if size > pol.MaxMessageBytes {
		return p, newErr(http.StatusRequestEntityTooLarge, CodeTooLarge,
			"Message is %d bytes; the limit is %d bytes (body plus decoded attachments).", size, pol.MaxMessageBytes).with("limit", pol.MaxMessageBytes)
	}
	if len(atts) > pol.MaxAttachments {
		return p, newErr(http.StatusRequestEntityTooLarge, CodeTooLarge,
			"Message has %d attachments; the limit is %d.", len(atts), pol.MaxAttachments).with("max_attachments", pol.MaxAttachments)
	}
	for _, a := range atts {
		if !pol.AllowsAttachmentType(a.ContentType) {
			return p, newErr(http.StatusUnsupportedMediaType, CodeAttachmentType,
				"Attachment %q has type %s, which is not allowed. Allowed types: %s.", a.Filename, a.ContentType, listOrNone(pol.AllowedAttachmentTypes)).
				with("allowed", nonNil(pol.AllowedAttachmentTypes))
		}
	}

	// --- encryption -----------------------------------------------------
	var mustEncrypt []string
	for _, a := range p.aliases {
		if pol.RequireEncryption || s.Config.Recipients[a].RequireEncryption {
			mustEncrypt = append(mustEncrypt, a)
		}
	}
	if len(mustEncrypt) > 0 && enc == encNone {
		return p, newErr(http.StatusForbidden, CodeEncryptionRequired,
			"Messages to %s must be encrypted. Set options.encrypt to \"pgp\".", strings.Join(mustEncrypt, ", ")).
			with("aliases", mustEncrypt)
	}
	var encryptTo []*openpgp.Entity
	var e2eArmor string
	switch enc {
	case encPGP:
		for _, a := range p.aliases {
			rc := s.Config.Recipients[a]
			k := rc.PublicKey
			if k == nil {
				return p, newErr(http.StatusUnprocessableEntity, CodeValidation,
					"Recipient %q has no PGP key configured, so options.encrypt \"pgp\" is unavailable for it (see encryption_available in GET /v1/capabilities).", a).
					with("alias", a)
			}
			if !rc.KeyUsable(s.now()) {
				return p, newErr(http.StatusServiceUnavailable, CodeEncryptionUnavail,
					"Recipient %q's PGP key has expired or been revoked, so nothing can be encrypted to it. Tell your operator to update the key; do not retry.", a).
					with("alias", a)
			}
			encryptTo = append(encryptTo, k)
		}
		p.encrypted = true
	case encE2E:
		clean, err := pgp.NormalizeCiphertext(*req.Body.PGPMessage)
		if err != nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "body.pgp_message is not valid ciphertext: %v.", err)
		}
		e2eArmor = clean
		p.encrypted = true
	}

	// --- signing --------------------------------------------------------
	sign := false
	switch {
	case enc == encE2E:
		// Never signed; require_signing was rejected above.
	case pol.RequireSigning:
		if req.Options.Sign != nil && !*req.Options.Sign {
			return p, newErr(http.StatusForbidden, CodeSigningRequired,
				"This agent's policy requires every message to be signed; options.sign cannot be false. Omit options.sign.")
		}
		sign = true
	case req.Options.Sign != nil:
		sign = *req.Options.Sign
	default:
		avail, _ := s.signingStatus(ctx, c.agent.ID)
		sign = avail && pol.HasService(policy.SvcSign)
	}
	var signer *openpgp.Entity
	if sign {
		var err error
		var fpr string
		signer, fpr, err = s.Keys.Signer(ctx, c.agent.ID)
		if err != nil {
			msg := "Signing is unavailable: the gateway could not load this agent's signing key. Tell your operator; do not retry."
			switch {
			case errors.Is(err, keys.ErrNotConfigured):
				msg = "Signing is unavailable: signing is not configured on this gateway. Tell your operator; do not retry."
			case errors.Is(err, keys.ErrExpired):
				msg = "Signing is unavailable: this agent's signing key has expired. Ask your operator to rotate it; do not retry."
			case errors.Is(err, keys.ErrNoKey):
				msg = "Signing is unavailable: this agent has no signing key. Tell your operator; do not retry."
			default:
				s.Log.Error("loading signing key", "agent", c.agent.Name, "err", err)
			}
			return p, newErr(http.StatusServiceUnavailable, CodeSigningUnavailable, "%s", msg)
		}
		p.fpr = fpr
		if !slices.Contains(p.services, policy.SvcSign) {
			p.services = append(p.services, policy.SvcSign)
		}
	}
	p.signed = sign

	// --- build ----------------------------------------------------------
	prefix := pol.Prefix(c.agent.Name)
	msg := &compose.Message{
		FromName:     s.Config.FromName(c.agent.Name),
		FromAddr:     s.Config.Upstream.From,
		Subject:      compose.CleanHeaderText(prefix+subject, 998),
		OuterSubject: compose.CleanHeaderText(prefix+"Encrypted message", 998),
		Agent:        c.agent.Name,
		AgentID:      c.agent.ID,
		TokenID:      c.token.ID,
		MessageID:    compose.NewMessageID(),
		Date:         s.now(),
		Thread:       thread,
		Priority:     prio,
		Attachments:  atts,
		Signer:       signer,
		EncryptTo:    encryptTo,
	}
	switch {
	case req.Body.Text != nil:
		msg.Text = *req.Body.Text
	case req.Body.Markdown != nil:
		html, err := compose.RenderMarkdown(*req.Body.Markdown)
		if err != nil {
			return p, newErr(http.StatusUnprocessableEntity, CodeValidation, "body.markdown could not be rendered: %v.", err)
		}
		msg.Text, msg.HTML = *req.Body.Markdown, html
	case req.Body.HTML != nil:
		clean := compose.SanitizeHTML(*req.Body.HTML)
		msg.HTML, msg.Text = clean, compose.HTMLToText(clean)
	case req.Body.PGPMessage != nil:
		msg.E2E = e2eArmor // re-armored by the gateway; never the agent's raw text
	}
	for _, a := range p.aliases {
		p.recipients = append(p.recipients, s.Config.Recipients[a].Address)
	}
	msg.To = p.recipients
	p.msg = msg
	p.subject = subject
	return p, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}

func fingerprintOf(r *config.Recipient) string { return pgp.Fingerprint(r.PublicKey) }
