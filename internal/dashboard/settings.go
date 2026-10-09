package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/tut1vog/email-me/internal/api/docs"
	"github.com/tut1vog/email-me/internal/compose"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/units"
)

// The Settings page edits the managed settings: one form per card, each
// saving the card merged into the saved settings. A save applies at once;
// the forms show the settings in effect.

// settingsForms holds every card's form values as text, so a rejected
// submission can be shown again exactly as typed.
type settingsForms struct {
	Upstream upstreamForm
	API      apiForm
	Policy   policyForm
	Audit    auditForm
	Signing  signingForm
}

type upstreamForm struct {
	Host, Port, Security, Username, Timeout, From, FromNameTemplate string
}

type apiForm struct {
	PublicURL, Docs, TrustedProxies string
	External                        bool
}

type auditForm struct {
	RetentionDays string
	LogSubject    bool
}

type signingForm struct{ KeyValidity string }

// defaultPort is the port ApplyManagedDefaults picks for a security mode.
func defaultPort(security string) int {
	switch security {
	case "tls":
		return 465
	case "none":
		return 25
	}
	return 587
}

// durationText shows a duration the way an operator writes it: "12h", not
// "12h0m0s".
func durationText(d units.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// parseDuration reads an optional duration field; blank means the default.
func parseDuration(label, v string, errs *[]string) units.Duration {
	if v = strings.TrimSpace(v); v == "" {
		return 0
	}
	d, err := units.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, label+": "+err.Error())
	}
	return d
}

// parseInt reads an optional number field; blank means the default.
func parseInt(label, v string, errs *[]string) int {
	if v = strings.TrimSpace(v); v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, label+" must be a number")
	}
	return n
}

func (s *Server) builtinPolicy() policy.Effective { return policy.Builtin(s.Keys.Enabled()) }

// settingsForms fills every card from the settings in cfg.
func (s *Server) settingsForms(cfg *config.Config) settingsForms {
	cur := cfg.Managed()
	u := cur.Upstream
	f := settingsForms{
		Upstream: upstreamForm{
			Host: u.SMTP.Host, Security: u.SMTP.Security, Username: u.SMTP.Username, Timeout: durationText(u.SMTP.Timeout),
			From: u.From, FromNameTemplate: u.FromNameTemplate,
		},
		API: apiForm{
			PublicURL: cur.API.PublicURL, Docs: cur.API.Docs,
			TrustedProxies: strings.Join(cur.API.TrustedProxies, ", "), External: cur.API.ExternalTransportEncryption,
		},
		Policy:  formFromPolicy(cur.Defaults.Policy, cur.Defaults.Policy.Apply(s.builtinPolicy())),
		Audit:   auditForm{RetentionDays: strconv.Itoa(cur.Audit.RetentionDays), LogSubject: cur.Audit.LogSubject},
		Signing: signingForm{KeyValidity: durationText(cur.Signing.KeyValidity)},
	}
	if u.SMTP.Port != 0 && u.SMTP.Port != defaultPort(u.SMTP.Security) {
		f.Upstream.Port = strconv.Itoa(u.SMTP.Port)
	}
	return f
}

// policyFormFromPost is the policy editor as submitted, for showing a
// rejected default policy again.
func policyFormFromPost(f url.Values) policyForm {
	on := func(k string) bool { return f.Get(k) == "on" }
	return policyForm{
		OvRecipients: on("ov_recipients"), Recipients: f["recipients"],
		OvServices: on("ov_services"), Services: f["services"],
		OvMaxBytes: on("ov_max_bytes"), MaxBytes: f.Get("max_bytes"),
		OvMaxAtt: on("ov_max_att"), MaxAtt: f.Get("max_att"),
		OvTypes: on("ov_types"), Types: f.Get("types"),
		OvRate: on("ov_rate"), PerHour: f.Get("per_hour"), PerDay: f.Get("per_day"),
		OvPrefix: on("ov_prefix"), Prefix: f.Get("prefix"),
		ReqEnc: f.Get("require_encryption"), ReqSign: f.Get("require_signing"),
	}
}

// upstreamConfigured reports whether sends can work at all.
func upstreamConfigured(c *config.Config) bool {
	return c.Upstream.SMTP.Host != "" && c.Upstream.From != ""
}

// missingUpstreamNote names what c's upstream still lacks before agents can
// send, or is empty when nothing is missing.
func missingUpstreamNote(c *config.Config) string {
	switch noHost, noFrom := c.Upstream.SMTP.Host == "", c.Upstream.From == ""; {
	case noHost && noFrom:
		return "No SMTP host or From address is set, so agents cannot send yet."
	case noHost:
		return "No SMTP host is set, so agents cannot send yet."
	case noFrom:
		return "No From address is set, so agents cannot send yet."
	}
	return ""
}

// configWarnings are cfg's warnings that the Needs-attention list and the
// Settings page show as such. A missing upstream and an unsealed password
// are left out: they have their own notices.
func configWarnings(cfg *config.Config) []string {
	var out []string
	for _, w := range cfg.Warnings {
		if w == config.UpstreamNotConfigured || w == settings.PasswordUnsealed {
			continue
		}
		out = append(out, w)
	}
	return out
}

// upstreamAddr is the upstream server in c, for display.
func upstreamAddr(c *config.Config) string {
	if c.Upstream.SMTP.Host == "" {
		return "not configured"
	}
	return c.Upstream.SMTP.Addr()
}

func passwordState(p settings.PasswordState) string {
	switch p {
	case settings.Sealed:
		return "sealed"
	case settings.Unsealed:
		return "unsealed"
	case settings.Undecryptable:
		return "undecryptable"
	}
	return "none"
}

func (s *Server) lastSMTPCheck() *smtpStatus {
	s.smtpMu.Lock()
	defer s.smtpMu.Unlock()
	return s.smtpCheck
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	s.settingsPage(w, r, http.StatusOK, cfg, s.settingsForms(cfg))
}

// settingsPage renders the Settings page for cfg, with forms in the cards.
func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, status int, cfg *config.Config, forms settingsForms) {
	var master string
	if m := s.Keys.Master(); m != nil {
		master = pgp.Fingerprint(m)
	}
	s.renderStatus(w, r, status, "settings", "Settings", map[string]any{
		"Form": forms,
		"Policy": map[string]any{
			"Form": forms.Policy, "Defaults": s.builtinPolicy(),
			"Recipients": cfg.RecipientList(), "AllServices": policy.AllServices,
		},
		"SMTP":           s.lastSMTPCheck(),
		"Configured":     upstreamConfigured(cfg),
		"Upstream":       upstreamAddr(cfg),
		"Password":       passwordState(s.Settings.PasswordState()),
		"HasPassword":    s.Settings.HasPassword(),
		"Securities":     []string{"starttls", "tls", "none"},
		"Aliases":        cfg.Aliases(),
		"SigningEnabled": s.Keys.Enabled(),
		"MasterFpr":      master,
		"Warnings":       configWarnings(cfg),
		"Config":         cfg,
	})
}

// cardSave is one card's submission: apply copies it into the saved
// settings (returning parse problems) and keep puts the submitted form
// back for a re-render. after, if set, runs once the settings are saved
// and current, with the settings before and after the save and the keys
// that changed; it returns a note for the confirmation.
type cardSave struct {
	id, title string
	problems  []string
	warnings  []string
	password  settings.PasswordChange
	apply     func(*config.Settings) []string
	keep      func(*settingsForms)
	after     func(r *http.Request, prev, now config.Settings, changed []string) string
}

// passwordKey stands for the SMTP password, which DiffSettings does not
// compare, in the keys a save changed.
const passwordKey = "upstream.smtp.password"

// saveCard saves a card merged into the current settings, which applies
// it. Problems re-render the page (422) with the card as submitted;
// success redirects to the card.
func (s *Server) saveCard(w http.ResponseWriter, r *http.Request, c cardSave) {
	cfg := s.Config()
	prev := cfg.Managed()
	hadPassword := s.Settings.HasPassword()
	cur := prev.Clone()
	problems := append(c.problems, c.apply(&cur)...)
	var warnings []string
	if len(problems) == 0 {
		var err error
		warnings, err = s.Settings.Save(r.Context(), cur, c.password)
		var ve *config.ValidationError
		switch {
		case errors.As(err, &ve):
			problems = ve.Problems
		case errors.Is(err, settings.ErrFileChanged):
			problems = []string{err.Error()}
		case err != nil:
			s.fail(w, "saving settings", err)
			return
		}
	}
	if len(problems) > 0 {
		s.flash(r, "error", "%s not saved: %s.", c.title, strings.Join(problems, "; "))
		forms := s.settingsForms(cfg)
		c.keep(&forms)
		s.settingsPage(w, r, http.StatusUnprocessableEntity, cfg, forms)
		return
	}
	now := s.Config().Managed()
	changed := config.DiffSettings(prev, now)
	if pw := c.password; pw.Set && (pw.Value != prev.Upstream.SMTP.Password || hadPassword != (pw.Value != "")) {
		changed = append(changed, passwordKey)
		slices.Sort(changed)
	}
	msg := c.title + " saved and applied."
	if len(changed) == 0 {
		msg = c.title + " saved; nothing changed."
	}
	if c.after != nil {
		if note := c.after(r, prev, now, changed); note != "" {
			msg += " " + note
		}
	}
	// Warnings the previous settings already had are on the Needs-attention
	// list; a save only mentions new ones.
	for _, w := range append(warnings, c.warnings...) {
		if !slices.Contains(cfg.Warnings, w) && w != config.UpstreamNotConfigured {
			msg += " Note: " + w + "."
		}
	}
	s.Log.Info("settings saved", "card", c.id, "changed", changed)
	s.flash(r, "ok", "%s", msg)
	s.redirect(w, r, "/settings#"+c.id)
}

func (s *Server) saveUpstream(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	form := upstreamForm{
		Host: strings.TrimSpace(f.Get("host")), Port: strings.TrimSpace(f.Get("port")), Security: f.Get("security"),
		Username: strings.TrimSpace(f.Get("username")), Timeout: strings.TrimSpace(f.Get("timeout")),
		From: strings.TrimSpace(f.Get("from")), FromNameTemplate: f.Get("from_name_template"),
	}
	c := cardSave{id: "upstream", title: "Upstream SMTP settings", keep: func(fs *settingsForms) { fs.Upstream = form }, after: s.afterUpstream}
	switch pw, remove := f.Get("password"), f.Get("remove_password") == "on"; {
	case pw != "" && remove:
		c.problems = append(c.problems, "either enter a new password or remove the stored one, not both")
	case pw != "":
		c.password = settings.PasswordChange{Set: true, Value: pw}
	case remove:
		c.password = settings.PasswordChange{Set: true}
	}
	c.apply = func(cur *config.Settings) []string {
		var errs []string
		u := &cur.Upstream
		u.SMTP.Host, u.SMTP.Security, u.SMTP.Username = form.Host, form.Security, form.Username
		u.SMTP.Port = parseInt("Port", form.Port, &errs)
		u.SMTP.Timeout = parseDuration("Timeout", form.Timeout, &errs)
		u.From, u.FromNameTemplate = form.From, form.FromNameTemplate
		return errs
	}
	s.saveCard(w, r, c)
}

// afterUpstream follows an upstream save: the last connection test was of
// other settings, agents left without a signing key for want of a From
// address get one now that it is set, and the flash says what is still
// missing before agents can send.
func (s *Server) afterUpstream(r *http.Request, prev, now config.Settings, changed []string) string {
	if len(changed) > 0 {
		s.smtpMu.Lock()
		s.smtpCheck = nil
		s.smtpMu.Unlock()
	}
	cfg := s.Config()
	var notes []string
	if s.Keys.Enabled() && prev.Upstream.From == "" && now.Upstream.From != "" {
		n, err := s.Keys.EnsureAll(r.Context(), cfg.AgentNames())
		if err != nil {
			s.Log.Error("generating signing keys after setting the From address", "err", err)
			s.flash(r, "error", "Signing keys for agents without one were not all generated: %v. Generate them on each agent's Signing tab.", err)
		}
		switch {
		case n == 1:
			notes = append(notes, "Generated a signing key for 1 agent.")
		case n > 1:
			notes = append(notes, fmt.Sprintf("Generated signing keys for %d agents.", n))
		}
	}
	if note := missingUpstreamNote(cfg); note != "" {
		notes = append(notes, note)
	}
	return strings.Join(notes, " ")
}

func (s *Server) saveAPI(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	form := apiForm{
		PublicURL: strings.TrimSpace(f.Get("public_url")), Docs: f.Get("docs"),
		TrustedProxies: f.Get("trusted_proxies"), External: f.Get("external_transport_encryption") == "on",
	}
	s.saveCard(w, r, cardSave{id: "api", title: "API settings",
		keep: func(fs *settingsForms) { fs.API = form },
		apply: func(cur *config.Settings) []string {
			cur.API.PublicURL, cur.API.Docs, cur.API.ExternalTransportEncryption = form.PublicURL, form.Docs, form.External
			cur.API.TrustedProxies = strings.FieldsFunc(form.TrustedProxies, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
			return nil
		},
	})
}

func (s *Server) saveDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	p, errs := s.parsePolicyForm(r)
	c := cardSave{id: "policy", title: "Default policy", problems: errs,
		keep:  func(fs *settingsForms) { fs.Policy = policyFormFromPost(r.PostForm) },
		apply: func(cur *config.Settings) []string { cur.Defaults.Policy = p; return nil },
	}
	if u := s.Config().UnknownAliases(p); len(u) > 0 {
		c.warnings = append(c.warnings, "it names recipients that do not exist and are ignored: "+strings.Join(u, ", "))
	}
	s.saveCard(w, r, c)
}

func (s *Server) saveAudit(w http.ResponseWriter, r *http.Request) {
	form := auditForm{RetentionDays: strings.TrimSpace(r.PostForm.Get("retention_days")), LogSubject: r.PostForm.Get("log_subject") == "on"}
	s.saveCard(w, r, cardSave{id: "audit", title: "Audit settings",
		keep: func(fs *settingsForms) { fs.Audit = form },
		apply: func(cur *config.Settings) []string {
			var errs []string
			cur.Audit.RetentionDays = parseInt("Retention", form.RetentionDays, &errs)
			cur.Audit.LogSubject = form.LogSubject
			return errs
		},
	})
}

func (s *Server) saveSigning(w http.ResponseWriter, r *http.Request) {
	if !s.Keys.Enabled() {
		s.flash(r, "error", "Signing is not configured: set kek.file in config.yaml first.")
		s.redirect(w, r, "/settings#signing")
		return
	}
	form := signingForm{KeyValidity: strings.TrimSpace(r.PostForm.Get("key_validity"))}
	s.saveCard(w, r, cardSave{id: "signing", title: "Signing settings",
		keep: func(fs *settingsForms) { fs.Signing = form },
		apply: func(cur *config.Settings) []string {
			var errs []string
			cur.Signing.KeyValidity = parseDuration("Key validity", form.KeyValidity, &errs)
			return errs
		},
	})
}

// setCertifyKey stores a pasted private key as the certification master
// key. The passphrase only decrypts it here; neither the key nor the
// passphrase is ever shown again.
func (s *Server) setCertifyKey(w http.ResponseWriter, r *http.Request) {
	defer s.redirect(w, r, "/settings#signing")
	if !s.Keys.Enabled() {
		s.flash(r, "error", "Signing is not configured: set kek.file in config.yaml first.")
		return
	}
	key := strings.TrimSpace(r.PostForm.Get("private_key"))
	if key == "" {
		s.flash(r, "error", "Certification key not set: paste an ASCII-armored private key.")
		return
	}
	e, err := s.Keys.SetMaster(r.Context(), []byte(key), []byte(r.PostForm.Get("passphrase")))
	if err != nil {
		s.flash(r, "error", "Certification key not set: %v.", err)
		return
	}
	fpr := pgp.Fingerprint(e)
	s.Log.Info("certification key set", "fingerprint", fpr)
	s.flash(r, "ok", "Certification key %s set. It certifies agent keys generated from now on; rotate an agent's key to certify it.", fpr)
}

func (s *Server) removeCertifyKey(w http.ResponseWriter, r *http.Request) {
	if err := s.Keys.RemoveMaster(r.Context()); err != nil {
		s.fail(w, "removing the certification key", err)
		return
	}
	s.Log.Info("certification key removed")
	s.flash(r, "ok", "Certification key removed. Keys it certified keep their certification; new keys are not certified.")
	s.redirect(w, r, "/settings#signing")
}

// extendWriteDeadline gives a response that waits on the upstream server
// room for the current upstream timeout, which the server's fixed write
// timeout does not follow.
func extendWriteDeadline(w http.ResponseWriter, cfg *config.Config) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(cfg.Upstream.SMTP.Timeout.D() + time.Minute))
}

func (s *Server) testSMTP(w http.ResponseWriter, r *http.Request) {
	cfg := s.Config()
	extendWriteDeadline(w, cfg)
	ctx, cancel := context.WithTimeout(r.Context(), cfg.Upstream.SMTP.Timeout.D()+5*time.Second)
	defer cancel()
	err := s.Sender.Check(ctx)
	st := &smtpStatus{At: s.now(), OK: err == nil}
	if err != nil {
		st.Err = err.Error()
		s.flash(r, "error", "SMTP connection test failed: %v", err)
	} else {
		msg := fmt.Sprintf("Connected and authenticated to %s.", cfg.Upstream.SMTP.Addr())
		if note := missingUpstreamNote(cfg); note != "" {
			msg += " " + note
		}
		s.flash(r, "ok", "%s", msg)
	}
	s.smtpMu.Lock()
	s.smtpCheck = st
	s.smtpMu.Unlock()
	s.redirect(w, r, safeNext(r.PostForm.Get("back")))
}

func (s *Server) testSend(w http.ResponseWriter, r *http.Request) {
	alias := r.PostForm.Get("alias")
	cfg := s.Config()
	rc, ok := cfg.Recipient(alias)
	if !ok {
		s.flash(r, "error", "Unknown recipient alias %q.", alias)
		s.redirect(w, r, "/settings#upstream")
		return
	}
	extendWriteDeadline(w, cfg)
	now := s.now()
	msg := &compose.Message{
		FromName: "email-me dashboard", FromAddr: cfg.Upstream.From, To: []string{rc.Address},
		Subject: "[email-me] Test message", Agent: "dashboard", MessageID: compose.NewMessageID(), Date: now,
		Text: "This is a test message sent from the email-me dashboard at " + now.UTC().Format(time.RFC1123) +
			".\n\nIf you can read it, delivery to the \"" + alias + "\" alias works.\n",
	}
	raw, err := compose.Build(msg)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), cfg.Upstream.SMTP.Timeout.D()+5*time.Second)
		defer cancel()
		err = s.Sender.Send(ctx, cfg.Upstream.From, []string{rc.Address}, raw)
	}
	if err != nil {
		s.flash(r, "error", "Test message to %s failed: %v", alias, err)
	} else {
		s.Log.Info("dashboard test message sent", "alias", alias)
		s.flash(r, "ok", "Test message sent to %s.", alias)
	}
	s.redirect(w, r, "/settings#upstream")
}

func (s *Server) guidePreview(w http.ResponseWriter, r *http.Request) {
	base := s.apiBaseURL()
	s.render(w, r, "guide", "Agent guide", map[string]any{
		"Guide": docs.Guide(base), "BaseURL": base,
	})
}
