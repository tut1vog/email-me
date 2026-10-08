package dashboard

import (
	"context"
	"errors"
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
	"github.com/tut1vog/email-me/internal/upstream"
)

// The Settings page edits the managed settings: one form per card, each
// saving the card merged into the saved settings. Saved settings apply on
// restart; the forms always show the saved values, not the running ones.

// settingsForms holds every card's form values as text, so a rejected
// submission can be shown again exactly as typed.
type settingsForms struct {
	Upstream  upstreamForm
	API       apiForm
	Policy    policyForm
	Dashboard dashboardForm
	Audit     auditForm
	Signing   signingForm
}

type upstreamForm struct {
	Host, Port, Security, Username, Timeout, From, FromNameTemplate string
	AllowPlaintext                                                  bool
}

type apiForm struct {
	PublicURL, Docs, TrustedProxies string
	External                        bool
}

type dashboardForm struct{ SessionTTL string }

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

// settingsForms fills every card from the saved settings.
func (s *Server) settingsForms() settingsForms {
	cur := s.Settings.Saved()
	u := cur.Upstream
	f := settingsForms{
		Upstream: upstreamForm{
			Host: u.SMTP.Host, Security: u.SMTP.Security, Username: u.SMTP.Username, Timeout: durationText(u.SMTP.Timeout),
			From: u.From, FromNameTemplate: u.FromNameTemplate, AllowPlaintext: u.SMTP.AllowPlaintext,
		},
		API: apiForm{
			PublicURL: cur.API.PublicURL, Docs: cur.API.Docs,
			TrustedProxies: strings.Join(cur.API.TrustedProxies, ", "), External: cur.API.ExternalTransportEncryption,
		},
		Policy:    formFromPolicy(cur.Defaults.Policy, cur.Defaults.Policy.Apply(s.builtinPolicy())),
		Dashboard: dashboardForm{SessionTTL: durationText(cur.Dashboard.SessionTTL)},
		Audit:     auditForm{RetentionDays: strconv.Itoa(cur.Audit.RetentionDays), LogSubject: cur.Audit.LogSubject},
		Signing:   signingForm{KeyValidity: durationText(cur.Signing.KeyValidity)},
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

// configWarnings are the config warnings the Needs-attention list and the
// Settings page show as such. Problems with the saved settings and a
// missing upstream are left out: they have their own notices and banner.
func (s *Server) configWarnings() []string {
	var out []string
	for _, w := range s.Config.Warnings {
		if strings.HasPrefix(w, settings.WarningPrefix) || w == config.UpstreamNotConfigured {
			continue
		}
		out = append(out, w)
	}
	return out
}

// upstreamAddr is the running upstream server, for display.
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
	s.settingsPage(w, r, http.StatusOK, s.settingsForms())
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, status int, forms settingsForms) {
	var master string
	if m := s.Keys.Master(); m != nil {
		master = pgp.Fingerprint(m)
	}
	pending := s.Settings.Pending()
	s.renderStatus(w, r, status, "settings", "Settings", map[string]any{
		"Form": forms,
		"Policy": map[string]any{
			"Form": forms.Policy, "Defaults": s.builtinPolicy(),
			"Recipients": s.Recipients.All(), "AllServices": policy.AllServices,
		},
		"SMTP":           s.lastSMTPCheck(),
		"Configured":     upstreamConfigured(s.Config),
		"Upstream":       upstreamAddr(s.Config),
		"Password":       passwordState(s.Settings.PasswordState()),
		"HasPassword":    s.Settings.HasPassword(),
		"TestSaved":      slices.ContainsFunc(pending, func(k string) bool { return strings.HasPrefix(k, "upstream.") }),
		"Securities":     []string{"starttls", "tls", "none"},
		"Aliases":        s.Recipients.Aliases(),
		"SigningEnabled": s.Keys.Enabled(),
		"MasterFpr":      master,
		"Warnings":       s.configWarnings(),
		"Config":         s.Config,
		"Pending":        pending,
	})
}

// cardSave is one card's submission: apply copies it into the saved
// settings (returning parse problems) and keep puts the submitted form
// back for a re-render.
type cardSave struct {
	id, title string
	problems  []string
	warnings  []string
	password  settings.PasswordChange
	apply     func(*config.Settings) []string
	keep      func(*settingsForms)
}

// saveCard saves a card merged into the saved settings. Problems re-render
// the page (422) with the card as submitted; success redirects to the card.
func (s *Server) saveCard(w http.ResponseWriter, r *http.Request, c cardSave) {
	cur := s.Settings.Saved()
	problems := append(c.problems, c.apply(&cur)...)
	var warnings []string
	if len(problems) == 0 {
		var err error
		warnings, err = s.Settings.Save(r.Context(), cur, c.password)
		var ve *config.ValidationError
		switch {
		case errors.As(err, &ve):
			problems = ve.Problems
		case err != nil:
			s.fail(w, "saving settings", err)
			return
		}
	}
	if len(problems) > 0 {
		s.flash(r, "error", "%s not saved: %s.", c.title, strings.Join(problems, "; "))
		forms := s.settingsForms()
		c.keep(&forms)
		s.settingsPage(w, r, http.StatusUnprocessableEntity, forms)
		return
	}
	pending := s.Settings.Pending()
	msg := c.title + " saved. Restart to apply."
	if len(pending) == 0 {
		msg = c.title + " saved. They match the running settings: no restart is needed."
	}
	// Warnings the running settings already have are on the Needs-attention
	// list; a save only mentions new ones.
	for _, w := range append(warnings, c.warnings...) {
		if !slices.Contains(s.Config.Warnings, w) && (w != config.UpstreamNotConfigured || c.id == "upstream") {
			msg += " Note: " + w + "."
		}
	}
	s.Log.Info("settings saved", "card", c.id, "pending", pending)
	s.flash(r, "ok", "%s", msg)
	s.redirect(w, r, "/settings#"+c.id)
}

func (s *Server) saveUpstream(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	form := upstreamForm{
		Host: strings.TrimSpace(f.Get("host")), Port: strings.TrimSpace(f.Get("port")), Security: f.Get("security"),
		Username: strings.TrimSpace(f.Get("username")), Timeout: strings.TrimSpace(f.Get("timeout")),
		From: strings.TrimSpace(f.Get("from")), FromNameTemplate: f.Get("from_name_template"),
		AllowPlaintext: f.Get("allow_plaintext") == "on",
	}
	c := cardSave{id: "upstream", title: "Upstream SMTP settings", keep: func(fs *settingsForms) { fs.Upstream = form }}
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
		u.SMTP.AllowPlaintext = form.AllowPlaintext
		u.From, u.FromNameTemplate = form.From, form.FromNameTemplate
		return errs
	}
	s.saveCard(w, r, c)
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
	if u := s.Recipients.UnknownAliases(p); len(u) > 0 {
		c.warnings = append(c.warnings, "it names recipients that do not exist and are ignored: "+strings.Join(u, ", "))
	}
	s.saveCard(w, r, c)
}

func (s *Server) saveDashboard(w http.ResponseWriter, r *http.Request) {
	form := dashboardForm{SessionTTL: strings.TrimSpace(r.PostForm.Get("session_ttl"))}
	s.saveCard(w, r, cardSave{id: "dashboard", title: "Dashboard settings",
		keep: func(fs *settingsForms) { fs.Dashboard = form },
		apply: func(cur *config.Settings) []string {
			var errs []string
			cur.Dashboard.SessionTTL = parseDuration("Session lifetime", form.SessionTTL, &errs)
			return errs
		},
	})
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
		s.flash(r, "error", "Signing is not configured: set signing.key_encryption_key_file in config.yaml first.")
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

func (s *Server) testSMTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.Config.Upstream.SMTP.Timeout.D()+5*time.Second)
	defer cancel()
	err := s.Sender.Check(ctx)
	st := &smtpStatus{At: s.now(), OK: err == nil}
	if err != nil {
		st.Err = err.Error()
		s.flash(r, "error", "SMTP connection test failed: %v", err)
	} else {
		s.flash(r, "ok", "Connected and authenticated to %s.", s.Config.Upstream.SMTP.Addr())
	}
	s.smtpMu.Lock()
	s.smtpCheck = st
	s.smtpMu.Unlock()
	s.redirect(w, r, safeNext(r.PostForm.Get("back")))
}

// testSMTPSaved checks the saved upstream server, before a restart puts it
// in use. It does not touch the running sender's status.
func (s *Server) testSMTPSaved(w http.ResponseWriter, r *http.Request) {
	cfg := s.Settings.SavedSMTP()
	if cfg.Host == "" {
		s.flash(r, "error", "The saved settings have no upstream host.")
		s.redirect(w, r, "/settings#upstream")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout.D()+5*time.Second)
	defer cancel()
	if err := upstream.NewSMTP(cfg).Check(ctx); err != nil {
		s.flash(r, "error", "Saved SMTP settings test failed: %v", err)
	} else {
		s.flash(r, "ok", "Connected and authenticated to %s with the saved settings. Restart to use them.", cfg.Addr())
	}
	s.redirect(w, r, "/settings#upstream")
}

func (s *Server) testSend(w http.ResponseWriter, r *http.Request) {
	alias := r.PostForm.Get("alias")
	rc, ok := s.Recipients.Get(alias)
	if !ok {
		s.flash(r, "error", "Unknown recipient alias %q.", alias)
		s.redirect(w, r, "/settings#upstream")
		return
	}
	now := s.now()
	msg := &compose.Message{
		FromName: "email-me dashboard", FromAddr: s.Config.Upstream.From, To: []string{rc.Address},
		Subject: "[email-me] Test message", Agent: "dashboard", MessageID: compose.NewMessageID(), Date: now,
		Text: "This is a test message sent from the email-me dashboard at " + now.UTC().Format(time.RFC1123) +
			".\n\nIf you can read it, delivery to the \"" + alias + "\" alias works.\n",
	}
	raw, err := compose.Build(msg)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), s.Config.Upstream.SMTP.Timeout.D()+5*time.Second)
		defer cancel()
		err = s.Sender.Send(ctx, s.Config.Upstream.From, []string{rc.Address}, raw)
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
	s.render(w, r, "guide", "Agent guide", map[string]any{
		"Guide": docs.Guide(s.apiBaseURL()), "BaseURL": s.apiBaseURL(),
	})
}
