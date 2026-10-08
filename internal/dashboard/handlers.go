package dashboard

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/api/docs"
	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/compose"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/units"
)

const expiryWarning = 30 * 24 * time.Hour

// apiBaseURL is the URL agents should use, for snippets and the guide preview.
func (s *Server) apiBaseURL() string {
	if s.Config.API.PublicURL != "" {
		return s.Config.API.PublicURL
	}
	_, port, _ := net.SplitHostPort(s.Config.API.Listen)
	scheme := "http"
	if s.Config.API.TLS.Enabled() {
		scheme = "https"
	}
	return scheme + "://localhost:" + port
}

// ---- overview -------------------------------------------------------------

type agentStats struct {
	Agent   *store.Agent
	Day     store.Counts
	Week    store.Counts
	Signing bool
}

// notice is one "Needs attention" item: what is wrong and where it is fixed.
type notice struct {
	Kind  string // danger | warn | info
	Title string // the subject, shown bold
	Text  string
	Link  string // the page where it is fixed
}

// noticeRank orders the attention list: danger, then warn, then info.
var noticeRank = map[string]int{"danger": 0, "warn": 1, "info": 2}

// totals sums the overview's stat tiles over all agents.
type totals struct {
	Agents, Enabled, ActiveTokens int
	Day, Week                     store.Counts
}

func addCounts(dst *store.Counts, m map[string]*store.Counts) {
	for _, c := range m { // includes "" (requests no agent was resolved for)
		dst.Sent += c.Sent
		dst.Rejected += c.Rejected
		dst.Failed += c.Failed
	}
}

// activeTokens counts an agent's tokens that are neither revoked nor expired.
func (s *Server) activeTokens(ctx context.Context, agentID string) (int, error) {
	toks, err := s.Store.ListTokens(ctx, agentID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range toks {
		if t.Active(s.now()) {
			n++
		}
	}
	return n, nil
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agents, err := s.Store.ListAgents(ctx)
	if err != nil {
		s.fail(w, "listing agents", err)
		return
	}
	tot := totals{Agents: len(agents)}
	for _, a := range agents {
		if a.Enabled {
			tot.Enabled++
		}
		n, err := s.activeTokens(ctx, a.ID)
		if err != nil {
			s.fail(w, "listing tokens", err)
			return
		}
		tot.ActiveTokens += n
	}
	now := s.now()
	day, err := s.Store.StatsSince(ctx, now.Add(-24*time.Hour))
	if err != nil {
		s.fail(w, "loading stats", err)
		return
	}
	week, err := s.Store.StatsSince(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		s.fail(w, "loading stats", err)
		return
	}
	addCounts(&tot.Day, day)
	addCounts(&tot.Week, week)
	var rows []agentStats
	for _, a := range agents {
		row := agentStats{Agent: a, Signing: s.Config.Effective(a.Policy).RequireSigning}
		if c := day[a.ID]; c != nil {
			row.Day = *c
		}
		if c := week[a.ID]; c != nil {
			row.Week = *c
		}
		rows = append(rows, row)
	}
	notices, insecure, err := s.notices(ctx, agents)
	if err != nil {
		s.fail(w, "computing warnings", err)
		return
	}
	s.smtpMu.Lock()
	smtp := s.smtpCheck
	s.smtpMu.Unlock()
	if smtp != nil && !smtp.OK {
		notices = append(notices, notice{Kind: "danger", Title: "Upstream SMTP",
			Text: "The last connection test failed: " + smtp.Err, Link: "/settings#upstream"})
		slices.SortStableFunc(notices, func(a, b notice) int { return noticeRank[a.Kind] - noticeRank[b.Kind] })
	}
	s.render(w, r, "overview", "Overview", map[string]any{
		"FirstRun": len(agents) == 0,
		"Rows":     rows,
		"Totals":   tot,
		"Notices":  notices,
		"Insecure": insecure,
		"SMTP":     smtp,
		"Upstream": s.Config.Upstream.SMTP.Addr(),
	})
}

type insecureAgent struct {
	Name           string
	ID             string
	RequireSigning bool
}

func (s *Server) notices(ctx context.Context, agents []*store.Agent) ([]notice, []insecureAgent, error) {
	var out []notice
	for _, w := range s.Config.Warnings {
		out = append(out, notice{Kind: "warn", Title: "Configuration", Text: w, Link: "/settings"})
	}
	if !s.Keys.Enabled() {
		out = append(out, notice{Kind: "info", Title: "Signing is not configured",
			Text: "Messages are not signed. Set signing.key_encryption_key_file to sign each agent's mail with its own key.",
			Link: "/settings#signing"})
	}
	now := s.now()
	for _, alias := range s.Config.Aliases() {
		rc := s.Config.Recipients[alias]
		if rc.PublicKey == nil {
			continue
		}
		exp := pgp.KeyExpiry(rc.PublicKey)
		title := "Recipient " + alias
		switch {
		case !rc.KeyUsable(now):
			msg := "PGP key expired or revoked: encrypted sends fail"
			if rc.RequireEncryption {
				msg += ", and it requires encryption, so nothing is delivered"
			}
			out = append(out, notice{Kind: "danger", Title: title, Text: msg + ". Update pgp_public_key_file and restart.", Link: "/recipients"})
		case !exp.IsZero() && exp.Sub(now) < expiryWarning:
			out = append(out, notice{Kind: "warn", Title: title, Text: "PGP key expires on " + exp.Format("2006-01-02") + ".", Link: "/recipients"})
		}
	}
	byID := map[string]*store.Agent{}
	for _, a := range agents {
		byID[a.ID] = a
		title := "Agent " + a.Name
		if u := s.Config.UnknownAliases(a.Policy); len(u) > 0 {
			out = append(out, notice{Kind: "warn", Title: title,
				Text: "Policy names aliases missing from config.yaml (ignored): " + strings.Join(u, ", ") + ".",
				Link: "/agents/" + a.ID + "/policy"})
		}
		if !s.Keys.Enabled() {
			continue
		}
		signing := "/agents/" + a.ID + "/signing"
		k, err := s.Keys.ActiveKey(ctx, a.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			out = append(out, notice{Kind: "warn", Title: title, Text: "No signing key.", Link: signing})
		case err != nil:
			return nil, nil, err
		case !now.Before(k.ExpiresAt):
			out = append(out, notice{Kind: "danger", Title: title,
				Text: fmt.Sprintf("Signing key expired on %s; signed sends fail until you rotate it.", k.ExpiresAt.Format("2006-01-02")), Link: signing})
		case k.ExpiresAt.Sub(now) < expiryWarning:
			out = append(out, notice{Kind: "warn", Title: title,
				Text: fmt.Sprintf("Signing key expires on %s. Rotate it soon.", k.ExpiresAt.Format("2006-01-02")), Link: signing})
		}
	}
	slices.SortStableFunc(out, func(a, b notice) int { return noticeRank[a.Kind] - noticeRank[b.Kind] })
	ids, err := s.Store.InsecureAgents(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		return nil, nil, err
	}
	var insecure []insecureAgent
	for _, id := range ids {
		ia := insecureAgent{ID: id, Name: id}
		if a := byID[id]; a != nil {
			ia.Name = a.Name
			ia.RequireSigning = s.Config.Effective(a.Policy).RequireSigning
		}
		insecure = append(insecure, ia)
	}
	return out, insecure, nil
}

// ---- agents ---------------------------------------------------------------

type agentRow struct {
	Agent        *store.Agent
	Effective    policy.Effective
	ActiveTokens int
	KeyFpr       string
}

func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agents, err := s.Store.ListAgents(ctx)
	if err != nil {
		s.fail(w, "listing agents", err)
		return
	}
	var rows []agentRow
	for _, a := range agents {
		n, err := s.activeTokens(ctx, a.ID)
		if err != nil {
			s.fail(w, "listing tokens", err)
			return
		}
		row := agentRow{Agent: a, Effective: s.Config.Effective(a.Policy), ActiveTokens: n}
		if k, err := s.Store.ActiveKey(ctx, a.ID); err == nil {
			row.KeyFpr = k.Fingerprint
		}
		rows = append(rows, row)
	}
	s.render(w, r, "agents", "Agents", map[string]any{"Rows": rows})
}

func (s *Server) newAgentPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "agent_new", "New agent", map[string]any{
		"Aliases":    s.Config.Aliases(),
		"Recipients": s.Config.Recipients,
		"Defaults":   s.Config.DefaultPolicy,
	})
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	desc := strings.TrimSpace(r.PostForm.Get("description"))
	if !config.AliasPattern.MatchString(name) {
		s.flash(r, "error", "Agent name must be 1-32 characters of lowercase letters, digits, '-' or '_', starting with a letter or digit.")
		s.redirect(w, r, "/agents/new")
		return
	}
	var p policy.Policy
	if rcpts := r.PostForm["recipients"]; len(rcpts) > 0 {
		for _, a := range rcpts {
			if _, ok := s.Config.Recipients[a]; !ok {
				s.flash(r, "error", "Unknown recipient alias %q.", a)
				s.redirect(w, r, "/agents/new")
				return
			}
		}
		p.Recipients = &rcpts
	}
	a, err := s.Store.CreateAgent(r.Context(), name, desc, p)
	if errors.Is(err, store.ErrConflict) {
		s.flash(r, "error", "An agent named %q already exists.", name)
		s.redirect(w, r, "/agents/new")
		return
	}
	if err != nil {
		s.fail(w, "creating agent", err)
		return
	}
	if s.Keys.Enabled() {
		if _, err := s.Keys.Create(r.Context(), a.ID, a.Name); err != nil {
			s.Log.Error("creating signing key", "agent", a.Name, "err", err)
			s.flash(r, "error", "Agent created, but generating its signing key failed: %v", err)
		}
	}
	s.Log.Info("agent created", "agent", a.Name)
	s.flash(r, "ok", "Agent %s created. Issue a token to let it send.", a.Name)
	s.redirect(w, r, "/agents/"+a.ID+"/tokens")
}

func (s *Server) loadAgent(w http.ResponseWriter, r *http.Request) *store.Agent {
	a, err := s.Store.GetAgent(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return nil
	}
	if err != nil {
		s.fail(w, "loading agent", err)
		return nil
	}
	return a
}

type policyForm struct {
	OvRecipients bool
	Recipients   []string
	OvServices   bool
	Services     []string
	OvMaxBytes   bool
	MaxBytes     string
	OvMaxAtt     bool
	MaxAtt       string
	OvTypes      bool
	Types        string
	OvRate       bool
	PerHour      string
	PerDay       string
	OvPrefix     bool
	Prefix       string
	ReqEnc       string
	ReqSign      string
}

func triState(b *bool) string {
	if b == nil {
		return "inherit"
	}
	return strconv.FormatBool(*b)
}

func formFromPolicy(p policy.Policy, eff policy.Effective) policyForm {
	f := policyForm{
		OvRecipients: p.Recipients != nil, Recipients: eff.Recipients,
		OvServices: p.Services != nil, Services: eff.Services,
		OvMaxBytes: p.MaxMessageBytes != nil, MaxBytes: units.ByteSize(eff.MaxMessageBytes).String(),
		OvMaxAtt: p.MaxAttachments != nil, MaxAtt: strconv.Itoa(eff.MaxAttachments),
		OvTypes: p.AllowedAttachmentTypes != nil, Types: strings.Join(eff.AllowedAttachmentTypes, ", "),
		OvRate: p.RateLimit != nil, PerHour: strconv.Itoa(eff.RateLimit.PerHour), PerDay: strconv.Itoa(eff.RateLimit.PerDay),
		OvPrefix: p.SubjectPrefix != nil, Prefix: eff.SubjectPrefix,
		ReqEnc: triState(p.RequireEncryption), ReqSign: triState(p.RequireSigning),
	}
	if p.Recipients != nil {
		f.Recipients = *p.Recipients // show configured-but-missing aliases too
	}
	return f
}

// agentShell is what every agent tab needs: the agent, its tokens and keys,
// and the data the shared header (chips and tab strip) renders.
type agentShell struct {
	Agent   *store.Agent
	Tokens  []*store.Token
	Key     *store.AgentKey // active signing key, or nil
	Retired []*store.AgentKey
	Data    map[string]any
}

// keyState summarises an agent's signing key for the tab header: "" when
// signing is not configured, else missing, expired, expiring or ok.
func keyState(enabled bool, k *store.AgentKey, now time.Time) string {
	switch {
	case !enabled:
		return ""
	case k == nil:
		return "missing"
	case !now.Before(k.ExpiresAt):
		return "expired"
	case k.ExpiresAt.Sub(now) < expiryWarning:
		return "expiring"
	}
	return "ok"
}

// loadShell loads the agent named in the path with its tokens and keys. It
// returns nil after writing an error response.
func (s *Server) loadShell(w http.ResponseWriter, r *http.Request) *agentShell {
	a := s.loadAgent(w, r)
	if a == nil {
		return nil
	}
	ctx := r.Context()
	toks, err := s.Store.ListTokens(ctx, a.ID)
	if err != nil {
		s.fail(w, "listing tokens", err)
		return nil
	}
	ks, err := s.Store.ListKeys(ctx, a.ID)
	if err != nil {
		s.fail(w, "listing keys", err)
		return nil
	}
	sh := &agentShell{Agent: a, Tokens: toks}
	for _, k := range ks {
		if k.RetiredAt == nil {
			sh.Key = k
		} else {
			sh.Retired = append(sh.Retired, k)
		}
	}
	now := s.now()
	active := 0
	for _, t := range toks {
		if t.Active(now) {
			active++
		}
	}
	sh.Data = map[string]any{
		"Agent":          a,
		"Unknown":        s.Config.UnknownAliases(a.Policy),
		"SigningEnabled": s.Keys.Enabled(),
		"ActiveTokens":   active,
		"Key":            sh.Key,
		"KeyState":       keyState(s.Keys.Enabled(), sh.Key, now),
		"UserID":         s.Keys.UserID(a.Name),
	}
	return sh
}

func (s *Server) agentOverview(w http.ResponseWriter, r *http.Request) {
	sh := s.loadShell(w, r)
	if sh == nil {
		return
	}
	ctx := r.Context()
	now := s.now()
	var counts [2]store.Counts
	for i, since := range []time.Duration{24 * time.Hour, 7 * 24 * time.Hour} {
		st, err := s.Store.StatsSince(ctx, now.Add(-since))
		if err != nil {
			s.fail(w, "loading stats", err)
			return
		}
		if c := st[sh.Agent.ID]; c != nil {
			counts[i] = *c
		}
	}
	var last *time.Time
	for _, t := range sh.Tokens {
		if t.LastUsedAt != nil && (last == nil || t.LastUsedAt.After(*last)) {
			last = t.LastUsedAt
		}
	}
	sh.Data["Day"], sh.Data["Week"] = counts[0], counts[1]
	sh.Data["Effective"] = s.Config.Effective(sh.Agent.Policy)
	sh.Data["LastUsed"] = last
	s.render(w, r, "agent", sh.Agent.Name, sh.Data)
}

func (s *Server) agentTokens(w http.ResponseWriter, r *http.Request) {
	sh := s.loadShell(w, r)
	if sh == nil {
		return
	}
	now := s.now()
	var active, inactive []*store.Token
	for _, t := range sh.Tokens {
		if t.Active(now) {
			active = append(active, t)
		} else {
			inactive = append(inactive, t)
		}
	}
	sh.Data["Active"], sh.Data["Inactive"], sh.Data["Now"] = active, inactive, now
	s.render(w, r, "agent_tokens", sh.Agent.Name, sh.Data)
}

func (s *Server) agentPolicy(w http.ResponseWriter, r *http.Request) {
	sh := s.loadShell(w, r)
	if sh == nil {
		return
	}
	eff := s.Config.Effective(sh.Agent.Policy)
	sh.Data["Form"] = formFromPolicy(sh.Agent.Policy, eff)
	sh.Data["Defaults"] = s.Config.DefaultPolicy
	sh.Data["Effective"] = eff
	sh.Data["Aliases"] = s.Config.Aliases()
	sh.Data["Recipients"] = s.Config.Recipients
	sh.Data["AllServices"] = policy.AllServices
	s.render(w, r, "agent_policy", sh.Agent.Name, sh.Data)
}

func (s *Server) agentSigning(w http.ResponseWriter, r *http.Request) {
	sh := s.loadShell(w, r)
	if sh == nil {
		return
	}
	state := sh.Data["KeyState"]
	sh.Data["KeyExpired"] = state == "expired"
	sh.Data["KeyExpiring"] = state == "expiring"
	sh.Data["RetiredKeys"] = sh.Retired
	s.render(w, r, "agent_signing", sh.Agent.Name, sh.Data)
}

func (s *Server) updateAgent(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	desc := strings.TrimSpace(r.PostForm.Get("description"))
	enabled := r.PostForm.Get("enabled") == "on"
	if err := s.Store.UpdateAgent(r.Context(), a.ID, desc, enabled); err != nil {
		s.fail(w, "updating agent", err)
		return
	}
	s.Log.Info("agent updated", "agent", a.Name, "enabled", enabled)
	s.flash(r, "ok", "Agent saved.")
	s.redirect(w, r, "/agents/"+a.ID)
}

// parsePolicyForm turns the policy editor form into a partial policy.
func (s *Server) parsePolicyForm(r *http.Request) (policy.Policy, []string) {
	f := r.PostForm
	on := func(k string) bool { return f.Get(k) == "on" }
	var p policy.Policy
	var errs []string
	if on("ov_recipients") {
		v := slices.Clone(f["recipients"])
		if v == nil {
			v = []string{}
		}
		p.Recipients = &v
	}
	if on("ov_services") {
		v := slices.Clone(f["services"])
		if v == nil {
			v = []string{}
		}
		p.Services = &v
	}
	if on("ov_max_bytes") {
		if b, err := units.ParseByteSize(f.Get("max_bytes")); err != nil {
			errs = append(errs, "Max message size: "+err.Error())
		} else {
			p.MaxMessageBytes = &b
		}
	}
	if on("ov_max_att") {
		if n, err := strconv.Atoi(strings.TrimSpace(f.Get("max_att"))); err != nil {
			errs = append(errs, "Max attachments must be a number")
		} else {
			p.MaxAttachments = &n
		}
	}
	if on("ov_types") {
		v := []string{}
		for _, t := range strings.Split(f.Get("types"), ",") {
			if t = strings.TrimSpace(t); t != "" {
				v = append(v, t)
			}
		}
		p.AllowedAttachmentTypes = &v
	}
	if on("ov_rate") {
		h, err1 := strconv.Atoi(strings.TrimSpace(f.Get("per_hour")))
		d, err2 := strconv.Atoi(strings.TrimSpace(f.Get("per_day")))
		if err1 != nil || err2 != nil {
			errs = append(errs, "Rate limits must be numbers")
		} else {
			p.RateLimit = &policy.RateLimit{PerHour: h, PerDay: d}
		}
	}
	if on("ov_prefix") {
		v := f.Get("prefix")
		p.SubjectPrefix = &v
	}
	tri := func(k string) (*bool, bool) {
		switch f.Get(k) {
		case "true":
			b := true
			return &b, true
		case "false":
			b := false
			return &b, true
		case "inherit", "":
			return nil, true
		}
		return nil, false
	}
	var ok bool
	if p.RequireEncryption, ok = tri("require_encryption"); !ok {
		errs = append(errs, "Invalid require_encryption value")
	}
	if p.RequireSigning, ok = tri("require_signing"); !ok {
		errs = append(errs, "Invalid require_signing value")
	}
	return p, errs
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	p, errs := s.parsePolicyForm(r)
	errs = append(errs, p.Validate()...)
	if u := s.Config.UnknownAliases(p); len(u) > 0 {
		errs = append(errs, "Unknown recipient aliases: "+strings.Join(u, ", "))
	}
	if len(errs) == 0 {
		errs = append(errs, s.Config.Effective(p).ValidateEffective(s.Keys.Enabled())...)
	}
	if len(errs) > 0 {
		s.flash(r, "error", "Policy not saved: %s", strings.Join(errs, "; "))
		s.redirect(w, r, "/agents/"+a.ID+"/policy")
		return
	}
	if err := s.Store.UpdateAgentPolicy(r.Context(), a.ID, p); err != nil {
		s.fail(w, "saving policy", err)
		return
	}
	s.Log.Info("agent policy updated", "agent", a.Name)
	s.flash(r, "ok", "Policy saved.")
	s.redirect(w, r, "/agents/"+a.ID+"/policy")
}

func (s *Server) deleteAgentPage(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	ks, err := s.Store.ListKeys(r.Context(), a.ID)
	if err != nil {
		s.fail(w, "listing keys", err)
		return
	}
	s.render(w, r, "agent_delete", "Delete "+a.Name, map[string]any{"Agent": a, "Keys": ks})
}

func (s *Server) deleteAgent(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	if r.PostForm.Get("confirm") != a.Name {
		s.flash(r, "error", "Type the agent name to confirm deletion.")
		s.redirect(w, r, "/agents/"+a.ID+"/delete")
		return
	}
	if err := s.Store.DeleteAgent(r.Context(), a.ID); err != nil {
		s.fail(w, "deleting agent", err)
		return
	}
	s.Log.Info("agent deleted", "agent", a.Name)
	s.flash(r, "ok", "Agent %s deleted, with its tokens and keys.", a.Name)
	s.redirect(w, r, "/agents")
}

// ---- tokens ---------------------------------------------------------------

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	f := r.PostForm
	label := compose.CleanHeaderText(f.Get("label"), 100)
	var expires *time.Time
	if d := strings.TrimSpace(f.Get("expires_days")); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3650 {
			s.flash(r, "error", "Expiry must be a number of days between 1 and 3650, or empty for no expiry.")
			s.redirect(w, r, "/agents/"+a.ID+"/tokens")
			return
		}
		t := s.now().Add(time.Duration(n) * 24 * time.Hour).UTC().Truncate(time.Second)
		expires = &t
	}
	var cidrs []string
	for _, c := range strings.Split(f.Get("cidrs"), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if p, err := netip.ParsePrefix(c); err == nil {
			cidrs = append(cidrs, p.Masked().String())
		} else if ip, err := netip.ParseAddr(c); err == nil {
			cidrs = append(cidrs, netip.PrefixFrom(ip, ip.BitLen()).String())
		} else {
			s.flash(r, "error", "%q is not an IP address or CIDR.", c)
			s.redirect(w, r, "/agents/"+a.ID+"/tokens")
			return
		}
	}
	token, id, hash := auth.NewToken()
	t := &store.Token{ID: id, AgentID: a.ID, SecretHash: hash, Label: label, AllowedCIDRs: cidrs,
		CreatedAt: s.now().UTC().Truncate(time.Second), ExpiresAt: expires}
	if err := s.Store.CreateToken(r.Context(), t); err != nil {
		s.fail(w, "creating token", err)
		return
	}
	s.Log.Info("token issued", "agent", a.Name, "token_id", id)
	base := s.apiBaseURL()
	s.render(w, r, "token", "New token for "+a.Name, map[string]any{
		"Agent":   a,
		"Token":   token,
		"TokenID": id,
		"BaseURL": base,
		"Snippet": onboardingSnippet(base),
	})
}

func onboardingSnippet(base string) string {
	return "You can email your operator through the email-me gateway.\n" +
		"Base URL: $EMAIL_ME_URL (currently " + base + ")\n" +
		"Your token is in the EMAIL_ME_TOKEN environment variable. Never include it in emails, logs, or files.\n" +
		"Before your first send, GET the base URL and follow the guide it returns."
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	tid := r.PathValue("tid")
	if err := s.Store.RevokeToken(r.Context(), a.ID, tid); errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.fail(w, "revoking token", err)
		return
	}
	s.Log.Info("token revoked", "agent", a.Name, "token_id", tid)
	s.flash(r, "ok", "Token %s revoked.", tid)
	s.redirect(w, r, "/agents/"+a.ID+"/tokens")
}

// ---- keys -----------------------------------------------------------------

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	if _, err := s.Keys.Create(r.Context(), a.ID, a.Name); err != nil {
		s.flash(r, "error", "Could not create signing key: %v", err)
	} else {
		s.Log.Info("signing key created", "agent", a.Name)
		s.flash(r, "ok", "Signing key created. Download its public key and import it into your mail client.")
	}
	s.redirect(w, r, "/agents/"+a.ID+"/signing")
}

func (s *Server) rotateKey(w http.ResponseWriter, r *http.Request) {
	a := s.loadAgent(w, r)
	if a == nil {
		return
	}
	k, err := s.Keys.Rotate(r.Context(), a.ID, a.Name)
	if err != nil {
		s.flash(r, "error", "Could not rotate signing key: %v", err)
	} else {
		s.Log.Info("signing key rotated", "agent", a.Name, "fingerprint", k.Fingerprint)
		s.flash(r, "ok", "Signing key rotated. Import the new public key. If you distributed the old key, publish its retired-reason revocation certificate (under retired keys): signatures it already made stay valid.")
	}
	s.redirect(w, r, "/agents/"+a.ID+"/signing")
}

func (s *Server) agentKey(w http.ResponseWriter, r *http.Request) (*store.Agent, *store.AgentKey) {
	a := s.loadAgent(w, r)
	if a == nil {
		return nil, nil
	}
	k, err := s.Store.GetKey(r.Context(), r.PathValue("fpr"))
	if err != nil || k.AgentID != a.ID {
		http.NotFound(w, r)
		return nil, nil
	}
	return a, k
}

func (s *Server) downloadPublicKey(w http.ResponseWriter, r *http.Request) {
	a, k := s.agentKey(w, r)
	if k == nil {
		return
	}
	serveKey(w, fmt.Sprintf("%s-%s.asc", a.Name, short16(k.Fingerprint)), k.PublicKey)
}

func (s *Server) downloadRevocation(w http.ResponseWriter, r *http.Request) {
	a, k := s.agentKey(w, r)
	if k == nil {
		return
	}
	serveKey(w, fmt.Sprintf("%s-%s-revocation-retired.asc", a.Name, short16(k.Fingerprint)), k.RevocationCert)
}

func (s *Server) downloadRevocationCompromised(w http.ResponseWriter, r *http.Request) {
	a, k := s.agentKey(w, r)
	if k == nil {
		return
	}
	serveKey(w, fmt.Sprintf("%s-%s-revocation-compromised.asc", a.Name, short16(k.Fingerprint)), k.RevocationCertCompromised)
}

func (s *Server) keyBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.Keys.Bundle(r.Context())
	if err != nil {
		s.fail(w, "building key bundle", err)
		return
	}
	serveKey(w, "email-me-keys.asc", b)
}

func serveKey(w http.ResponseWriter, filename, body string) {
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Write([]byte(body))
}

func short16(fpr string) string {
	if len(fpr) > 16 {
		return fpr[len(fpr)-16:]
	}
	return fpr
}

// ---- recipients -----------------------------------------------------------

type recipientRow struct {
	Alias     string
	R         *config.Recipient
	KeyFpr    string
	KeyExpiry time.Time
}

func (s *Server) recipients(w http.ResponseWriter, r *http.Request) {
	var rows []recipientRow
	for _, alias := range s.Config.Aliases() {
		rc := s.Config.Recipients[alias]
		row := recipientRow{Alias: alias, R: rc}
		if rc.PublicKey != nil {
			row.KeyFpr = pgp.Fingerprint(rc.PublicKey)
			row.KeyExpiry = pgp.KeyExpiry(rc.PublicKey)
		}
		rows = append(rows, row)
	}
	s.render(w, r, "recipients", "Recipients", map[string]any{"Rows": rows})
}

// ---- audit ----------------------------------------------------------------

const auditPageSize = 100

func (s *Server) auditFilter(r *http.Request) (store.AuditFilter, string) {
	q := r.URL.Query()
	f := store.AuditFilter{AgentID: q.Get("agent"), Status: q.Get("status")}
	if !slices.Contains([]string{"", store.StatusSent, store.StatusRejected, store.StatusFailed}, f.Status) {
		f.Status = ""
	}
	period := q.Get("period")
	switch period {
	case "24h":
		f.Since = s.now().Add(-24 * time.Hour)
	case "30d":
		f.Since = s.now().Add(-30 * 24 * time.Hour)
	case "all":
	default:
		period = "7d"
		f.Since = s.now().Add(-7 * 24 * time.Hour)
	}
	return f, period
}

func (s *Server) agentNames(ctx context.Context) (map[string]string, []*store.Agent, error) {
	agents, err := s.Store.ListAgents(ctx)
	if err != nil {
		return nil, nil, err
	}
	names := map[string]string{}
	for _, a := range agents {
		names[a.ID] = a.Name
	}
	return names, agents, nil
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	f, period := s.auditFilter(r)
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pg = max(pg, 1)
	f.Limit, f.Offset = auditPageSize+1, (pg-1)*auditPageSize
	rows, err := s.Store.ListAudit(r.Context(), f)
	if err != nil {
		s.fail(w, "loading audit log", err)
		return
	}
	more := len(rows) > auditPageSize
	if more {
		rows = rows[:auditPageSize]
	}
	names, agents, err := s.agentNames(r.Context())
	if err != nil {
		s.fail(w, "listing agents", err)
		return
	}
	s.render(w, r, "audit", "Audit log", map[string]any{
		"Rows": rows, "Names": names, "Agents": agents, "Filter": f, "Period": period,
		"Page": pg, "More": more, "LogSubject": s.Config.Audit.LogSubject,
		"Query": r.URL.Query(),
	})
}

func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request) {
	f, _ := s.auditFilter(r)
	rows, err := s.Store.ListAudit(r.Context(), f)
	if err != nil {
		s.fail(w, "loading audit log", err)
		return
	}
	names, _, err := s.agentNames(r.Context())
	if err != nil {
		s.fail(w, "listing agents", err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="email-me-audit.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"time", "agent", "token_id", "source_ip", "recipients", "size_bytes", "attachments", "services",
		"encrypted", "signed", "signing_key", "transport", "status", "error", "upstream_code", "message_id", "subject"})
	for _, e := range rows {
		agent := names[e.AgentID]
		if agent == "" {
			agent = e.AgentID
		}
		up := ""
		if e.UpstreamCode != 0 {
			up = strconv.Itoa(e.UpstreamCode)
		}
		cw.Write([]string{e.TS.Format(time.RFC3339), csvSafe(agent), e.TokenID, e.SourceIP, strings.Join(e.Recipients, " "),
			strconv.FormatInt(e.SizeBytes, 10), strconv.Itoa(e.AttachmentCount), strings.Join(e.Services, " "),
			strconv.FormatBool(e.Encrypted), strconv.FormatBool(e.Signed), e.SigningKeyFpr, e.Transport, e.Status, e.ErrorCode,
			up, e.MessageID, csvSafe(e.Subject)})
	}
	cw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ---- settings -------------------------------------------------------------

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	y, err := yaml.Marshal(s.Config)
	if err != nil {
		s.fail(w, "rendering config", err)
		return
	}
	s.smtpMu.Lock()
	smtp := s.smtpCheck
	s.smtpMu.Unlock()
	var master string
	if m := s.Keys.Master(); m != nil {
		master = pgp.Fingerprint(m)
	}
	s.render(w, r, "settings", "Settings", map[string]any{
		"ConfigYAML":     string(y),
		"SMTP":           smtp,
		"Upstream":       s.Config.Upstream.SMTP.Addr(),
		"Aliases":        s.Config.Aliases(),
		"SigningEnabled": s.Keys.Enabled(),
		"MasterFpr":      master,
		"Warnings":       s.Config.Warnings,
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

func (s *Server) testSend(w http.ResponseWriter, r *http.Request) {
	alias := r.PostForm.Get("alias")
	rc, ok := s.Config.Recipients[alias]
	if !ok {
		s.flash(r, "error", "Unknown recipient alias %q.", alias)
		s.redirect(w, r, "/settings")
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
	s.redirect(w, r, "/settings")
}

func (s *Server) guidePreview(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "guide", "Agent guide", map[string]any{
		"Guide": docs.Guide(s.apiBaseURL()), "BaseURL": s.apiBaseURL(),
	})
}
