// Package config loads, validates and edits config.yaml, the operator's
// source of truth: the bootstrap keys (listen addresses, TLS, the
// key-encryption key, log), the managed settings, the recipients and the
// agents. Validation collects every problem so the operator can fix them in
// one pass. Files the configuration names are relative to its directory.
//
// Bootstrap keys apply when the gateway starts. Everything else is also
// edited on the dashboard, which writes the file and applies the change at
// once (see Settings and Document).
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/units"
)

// AliasPattern is the syntax of recipient aliases and agent names.
var AliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type Config struct {
	API        API                   `yaml:"api"`
	Dashboard  Dashboard             `yaml:"dashboard"`
	Upstream   Upstream              `yaml:"upstream"`
	KEK        KEK                   `yaml:"kek"`
	Signing    Signing               `yaml:"signing"`
	Defaults   Defaults              `yaml:"defaults"`
	Audit      Audit                 `yaml:"audit"`
	Log        Log                   `yaml:"log"`
	Recipients map[string]*Recipient `yaml:"recipients"`
	Agents     map[string]*Agent     `yaml:"agents"`

	// Dir is the directory relative paths in the file resolve against: the
	// file's own.
	Dir string `yaml:"-"`
	// DefaultPolicy is built-in defaults overlaid with defaults.policy.
	DefaultPolicy policy.Effective `yaml:"-"`
	// Warnings are non-fatal problems to log at startup and show on the
	// dashboard: BootstrapWarnings and the managed configuration's.
	Warnings []string `yaml:"-"`
	// BootstrapWarnings are the bootstrap keys' warnings, which hold until
	// the next start.
	BootstrapWarnings []string `yaml:"-"`
	// Fingerprint identifies the config.yaml that Load read (see
	// FileFingerprint), so a later change to the file can be detected.
	Fingerprint string `yaml:"-"`
	// Raw is the file as read, which a Document edits.
	Raw []byte `yaml:"-"`
}

type API struct {
	Listen                      string   `yaml:"listen"`
	PublicURL                   string   `yaml:"public_url"`
	Docs                        string   `yaml:"docs"`
	TLS                         TLS      `yaml:"tls"`
	TrustedProxies              []string `yaml:"trusted_proxies"`
	ExternalTransportEncryption bool     `yaml:"external_transport_encryption"`

	TrustedNets []netip.Prefix   `yaml:"-"`
	Certificate *tls.Certificate `yaml:"-"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled reports whether built-in TLS is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

type Dashboard struct {
	Listen string `yaml:"listen"`
}

type Upstream struct {
	SMTP             SMTP   `yaml:"smtp" json:"smtp"`
	From             string `yaml:"from" json:"from"`
	FromNameTemplate string `yaml:"from_name_template" json:"from_name_template"`
}

// SMTP is the upstream server. The password is never in config.yaml: it is
// entered on the dashboard and kept sealed in the state database.
type SMTP struct {
	Host     string         `yaml:"host" json:"host"`
	Port     int            `yaml:"port" json:"port"`
	Security string         `yaml:"security" json:"security"`
	Username string         `yaml:"username" json:"username"`
	Timeout  units.Duration `yaml:"timeout" json:"timeout"`

	Password string `yaml:"-" json:"-"`
}

// Addr returns host:port.
func (s SMTP) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Recipient is a recipients: entry, an alias agents may address.
type Recipient struct {
	Alias             string `yaml:"-"` // the entry's key
	Address           string `yaml:"address"`
	Description       string `yaml:"description,omitempty"`
	PGPPublicKey      string `yaml:"pgp_public_key,omitempty"` // ASCII armor
	RequireEncryption bool   `yaml:"require_encryption,omitempty"`

	// Key is PGPPublicKey parsed, nil without one.
	Key *openpgp.Entity `yaml:"-"`
}

// KeyUsable reports whether the recipient's PGP key can encrypt at now.
// Keys are checked when added but can expire (or be found revoked) later.
func (r *Recipient) KeyUsable(now time.Time) bool {
	return r.Key != nil && pgp.CheckEncryptionKey(r.Key, now) == nil
}

// Fingerprint returns the key's fingerprint, or "" without a key.
func (r *Recipient) Fingerprint() string {
	if r.Key == nil {
		return ""
	}
	return pgp.Fingerprint(r.Key)
}

// KeyExpiry returns when the key expires; zero without a key or expiry.
func (r *Recipient) KeyExpiry() time.Time {
	if r.Key == nil {
		return time.Time{}
	}
	return pgp.KeyExpiry(r.Key)
}

// Agent is an agents: entry. Its name is its identity: tokens, signing keys
// and audit rows in the state database refer to it by name.
type Agent struct {
	Name        string        `yaml:"-"` // the entry's key
	Description string        `yaml:"description,omitempty"`
	Disabled    bool          `yaml:"disabled,omitempty"`
	Policy      policy.Policy `yaml:"policy,omitempty"`
}

// Enabled reports whether the agent may send.
func (a *Agent) Enabled() bool { return !a.Disabled }

// MaxDescription is the longest agent or recipient description, in characters.
const MaxDescription = 200

// KEK names the key-encryption key that protects every credential in the
// state database. The previous key is set only while rotating it.
type KEK struct {
	File         string `yaml:"file"`
	PreviousFile string `yaml:"previous_file"`

	Key      []byte `yaml:"-"` // nil: no KEK
	Previous []byte `yaml:"-"` // nil: none
}

// Configured reports whether a KEK is set.
func (k KEK) Configured() bool { return len(k.Key) == 32 }

// Signing is the signing section. Its settings are kept whether or not a
// KEK is configured; signing itself exists exactly when one is.
type Signing struct {
	KeyValidity units.Duration `yaml:"key_validity"`
}

type Defaults struct {
	Policy policy.Policy `yaml:"policy" json:"policy"`
}

type Audit struct {
	RetentionDays int  `yaml:"retention_days" json:"retention_days"`
	LogSubject    bool `yaml:"log_subject" json:"log_subject"`
}

type Log struct {
	Level string `yaml:"level"`
}

// SigningConfigured reports whether the sign service can work at all.
func (c *Config) SigningConfigured() bool { return c.KEK.Configured() }

// FromName renders the From display name for an agent.
func (c *Config) FromName(agent string) string {
	return strings.ReplaceAll(c.Upstream.FromNameTemplate, "{agent}", agent)
}

// Load reads, defaults and validates a config file and every file it
// names, which are relative to its directory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	c, err := Parse(data, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	c.Fingerprint = Fingerprint(data)
	return c, nil
}

// FileFingerprint returns the fingerprint of the config file at path, to
// compare with a loaded Config's. Only the file itself is hashed: a secret
// file it names can change without changing the fingerprint.
func FileFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return Fingerprint(data), nil
}

// Fingerprint identifies a config file's contents.
func Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Parse is Load without the file read; dir is where relative paths
// resolve. The files the configuration names are still read.
func Parse(data []byte, dir string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	c.Dir, c.Raw = dir, data
	c.applyBootstrapDefaults()
	v := &validator{}
	c.validateBootstrap(v)
	boot := len(v.warns)
	c.ApplyManagedDefaults()
	c.validateManaged(v)
	if len(v.errs) > 0 {
		return nil, &ValidationError{Problems: v.errs}
	}
	c.BootstrapWarnings = v.warns[:boot:boot]
	c.Warnings = v.warns
	return &c, nil
}

// ValidateManaged applies defaults to everything the dashboard edits (the
// managed settings, recipients and agents) and validates it, collecting
// every problem. It also sets the derived fields (API.TrustedNets,
// DefaultPolicy, each recipient's Alias and Key, each agent's Name) and
// normalizes values (public_url loses its trailing slash). Warnings are
// returned, not added to c.Warnings.
func (c *Config) ValidateManaged() (problems, warnings []string) {
	c.ApplyManagedDefaults()
	v := &validator{}
	c.validateManaged(v)
	return v.errs, v.warns
}

// Path resolves a path from the file against its directory.
func (c *Config) Path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir, p)
}

// ValidationError lists every problem found in the config.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

type validator struct{ errs, warns []string }

func (v *validator) add(format string, args ...any) {
	v.errs = append(v.errs, fmt.Sprintf(format, args...))
}

func (v *validator) warn(format string, args ...any) {
	v.warns = append(v.warns, fmt.Sprintf(format, args...))
}

func (c *Config) applyBootstrapDefaults() {
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:8025"
	}
	if c.Dashboard.Listen == "" {
		c.Dashboard.Listen = "127.0.0.1:8026"
	}
	if c.KEK.File == "" {
		c.KEK.File = "kek"
	}
	if c.KEK.PreviousFile == "" {
		c.KEK.PreviousFile = "previous_kek"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
}

// ApplyManagedDefaults fills unset managed settings with their defaults.
func (c *Config) ApplyManagedDefaults() {
	if c.API.Docs == "" {
		c.API.Docs = "public"
	}
	if c.Upstream.SMTP.Security == "" {
		c.Upstream.SMTP.Security = "starttls"
	}
	if c.Upstream.SMTP.Port == 0 {
		switch c.Upstream.SMTP.Security {
		case "tls":
			c.Upstream.SMTP.Port = 465
		case "none":
			c.Upstream.SMTP.Port = 25
		default:
			c.Upstream.SMTP.Port = 587
		}
	}
	if c.Upstream.SMTP.Timeout == 0 {
		c.Upstream.SMTP.Timeout = units.Duration(30 * time.Second)
	}
	if c.Upstream.FromNameTemplate == "" {
		c.Upstream.FromNameTemplate = "{agent} via email-me"
	}
	if c.Signing.KeyValidity == 0 {
		c.Signing.KeyValidity = units.Duration(2 * 365 * 24 * time.Hour)
	}
	if c.Audit.RetentionDays == 0 {
		c.Audit.RetentionDays = 30
	}
}

// validateBootstrap checks the keys that apply at start only.
func (c *Config) validateBootstrap(v *validator) {
	c.validateListenTLS(v)
	c.validateDashboard(v)
	c.validateKEK(v)
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level) {
		v.add("log.level must be one of debug, info, warn, error")
	}
}

// validateManaged checks what the dashboard edits.
func (c *Config) validateManaged(v *validator) {
	c.validateAPISettings(v)
	c.validateUpstream(v)
	if d := c.Signing.KeyValidity.D(); d < 24*time.Hour || d > 50*365*24*time.Hour {
		v.add("signing.key_validity must be between 1d and 50y")
	}
	c.validateDefaults(v)
	if c.Audit.RetentionDays < 1 {
		v.add("audit.retention_days must be at least 1")
	}
	c.validateRecipients(v)
	c.validateAgents(v)
}

func (c *Config) validateListenTLS(v *validator) {
	a := &c.API
	if _, _, err := net.SplitHostPort(a.Listen); err != nil {
		v.add("api.listen: %v", err)
	}
	if a.TLS.Enabled() {
		if a.TLS.CertFile == "" || a.TLS.KeyFile == "" {
			v.add("api.tls: both cert_file and key_file are required")
		} else if cert, err := tls.LoadX509KeyPair(c.Path(a.TLS.CertFile), c.Path(a.TLS.KeyFile)); err != nil {
			v.add("api.tls: %v", err)
		} else {
			a.Certificate = &cert
		}
	}
}

func (c *Config) validateAPISettings(v *validator) {
	a := &c.API
	if a.Docs != "public" && a.Docs != "authenticated" {
		v.add("api.docs must be public or authenticated")
	}
	// Assigned, not appended: a Config is validated again after every save.
	var nets []netip.Prefix
	for _, p := range a.TrustedProxies {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				v.add("api.trusted_proxies: %q is not an IP or CIDR", p)
				continue
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		nets = append(nets, pfx.Masked())
	}
	a.TrustedNets = nets
	if a.PublicURL != "" {
		u, err := url.Parse(a.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			v.add("api.public_url must be an absolute http(s) URL")
		} else {
			a.PublicURL = strings.TrimRight(a.PublicURL, "/")
			if u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) && !a.TLS.Enabled() && !a.ExternalTransportEncryption {
				v.warn("api.public_url %s is plain HTTP on a non-localhost host: agent tokens and (because signing needs plaintext) message content cross the network unencrypted. Use TLS (api.tls or a TLS reverse proxy) or an encrypted tunnel with external_transport_encryption: true", a.PublicURL)
			}
		}
	}
}

func (c *Config) validateDashboard(v *validator) {
	d := &c.Dashboard
	if _, _, err := net.SplitHostPort(d.Listen); err != nil {
		v.add("dashboard.listen: %v", err)
	}
}

// UpstreamNotConfigured is the warning for a missing upstream host or From
// address.
const UpstreamNotConfigured = "upstream SMTP is not configured: set it on the Settings page"

// SMTPPasswordMissing is the warning for a username without a password.
const SMTPPasswordMissing = "upstream SMTP has a username but no password: enter it on the Settings page"

// validateUpstream checks the upstream settings. A missing host, from
// address or password is only a warning: a fresh install starts without
// them and the operator sets them on the dashboard; sends fail until then.
func (c *Config) validateUpstream(v *validator) {
	s := &c.Upstream.SMTP
	if s.Host == "" || c.Upstream.From == "" {
		v.warn(UpstreamNotConfigured)
	}
	if s.Host != "" && !validHost(s.Host) {
		v.add("upstream.smtp.host must be a hostname or IP address, without a port")
	}
	if s.Port < 1 || s.Port > 65535 {
		v.add("upstream.smtp.port must be 1-65535")
	}
	if s.Timeout.D() <= 0 {
		v.add("upstream.smtp.timeout must be positive")
	}
	switch s.Security {
	case "starttls", "tls":
	case "none":
		if s.Host != "" && !IsLoopbackHost(s.Host) {
			v.add("upstream.smtp.security none is only allowed to localhost")
		}
	default:
		v.add("upstream.smtp.security must be starttls, tls or none")
	}
	if s.Username != "" && s.Password == "" {
		v.warn(SMTPPasswordMissing)
	}
	if c.Upstream.From != "" {
		if a, err := mail.ParseAddress(c.Upstream.From); err != nil || a.Name != "" {
			v.add("upstream.from must be a bare email address")
		}
	}
	if strings.ContainsAny(c.Upstream.FromNameTemplate, "\r\n") {
		v.add("upstream.from_name_template must not contain line breaks")
	}
}

// validateRecipients checks the recipients and parses their keys. None is
// fine: recipients can be added on the dashboard. A key that has expired
// since it was added is only a warning: sends that need it fail until it is
// replaced.
func (c *Config) validateRecipients(v *validator) {
	now := time.Now()
	for _, alias := range sortedKeys(c.Recipients) {
		r := c.Recipients[alias]
		if r == nil {
			v.add("recipients.%s is empty", alias)
			continue
		}
		r.Alias, r.Key = alias, nil
		if !AliasPattern.MatchString(alias) {
			v.add("recipients: alias %q must match %s", alias, AliasPattern)
		}
		if a, err := mail.ParseAddress(r.Address); err != nil || a.Name != "" {
			v.add("recipients.%s.address must be a bare email address", alias)
		}
		validateDescription(v, "recipients."+alias, r.Description)
		if r.PGPPublicKey == "" {
			if r.RequireEncryption {
				v.add("recipients.%s.require_encryption needs pgp_public_key (nothing could ever be delivered)", alias)
			}
			continue
		}
		e, err := pgp.ReadPublicKey([]byte(r.PGPPublicKey))
		switch {
		case err != nil:
			v.add("recipients.%s.pgp_public_key: %v", alias, err)
		case e.PrivateKey != nil:
			v.add("recipients.%s.pgp_public_key is a private key; use the public key (gpg --export --armor)", alias)
		default:
			r.Key = e
			if err := pgp.CheckEncryptionKey(e, now); err != nil {
				v.warn("recipient %s: %v; encrypted sends to it fail until the key is replaced", alias, err)
			}
		}
	}
}

// validateAgents checks the agents and their policies. A policy alias that
// names no recipient is only a warning: it is ignored.
func (c *Config) validateAgents(v *validator) {
	signing := c.SigningConfigured()
	for _, name := range sortedKeys(c.Agents) {
		a := c.Agents[name]
		if a == nil {
			// An agent with nothing set: every field has a default.
			a = &Agent{}
			c.Agents[name] = a
		}
		a.Name = name
		if !AliasPattern.MatchString(name) {
			v.add("agents: name %q must match %s", name, AliasPattern)
		}
		validateDescription(v, "agents."+name, a.Description)
		for _, e := range a.Policy.Validate() {
			v.add("agents.%s.policy: %s", name, e)
		}
		for _, e := range a.Policy.Apply(c.DefaultPolicy).ValidateEffective(signing) {
			v.add("agents.%s.policy: %s", name, e)
		}
		if u := c.UnknownAliases(a.Policy); len(u) > 0 {
			v.warn("agent %s: its policy names recipients that do not exist and are ignored: %s", name, strings.Join(u, ", "))
		}
	}
}

func validateDescription(v *validator, key, d string) {
	if utf8.RuneCountInString(d) > MaxDescription {
		v.add("%s.description must be at most %d characters", key, MaxDescription)
	}
	if strings.ContainsAny(d, "\r\n") {
		v.add("%s.description must be a single line", key)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// validateKEK reads the key-encryption keys. An empty kek.file means no
// KEK, which turns signing off; a missing or empty previous_file means none,
// so it can stay configured between rotations. Signing is available exactly
// when a KEK is.
func (c *Config) validateKEK(v *validator) {
	k := &c.KEK
	if raw, err := os.ReadFile(c.Path(k.File)); err != nil {
		v.add("kek.file: %v", err)
	} else if len(bytes.TrimSpace(raw)) > 0 {
		if k.Key, err = ParseKEK(raw); err != nil {
			v.add("kek.file: %v", err)
		}
	}
	raw, err := os.ReadFile(c.Path(k.PreviousFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		v.add("kek.previous_file: %v", err)
	case len(bytes.TrimSpace(raw)) > 0:
		if k.Previous, err = ParseKEK(raw); err != nil {
			v.add("kek.previous_file: %v", err)
		}
	}
	if k.Previous != nil && k.Key == nil {
		v.add("kek.previous_file is set but kek.file is empty: a rotation needs the new KEK in kek.file")
	}
}

func (c *Config) validateDefaults(v *validator) {
	p := c.Defaults.Policy
	for _, e := range p.Validate() {
		v.add("defaults.policy: %s", e)
	}
	signing := c.SigningConfigured()
	if p.RequireSigning != nil && *p.RequireSigning && !signing {
		v.add("defaults.policy.require_signing is true but signing is not configured")
	}
	eff := p.Apply(policy.Builtin(signing))
	if eff.RequireSigning && eff.HasService(policy.SvcE2E) {
		v.add("defaults.policy: require_signing and the e2e service are mutually exclusive (the gateway cannot sign ciphertext it cannot read)")
	}
	c.DefaultPolicy = eff
	if u := c.UnknownAliases(p); len(u) > 0 {
		v.warn("defaults.policy.recipients names recipients that do not exist and are ignored: %s", strings.Join(u, ", "))
	}
}

// Recipient returns the recipient with this alias.
func (c *Config) Recipient(alias string) (*Recipient, bool) {
	r, ok := c.Recipients[alias]
	return r, ok && r != nil
}

// RecipientList returns every recipient, sorted by alias.
func (c *Config) RecipientList() []*Recipient {
	out := make([]*Recipient, 0, len(c.Recipients))
	for _, a := range sortedKeys(c.Recipients) {
		out = append(out, c.Recipients[a])
	}
	return out
}

// Aliases returns the recipient aliases, sorted.
func (c *Config) Aliases() []string { return sortedKeys(c.Recipients) }

// Agent returns the agent with this name.
func (c *Config) Agent(name string) (*Agent, bool) {
	a, ok := c.Agents[name]
	return a, ok && a != nil
}

// AgentList returns every agent, sorted by name.
func (c *Config) AgentList() []*Agent {
	out := make([]*Agent, 0, len(c.Agents))
	for _, n := range sortedKeys(c.Agents) {
		out = append(out, c.Agents[n])
	}
	return out
}

// AgentNames returns the agent names, sorted.
func (c *Config) AgentNames() []string { return sortedKeys(c.Agents) }

// Effective resolves an agent's partial policy against the default policy,
// dropping aliases that name no recipient.
func (c *Config) Effective(p policy.Policy) policy.Effective {
	e := p.Apply(c.DefaultPolicy)
	kept := make([]string, 0, len(e.Recipients))
	for _, a := range e.Recipients {
		if _, ok := c.Recipient(a); ok && !slices.Contains(kept, a) {
			kept = append(kept, a)
		}
	}
	e.Recipients = kept
	return e
}

// UnknownAliases returns the aliases a partial policy names that are not
// recipients.
func (c *Config) UnknownAliases(p policy.Policy) []string {
	var out []string
	if p.Recipients != nil {
		for _, a := range *p.Recipients {
			if _, ok := c.Recipient(a); !ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// ReferencingAgents returns the agents whose own policy names alias. Agents
// that inherit the default recipients are not included.
func (c *Config) ReferencingAgents(alias string) []*Agent {
	var out []*Agent
	for _, a := range c.AgentList() {
		if a.Policy.Recipients != nil && slices.Contains(*a.Policy.Recipients, alias) {
			out = append(out, a)
		}
	}
	return out
}

// ParseKEK accepts 64 hex characters, base64 of 32 bytes, or 32 raw bytes.
func ParseKEK(raw []byte) ([]byte, error) {
	s := strings.TrimSpace(string(raw))
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if len(raw) == 32 {
		return raw, nil
	}
	return nil, errors.New("must contain 32 random bytes as 64 hex characters (openssl rand -hex 32), base64, or raw bytes")
}

// validHost reports whether host looks like a hostname or IP address (no
// port, scheme or whitespace).
func validHost(host string) bool {
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return true
	}
	return !strings.ContainsAny(host, ":/ \t\r\n[]@")
}

// IsLoopbackHost reports whether a hostname (no port) is localhost or a loopback IP.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}
