// Package config loads and validates config.yaml and the files it
// references. Validation collects every problem so the operator can fix them
// in one pass.
//
// Keys are of two kinds. Bootstrap keys (listen addresses, TLS, the
// key-encryption key, log) are read from config.yaml on every start and validated by
// Parse. Managed keys (see Settings) live in the state database and are
// edited on the dashboard; their sections in config.yaml only seed an empty
// database, and are validated then by ValidateSeed.
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/units"
)

// AliasPattern is the syntax of recipient aliases and agent names.
var AliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type Config struct {
	DataDir    string                `yaml:"data_dir"`
	API        API                   `yaml:"api"`
	Dashboard  Dashboard             `yaml:"dashboard"`
	Upstream   Upstream              `yaml:"upstream"`
	Recipients map[string]*Recipient `yaml:"recipients"`
	KEK        KEK                   `yaml:"kek"`
	Signing    *Signing              `yaml:"signing"`
	Defaults   Defaults              `yaml:"defaults"`
	Audit      Audit                 `yaml:"audit"`
	Log        Log                   `yaml:"log"`

	// DefaultPolicy is built-in defaults overlaid with defaults.policy.
	DefaultPolicy policy.Effective `yaml:"-"`
	// Warnings are non-fatal problems to log at startup and show on the dashboard.
	Warnings []string `yaml:"-"`
	// Fingerprint identifies the config.yaml that Load read (see
	// FileFingerprint), so a later change to the file can be detected.
	Fingerprint string `yaml:"-"`
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
	Listen     string         `yaml:"listen"`
	SessionTTL units.Duration `yaml:"session_ttl"`
}

type Upstream struct {
	SMTP             SMTP   `yaml:"smtp" json:"smtp"`
	From             string `yaml:"from" json:"from"`
	FromNameTemplate string `yaml:"from_name_template" json:"from_name_template"`
}

// SMTP is the upstream server. The password is never in config.yaml nor
// part of the stored settings document: it is entered on the dashboard and
// kept sealed in its own column.
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

// Recipient is a recipients: entry. Entries are seeds: they are inserted
// into the state database only when it has no recipients (first boot) and
// ignored otherwise. Recipients are managed from the dashboard.
type Recipient struct {
	Address           string `yaml:"address"`
	Description       string `yaml:"description"`
	PGPPublicKeyFile  string `yaml:"pgp_public_key_file"`
	RequireEncryption bool   `yaml:"require_encryption"`

	// PublicKeyArmor is the key file's key, re-armored canonically.
	PublicKeyArmor string `yaml:"-"`
}

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

// Signing is the signing section. It is set exactly when a KEK is
// configured, which is what signing needs.
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
func (c *Config) SigningConfigured() bool { return c.Signing != nil && c.KEK.Configured() }

// FromName renders the From display name for an agent.
func (c *Config) FromName(agent string) string {
	return strings.ReplaceAll(c.Upstream.FromNameTemplate, "{agent}", agent)
}

// Load reads, defaults and validates a config file and all referenced secrets.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, err
	}
	c.Fingerprint = fingerprint(data)
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
	return fingerprint(data), nil
}

func fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Parse is Load without the file read (the files it names are still read).
// It validates the bootstrap keys only; managed keys are decoded (they may
// seed the state database) but not defaulted or checked: see ValidateSeed
// and ValidateManaged.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	c.applyBootstrapDefaults()
	v := &validator{}
	c.validateBootstrap(v)
	if len(v.errs) > 0 {
		return nil, &ValidationError{Problems: v.errs}
	}
	c.Warnings = append(c.Warnings, v.warns...)
	return &c, nil
}

// ValidateManaged applies defaults to the managed settings and validates
// them, collecting every problem. It also sets the derived fields
// (API.TrustedNets, DefaultPolicy) and normalizes values (public_url loses
// its trailing slash). Warnings are returned, not added to c.Warnings.
func (c *Config) ValidateManaged() (problems, warnings []string) {
	c.ApplyManagedDefaults()
	v := &validator{}
	c.validateManaged(v)
	return v.errs, v.warns
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
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.API.Listen == "" {
		c.API.Listen = "0.0.0.0:8025"
	}
	if c.Dashboard.Listen == "" {
		c.Dashboard.Listen = "0.0.0.0:8026"
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
	if c.Dashboard.SessionTTL == 0 {
		c.Dashboard.SessionTTL = units.Duration(12 * time.Hour)
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
	if c.Signing != nil && c.Signing.KeyValidity == 0 {
		c.Signing.KeyValidity = units.Duration(2 * 365 * 24 * time.Hour)
	}
	if c.Audit.RetentionDays == 0 {
		c.Audit.RetentionDays = 30
	}
}

// validateBootstrap checks the keys read from config.yaml on every start,
// and the recipient seeds.
func (c *Config) validateBootstrap(v *validator) {
	c.validateListenTLS(v)
	c.validateDashboard(v)
	c.validateRecipients(v)
	c.validateKEK(v)
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level) {
		v.add("log.level must be one of debug, info, warn, error")
	}
}

// validateManaged checks the settings managed on the dashboard.
func (c *Config) validateManaged(v *validator) {
	c.validateAPISettings(v)
	if c.Dashboard.SessionTTL.D() < time.Minute {
		v.add("dashboard.session_ttl must be at least 1m")
	}
	c.validateUpstream(v)
	if s := c.Signing; s != nil && (s.KeyValidity.D() < 24*time.Hour || s.KeyValidity.D() > 50*365*24*time.Hour) {
		v.add("signing.key_validity must be between 1d and 50y")
	}
	c.validateDefaults(v)
	if c.Audit.RetentionDays < 1 {
		v.add("audit.retention_days must be at least 1")
	}
}

func (c *Config) validateListenTLS(v *validator) {
	a := &c.API
	if _, _, err := net.SplitHostPort(a.Listen); err != nil {
		v.add("api.listen: %v", err)
	}
	if a.TLS.Enabled() {
		if a.TLS.CertFile == "" || a.TLS.KeyFile == "" {
			v.add("api.tls: both cert_file and key_file are required")
		} else if cert, err := tls.LoadX509KeyPair(a.TLS.CertFile, a.TLS.KeyFile); err != nil {
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

// validateRecipients checks the recipient seeds. None is fine: recipients
// can be added from the dashboard.
func (c *Config) validateRecipients(v *validator) {
	aliases := make([]string, 0, len(c.Recipients))
	for a := range c.Recipients {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		r := c.Recipients[alias]
		if r == nil {
			v.add("recipients.%s is empty", alias)
			continue
		}
		if !AliasPattern.MatchString(alias) {
			v.add("recipients: alias %q must match %s", alias, AliasPattern)
		}
		if a, err := mail.ParseAddress(r.Address); err != nil || a.Name != "" {
			v.add("recipients.%s.address must be a bare email address", alias)
		}
		if r.PGPPublicKeyFile != "" {
			data, err := os.ReadFile(r.PGPPublicKeyFile)
			if err != nil {
				v.add("recipients.%s.pgp_public_key_file: %v", alias, err)
				continue
			}
			e, err := pgp.ParsePublicKey(data)
			if err != nil {
				v.add("recipients.%s.pgp_public_key_file: %v", alias, err)
				continue
			}
			armored, err := pgp.ArmorPublic(e)
			if err != nil {
				v.add("recipients.%s.pgp_public_key_file: %v", alias, err)
				continue
			}
			r.PublicKeyArmor = armored
		} else if r.RequireEncryption {
			v.add("recipients.%s.require_encryption needs pgp_public_key_file (nothing could ever be delivered)", alias)
		}
	}
}

// validateKEK reads the key-encryption keys. An empty kek.file means no
// KEK, so compose can always mount the secret; a missing or empty
// previous_file means none, so it can stay configured between rotations.
// Signing is available exactly when a KEK is.
func (c *Config) validateKEK(v *validator) {
	k := &c.KEK
	if k.File != "" {
		if raw, err := os.ReadFile(k.File); err != nil {
			v.add("kek.file: %v", err)
		} else if len(bytes.TrimSpace(raw)) > 0 {
			if k.Key, err = ParseKEK(raw); err != nil {
				v.add("kek.file: %v", err)
			}
		}
	}
	if k.PreviousFile != "" {
		raw, err := os.ReadFile(k.PreviousFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			v.add("kek.previous_file: %v", err)
		case len(bytes.TrimSpace(raw)) > 0:
			if k.Previous, err = ParseKEK(raw); err != nil {
				v.add("kek.previous_file: %v", err)
			}
		}
	}
	if k.Previous != nil && k.Key == nil {
		v.add("kek.previous_file is set but kek.file is not: a rotation needs the new KEK in kek.file")
	}
	switch {
	case k.Key == nil:
		c.Signing = nil
	case c.Signing == nil:
		c.Signing = &Signing{}
	}
}

func (c *Config) validateDefaults(v *validator) {
	p := c.Defaults.Policy
	for _, e := range p.Validate() {
		v.add("defaults.policy: %s", e)
	}
	signing := c.Signing != nil
	if p.RequireSigning != nil && *p.RequireSigning && !signing {
		v.add("defaults.policy.require_signing is true but signing is not configured")
	}
	eff := p.Apply(policy.Builtin(signing))
	if eff.RequireSigning && eff.HasService(policy.SvcE2E) {
		v.add("defaults.policy: require_signing and the e2e service are mutually exclusive (the gateway cannot sign ciphertext it cannot read)")
	}
	c.DefaultPolicy = eff
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
