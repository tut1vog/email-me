// Package config loads and validates config.yaml and the secret files it
// references. Validation collects every problem so the operator can fix them
// in one pass.
//
// Keys are of two kinds. Bootstrap keys (listen addresses, TLS, secret
// files, log) are read from config.yaml on every start and validated by
// Parse. Managed keys (see Settings) live in the state database and are
// edited on the dashboard; their sections in config.yaml only seed an empty
// database, and are validated then by ValidateSeed.
package config

import (
	"bytes"
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

	"github.com/ProtonMail/go-crypto/openpgp"
	"gopkg.in/yaml.v3"

	"github.com/tut1vog/email-me/internal/auth"
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
	Signing    *Signing              `yaml:"signing"`
	Defaults   Defaults              `yaml:"defaults"`
	Audit      Audit                 `yaml:"audit"`
	Log        Log                   `yaml:"log"`

	// DefaultPolicy is built-in defaults overlaid with defaults.policy.
	DefaultPolicy policy.Effective `yaml:"-"`
	// Warnings are non-fatal problems to log at startup and show on the dashboard.
	Warnings []string `yaml:"-"`
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
	Listen            string         `yaml:"listen"`
	AdminPasswordFile string         `yaml:"admin_password_file"`
	SessionTTL        units.Duration `yaml:"session_ttl"`

	AdminPasswordHash string `yaml:"-"`
}

type Upstream struct {
	SMTP             SMTP   `yaml:"smtp" json:"smtp"`
	From             string `yaml:"from" json:"from"`
	FromNameTemplate string `yaml:"from_name_template" json:"from_name_template"`
}

// SMTP is the upstream server. The password is never part of the stored
// settings document: it is read from password_file when seeding and kept
// in its own column afterwards.
type SMTP struct {
	Host           string         `yaml:"host" json:"host"`
	Port           int            `yaml:"port" json:"port"`
	Security       string         `yaml:"security" json:"security"`
	Username       string         `yaml:"username" json:"username"`
	PasswordFile   string         `yaml:"password_file" json:"-"`
	Timeout        units.Duration `yaml:"timeout" json:"timeout"`
	AllowPlaintext bool           `yaml:"allow_plaintext" json:"allow_plaintext"`

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

type Signing struct {
	KeyEncryptionKeyFile string         `yaml:"key_encryption_key_file"`
	KeyValidity          units.Duration `yaml:"key_validity"`
	CertifyWith          *CertifyWith   `yaml:"certify_with"`

	KEK    []byte          `yaml:"-"`
	Master *openpgp.Entity `yaml:"-"`
}

type CertifyWith struct {
	PGPPrivateKeyFile string `yaml:"pgp_private_key_file"`
	PassphraseFile    string `yaml:"passphrase_file"`
}

type Defaults struct {
	Policy policy.Policy `yaml:"policy" json:"policy"`
}

type Audit struct {
	RetentionDays int  `yaml:"retention_days" json:"retention_days"`
	LogSubject    bool `yaml:"log_subject" json:"log_subject"`
}

type Log struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// SigningConfigured reports whether the sign service can work at all.
func (c *Config) SigningConfigured() bool { return c.Signing != nil && len(c.Signing.KEK) == 32 }

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
	return Parse(data)
}

// Parse is Load without the file read (secrets are still read from disk).
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
	c.validateManaged(v, false)
	return v.errs, v.warns
}

// ValidateSeed is ValidateManaged for the managed sections of config.yaml
// when they seed an empty state database: it also reads
// upstream.smtp.password_file into Upstream.SMTP.Password.
func (c *Config) ValidateSeed() (problems, warnings []string) {
	c.ApplyManagedDefaults()
	v := &validator{}
	c.validateManaged(v, true)
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
	if c.Log.Format == "" {
		c.Log.Format = "json"
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
	c.validateSigning(v)
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, c.Log.Level) {
		v.add("log.level must be one of debug, info, warn, error")
	}
	if !slices.Contains([]string{"json", "text"}, c.Log.Format) {
		v.add("log.format must be json or text")
	}
}

// validateManaged checks the settings managed on the dashboard. seed means
// they come from config.yaml, so the SMTP password is read from its file.
func (c *Config) validateManaged(v *validator, seed bool) {
	c.validateAPISettings(v)
	if c.Dashboard.SessionTTL.D() < time.Minute {
		v.add("dashboard.session_ttl must be at least 1m")
	}
	c.validateUpstream(v, seed)
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
	if d.AdminPasswordFile == "" {
		v.add("dashboard.admin_password_file is required")
		return
	}
	secret, err := readSecret(d.AdminPasswordFile)
	if err != nil {
		v.add("dashboard.admin_password_file: %v", err)
		return
	}
	if auth.IsArgon2Hash(secret) {
		if err := auth.ValidateHash(secret); err != nil {
			v.add("dashboard.admin_password_file: %v", err)
			return
		}
		d.AdminPasswordHash = secret
		return
	}
	if len([]rune(secret)) < 12 {
		v.add("dashboard.admin_password_file: password must be at least 12 characters")
		return
	}
	hash, err := auth.HashPassword(secret)
	if err != nil {
		v.add("dashboard.admin_password_file: hashing: %v", err)
		return
	}
	d.AdminPasswordHash = hash
}

// validateUpstream checks the upstream settings. A missing host or from
// address is only a warning: a fresh install starts without them and the
// operator sets them on the dashboard; sends fail until then.
func (c *Config) validateUpstream(v *validator, seed bool) {
	s := &c.Upstream.SMTP
	if s.Host == "" || c.Upstream.From == "" {
		v.warn("upstream SMTP is not configured: set it on the Settings page")
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
		if s.Host == "" || IsLoopbackHost(s.Host) {
			break
		}
		if !s.AllowPlaintext {
			v.add("upstream.smtp.security none is only allowed to localhost; set allow_plaintext: true to override (development only)")
		} else {
			v.warn("upstream.smtp uses plaintext SMTP to a non-localhost host (allow_plaintext: true); use this for development only")
		}
	default:
		v.add("upstream.smtp.security must be starttls, tls or none")
	}
	if s.Username != "" {
		switch {
		case !seed:
			if s.Password == "" {
				v.add("upstream.smtp.password is required when username is set")
			}
		case s.PasswordFile == "":
			v.add("upstream.smtp.password_file is required when username is set")
		default:
			if pw, err := readSecret(s.PasswordFile); err != nil {
				v.add("upstream.smtp.password_file: %v", err)
			} else {
				s.Password = pw
			}
		}
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

func (c *Config) validateSigning(v *validator) {
	s := c.Signing
	if s == nil {
		return
	}
	if s.KeyEncryptionKeyFile == "" {
		v.add("signing.key_encryption_key_file is required when signing is configured")
	} else if raw, err := os.ReadFile(s.KeyEncryptionKeyFile); err != nil {
		v.add("signing.key_encryption_key_file: %v", err)
	} else if kek, err := ParseKEK(raw); err != nil {
		v.add("signing.key_encryption_key_file: %v", err)
	} else {
		s.KEK = kek
	}
	if cw := s.CertifyWith; cw != nil {
		data, err := os.ReadFile(cw.PGPPrivateKeyFile)
		if err != nil {
			v.add("signing.certify_with.pgp_private_key_file: %v", err)
			return
		}
		var pass []byte
		if cw.PassphraseFile != "" {
			p, err := readSecret(cw.PassphraseFile)
			if err != nil {
				v.add("signing.certify_with.passphrase_file: %v", err)
				return
			}
			pass = []byte(p)
		}
		master, err := pgp.ParsePrivateKey(data, pass)
		if err != nil {
			v.add("signing.certify_with: %v", err)
			return
		}
		s.Master = master
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

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", errors.New("file is empty")
	}
	return s, nil
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
