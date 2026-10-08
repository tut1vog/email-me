package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"

	"github.com/tut1vog/email-me/internal/units"
)

// Settings are the managed keys: stored in the state database as JSON,
// edited on the dashboard and applied on restart. Their sections in
// config.yaml only seed an empty database. The SMTP password is not part
// of the document (see SMTP).
type Settings struct {
	API       APISettings       `json:"api"`
	Dashboard DashboardSettings `json:"dashboard"`
	Upstream  Upstream          `json:"upstream"`
	Signing   SigningSettings   `json:"signing"`
	Defaults  Defaults          `json:"defaults"`
	Audit     Audit             `json:"audit"`
}

// APISettings are the managed keys of the api section.
type APISettings struct {
	PublicURL                   string   `json:"public_url"`
	Docs                        string   `json:"docs"`
	TrustedProxies              []string `json:"trusted_proxies,omitempty"`
	ExternalTransportEncryption bool     `json:"external_transport_encryption"`
}

// DashboardSettings are the managed keys of the dashboard section.
type DashboardSettings struct {
	SessionTTL units.Duration `json:"session_ttl"`
}

// SigningSettings are the managed keys of the signing section. They apply
// only while signing is configured (signing.key_encryption_key_file).
type SigningSettings struct {
	KeyValidity units.Duration `json:"key_validity"`
}

// Managed returns a copy of c's managed settings. The in-memory SMTP
// password is copied too; it is dropped only when encoding to JSON.
func (c *Config) Managed() Settings {
	s := Settings{
		API: APISettings{
			PublicURL:                   c.API.PublicURL,
			Docs:                        c.API.Docs,
			TrustedProxies:              c.API.TrustedProxies,
			ExternalTransportEncryption: c.API.ExternalTransportEncryption,
		},
		Dashboard: DashboardSettings{SessionTTL: c.Dashboard.SessionTTL},
		Upstream:  c.Upstream,
		Defaults:  c.Defaults,
		Audit:     c.Audit,
	}
	if c.Signing != nil {
		s.Signing.KeyValidity = c.Signing.KeyValidity
	}
	return s.Clone()
}

// SetManaged replaces every managed key of c with a copy of s. It never
// creates c.Signing: a nil Signing means signing is not configured, and
// s.Signing is then ignored. Derived fields (API.TrustedNets,
// DefaultPolicy) are refreshed by ValidateManaged.
func (c *Config) SetManaged(s Settings) {
	s = s.Clone()
	c.API.PublicURL = s.API.PublicURL
	c.API.Docs = s.API.Docs
	c.API.TrustedProxies = s.API.TrustedProxies
	c.API.ExternalTransportEncryption = s.API.ExternalTransportEncryption
	c.Dashboard.SessionTTL = s.Dashboard.SessionTTL
	c.Upstream = s.Upstream
	if c.Signing != nil {
		c.Signing.KeyValidity = s.Signing.KeyValidity
	}
	c.Defaults = s.Defaults
	c.Audit = s.Audit
}

// Clone returns a deep copy of s.
func (s Settings) Clone() Settings {
	s.API.TrustedProxies = slices.Clone(s.API.TrustedProxies)
	p := &s.Defaults.Policy
	p.Recipients = cloneStrings(p.Recipients)
	p.Services = cloneStrings(p.Services)
	p.MaxMessageBytes = clonePtr(p.MaxMessageBytes)
	p.MaxAttachments = clonePtr(p.MaxAttachments)
	p.AllowedAttachmentTypes = cloneStrings(p.AllowedAttachmentTypes)
	p.RateLimit = clonePtr(p.RateLimit)
	p.SubjectPrefix = clonePtr(p.SubjectPrefix)
	p.RequireEncryption = clonePtr(p.RequireEncryption)
	p.RequireSigning = clonePtr(p.RequireSigning)
	return s
}

// IsZero reports whether no managed key is set, e.g. a config.yaml that
// has only bootstrap keys.
func (s Settings) IsZero() bool { return reflect.ValueOf(s).IsZero() }

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStrings(p *[]string) *[]string {
	if p == nil {
		return nil
	}
	v := slices.Clone(*p)
	return &v
}

// DiffSettings returns the dotted keys (as in config.yaml, e.g.
// "upstream.smtp.port") whose values differ between a and b, sorted. A
// policy field set in one and inherited in the other differs. The SMTP
// password is not compared.
func DiffSettings(a, b Settings) []string {
	var out []string
	diffJSON("", jsonTree(a), jsonTree(b), &out)
	sort.Strings(out)
	return out
}

func jsonTree(s Settings) any {
	data, err := json.Marshal(s)
	if err != nil {
		panic(err) // Settings has no type that can fail to encode
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		panic(err)
	}
	return v
}

func diffJSON(key string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if !aok || !bok {
		if !reflect.DeepEqual(a, b) {
			*out = append(*out, key)
		}
		return
	}
	seen := map[string]bool{}
	for _, m := range []map[string]any{am, bm} {
		for k := range m {
			if seen[k] {
				continue
			}
			seen[k] = true
			sub := k
			if key != "" {
				sub = key + "." + k
			}
			diffJSON(sub, am[k], bm[k], out)
		}
	}
}
