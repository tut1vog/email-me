// Package policy defines per-agent authorization policies and how agent
// overrides combine with configured defaults into an effective policy.
package policy

import (
	"fmt"
	"mime"
	"slices"
	"strings"

	"github.com/tut1vog/email-me/internal/units"
)

// Services an agent may be granted.
const (
	SvcMarkdown    = "markdown"
	SvcHTML        = "html"
	SvcAttachments = "attachments"
	SvcEncrypt     = "encrypt"
	SvcE2E         = "e2e"
	SvcSign        = "sign"
	SvcThread      = "thread"
	SvcPriority    = "priority"
)

// AllServices lists every service in display order.
var AllServices = []string{SvcMarkdown, SvcHTML, SvcAttachments, SvcEncrypt, SvcE2E, SvcSign, SvcThread, SvcPriority}

// RateLimit caps successful sends per rolling hour and day.
type RateLimit struct {
	PerHour int `yaml:"per_hour" json:"per_hour"`
	PerDay  int `yaml:"per_day" json:"per_day"`
}

// Policy is a partial policy: nil fields inherit from the next layer
// (agent override → configured defaults → built-in defaults).
type Policy struct {
	Recipients             *[]string       `yaml:"recipients" json:"recipients,omitempty"`
	Services               *[]string       `yaml:"services" json:"services,omitempty"`
	MaxMessageBytes        *units.ByteSize `yaml:"max_message_bytes" json:"max_message_bytes,omitempty"`
	MaxAttachments         *int            `yaml:"max_attachments" json:"max_attachments,omitempty"`
	AllowedAttachmentTypes *[]string       `yaml:"allowed_attachment_types" json:"allowed_attachment_types,omitempty"`
	RateLimit              *RateLimit      `yaml:"rate_limit" json:"rate_limit,omitempty"`
	SubjectPrefix          *string         `yaml:"subject_prefix" json:"subject_prefix,omitempty"`
	RequireEncryption      *bool           `yaml:"require_encryption" json:"require_encryption,omitempty"`
	RequireSigning         *bool           `yaml:"require_signing" json:"require_signing,omitempty"`
}

// Effective is a fully resolved policy.
type Effective struct {
	Recipients             []string
	Services               []string
	MaxMessageBytes        int64
	MaxAttachments         int
	AllowedAttachmentTypes []string
	RateLimit              RateLimit
	SubjectPrefix          string
	RequireEncryption      bool
	RequireSigning         bool
}

// Builtin returns the built-in defaults. Signing is on by default when the
// gateway has signing configured.
func Builtin(signingConfigured bool) Effective {
	services := []string{SvcMarkdown, SvcAttachments, SvcThread}
	if signingConfigured {
		services = append(services, SvcSign)
	}
	return Effective{
		Recipients:             []string{},
		Services:               services,
		MaxMessageBytes:        10 << 20,
		MaxAttachments:         10,
		AllowedAttachmentTypes: []string{},
		RateLimit:              RateLimit{PerHour: 20, PerDay: 100},
		SubjectPrefix:          "[{agent}] ",
		RequireEncryption:      false,
		RequireSigning:         signingConfigured,
	}
}

// Apply overlays p onto base.
func (p Policy) Apply(base Effective) Effective {
	e := base
	if p.Recipients != nil {
		e.Recipients = slices.Clone(*p.Recipients)
	}
	if p.Services != nil {
		e.Services = slices.Clone(*p.Services)
	}
	if p.MaxMessageBytes != nil {
		e.MaxMessageBytes = int64(*p.MaxMessageBytes)
	}
	if p.MaxAttachments != nil {
		e.MaxAttachments = *p.MaxAttachments
	}
	if p.AllowedAttachmentTypes != nil {
		e.AllowedAttachmentTypes = slices.Clone(*p.AllowedAttachmentTypes)
	}
	if p.RateLimit != nil {
		e.RateLimit = *p.RateLimit
	}
	if p.SubjectPrefix != nil {
		e.SubjectPrefix = *p.SubjectPrefix
	}
	if p.RequireEncryption != nil {
		e.RequireEncryption = *p.RequireEncryption
	}
	if p.RequireSigning != nil {
		e.RequireSigning = *p.RequireSigning
	}
	// require_signing implies the sign service.
	if e.RequireSigning && !slices.Contains(e.Services, SvcSign) {
		e.Services = append(e.Services, SvcSign)
	}
	return e
}

// Validate checks a partial policy's own fields.
func (p Policy) Validate() []string {
	var errs []string
	if p.Services != nil {
		for _, s := range *p.Services {
			if !slices.Contains(AllServices, s) {
				errs = append(errs, fmt.Sprintf("unknown service %q (valid: %s)", s, strings.Join(AllServices, ", ")))
			}
		}
	}
	if p.MaxMessageBytes != nil && *p.MaxMessageBytes <= 0 {
		errs = append(errs, "max_message_bytes must be positive")
	}
	if p.MaxAttachments != nil && *p.MaxAttachments < 0 {
		errs = append(errs, "max_attachments must not be negative")
	}
	if p.AllowedAttachmentTypes != nil {
		for _, t := range *p.AllowedAttachmentTypes {
			if !validTypePattern(t) {
				errs = append(errs, fmt.Sprintf("invalid attachment type pattern %q (use type/subtype or type/*)", t))
			}
		}
	}
	if p.RateLimit != nil && (p.RateLimit.PerHour <= 0 || p.RateLimit.PerDay <= 0) {
		errs = append(errs, "rate_limit.per_hour and rate_limit.per_day must be positive")
	}
	if p.SubjectPrefix != nil && strings.ContainsAny(*p.SubjectPrefix, "\r\n") {
		errs = append(errs, "subject_prefix must not contain line breaks")
	}
	return errs
}

// ValidateEffective checks cross-field rules on a resolved policy.
func (e Effective) ValidateEffective(signingConfigured bool) []string {
	var errs []string
	if e.RequireSigning && !signingConfigured {
		errs = append(errs, "require_signing is true but signing is not configured on this gateway")
	}
	if e.RequireSigning && e.HasService(SvcE2E) {
		errs = append(errs, "require_signing and the e2e service are mutually exclusive: the gateway cannot sign ciphertext it cannot read. Set require_signing to false for agents that need e2e")
	}
	return errs
}

// HasService reports whether the service is granted.
func (e Effective) HasService(s string) bool { return slices.Contains(e.Services, s) }

// AllowsRecipient reports whether the alias is granted.
func (e Effective) AllowsRecipient(alias string) bool { return slices.Contains(e.Recipients, alias) }

// Prefix renders the subject prefix for an agent.
func (e Effective) Prefix(agent string) string {
	return strings.ReplaceAll(e.SubjectPrefix, "{agent}", agent)
}

// AllowsAttachmentType reports whether a content type matches the allowlist
// (an empty allowlist allows everything).
func (e Effective) AllowsAttachmentType(contentType string) bool {
	if len(e.AllowedAttachmentTypes) == 0 {
		return true
	}
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	for _, pat := range e.AllowedAttachmentTypes {
		pat = strings.ToLower(pat)
		if pat == mt {
			return true
		}
		if strings.HasSuffix(pat, "/*") && strings.HasPrefix(mt, strings.TrimSuffix(pat, "*")) {
			return true
		}
	}
	return false
}

func validTypePattern(t string) bool {
	parts := strings.Split(t, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[0] == "*" {
		return false
	}
	if parts[1] == "*" {
		return true
	}
	_, _, err := mime.ParseMediaType(t)
	return err == nil
}
