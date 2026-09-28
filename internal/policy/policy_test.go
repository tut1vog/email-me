package policy

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/units"
)

func ptr[T any](v T) *T { return &v }

func TestBuiltinSigningDefault(t *testing.T) {
	on := Builtin(true)
	if !on.RequireSigning || !on.HasService(SvcSign) {
		t.Fatal("signing must be on by default when configured")
	}
	off := Builtin(false)
	if off.RequireSigning || off.HasService(SvcSign) {
		t.Fatal("signing must be off when not configured")
	}
	if len(on.Recipients) != 0 {
		t.Fatal("no recipients by default")
	}
}

func TestApplyOverrides(t *testing.T) {
	base := Builtin(true)
	p := Policy{
		Recipients:      ptr([]string{"me"}),
		Services:        ptr([]string{SvcMarkdown}),
		MaxMessageBytes: ptr(units.ByteSize(1024)),
		RateLimit:       &RateLimit{PerHour: 1, PerDay: 2},
		RequireSigning:  ptr(false),
	}
	e := p.Apply(base)
	if !slices.Equal(e.Recipients, []string{"me"}) || e.MaxMessageBytes != 1024 || e.RateLimit.PerHour != 1 || e.RequireSigning {
		t.Fatalf("overrides not applied: %+v", e)
	}
	if e.HasService(SvcSign) {
		t.Fatal("services override should replace, not merge")
	}
	// Inherit when nil.
	e2 := Policy{}.Apply(base)
	if e2.MaxMessageBytes != base.MaxMessageBytes || !e2.RequireSigning {
		t.Fatal("nil fields must inherit")
	}
	// require_signing implies the sign service.
	e3 := Policy{Services: ptr([]string{SvcMarkdown}), RequireSigning: ptr(true)}.Apply(Builtin(false))
	if !e3.HasService(SvcSign) {
		t.Fatal("require_signing must imply the sign service")
	}
	// Empty override (not nil) clears.
	e4 := Policy{Recipients: ptr([]string{})}.Apply(Effective{Recipients: []string{"me"}})
	if len(e4.Recipients) != 0 {
		t.Fatal("empty override must clear")
	}
}

func TestPolicyJSONRoundTripKeepsInheritance(t *testing.T) {
	p := Policy{Recipients: ptr([]string{}), RequireSigning: ptr(false)}
	b, _ := json.Marshal(p)
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	if q.Recipients == nil || len(*q.Recipients) != 0 {
		t.Fatalf("empty recipients override lost: %s", b)
	}
	if q.Services != nil || q.MaxMessageBytes != nil {
		t.Fatalf("unset fields must stay nil: %s", b)
	}
	if q.RequireSigning == nil || *q.RequireSigning {
		t.Fatalf("explicit false lost: %s", b)
	}
}

func TestValidate(t *testing.T) {
	p := Policy{
		Services:               ptr([]string{"markdown", "fax"}),
		MaxMessageBytes:        ptr(units.ByteSize(0)),
		MaxAttachments:         ptr(-1),
		AllowedAttachmentTypes: ptr([]string{"text/*", "*/*", "bogus"}),
		RateLimit:              &RateLimit{PerHour: 0, PerDay: 1},
		SubjectPrefix:          ptr("a\nb"),
	}
	errs := p.Validate()
	joined := strings.Join(errs, "|")
	for _, want := range []string{"fax", "max_message_bytes", "max_attachments", "*/*", "bogus", "rate_limit", "line breaks"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing error about %q in %v", want, errs)
		}
	}
	if strings.Contains(joined, `"text/*"`) {
		t.Error("text/* is valid")
	}
}

func TestValidateEffectiveSigningRules(t *testing.T) {
	e := Builtin(true)
	e.Services = append(e.Services, SvcE2E)
	if errs := e.ValidateEffective(true); len(errs) != 1 || !strings.Contains(errs[0], "mutually exclusive") {
		t.Fatalf("require_signing + e2e must be rejected: %v", errs)
	}
	e.RequireSigning = false
	if errs := e.ValidateEffective(true); len(errs) != 0 {
		t.Fatalf("e2e without require_signing is fine: %v", errs)
	}
	s := Builtin(false)
	s.RequireSigning = true
	if errs := s.ValidateEffective(false); len(errs) == 0 {
		t.Fatal("require_signing without signing configured must be rejected")
	}
}

func TestAttachmentTypes(t *testing.T) {
	e := Effective{AllowedAttachmentTypes: []string{"text/*", "application/pdf"}}
	for ct, want := range map[string]bool{
		"text/csv": true, "text/plain; charset=utf-8": true, "application/pdf": true,
		"application/x-msdownload": false, "texty/plain": false, "garbage": false,
	} {
		if got := e.AllowsAttachmentType(ct); got != want {
			t.Errorf("AllowsAttachmentType(%q) = %v", ct, got)
		}
	}
	if !(Effective{}).AllowsAttachmentType("application/x-anything") {
		t.Error("empty allowlist allows everything")
	}
}

func TestPrefix(t *testing.T) {
	if got := (Effective{SubjectPrefix: "[{agent}] "}).Prefix("bench"); got != "[bench] " {
		t.Fatal(got)
	}
}
