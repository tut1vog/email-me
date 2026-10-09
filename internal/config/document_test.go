package config_test

import (
	"strings"
	"testing"

	emailme "github.com/tut1vog/email-me"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/policy"
)

func edit(t *testing.T, src string, f func(d *config.Document)) string {
	t.Helper()
	d, err := config.ParseDocument([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	f(d)
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The starter file comes back byte for byte, so a dashboard save changes
// only the lines it must.
func TestDocumentRoundTripsTheExample(t *testing.T) {
	if got := edit(t, string(emailme.ExampleConfig), func(*config.Document) {}); got != string(emailme.ExampleConfig) {
		t.Fatalf("the example does not round-trip:\n%s", got)
	}
}

func TestDocumentSet(t *testing.T) {
	src := `# header

upstream:
  smtp:
    # the server
    host: ""
    port: 587 # submission
  from: ""

recipients: {}
`
	got := edit(t, src, func(d *config.Document) {
		d.Set([]string{"upstream", "smtp", "host"}, "smtp.example.com")
		d.Set([]string{"upstream", "smtp", "port"}, 587) // unchanged: left as written
		d.Set([]string{"upstream", "smtp", "username"}, "me")
		d.Set([]string{"audit", "retention_days"}, 7)
		d.Set([]string{"recipients", "me"}, &config.Recipient{Address: "me@example.com"})
	})
	want := `# header

upstream:
  smtp:
    # the server
    host: smtp.example.com
    port: 587 # submission
    username: me
  from: ""

recipients:
  me:
    address: me@example.com

audit:
  retention_days: 7
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDocumentMergesEntries(t *testing.T) {
	src := `agents:
  # the nightly job
  nightly:
    # shown on the dashboard
    description: old
    policy:
      recipients: [me] # only me
      max_attachments: 3
  other:
    description: kept
`
	five := 5
	got := edit(t, src, func(d *config.Document) {
		d.Set([]string{"agents", "nightly"}, &config.Agent{Description: "new", Disabled: true,
			Policy: policy.Policy{Recipients: &[]string{"me", "work"}, MaxAttachments: &five}})
		d.Delete([]string{"agents", "missing"})
	})
	// A new key goes after the existing ones.
	want := `agents:
  # the nightly job
  nightly:
    # shown on the dashboard
    description: new
    policy:
      recipients: [me, work] # only me
      max_attachments: 5
    disabled: true
  other:
    description: kept
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	// Fields the new entry leaves out are removed; so is an entry.
	got = edit(t, got, func(d *config.Document) {
		d.Set([]string{"agents", "nightly"}, &config.Agent{})
		d.Delete([]string{"agents", "other"})
	})
	if want := "agents:\n  # the nightly job\n  nightly: {}\n"; got != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestDocumentEmptyAndInvalid(t *testing.T) {
	if got := edit(t, "", func(d *config.Document) { d.Set([]string{"log", "level"}, "debug") }); got != "log:\n  level: debug\n" {
		t.Fatalf("empty file: %q", got)
	}
	if got := edit(t, "agents:\n", func(d *config.Document) { d.Set([]string{"agents", "a", "description"}, "x") }); got != "agents:\n  a:\n    description: x\n" {
		t.Fatalf("null section: %q", got)
	}
	for _, bad := range []string{"- a\n- b\n", "just a string\n", "a: [\n"} {
		if _, err := config.ParseDocument([]byte(bad)); err == nil {
			t.Errorf("%q must not parse as a config document", bad)
		}
	}
}

func TestValueAt(t *testing.T) {
	ten := 10
	s := config.Settings{Defaults: config.Defaults{Policy: policy.Policy{MaxAttachments: &ten}}}
	if n, ok, err := config.ValueAt(s, strings.Split("defaults.policy.max_attachments", ".")); err != nil || !ok || n.Value != "10" {
		t.Fatalf("set field: %v %v %v", n, ok, err)
	}
	if _, ok, _ := config.ValueAt(s, strings.Split("defaults.policy.subject_prefix", ".")); ok {
		t.Fatal("an unset policy field is absent")
	}
}
