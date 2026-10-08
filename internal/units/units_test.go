package units

import (
	"encoding/json"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestParseByteSize(t *testing.T) {
	cases := map[string]ByteSize{
		"10MiB": 10 << 20, "512KiB": 512 << 10, "1GiB": 1 << 30, "1MB": 1000000, "2K": 2048, "1024": 1024, "7B": 7, " 3 MiB ": 3 << 20,
	}
	for in, want := range cases {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("ParseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "MiB", "-1", "ten", "1XB"} {
		if _, err := ParseByteSize(bad); err == nil {
			t.Errorf("ParseByteSize(%q) should fail", bad)
		}
	}
	if s := ByteSize(10 << 20).String(); s != "10MiB" {
		t.Errorf("String() = %q", s)
	}
}

func TestByteSizeJSONAndYAML(t *testing.T) {
	var b ByteSize
	if err := json.Unmarshal([]byte(`"2MiB"`), &b); err != nil || b != 2<<20 {
		t.Fatalf("json string: %d %v", b, err)
	}
	if err := json.Unmarshal([]byte(`4096`), &b); err != nil || b != 4096 {
		t.Fatalf("json number: %d %v", b, err)
	}
	out, _ := json.Marshal(ByteSize(4096))
	if string(out) != "4096" {
		t.Fatalf("marshal = %s", out)
	}
	var y struct {
		S ByteSize `yaml:"s"`
	}
	if err := yaml.Unmarshal([]byte("s: 1MiB"), &y); err != nil || y.S != 1<<20 {
		t.Fatalf("yaml: %d %v", y.S, err)
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"30s": 30 * time.Second, "12h": 12 * time.Hour, "90d": 90 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "2y": 2 * 365 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got.D() != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got.D(), err, want)
		}
	}
	for _, bad := range []string{"", "d", "-3d", "soon"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) should fail", bad)
		}
	}
	if s := Duration(2 * 365 * 24 * time.Hour).String(); s != "2y" {
		t.Errorf("String() = %q", s)
	}
}

func TestDurationJSON(t *testing.T) {
	for _, d := range []Duration{0, Duration(30 * time.Second), Duration(90 * time.Minute), Duration(12 * time.Hour), Duration(90 * 24 * time.Hour), Duration(2 * 365 * 24 * time.Hour)} {
		out, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var back Duration
		if err := json.Unmarshal(out, &back); err != nil || back != d {
			t.Errorf("round trip %v via %s = %v, %v", d.D(), out, back.D(), err)
		}
	}
	if out, _ := json.Marshal(Duration(2 * 365 * 24 * time.Hour)); string(out) != `"2y"` {
		t.Fatalf("marshal = %s", out)
	}
	var d Duration
	if err := json.Unmarshal([]byte(`"90d"`), &d); err != nil || d.D() != 90*24*time.Hour {
		t.Fatalf("json string: %v %v", d.D(), err)
	}
	if err := json.Unmarshal([]byte(`1000000000`), &d); err != nil || d.D() != time.Second {
		t.Fatalf("json number: %v %v", d.D(), err)
	}
	for _, bad := range []string{`"soon"`, `-1`, `true`, `""`} {
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("Unmarshal(%s) should fail", bad)
		}
	}
}
