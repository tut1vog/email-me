package docs

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestGuideGolden(t *testing.T) {
	got := Guide("https://email-me.example.ts.net")
	const golden = "testdata/guide.golden.md"
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/api/docs -update)", err)
	}
	if got != string(want) {
		t.Fatal("rendered guide differs from testdata/guide.golden.md; review the change and run with -update")
	}
}

func TestGuideBudget(t *testing.T) {
	g := Guide("https://email-me.example.ts.net")
	// Rough token estimate: ~4 characters per token for English prose and code.
	if tokens := len(g) / 4; tokens > 1600 {
		t.Fatalf("guide is ~%d tokens; the design budget is ~1.5k", tokens)
	}
	if strings.Contains(g, "{{") {
		t.Fatal("unrendered template action")
	}
}

func TestOpenAPIJSONSetsServer(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(OpenAPIJSON("https://x.example"), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["servers"].([]any)[0].(map[string]any)["url"] != "https://x.example" {
		t.Fatal(doc["servers"])
	}
	// The shared spec map must not be mutated between calls.
	json.Unmarshal(OpenAPIJSON("https://y.example"), &doc)
	if doc["servers"].([]any)[0].(map[string]any)["url"] != "https://y.example" {
		t.Fatal("server URL leaked between calls")
	}
}
