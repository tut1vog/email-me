// Package docs embeds the agent guide and the OpenAPI document.
package docs

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"text/template"

	"gopkg.in/yaml.v3"
)

//go:embed guide.md.tmpl
var guideSrc string

//go:embed openapi.yaml
var openapiYAML []byte

var guideTmpl = template.Must(template.New("guide").Parse(guideSrc))

// Guide renders the agent guide for a base URL. The guide contains no
// deployment-specific data other than the base URL.
func Guide(baseURL string) string {
	var buf bytes.Buffer
	if err := guideTmpl.Execute(&buf, struct{ BaseURL string }{baseURL}); err != nil {
		panic(err) // template is static and tested
	}
	return buf.String()
}

// OpenAPIYAML returns the embedded spec source.
func OpenAPIYAML() []byte { return openapiYAML }

var spec = func() map[string]any {
	var m map[string]any
	if err := yaml.Unmarshal(openapiYAML, &m); err != nil {
		panic(fmt.Sprintf("docs: embedded openapi.yaml is invalid: %v", err))
	}
	return m
}()

// OpenAPIJSON returns the spec as JSON with its server URL set to baseURL.
func OpenAPIJSON(baseURL string) []byte {
	m := make(map[string]any, len(spec))
	for k, v := range spec {
		m[k] = v
	}
	m["servers"] = []any{map[string]any{"url": baseURL}}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("docs: encoding openapi: %v", err))
	}
	return b
}
