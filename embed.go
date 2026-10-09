// Package emailme holds the project's files that the binary embeds.
package emailme

import _ "embed"

// ExampleConfig is config.example.yaml, the annotated starter configuration
// that `email-me start` writes on its first run.
//
//go:embed config.example.yaml
var ExampleConfig []byte
