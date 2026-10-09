package config

import (
	"bytes"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is config.yaml as a YAML node tree, edited key by key: a save
// on the dashboard changes only the keys it changed, and the rest of the
// file, comments and order included, stays as the operator wrote it.
type Document struct {
	doc yaml.Node // a DocumentNode holding one MappingNode
	// spaced are the top-level keys a blank line preceded in the file, which
	// yaml.v3 drops; spacing is whether any was, so new sections follow suit.
	spaced  map[string]bool
	spacing bool
	had     map[string]bool // the top-level keys of the parsed file
}

// ParseDocument parses a config file for editing. An empty file is an
// empty mapping.
func ParseDocument(data []byte) (*Document, error) {
	d := &Document{}
	if err := yaml.Unmarshal(data, &d.doc); err != nil {
		return nil, err
	}
	if d.doc.Kind == 0 {
		d.doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if d.doc.Kind != yaml.DocumentNode || len(d.doc.Content) != 1 || d.doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config.yaml must be a mapping of sections")
	}
	d.spaced, d.had = map[string]bool{}, map[string]bool{}
	for i := 0; i+1 < len(d.root().Content); i += 2 {
		d.had[d.root().Content[i].Value] = true
	}
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		if !topLevelKey(l) {
			continue
		}
		j := i
		for j > 0 && strings.HasPrefix(lines[j-1], "#") {
			j--
		}
		if j > 0 && strings.TrimSpace(lines[j-1]) == "" {
			key, _, _ := strings.Cut(l, ":")
			d.spaced[key] = true
			d.spacing = true
		}
	}
	return d, nil
}

func (d *Document) root() *yaml.Node { return d.doc.Content[0] }

// Set sets the key at path to v, encoded as YAML, creating the mappings on
// the way. A mapping is merged into the current one key by key; a value that
// encodes the same as the current one is left as it is, and a replaced value
// keeps the old one's comments.
func (d *Document) Set(path []string, v any) error {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return err
	}
	d.SetNode(path, &n)
	return nil
}

// flowLists writes lists of scalars in flow style ([a, b]), as people
// write them by hand.
func flowLists(n *yaml.Node) {
	if n.Kind == yaml.SequenceNode {
		flow := true
		for _, c := range n.Content {
			flow = flow && c.Kind == yaml.ScalarNode
		}
		if flow {
			n.Style |= yaml.FlowStyle
		}
	}
	for _, c := range n.Content {
		flowLists(c)
	}
}

// SetNode is Set with an encoded value.
func (d *Document) SetNode(path []string, n *yaml.Node) {
	flowLists(n)
	m := d.root()
	for i, k := range path {
		idx := find(m, k)
		if i == len(path)-1 {
			if idx < 0 {
				appendPair(m, k, n)
				return
			}
			m.Content[idx+1] = merge(m.Content[idx+1], n)
			return
		}
		switch {
		case idx < 0:
			child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			appendPair(m, k, child)
			m = child
		case m.Content[idx+1].Kind != yaml.MappingNode:
			// A null (an empty section) or a scalar where a section belongs.
			child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			keepComments(child, m.Content[idx+1])
			m.Content[idx+1] = child
			m = child
		default:
			m = m.Content[idx+1]
		}
	}
}

// Delete removes the key at path, if present.
func (d *Document) Delete(path []string) {
	m := d.root()
	for i, k := range path {
		idx := find(m, k)
		if idx < 0 {
			return
		}
		if i == len(path)-1 {
			m.Content = append(m.Content[:idx], m.Content[idx+2:]...)
			return
		}
		if m = m.Content[idx+1]; m.Kind != yaml.MappingNode {
			return
		}
	}
}

// Bytes encodes the document. yaml.v3 drops blank lines, so they are put
// back before the top-level sections that had one, and new sections.
func (d *Document) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if len(d.root().Content) == 0 {
		return nil, nil
	}
	if err := enc.Encode(&d.doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return d.spaceSections(buf.Bytes()), nil
}

// spaceSections inserts a blank line before each top-level key that had
// one (or is new, if the file spaced its sections), and before the comment
// lines directly above it.
func (d *Document) spaceSections(data []byte) []byte {
	lines := strings.SplitAfter(string(data), "\n")
	var out []string
	for i, l := range lines {
		key, _, _ := strings.Cut(l, ":")
		if i > 0 && topLevelKey(l) && (d.spaced[key] || d.spacing && !d.had[key]) {
			j := len(out)
			for j > 0 && strings.HasPrefix(out[j-1], "#") {
				j--
			}
			if j > 0 && strings.TrimSpace(out[j-1]) != "" {
				out = append(out[:j], append([]string{"\n"}, out[j:]...)...)
			}
		}
		out = append(out, l)
	}
	return []byte(strings.Join(out, ""))
}

func topLevelKey(l string) bool {
	return l != "" && l[0] != ' ' && l[0] != '#' && l[0] != '-' && l[0] != '\n' && strings.Contains(l, ":")
}

// ValueAt encodes v and returns the node at path in it, or false when the
// path is absent (a field omitted when empty).
func ValueAt(v any, path []string) (*yaml.Node, bool, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, false, err
	}
	m := &n
	for _, k := range path {
		if m.Kind != yaml.MappingNode {
			return nil, false, nil
		}
		idx := find(m, k)
		if idx < 0 {
			return nil, false, nil
		}
		m = m.Content[idx+1]
	}
	return m, true, nil
}

// merge returns what replaces old with n: old itself, with n merged into it
// when both are mappings or left as it is when they encode the same, else
// n with old's comments.
func merge(old, n *yaml.Node) *yaml.Node {
	if old.Kind == yaml.MappingNode && n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i].Value, n.Content[i+1]
			if idx := find(old, k); idx >= 0 {
				old.Content[idx+1] = merge(old.Content[idx+1], v)
			} else {
				appendPair(old, k, v)
			}
		}
		for i := 0; i+1 < len(old.Content); {
			if find(n, old.Content[i].Value) < 0 {
				old.Content = append(old.Content[:i], old.Content[i+2:]...)
				continue
			}
			i += 2
		}
		if len(old.Content) == 0 {
			old.Style = n.Style
		}
		return old
	}
	if render(old) == render(n) {
		return old
	}
	keepComments(n, old)
	return n
}

// find returns the index of key k in mapping m, or -1.
func find(m *yaml.Node, k string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return i
		}
	}
	return -1
}

func appendPair(m *yaml.Node, k string, v *yaml.Node) {
	// An empty mapping written as {} would otherwise stay in flow style.
	m.Style &^= yaml.FlowStyle
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
}

func keepComments(n, old *yaml.Node) {
	if n.HeadComment == "" {
		n.HeadComment = old.HeadComment
	}
	if n.LineComment == "" {
		n.LineComment = old.LineComment
	}
	if n.FootComment == "" {
		n.FootComment = old.FootComment
	}
}

// render encodes a node without its comments, to compare values.
func render(n *yaml.Node) string {
	cp := *n
	cp.HeadComment, cp.LineComment, cp.FootComment = "", "", ""
	b, err := yaml.Marshal(&cp)
	if err != nil {
		return ""
	}
	return string(b)
}
