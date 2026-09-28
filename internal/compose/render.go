package compose

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"golang.org/x/net/html"
)

var md = goldmark.New(
	// GFM, spelled out so tables can use align attributes (style attributes
	// are stripped by the sanitizer).
	goldmark.WithExtensions(
		extension.Linkify,
		extension.Strikethrough,
		extension.TaskList,
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute)),
	),
	// Raw HTML inside markdown is omitted (goldmark default, no WithUnsafe).
)

var sanitizer = func() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowStandardURLs()
	p.AllowURLSchemes("http", "https", "mailto")
	p.RequireParseableURLs(true)
	p.AllowAttrs("href").OnElements("a")
	p.AddTargetBlankToFullyQualifiedLinks(true)
	p.RequireNoReferrerOnLinks(true)
	p.AllowElements(
		"p", "br", "hr", "div", "span",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"strong", "b", "em", "i", "u", "s", "del", "ins", "mark", "small", "sub", "sup",
		"code", "pre", "kbd", "samp", "blockquote",
		"ul", "ol", "li", "dl", "dt", "dd",
		"table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
	)
	p.AllowAttrs("align").OnElements("th", "td")
	p.AllowAttrs("start").Matching(regexp.MustCompile(`^[0-9]+$`)).OnElements("ol")
	// GFM task lists.
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
	p.AllowAttrs("checked", "disabled").OnElements("input")
	// No <img>: remote images are tracking beacons and are never allowed.
	return p
}()

// RenderMarkdown converts GitHub-flavored markdown to sanitized HTML.
func RenderMarkdown(src string) (string, error) {
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "", err
	}
	return SanitizeHTML(buf.String()), nil
}

// SanitizeHTML applies the strict email allowlist.
func SanitizeHTML(s string) string { return sanitizer.Sanitize(s) }

const stylesheet = `body{margin:0;padding:0}
.email-me{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#1f2328;max-width:760px;padding:16px}
.email-me pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
.email-me code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.email-me table{border-collapse:collapse;margin:8px 0}
.email-me th,.email-me td{border:1px solid #d0d7de;padding:4px 10px}
.email-me th{background:#f6f8fa}
.email-me blockquote{margin:0;padding-left:12px;border-left:4px solid #d0d7de;color:#59636e}`

// Document wraps sanitized body HTML in a minimal email document.
func Document(body string) string {
	return "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><style>" + stylesheet +
		"</style></head><body><div class=\"email-me\">\n" + body + "\n</div></body></html>\n"
}

var blockElems = map[string]bool{
	"p": true, "div": true, "br": true, "hr": true, "li": true, "tr": true, "table": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"pre": true, "blockquote": true, "ul": true, "ol": true, "dl": true, "dt": true, "dd": true,
}

var multiBlank = regexp.MustCompile(`\n{3,}`)

// HTMLToText derives a readable plain-text alternative from HTML.
func HTMLToText(s string) string {
	z := html.NewTokenizer(strings.NewReader(s))
	var b strings.Builder
	var pre, skip int
	var href []string
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			out := multiBlank.ReplaceAllString(b.String(), "\n\n")
			return strings.TrimSpace(out) + "\n"
		case html.TextToken:
			if skip > 0 {
				continue
			}
			t := string(z.Text())
			if pre == 0 {
				t = strings.Join(strings.Fields(t), " ")
				if t == "" {
					continue
				}
				if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") && !strings.HasSuffix(b.String(), " ") {
					b.WriteByte(' ')
				}
			}
			b.WriteString(t)
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			name, hasAttr := z.TagName()
			tag := string(name)
			start := tt != html.EndTagToken
			switch tag {
			case "style", "script", "head", "title":
				if tt == html.StartTagToken {
					skip++
				} else if tt == html.EndTagToken && skip > 0 {
					skip--
				}
				continue
			case "pre":
				if tt == html.StartTagToken {
					pre++
				} else if tt == html.EndTagToken && pre > 0 {
					pre--
				}
			case "a":
				if start {
					link := ""
					for hasAttr {
						var k, v []byte
						k, v, hasAttr = z.TagAttr()
						if string(k) == "href" {
							link = string(v)
						}
					}
					href = append(href, link)
				} else if n := len(href); n > 0 {
					if l := href[n-1]; l != "" && !strings.HasPrefix(l, "mailto:") {
						b.WriteString(" <" + l + ">")
					}
					href = href[:n-1]
				}
				continue
			}
			if blockElems[tag] {
				if !strings.HasSuffix(b.String(), "\n") && b.Len() > 0 {
					b.WriteByte('\n')
				}
				if start && tag == "li" {
					b.WriteString("- ")
				}
				if !start && (tag == "p" || tag == "table" || tag == "pre" || tag == "blockquote" || strings.HasPrefix(tag, "h")) {
					b.WriteByte('\n')
				}
			} else if tag == "td" || tag == "th" {
				if !start {
					b.WriteString(" |")
				}
			}
		}
	}
}
