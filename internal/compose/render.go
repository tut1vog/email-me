package compose

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"
	"github.com/microcosm-cc/bluemonday/css"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"golang.org/x/net/html"
)

var md = goldmark.New(
	// GFM, spelled out so tables can use align attributes (style attributes
	// are stripped by the markdown sanitizer).
	goldmark.WithExtensions(
		extension.Linkify,
		extension.Strikethrough,
		extension.TaskList,
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute)),
	),
	// Raw HTML inside markdown is omitted (goldmark default, no WithUnsafe).
)

// basePolicy allows plain document structure and links, nothing that loads.
func basePolicy() *bluemonday.Policy {
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
	return p
}

// markdownPolicy is the strict allowlist for rendered markdown, which the
// gateway's stylesheet presents.
var markdownPolicy = func() *bluemonday.Policy {
	p := basePolicy()
	// GFM task lists.
	p.AllowAttrs("type").Matching(regexp.MustCompile(`^checkbox$`)).OnElements("input")
	p.AllowAttrs("checked", "disabled").OnElements("input")
	// No <img>: remote images are tracking beacons and are never allowed.
	return p
}()

// ContentIDPattern is what an inline image's content ID may look like.
var ContentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var (
	dimension = regexp.MustCompile(`^[0-9]{1,4}(%|px)?$`)
	number    = regexp.MustCompile(`^[0-9]{1,4}$`)
	colorAttr = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,20})$`)
	cidSrc    = regexp.MustCompile(`^(?i:cid):[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// htmlPolicy is the allowlist for agent-authored HTML such as newsletters:
// presentation (inline styles, legacy table layout) is allowed, anything that
// loads or acts is not. Images may only reference inline parts (cid:).
var htmlPolicy = func() *bluemonday.Policy {
	p := basePolicy()
	p.AllowElements("center", "font", "colgroup", "col",
		"section", "article", "header", "footer", "main", "figure", "figcaption")

	p.AllowURLSchemes("cid")
	p.AllowAttrs("src").Matching(cidSrc).OnElements("img")
	p.AllowAttrs("alt", "title").OnElements("img")
	p.AllowAttrs("width", "height").Matching(dimension).OnElements("img", "table", "tr", "td", "th", "col")
	p.AllowAttrs("border", "cellpadding", "cellspacing").Matching(number).OnElements("table", "img")
	p.AllowAttrs("colspan", "rowspan", "span").Matching(number).OnElements("td", "th", "col", "colgroup")
	p.AllowAttrs("bgcolor").Matching(colorAttr).OnElements("table", "tr", "td", "th")
	p.AllowAttrs("align").Matching(regexp.MustCompile(`^(?i:left|center|right|justify)$`)).
		OnElements("table", "tr", "img", "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "col")
	p.AllowAttrs("valign").Matching(regexp.MustCompile(`^(?i:top|middle|bottom|baseline)$`)).OnElements("tr", "td", "th", "col")
	p.AllowAttrs("color").Matching(colorAttr).OnElements("font")
	p.AllowAttrs("face").Matching(regexp.MustCompile(`^[A-Za-z0-9 ,'"-]{1,100}$`)).OnElements("font")
	p.AllowAttrs("size").Matching(regexp.MustCompile(`^[+-]?[1-7]$`)).OnElements("font")
	p.AllowAttrs("role").Matching(regexp.MustCompile(`^presentation$`)).OnElements("table")
	p.AllowAttrs("dir").Matching(regexp.MustCompile(`^(?i:ltr|rtl|auto)$`)).Globally()

	// Inline styles: typography, color, box and table properties, each value
	// checked by bluemonday's per-property validator. Nothing that takes a
	// url() (background-image, list-style-image, border-image, content,
	// cursor) and no positioning, so styles can neither load anything nor
	// overlay the message.
	p.AllowStyles(
		"color", "background-color",
		"font", "font-family", "font-size", "font-style", "font-variant", "font-weight",
		"line-height", "letter-spacing", "word-spacing",
		"text-align", "text-decoration", "text-indent", "text-transform",
		"vertical-align", "white-space", "word-break", "word-wrap", "overflow-wrap", "direction",
		"width", "min-width", "max-width", "height", "min-height", "max-height",
		"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
		"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
		"border", "border-top", "border-right", "border-bottom", "border-left",
		"border-color", "border-style", "border-width",
		"border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
		"border-top-style", "border-right-style", "border-bottom-style", "border-left-style",
		"border-top-width", "border-right-width", "border-bottom-width", "border-left-width",
		"border-radius", "border-top-left-radius", "border-top-right-radius",
		"border-bottom-left-radius", "border-bottom-right-radius",
		"border-collapse", "border-spacing", "table-layout",
		"display", "box-sizing", "float", "clear", "overflow", "opacity", "visibility",
		"list-style-type", "list-style-position",
	).Globally()
	// The background shorthand may also carry an image URL: allow colors only.
	p.AllowStyles("background").MatchingHandler(css.ColorHandler).Globally()
	return p
}()

// RenderMarkdown converts GitHub-flavored markdown to sanitized HTML.
func RenderMarkdown(src string) (string, error) {
	var buf bytes.Buffer
	if err := md.Convert([]byte(src), &buf); err != nil {
		return "", err
	}
	return markdownPolicy.Sanitize(buf.String()), nil
}

// SanitizeHTML applies the agent-HTML allowlist.
func SanitizeHTML(s string) string { return htmlPolicy.Sanitize(s) }

// ImageSources lists the src of every <img> in s, in order.
func ImageSources(s string) []string {
	z := html.NewTokenizer(strings.NewReader(s))
	var srcs []string
	for {
		switch z.Next() {
		case html.ErrorToken:
			return srcs
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "img" {
				continue
			}
			src := ""
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				if string(k) == "src" {
					src = strings.TrimSpace(string(v))
				}
			}
			srcs = append(srcs, src)
		}
	}
}

const stylesheet = `body{margin:0;padding:0}
.email-me{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#1f2328;max-width:760px;padding:16px}
.email-me pre{background:#f6f8fa;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
.email-me code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.email-me table{border-collapse:collapse;margin:8px 0}
.email-me th,.email-me td{border:1px solid #d0d7de;padding:4px 10px}
.email-me th{background:#f6f8fa}
.email-me blockquote{margin:0;padding-left:12px;border-left:4px solid #d0d7de;color:#59636e}`

// MarkdownDocument wraps rendered markdown in an email document styled by
// the gateway.
func MarkdownDocument(body string) string {
	return "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><style>" + stylesheet +
		"</style></head><body><div class=\"email-me\">\n" + body + "\n</div></body></html>\n"
}

// HTMLDocument wraps sanitized agent HTML in an email document without a
// stylesheet: the agent's inline styles are the presentation.
func HTMLDocument(body string) string {
	return "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"></head><body style=\"margin:0;padding:0\">\n" +
		body + "\n</body></html>\n"
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
