// Package policy parses, validates and compiles ifcproxy YAML policies.
//
// Policy format (v1):
//
//	version: 1                 # optional, must be 1
//	max_args_bytes: 1048576    # optional, calls with larger arguments are denied
//	tools:
//	  fetch_url: {produces: [untrusted], sink: external}
//	  read_file: {produces: [private]}
//	  send_email: {sink: external}
//	  echo: {}
//	rules:
//	  - tool: sink:external          # a tool name, "*" or "sink:external"
//	    when: [untrusted, private]   # all listed labels must be present in the session
//	    action: deny                 # allow | deny | ask
//	    reason: lethal trifecta
//
// Rules are evaluated in file order; the first rule whose tool selector
// matches and whose "when" labels are all present in the session decides.
// A declared tool with no matching rule is allowed; an undeclared tool is denied.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

// Action is the outcome of a rule. The zero value is Deny so that an
// uninitialised Action fails closed.
type Action uint8

const (
	Deny Action = iota
	Allow
	Ask
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Ask:
		return "ask"
	default:
		return "deny"
	}
}

// Rule selectors that are not tool names.
const (
	SelectAll  = "*"
	SelectSink = "sink:external"
)

// DefaultMaxArgsBytes is used when the policy does not set max_args_bytes.
const DefaultMaxArgsBytes = 1 << 20

const (
	maxPolicyBytes = 1 << 20
	maxToolName    = 128
	maxArgsLimit   = 1 << 30
)

// Rule is a compiled policy rule.
type Rule struct {
	Index  int    // position in the rules list (0-based)
	Line   int    // line in the policy file
	Tool   string // tool name, SelectAll or SelectSink
	When   taint.Label
	Action Action
	Reason string
}

// Tool is a compiled tool declaration.
type Tool struct {
	Name     string
	Line     int
	Produces taint.Label
	Sink     bool
	rules    []int32 // indices into Policy.Rules that apply to this tool, in order
}

// Policy is an immutable compiled policy. It is safe for concurrent use.
type Policy struct {
	Source       string
	MaxArgsBytes int
	Tools        []Tool
	Rules        []Rule
	index        map[string]int32
}

// ToolIndex returns the index in p.Tools of the tool with exactly this name.
// It does not allocate.
func (p *Policy) ToolIndex(name string) (int, bool) {
	i, ok := p.index[name]
	return int(i), ok
}

// Match returns the index of the first rule for tool ti whose labels are all
// contained in labels, or -1. It does not allocate.
func (p *Policy) Match(ti int, labels taint.Label) int {
	for _, ri := range p.Tools[ti].rules {
		if labels&p.Rules[ri].When == p.Rules[ri].When {
			return int(ri)
		}
	}
	return -1
}

// FieldError is a validation error located in the policy source.
type FieldError struct {
	Line, Column int
	Path         string // e.g. rules[2].action
	Msg          string
}

func (e *FieldError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("%d:%d: %s", e.Line, e.Column, e.Msg)
	}
	return fmt.Sprintf("%d:%d: %s: %s", e.Line, e.Column, e.Path, e.Msg)
}

// Errors is the list of all problems found in a policy.
type Errors struct {
	Source string
	List   []*FieldError
}

func (e *Errors) Error() string {
	var b strings.Builder
	for i, fe := range e.List {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(e.Source)
		b.WriteByte(':')
		b.WriteString(fe.Error())
	}
	return b.String()
}

// Load reads and parses the policy file at path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data, path)
}

// Parse parses and validates a policy. source is used in error messages.
func Parse(data []byte, source string) (*Policy, error) {
	ps := &parser{errs: &Errors{Source: source}}
	if len(data) > maxPolicyBytes {
		ps.errAt(1, 1, "", "policy is larger than %d bytes", maxPolicyBytes)
		return nil, ps.errs
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			ps.errAt(1, 1, "", "policy is empty")
		} else {
			ps.errAt(yamlErrLine(err), 1, "", "%s", strings.TrimPrefix(err.Error(), "yaml: "))
		}
		return nil, ps.errs
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		line := extra.Line
		if err != nil {
			line = yamlErrLine(err)
		}
		ps.errAt(line, 1, "", "policy must contain exactly one YAML document")
		return nil, ps.errs
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		ps.errAt(doc.Line, doc.Column, "", "policy must be a YAML mapping")
		return nil, ps.errs
	}
	if !ps.checkPlain(doc.Content[0], "") {
		return nil, ps.errs
	}
	p := ps.parseRoot(doc.Content[0], source)
	if len(ps.errs.List) > 0 {
		return nil, ps.errs
	}
	return p, nil
}

type parser struct {
	errs *Errors
}

func (ps *parser) errAt(line, col int, path, format string, args ...any) {
	ps.errs.List = append(ps.errs.List, &FieldError{Line: line, Column: col, Path: path, Msg: fmt.Sprintf(format, args...)})
}

func (ps *parser) err(n *yaml.Node, path, format string, args ...any) {
	ps.errAt(n.Line, n.Column, path, format, args...)
}

// checkPlain rejects YAML features that make policies hard to audit or can
// be abused (anchors/aliases enable exponential expansion; custom tags change
// value interpretation).
func (ps *parser) checkPlain(n *yaml.Node, path string) bool {
	ok := true
	var walk func(n *yaml.Node, depth int)
	walk = func(n *yaml.Node, depth int) {
		if depth > 64 {
			ps.err(n, path, "nesting too deep")
			ok = false
			return
		}
		if n.Kind == yaml.AliasNode || n.Anchor != "" {
			ps.err(n, path, "YAML anchors and aliases are not supported")
			ok = false
			return
		}
		if n.Style&yaml.TaggedStyle != 0 {
			ps.err(n, path, "explicit YAML tags are not supported")
			ok = false
			return
		}
		for _, c := range n.Content {
			walk(c, depth+1)
		}
	}
	walk(n, 0)
	return ok
}

type kv struct{ k, v *yaml.Node }

// mapping returns the key/value pairs of a mapping node, reporting unknown
// keys (if allowed != nil), duplicate keys and non-scalar keys.
func (ps *parser) mapping(n *yaml.Node, path string, allowed []string) ([]kv, bool) {
	if n.Kind != yaml.MappingNode {
		ps.err(n, path, "expected a mapping, got %s", kindName(n))
		return nil, false
	}
	out := make([]kv, 0, len(n.Content)/2)
	seen := make(map[string]bool, len(n.Content)/2)
	ok := true
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			ps.err(k, path, "mapping keys must be scalars")
			ok = false
			continue
		}
		if seen[k.Value] {
			ps.err(k, join(path, k.Value), "duplicate key")
			ok = false
			continue
		}
		seen[k.Value] = true
		if allowed != nil && !contains(allowed, k.Value) {
			ps.err(k, join(path, k.Value), "unknown field (allowed: %s)", strings.Join(allowed, ", "))
			ok = false
			continue
		}
		out = append(out, kv{k, v})
	}
	return out, ok
}

func (ps *parser) scalar(n *yaml.Node, path string) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		ps.err(n, path, "expected a scalar, got %s", kindName(n))
		return "", false
	}
	return n.Value, true
}

func (ps *parser) labels(n *yaml.Node, path string) (taint.Label, bool) {
	if isNull(n) {
		return taint.None, true
	}
	if n.Kind != yaml.SequenceNode {
		ps.err(n, path, "expected a list of labels, e.g. [untrusted, private]")
		return taint.None, false
	}
	var l taint.Label
	ok := true
	for i, c := range n.Content {
		ep := fmt.Sprintf("%s[%d]", path, i)
		s, sok := ps.scalar(c, ep)
		if !sok {
			ok = false
			continue
		}
		v, vok := taint.Parse(s)
		if !vok {
			ps.err(c, ep, "unknown label %q (allowed: %s)", s, strings.Join(taint.ValidNames(), ", "))
			ok = false
			continue
		}
		if l&v != 0 {
			ps.err(c, ep, "duplicate label %q", s)
			ok = false
			continue
		}
		l |= v
	}
	return l, ok
}

func (ps *parser) parseRoot(root *yaml.Node, source string) *Policy {
	p := &Policy{Source: source, MaxArgsBytes: DefaultMaxArgsBytes, index: map[string]int32{}}
	pairs, _ := ps.mapping(root, "", []string{"version", "max_args_bytes", "tools", "rules"})
	var toolsNode, rulesNode *yaml.Node
	for _, e := range pairs {
		switch e.k.Value {
		case "version":
			if s, ok := ps.scalar(e.v, "version"); ok && s != "1" {
				ps.err(e.v, "version", "unsupported version %q (only 1 is supported)", s)
			}
		case "max_args_bytes":
			s, ok := ps.scalar(e.v, "max_args_bytes")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(s)
			if err != nil || n <= 0 || n > maxArgsLimit {
				ps.err(e.v, "max_args_bytes", "must be an integer in 1..%d", maxArgsLimit)
				continue
			}
			p.MaxArgsBytes = n
		case "tools":
			toolsNode = e.v
		case "rules":
			rulesNode = e.v
		}
	}
	if toolsNode == nil {
		ps.err(root, "tools", "required field is missing")
		return p
	}
	ps.parseTools(p, toolsNode)
	if rulesNode != nil {
		ps.parseRules(p, rulesNode)
	}
	if len(ps.errs.List) == 0 {
		ps.compile(p)
		ps.checkSinkCoverage(p)
	}
	return p
}

func (ps *parser) parseTools(p *Policy, n *yaml.Node) {
	pairs, _ := ps.mapping(n, "tools", nil)
	if n.Kind == yaml.MappingNode && len(pairs) == 0 && len(n.Content) == 0 {
		ps.err(n, "tools", "at least one tool must be declared")
	}
	folded := map[string]string{}
	for _, e := range pairs {
		name := e.k.Value
		path := "tools." + name
		if msg := checkToolName(name); msg != "" {
			ps.err(e.k, path, "%s", msg)
			continue
		}
		lower := strings.ToLower(name)
		if prev, dup := folded[lower]; dup {
			ps.err(e.k, path, "tool name differs from %q only by case; names must be unambiguous", prev)
			continue
		}
		folded[lower] = name
		t := Tool{Name: name, Line: e.k.Line}
		if !isNull(e.v) {
			fields, _ := ps.mapping(e.v, path, []string{"produces", "sink"})
			for _, f := range fields {
				switch f.k.Value {
				case "produces":
					t.Produces, _ = ps.labels(f.v, path+".produces")
				case "sink":
					s, ok := ps.scalar(f.v, path+".sink")
					if !ok {
						continue
					}
					switch s {
					case "external":
						t.Sink = true
					case "none":
					default:
						ps.err(f.v, path+".sink", "unknown sink %q (allowed: external, none)", s)
					}
				}
			}
		}
		p.index[name] = int32(len(p.Tools))
		p.Tools = append(p.Tools, t)
	}
}

func (ps *parser) parseRules(p *Policy, n *yaml.Node) {
	if isNull(n) {
		return
	}
	if n.Kind != yaml.SequenceNode {
		ps.err(n, "rules", "expected a list of rules, got %s", kindName(n))
		return
	}
	for i, rn := range n.Content {
		path := fmt.Sprintf("rules[%d]", i)
		fields, _ := ps.mapping(rn, path, []string{"tool", "when", "action", "reason"})
		r := Rule{Index: i, Line: rn.Line}
		var haveTool, haveAction bool
		for _, f := range fields {
			fp := path + "." + f.k.Value
			switch f.k.Value {
			case "tool":
				s, ok := ps.scalar(f.v, fp)
				if !ok {
					continue
				}
				haveTool = true
				switch {
				case s == SelectAll || s == SelectSink:
				default:
					if _, known := p.index[s]; !known {
						if alt := caseMatch(p, s); alt != "" {
							ps.err(f.v, fp, "unknown tool %q (did you mean %q? names are case-sensitive)", s, alt)
						} else {
							ps.err(f.v, fp, "unknown tool %q (declare it under tools, or use %q / %q)", s, SelectAll, SelectSink)
						}
					}
				}
				r.Tool = s
			case "when":
				r.When, _ = ps.labels(f.v, fp)
			case "action":
				s, ok := ps.scalar(f.v, fp)
				if !ok {
					continue
				}
				haveAction = true
				switch s {
				case "allow":
					r.Action = Allow
				case "deny":
					r.Action = Deny
				case "ask":
					r.Action = Ask
				default:
					ps.err(f.v, fp, "unknown action %q (allowed: allow, deny, ask)", s)
				}
			case "reason":
				if s, ok := ps.scalar(f.v, fp); ok {
					r.Reason = s
				}
			}
		}
		if rn.Kind == yaml.MappingNode {
			if !haveTool {
				ps.err(rn, path+".tool", "required field is missing")
			}
			if !haveAction {
				ps.err(rn, path+".action", "required field is missing")
			}
		}
		if r.Reason == "" {
			r.Reason = fmt.Sprintf("rules[%d] (%s)", i, r.Action)
		}
		p.Rules = append(p.Rules, r)
	}
}

func (ps *parser) compile(p *Policy) {
	for ti := range p.Tools {
		t := &p.Tools[ti]
		for ri := range p.Rules {
			r := &p.Rules[ri]
			if r.Tool == t.Name || r.Tool == SelectAll || (r.Tool == SelectSink && t.Sink) {
				t.rules = append(t.rules, int32(ri))
			}
		}
	}
}

// checkSinkCoverage requires every external sink to have an explicit decision
// for a fully tainted session: either a deny/ask rule, or an allow rule that
// names the tool explicitly (a deliberate, reviewable exception). This stops
// a policy from silently allowing the lethal trifecta by omission.
func (ps *parser) checkSinkCoverage(p *Policy) {
	for ti := range p.Tools {
		t := &p.Tools[ti]
		if !t.Sink {
			continue
		}
		ri := p.Match(ti, taint.Known)
		path := "tools." + t.Name
		switch {
		case ri < 0:
			ps.errAt(t.Line, 1, path, "external sink has no rule for a session with [untrusted, private]; add a deny/ask rule (e.g. tool: %s) or an explicit allow rule naming this tool", SelectSink)
		case p.Rules[ri].Action == Allow && p.Rules[ri].Tool != t.Name:
			ps.errAt(p.Rules[ri].Line, 1, fmt.Sprintf("rules[%d]", ri), "wildcard allow would let external sink %q run in a session with [untrusted, private]; add a deny/ask rule before it or an explicit allow rule naming the tool", t.Name)
		}
	}
}

// checkToolName enforces the MCP tool-name character set (1-128 chars of
// A-Z a-z 0-9 _ - . /). Returns "" if valid.
func checkToolName(s string) string {
	if s == "" {
		return "tool name must not be empty"
	}
	if len(s) > maxToolName {
		return fmt.Sprintf("tool name longer than %d characters", maxToolName)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '/') {
			return fmt.Sprintf("invalid character %q in tool name (allowed: A-Z a-z 0-9 _ - . /)", c)
		}
	}
	return ""
}

func caseMatch(p *Policy, s string) string {
	for _, t := range p.Tools {
		if strings.EqualFold(t.Name, s) {
			return t.Name
		}
	}
	return ""
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		if isNull(n) {
			return "null"
		}
		return fmt.Sprintf("scalar %q", n.Value)
	default:
		return "an unsupported node"
	}
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// yamlErrLine extracts the line number from a yaml.v3 syntax error message
// ("yaml: line 7: ..."), defaulting to 1.
func yamlErrLine(err error) int {
	msg := err.Error()
	i := strings.Index(msg, "line ")
	if i < 0 {
		return 1
	}
	j := i + len("line ")
	k := j
	for k < len(msg) && msg[k] >= '0' && msg[k] <= '9' {
		k++
	}
	n, convErr := strconv.Atoi(msg[j:k])
	if convErr != nil || n < 1 {
		return 1
	}
	return n
}
