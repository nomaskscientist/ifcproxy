package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

const validPolicy = `version: 1
max_args_bytes: 4096
tools:
  fetch_url: {produces: [untrusted], sink: external}
  read_file: {produces: [private]}
  send_email: {sink: external}
  echo:
rules:
  - tool: send_email
    when: [private]
    action: ask
    reason: private data leaving via email
  - tool: sink:external
    when: [untrusted, private]
    action: deny
    reason: lethal trifecta
`

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(validPolicy), "p.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxArgsBytes != 4096 {
		t.Errorf("MaxArgsBytes = %d", p.MaxArgsBytes)
	}
	if len(p.Tools) != 4 || len(p.Rules) != 2 {
		t.Fatalf("tools=%d rules=%d", len(p.Tools), len(p.Rules))
	}
	fi, ok := p.ToolIndex("fetch_url")
	if !ok || p.Tools[fi].Produces != taint.Untrusted || !p.Tools[fi].Sink {
		t.Errorf("fetch_url = %+v", p.Tools[fi])
	}
	if _, ok := p.ToolIndex("FETCH_URL"); ok {
		t.Error("lookup must be case-sensitive")
	}
	si, _ := p.ToolIndex("send_email")
	if got := p.Match(si, taint.Private); got != 0 {
		t.Errorf("send_email/private matched %d", got)
	}
	if got := p.Match(si, taint.Untrusted); got != -1 {
		t.Errorf("send_email/untrusted matched %d", got)
	}
	if got := p.Match(fi, taint.Known); got != 1 {
		t.Errorf("fetch_url/all matched %d", got)
	}
	if p.Rules[1].Line != 13 {
		t.Errorf("rule line = %d", p.Rules[1].Line)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string // substring of the error, including location
	}{
		{"empty", "", "p.yaml:1:1: policy is empty"},
		{"syntax", "tools: [\n", "p.yaml:"},
		{"not mapping", "- a\n", "expected a mapping"},
		{"unknown root field", "tools: {a: {}}\nrulez: []\n", "p.yaml:2:1: rulez: unknown field"},
		{"missing tools", "rules: []\n", "tools: required field is missing"},
		{"no tools", "tools: {}\n", "at least one tool must be declared"},
		{"bad version", "version: 2\ntools: {a: {}}\n", "1:10: version: unsupported version"},
		{"bad max args", "max_args_bytes: -1\ntools: {a: {}}\n", "max_args_bytes: must be an integer"},
		{"unknown label", "tools:\n  a: {produces: [secret]}\n", "2:18: tools.a.produces[0]: unknown label \"secret\""},
		{"label case", "tools:\n  a: {produces: [Untrusted]}\n", "unknown label \"Untrusted\""},
		{"duplicate label", "tools:\n  a: {produces: [private, private]}\n", "duplicate label"},
		{"bad sink", "tools:\n  a: {sink: internet}\n", "tools.a.sink: unknown sink"},
		{"unknown tool field", "tools:\n  a: {produce: [private]}\n", "tools.a.produce: unknown field"},
		{"bad tool name", "tools:\n  \"send email\": {}\n", "invalid character ' '"},
		{"case-ambiguous tools", "tools:\n  Send: {}\n  send: {}\n", "differs from \"Send\" only by case"},
		{"duplicate tool", "tools:\n  a: {}\n  a: {}\n", "3:3: tools.a: duplicate key"},
		{"rule unknown tool", "tools: {a: {}}\nrules:\n  - {tool: b, action: deny}\n", "3:12: rules[0].tool: unknown tool \"b\""},
		{"rule tool case hint", "tools: {abc: {}}\nrules:\n  - {tool: ABC, action: deny}\n", "did you mean \"abc\""},
		{"rule bad action", "tools: {a: {}}\nrules:\n  - {tool: a, action: alow}\n", "rules[0].action: unknown action \"alow\""},
		{"rule missing action", "tools: {a: {}}\nrules:\n  - {tool: a}\n", "rules[0].action: required field is missing"},
		{"rule missing tool", "tools: {a: {}}\nrules:\n  - {action: deny}\n", "rules[0].tool: required field is missing"},
		{"rule unknown field", "tools: {a: {}}\nrules:\n  - {tool: a, action: deny, whn: [private]}\n", "rules[0].whn: unknown field"},
		{"rules not list", "tools: {a: {}}\nrules: {tool: a}\n", "rules: expected a list"},
		{"anchor", "tools:\n  a: &x {}\n  b: *x\n", "anchors and aliases are not supported"},
		{"tag", "tools:\n  a: !!map {}\n", "explicit YAML tags are not supported"},
		{"two docs", "tools: {a: {}}\n---\ntools: {b: {}}\n", "exactly one YAML document"},
		{"uncovered sink", "tools:\n  s: {sink: external}\n", "2:1: tools.s: external sink has no rule"},
		{"wildcard allow sink", "tools:\n  s: {sink: external}\nrules:\n  - {tool: \"*\", action: allow}\n", "rules[0]: wildcard allow would let external sink \"s\""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src), "p.yaml")
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			var errs *Errors
			if !errors.As(err, &errs) {
				t.Fatalf("error type %T", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestExplicitAllowForSinkIsAccepted(t *testing.T) {
	src := "tools:\n  s: {sink: external}\nrules:\n  - {tool: s, action: allow, reason: reviewed exception}\n"
	if _, err := Parse([]byte(src), "p.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestReportsAllErrors(t *testing.T) {
	src := "tools:\n  a: {produces: [x]}\n  b: {sink: y}\nrules:\n  - {tool: c, action: z}\n"
	_, err := Parse([]byte(src), "p.yaml")
	var errs *Errors
	if !errors.As(err, &errs) || len(errs.List) != 4 {
		t.Fatalf("want 4 errors, got %v", err)
	}
}

func TestDefaultReason(t *testing.T) {
	p, err := Parse([]byte("tools: {a: {}}\nrules:\n  - {tool: a, action: deny}\n"), "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.Rules[0].Reason != "rules[0] (deny)" {
		t.Fatalf("reason %q", p.Rules[0].Reason)
	}
}

func TestActionZeroValueIsDeny(t *testing.T) {
	var a Action
	if a != Deny || a.String() != "deny" {
		t.Fatal("zero Action must be deny")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(validPolicy))
	f.Add([]byte("tools: {a: {}}\n"))
	f.Add([]byte("tools:\n  a: &x {}\n  b: *x\n"))
	f.Add([]byte("rules: [{tool: '*', when: [untrusted], action: ask}]\ntools: {x: {produces: [private]}}\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data, "fuzz")
		if err != nil {
			var errs *Errors
			if !errors.As(err, &errs) || len(errs.List) == 0 {
				t.Fatalf("error without locations: %v", err)
			}
			for _, fe := range errs.List {
				if fe.Line < 0 || fe.Column < 0 {
					t.Fatalf("bad location %+v", fe)
				}
			}
			return
		}
		if len(p.Tools) == 0 || p.MaxArgsBytes <= 0 {
			t.Fatalf("invalid compiled policy accepted: %+v", p)
		}
		for i, tool := range p.Tools {
			if j, ok := p.ToolIndex(tool.Name); !ok || j != i {
				t.Fatalf("index mismatch for %q", tool.Name)
			}
			if checkToolName(tool.Name) != "" {
				t.Fatalf("invalid tool name accepted: %q", tool.Name)
			}
			if tool.Sink {
				ri := p.Match(i, taint.Known)
				if ri < 0 || (p.Rules[ri].Action == Allow && p.Rules[ri].Tool != tool.Name) {
					t.Fatalf("uncovered sink %q accepted", tool.Name)
				}
			}
			for _, ri := range tool.rules {
				r := p.Rules[ri]
				if r.Tool != tool.Name && r.Tool != SelectAll && !(r.Tool == SelectSink && tool.Sink) {
					t.Fatalf("rule %d wrongly attached to %q", ri, tool.Name)
				}
			}
		}
		for _, r := range p.Rules {
			if r.When&^taint.Known != 0 || r.Action > Ask {
				t.Fatalf("bad rule %+v", r)
			}
		}
	})
}
