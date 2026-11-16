package monitor

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nomaskscientist/ifcproxy/internal/policy"
	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

const testPolicy = `
max_args_bytes: 64
tools:
  fetch_url:   {produces: [untrusted], sink: external}
  read_inbox:  {produces: [untrusted, private]}
  read_file:   {produces: [private]}
  summarize:   {}
  send_email:  {sink: external}
  post_issue:  {sink: external}
  delete_repo: {}
rules:
  - tool: delete_repo
    action: ask
    reason: destructive
  - tool: send_email
    when: [private]
    action: ask
    reason: private data may leave via email
  - tool: sink:external
    when: [untrusted, private]
    action: deny
    reason: lethal trifecta
`

func mustMonitor(t testing.TB, src string) *Monitor {
	t.Helper()
	p, err := policy.Parse([]byte(src), "test")
	if err != nil {
		t.Fatal(err)
	}
	return New(p)
}

func TestDecideScenarios(t *testing.T) {
	m := mustMonitor(t, testPolicy)
	tests := []struct {
		name     string
		observed []string // tool results already delivered to the client
		tool     string
		args     string
		action   policy.Action
		code     Code
		reason   string
	}{
		{"fresh session sink allowed", nil, "post_issue", `{}`, policy.Allow, Default, ReasonDefault},
		{"untrusted only", []string{"fetch_url"}, "post_issue", `{}`, policy.Allow, Default, ""},
		{"private only", []string{"read_file"}, "post_issue", `{}`, policy.Allow, Default, ""},
		{"trifecta fetch+read -> post", []string{"fetch_url", "read_file"}, "post_issue", `{}`, policy.Deny, Matched, "lethal trifecta"},
		{"trifecta order reversed", []string{"read_file", "fetch_url"}, "post_issue", `{}`, policy.Deny, Matched, "lethal trifecta"},
		{"trifecta via single tool", []string{"read_inbox"}, "fetch_url", `{}`, policy.Deny, Matched, "lethal trifecta"},
		{"fetch is itself a sink", []string{"read_file", "fetch_url"}, "fetch_url", `{}`, policy.Deny, Matched, "lethal trifecta"},
		{"chain through laundering tool", []string{"fetch_url", "summarize", "read_file", "summarize"}, "post_issue", `{}`, policy.Deny, Matched, ""},
		{"specific rule first: email ask", []string{"read_file"}, "send_email", `{}`, policy.Ask, Matched, "private data may leave via email"},
		{"email with full taint still ask (first match)", []string{"read_inbox"}, "send_email", `{}`, policy.Ask, Matched, ""},
		{"non-sink tool unaffected", []string{"read_inbox"}, "read_file", `{}`, policy.Allow, Default, ""},
		{"unconditional ask", nil, "delete_repo", `{}`, policy.Ask, Matched, "destructive"},
		{"unknown tool denied", nil, "rm_rf", `{}`, policy.Deny, UnknownTool, ReasonUnknownTool},
		{"case variant denied", nil, "Post_Issue", `{}`, policy.Deny, UnknownTool, ""},
		{"trailing space denied", nil, "post_issue ", `{}`, policy.Deny, UnknownTool, ""},
		{"empty name denied", nil, "", `{}`, policy.Deny, UnknownTool, ""},
		{"args too large", nil, "summarize", `{"x":"` + strings.Repeat("a", 64) + `"}`, policy.Deny, ArgsTooLarge, ReasonArgsTooLarge},
		{"args at limit ok", nil, "summarize", `{"x":"` + strings.Repeat("a", 56) + `"}`, policy.Allow, Default, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := taint.NewSession("t")
			for _, o := range tt.observed {
				m.Observe(s, o)
			}
			d := m.Decide(s, tt.tool, []byte(tt.args))
			if d.Action != tt.action || d.Code != tt.code {
				t.Fatalf("got %v/%v (%q), want %v/%v", d.Action, d.Code, d.Reason, tt.action, tt.code)
			}
			if tt.reason != "" && d.Reason != tt.reason {
				t.Fatalf("reason %q, want %q", d.Reason, tt.reason)
			}
			if d.Labels != s.Labels() {
				t.Fatalf("decision labels %v, session %v", d.Labels, s.Labels())
			}
			if (d.Code == Matched) != (d.Rule >= 0) {
				t.Fatalf("rule index %d inconsistent with code %v", d.Rule, d.Code)
			}
		})
	}
}

func TestDecideDoesNotChangeLabels(t *testing.T) {
	m := mustMonitor(t, testPolicy)
	s := taint.NewSession("t")
	m.Decide(s, "fetch_url", []byte(`{}`))
	m.Decide(s, "nope", nil)
	if s.Labels() != taint.None {
		t.Fatalf("Decide modified session: %v", s.Labels())
	}
}

func TestObserveUnknownToolIsMaximal(t *testing.T) {
	m := mustMonitor(t, testPolicy)
	s := taint.NewSession("t")
	if got := m.Observe(s, "nope"); got != taint.Known {
		t.Fatalf("added %v", got)
	}
}

func TestLabelsNeverDecrease(t *testing.T) {
	m := mustMonitor(t, testPolicy)
	s := taint.NewSession("t")
	prev := taint.None
	for _, tool := range []string{"summarize", "fetch_url", "summarize", "read_file", "delete_repo", "summarize"} {
		m.Observe(s, tool)
		if !s.Labels().Has(prev) {
			t.Fatalf("labels dropped from %v to %v", prev, s.Labels())
		}
		prev = s.Labels()
	}
}

// benchPolicy builds a policy of realistic size: n tools, a handful of rules
// per tool class plus wildcard rules, with the deciding rule last.
func benchPolicy(n int) string {
	var b strings.Builder
	b.WriteString("tools:\n")
	for i := 0; i < n; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "  tool_%d: {produces: [untrusted]}\n", i)
		case 1:
			fmt.Fprintf(&b, "  tool_%d: {produces: [private]}\n", i)
		case 2:
			fmt.Fprintf(&b, "  tool_%d: {sink: external}\n", i)
		default:
			fmt.Fprintf(&b, "  tool_%d: {}\n", i)
		}
	}
	b.WriteString("rules:\n")
	for i := 3; i < n; i += 4 {
		fmt.Fprintf(&b, "  - {tool: tool_%d, when: [untrusted, private], action: ask}\n", i)
	}
	b.WriteString("  - {tool: '*', when: [untrusted, private], action: ask}\n")
	b.WriteString("  - {tool: sink:external, when: [untrusted, private], action: deny, reason: trifecta}\n")
	return b.String()
}

func TestDecideZeroAlloc(t *testing.T) {
	m := mustMonitor(t, benchPolicy(64))
	s := taint.NewSession("b")
	s.Add(taint.Untrusted | taint.Private)
	args := []byte(`{"to":"a@example.com"}`)
	for _, tool := range []string{"tool_2", "tool_3", "tool_0", "unknown"} {
		n := testing.AllocsPerRun(1000, func() { _ = m.Decide(s, tool, args) })
		if n != 0 {
			t.Fatalf("Decide(%s) allocates %v times", tool, n)
		}
	}
}

// TestDecideP99 checks the latency budget: p99 of Decide < 50µs.
func TestDecideP99(t *testing.T) {
	if testing.Short() {
		t.Skip("latency test skipped in -short mode")
	}
	m := mustMonitor(t, benchPolicy(256))
	s := taint.NewSession("p99")
	s.Add(taint.Untrusted | taint.Private)
	args := []byte(`{"to":"a@example.com"}`)
	const n = 200000
	d := make([]time.Duration, n)
	tools := []string{"tool_2", "tool_255", "tool_0", "nope"}
	for i := range d {
		tool := tools[i&3]
		t0 := time.Now()
		_ = m.Decide(s, tool, args)
		d[i] = time.Since(t0)
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	p50, p99, max := d[n/2], d[n*99/100], d[n-1]
	t.Logf("Decide latency over %d calls: p50=%v p99=%v max=%v", n, p50, p99, max)
	if p99 >= 50*time.Microsecond {
		t.Fatalf("p99 %v exceeds 50µs budget", p99)
	}
}

func BenchmarkDecide(b *testing.B) {
	for _, n := range []int{8, 64, 256} {
		m := mustMonitor(b, benchPolicy(n))
		s := taint.NewSession("b")
		s.Add(taint.Untrusted | taint.Private)
		args := []byte(`{"to":"a@example.com","body":"hello"}`)
		sinkTool := fmt.Sprintf("tool_%d", n-2) // sink: falls through to the last rule
		b.Run(fmt.Sprintf("tools=%d/sink-deny", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = m.Decide(s, sinkTool, args)
			}
		})
		b.Run(fmt.Sprintf("tools=%d/unknown", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = m.Decide(s, "not_a_tool", args)
			}
		})
		b.Run(fmt.Sprintf("tools=%d/parallel", n), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = m.Decide(s, sinkTool, args)
				}
			})
		})
	}
}
