// Package monitor makes allow/deny/ask decisions for tool calls based on the
// compiled policy and the session's accumulated taint labels.
package monitor

import (
	"github.com/nomaskscientist/ifcproxy/internal/policy"
	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

// Code says why a decision was made.
type Code uint8

const (
	// Matched: a policy rule decided.
	Matched Code = iota
	// Default: the tool is declared and no rule matched; allowed.
	Default
	// UnknownTool: the tool is not declared in the policy; denied.
	UnknownTool
	// ArgsTooLarge: the arguments exceed max_args_bytes; denied.
	ArgsTooLarge
)

func (c Code) String() string {
	switch c {
	case Matched:
		return "rule"
	case Default:
		return "default-allow"
	case UnknownTool:
		return "unknown-tool"
	case ArgsTooLarge:
		return "args-too-large"
	default:
		return "invalid"
	}
}

// Fixed reasons for decisions that are not made by a rule.
const (
	ReasonUnknownTool  = "tool is not declared in the policy (default deny)"
	ReasonArgsTooLarge = "tool arguments exceed max_args_bytes"
	ReasonDefault      = "declared tool, no rule matched"
)

// Decision is the result of Decide. It contains no pointers into mutable
// state and is returned by value without allocation.
type Decision struct {
	Action policy.Action
	Code   Code
	Rule   int    // index into Policy.Rules, or -1
	Reason string // human-readable explanation
	Labels taint.Label
}

// Monitor evaluates a policy. It is immutable and safe for concurrent use.
type Monitor struct {
	p *policy.Policy
}

// New returns a monitor for p.
func New(p *policy.Policy) *Monitor { return &Monitor{p: p} }

// Policy returns the policy the monitor evaluates.
func (m *Monitor) Policy() *policy.Policy { return m.p }

// Decide returns the decision for calling tool with the given raw JSON
// arguments in session s. It is the hot path: it performs no allocation.
func (m *Monitor) Decide(s *taint.Session, tool string, args []byte) Decision {
	labels := s.Labels()
	ti, ok := m.p.ToolIndex(tool)
	if !ok {
		return Decision{Action: policy.Deny, Code: UnknownTool, Rule: -1, Reason: ReasonUnknownTool, Labels: labels}
	}
	if len(args) > m.p.MaxArgsBytes {
		return Decision{Action: policy.Deny, Code: ArgsTooLarge, Rule: -1, Reason: ReasonArgsTooLarge, Labels: labels}
	}
	if ri := m.p.Match(ti, labels); ri >= 0 {
		r := &m.p.Rules[ri]
		return Decision{Action: r.Action, Code: Matched, Rule: ri, Reason: r.Reason, Labels: labels}
	}
	return Decision{Action: policy.Allow, Code: Default, Rule: -1, Reason: ReasonDefault, Labels: labels}
}

// Produces returns the labels a result of tool carries. Unknown tools carry
// every known label: if such a result ever reaches the client (it should not,
// since unknown tools are denied), it is treated as maximally tainted.
func (m *Monitor) Produces(tool string) taint.Label {
	ti, ok := m.p.ToolIndex(tool)
	if !ok {
		return taint.Known
	}
	return m.p.Tools[ti].Produces
}

// Observe records that a result of tool is about to reach the client and
// returns the labels newly added to the session.
func (m *Monitor) Observe(s *taint.Session, tool string) taint.Label {
	return s.Add(m.Produces(tool))
}
