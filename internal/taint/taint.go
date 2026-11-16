// Package taint implements session-level information-flow labels.
//
// A Label is a bit mask. A Session accumulates labels monotonically: labels
// are only ever added, never removed, for the lifetime of the session. All
// Session methods are safe for concurrent use and do not allocate.
package taint

import (
	"strings"
	"sync/atomic"
)

// Label is a set of taint labels encoded as a bit mask.
type Label uint32

const (
	// Untrusted marks content that may have been written by a third party
	// (web pages, inbound e-mail, issue comments, ...): a prompt-injection source.
	Untrusted Label = 1 << iota
	// Private marks data the user would not want to leave the machine/tenant.
	Private
)

// None is the empty label set.
const None Label = 0

// Known is the union of all labels defined in v1.
const Known = Untrusted | Private

var labelNames = [...]struct {
	l    Label
	name string
}{
	{Untrusted, "untrusted"},
	{Private, "private"},
}

// Parse returns the label with the given canonical (lower-case) name.
func Parse(name string) (Label, bool) {
	for _, ln := range labelNames {
		if ln.name == name {
			return ln.l, true
		}
	}
	return None, false
}

// ValidNames lists the accepted label names, for error messages.
func ValidNames() []string {
	out := make([]string, 0, len(labelNames))
	for _, ln := range labelNames {
		out = append(out, ln.name)
	}
	return out
}

// Has reports whether l contains every label in m.
func (l Label) Has(m Label) bool { return l&m == m }

// Names returns the names of the labels in l in canonical order.
// Bits that do not correspond to a known label are reported as "unknown".
func (l Label) Names() []string {
	out := make([]string, 0, len(labelNames))
	for _, ln := range labelNames {
		if l&ln.l != 0 {
			out = append(out, ln.name)
		}
	}
	if l&^Known != 0 {
		out = append(out, "unknown")
	}
	return out
}

// String renders l as "a|b", or "none" for the empty set.
func (l Label) String() string {
	if l == None {
		return "none"
	}
	return strings.Join(l.Names(), "|")
}

// Session is the taint state of one proxied MCP session.
type Session struct {
	id   string
	bits atomic.Uint32
}

// NewSession returns an empty session with the given identifier.
func NewSession(id string) *Session { return &Session{id: id} }

// ID returns the session identifier.
func (s *Session) ID() string { return s.id }

// Labels returns a snapshot of the labels accumulated so far.
func (s *Session) Labels() Label { return Label(s.bits.Load()) }

// Add merges l into the session and returns the labels that were newly added
// by this call (None if all of l was already present).
func (s *Session) Add(l Label) Label {
	for {
		old := s.bits.Load()
		next := old | uint32(l)
		if next == old {
			return None
		}
		if s.bits.CompareAndSwap(old, next) {
			return Label(next &^ old)
		}
	}
}
