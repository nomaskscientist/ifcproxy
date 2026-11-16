// Package audit defines audit events and a JSONL sink for them.
package audit

import (
	"encoding/json"
	"time"
)

// Event kinds.
const (
	KindCall   = "call"   // a tools/call request was decided
	KindTaint  = "taint"  // a server message added labels to the session
	KindReject = "reject" // a client message was rejected before any decision (malformed, ambiguous, ...)
	KindError  = "error"  // an internal error that affected enforcement (e.g. shared session file)
)

// Event is one audit record. Arguments are included only when the proxy
// runs with --log-args.
type Event struct {
	Time     time.Time       `json:"time"`
	Session  string          `json:"session"`
	Kind     string          `json:"event"`
	ID       json.RawMessage `json:"id,omitempty"`
	Tool     string          `json:"tool,omitempty"`
	Decision string          `json:"decision,omitempty"` // allow | deny | ask-allow | ask-deny
	Policy   string          `json:"policy_action,omitempty"`
	Code     string          `json:"code,omitempty"`
	Rule     *int            `json:"rule,omitempty"`
	RuleLine int             `json:"rule_line,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Labels   []string        `json:"labels"`
	Added    []string        `json:"added,omitempty"`
	DryRun   bool            `json:"dry_run,omitempty"`
	Forward  bool            `json:"forwarded"`
	Args     json.RawMessage `json:"args,omitempty"`
}

// Sink receives audit events. Implementations must be safe for concurrent use.
type Sink interface {
	Log(e *Event)
}
