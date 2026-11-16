// Package ask obtains human confirmation for tool calls whose policy action is "ask".
package ask

import (
	"context"

	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

// Request describes a call awaiting confirmation.
type Request struct {
	Session string
	Tool    string
	Labels  taint.Label
	Reason  string
	Args    []byte // raw JSON arguments; untrusted, must be sanitised before display
}

// Asker answers whether a call may proceed. An error means "no answer" and is
// treated as a denial by the proxy.
type Asker interface {
	Ask(ctx context.Context, r Request) (bool, error)
}

// Static answers every request with a fixed value (--ask-mode=allow|deny).
type Static bool

// Ask implements Asker.
func (s Static) Ask(context.Context, Request) (bool, error) { return bool(s), nil }
