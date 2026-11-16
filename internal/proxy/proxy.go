// Package proxy implements the stdio MCP proxy: it forwards newline-delimited
// JSON-RPC messages between a client and a server, decides every tools/call
// request with the monitor, and taints the session from tool results before
// they reach the client.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"ifcproxy/internal/ask"
	"ifcproxy/internal/audit"
	"ifcproxy/internal/monitor"
	"ifcproxy/internal/policy"
	"ifcproxy/internal/taint"
)

// Defaults for Config.
const (
	DefaultMaxMessageBytes = 16 << 20
	DefaultMaxPending      = 4096
)

// Config configures a Proxy.
type Config struct {
	Monitor *monitor.Monitor // required
	Session *taint.Session   // required
	Store   *taint.Store     // optional shared session file
	Asker   ask.Asker        // optional; nil means "ask" is answered with deny
	Audit   audit.Sink       // optional

	DryRun  bool // decide and log, but forward everything
	LogArgs bool // include tool arguments in audit events

	MaxMessageBytes int // per-message limit in both directions
	MaxPending      int // max in-flight client requests

	// OnClientEOF is called once when the client closes its output (after the
	// server's stdin has been closed).
	OnClientEOF func()
	// Now returns the current time (for tests); defaults to time.Now.
	Now func() time.Time
}

type pending struct {
	kind     pendingKind
	name     string
	produces taint.Label
}

// Proxy is a single client<->server stdio session.
type Proxy struct {
	cfg Config

	outMu sync.Mutex // serialises writes to the client

	mu      sync.Mutex
	pending map[string]pending
	tasks   map[string]taint.Label // taskId -> labels of the task-augmented call that created it
}

// New validates cfg and returns a Proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.Monitor == nil || cfg.Session == nil {
		return nil, errors.New("proxy: Monitor and Session are required")
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = DefaultMaxPending
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Proxy{cfg: cfg, pending: make(map[string]pending), tasks: make(map[string]taint.Label)}, nil
}

// Run proxies until the server closes its output. Client EOF closes serverIn
// so that the server can shut down; Run then returns once the server's output
// is drained.
func (p *Proxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader) error {
	cerr := make(chan error, 1)
	go func() {
		err := p.clientLoop(ctx, clientIn, clientOut, serverIn)
		serverIn.Close()
		if p.cfg.OnClientEOF != nil {
			p.cfg.OnClientEOF()
		}
		cerr <- err
	}()
	serr := p.serverLoop(serverOut, clientOut)
	if serr != nil {
		return serr
	}
	select {
	case err := <-cerr:
		return err
	default:
		return nil
	}
}

// ---- client -> server ----

func (p *Proxy) clientLoop(ctx context.Context, in io.Reader, clientOut io.Writer, serverIn io.Writer) error {
	lr := newLineReader(in, p.cfg.MaxMessageBytes)
	discard := func([]byte) error { return nil }
	for {
		line, oversized, err := lr.next(discard)
		if oversized {
			p.audit(&audit.Event{Kind: audit.KindReject, Reason: fmt.Sprintf("client message exceeds %d bytes", p.cfg.MaxMessageBytes)})
			if werr := p.writeClient(clientOut, errorResponse(nil, &rpcError{codeInvalidRequest, fmt.Sprintf("message exceeds %d bytes", p.cfg.MaxMessageBytes)})); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read client: %w", err)
		}
		if oversized {
			continue
		}
		fwd, replies := p.handleClientLine(ctx, line)
		if fwd != nil {
			if _, err := serverIn.Write(fwd); err != nil {
				return fmt.Errorf("write server: %w", err)
			}
		}
		if replies != nil {
			if err := p.writeClient(clientOut, replies); err != nil {
				return err
			}
		}
	}
}

// handleClientLine returns the bytes to forward to the server (nil for none)
// and the bytes to send back to the client (nil for none).
func (p *Proxy) handleClientLine(ctx context.Context, line []byte) (fwd, reply []byte) {
	body := bytes.TrimSpace(line)
	if len(body) == 0 {
		return withNewline(line), nil
	}
	if !utf8.Valid(body) || !json.Valid(body) {
		p.audit(&audit.Event{Kind: audit.KindReject, Reason: "invalid JSON from client"})
		return nil, errorResponse(nil, &rpcError{codeParseError, "parse error: message is not valid UTF-8 JSON"})
	}
	if body[0] != '[' {
		f, r := p.handleClientElement(ctx, body)
		if f {
			return withNewline(line), r
		}
		return nil, r
	}
	// Batch (JSON-RPC 2.0; removed from MCP in 2025-06-18 but still accepted by
	// some peers). Every element is decided independently.
	var elems []json.RawMessage
	if err := json.Unmarshal(body, &elems); err != nil {
		return nil, errorResponse(nil, &rpcError{codeParseError, "parse error"})
	}
	if len(elems) == 0 {
		return withNewline(line), nil
	}
	var kept []json.RawMessage
	var replies []json.RawMessage
	for _, e := range elems {
		f, r := p.handleClientElement(ctx, e)
		if f {
			kept = append(kept, e)
		}
		if r != nil {
			replies = append(replies, r)
		}
	}
	if len(kept) == len(elems) {
		fwd = withNewline(line)
	} else if len(kept) > 0 {
		b, _ := json.Marshal(kept)
		fwd = append(b, '\n')
	}
	if len(replies) > 0 {
		b, _ := json.Marshal(replies)
		reply = b
	}
	return fwd, reply
}

// handleClientElement decides one JSON-RPC message from the client.
func (p *Proxy) handleClientElement(ctx context.Context, raw []byte) (forward bool, reply []byte) {
	m, err := parseMessage(raw)
	if err != nil {
		return false, p.reject(nil, "", err)
	}
	if !m.hasMethod {
		// A response to a server->client request (or junk the server will
		// reject). Not a tool call: pass through unchanged.
		return true, nil
	}
	if isObfuscatedToolsCall(m.method) {
		return false, p.reject(m.id, "", errInvalid(fmt.Sprintf("non-canonical method %q refused", m.method)))
	}
	if m.method != "tools/call" {
		if !m.hasID {
			if m.method == "notifications/cancelled" {
				p.cancel(m.params)
			}
			return true, nil // notification
		}
		key, ok := idKey(m.id)
		if !ok {
			return true, nil // invalid id: server will reply with an error we do not track
		}
		e, _ := p.taskRequest(m.method, m.params)
		if err := p.register(key, e); err != nil {
			return false, p.reject(m.id, "", err)
		}
		return true, nil
	}
	return p.handleToolsCall(ctx, m)
}

func (p *Proxy) handleToolsCall(ctx context.Context, m message) (bool, []byte) {
	if string(m.jsonrpc) != `"2.0"` {
		return false, p.reject(m.id, "", errInvalid(`tools/call requires "jsonrpc": "2.0"`))
	}
	if !m.hasID {
		// A notification cannot carry a result back, but a lenient server
		// might still execute it. Drop it.
		p.reject(nil, "", errInvalid("tools/call sent as a notification (no id) dropped"))
		return false, nil
	}
	key, ok := idKey(m.id)
	if !ok {
		return false, p.reject(nil, "", errInvalid("tools/call id must be a string or a number"))
	}
	tc, err := parseToolCall(m.params)
	if err != nil {
		return false, p.reject(m.id, "", err)
	}
	p.syncStore()
	d := p.cfg.Monitor.Decide(p.cfg.Session, tc.name, tc.args)
	ev := &audit.Event{
		Kind:   audit.KindCall,
		ID:     m.id,
		Tool:   tc.name,
		Policy: d.Action.String(),
		Code:   d.Code.String(),
		Reason: d.Reason,
		Labels: d.Labels.Names(),
		DryRun: p.cfg.DryRun,
	}
	if d.Rule >= 0 {
		ri := d.Rule
		ev.Rule = &ri
		ev.RuleLine = p.cfg.Monitor.Policy().Rules[ri].Line
	}
	if p.cfg.LogArgs {
		ev.Args = tc.args
	}

	allowed := false
	switch d.Action {
	case policy.Allow:
		allowed, ev.Decision = true, "allow"
	case policy.Ask:
		if p.cfg.DryRun {
			ev.Decision = "ask"
		} else if p.cfg.Asker != nil {
			ok, aerr := p.cfg.Asker.Ask(ctx, ask.Request{Session: p.cfg.Session.ID(), Tool: tc.name, Labels: d.Labels, Reason: d.Reason, Args: tc.args})
			if aerr != nil {
				ev.Reason = d.Reason + "; confirmation failed: " + aerr.Error()
			}
			if ok && aerr == nil {
				allowed, ev.Decision = true, "ask-allow"
			} else {
				ev.Decision = "ask-deny"
			}
		} else {
			ev.Decision = "ask-deny"
			ev.Reason = d.Reason + "; no confirmation channel configured"
		}
	default:
		ev.Decision = "deny"
	}

	if allowed || p.cfg.DryRun {
		kind := kindToolCall
		if tc.task {
			kind = kindTaskCall
		}
		if err := p.register(key, pending{kind: kind, name: tc.name, produces: p.cfg.Monitor.Produces(tc.name)}); err != nil {
			ev.Decision, ev.Reason = "deny", err.Error()
			p.audit(ev)
			return false, errorResponse(m.id, err.(*rpcError))
		}
		ev.Forward = true
		p.audit(ev)
		return true, nil
	}
	p.audit(ev)
	return false, p.denyResponse(m.id, tc.name, d, ev)
}

func (p *Proxy) denyResponse(id json.RawMessage, tool string, d monitor.Decision, ev *audit.Event) []byte {
	text := fmt.Sprintf("ifcproxy blocked the call to tool %q: %s (decision: %s; session labels: %s",
		tool, ev.Reason, ev.Decision, d.Labels)
	if d.Rule >= 0 {
		text += fmt.Sprintf("; policy rule #%d at line %d", d.Rule, ev.RuleLine)
	}
	text += "). The tool was not executed."
	return marshalResponse(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: deniedResult{
			Content: []textContent{{Type: "text", Text: text}},
			IsError: true,
			Meta: map[string]denyMeta{"ifcproxy/decision": {
				Action: ev.Decision, Code: d.Code.String(), Rule: ev.Rule, Labels: d.Labels.Names(),
			}},
		},
	})
}

// reject audits a protocol-level rejection and returns the error response.
func (p *Proxy) reject(id json.RawMessage, tool string, err error) []byte {
	var re *rpcError
	if !errors.As(err, &re) {
		re = &rpcError{codeInvalidRequest, err.Error()}
	}
	p.audit(&audit.Event{Kind: audit.KindReject, ID: safeIDOrNil(id), Tool: tool, Reason: re.msg, Labels: p.cfg.Session.Labels().Names()})
	return errorResponse(id, re)
}

func safeIDOrNil(id json.RawMessage) json.RawMessage {
	if _, ok := idKey(id); ok {
		return id
	}
	return nil
}

func (p *Proxy) register(key string, e pending) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.pending[key]; dup {
		return errInvalid("request id is already in flight; ids must be unique")
	}
	if len(p.pending) >= p.cfg.MaxPending {
		return &rpcError{codeServerBusy, fmt.Sprintf("too many in-flight requests (limit %d)", p.cfg.MaxPending)}
	}
	p.pending[key] = e
	return nil
}

// cancel handles notifications/cancelled from the client. The server should
// not answer a cancelled request, so its pending entry is dropped to keep the
// table bounded. A cancelled tool call may still have produced output (the
// response can race the cancellation), so its labels are added now —
// conservatively — before the entry is forgotten.
func (p *Proxy) cancel(params json.RawMessage) {
	var reqID json.RawMessage
	if len(params) == 0 || params[0] != '{' {
		return
	}
	if walkObject(params, func(k string, v json.RawMessage) error {
		if k == "requestId" {
			reqID = v
		}
		return nil
	}, []string{"requestId"}) != nil {
		return
	}
	key, ok := idKey(reqID)
	if !ok {
		return
	}
	p.mu.Lock()
	e, found := p.pending[key]
	delete(p.pending, key)
	p.mu.Unlock()
	if found && e.kind == kindTaskList {
		e.produces = taint.Known // the listing may already be on its way
	}
	if found && e.kind != kindPlain {
		p.taintTool(e)
	}
}

// ---- server -> client ----

func (p *Proxy) serverLoop(in io.Reader, clientOut io.Writer) error {
	lr := newLineReader(in, p.cfg.MaxMessageBytes)
	for {
		streaming := false
		overflow := func(chunk []byte) error {
			if !streaming {
				// Too large to inspect: attribute it to every pending tool
				// call (conservative), then stream it through unchanged.
				streaming = true
				p.outMu.Lock()
				p.taint(p.pendingUnion(), "oversized server message")
			}
			_, err := clientOut.Write(chunk)
			return err
		}
		line, _, err := lr.next(overflow)
		if streaming {
			p.outMu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read server: %w", err)
		}
		if line == nil {
			continue
		}
		p.observeServerLine(line)
		if err := p.writeClient(clientOut, line); err != nil {
			return err
		}
	}
}

// observeServerLine adds the labels carried by a server message to the
// session. It must complete before the message is written to the client.
func (p *Proxy) observeServerLine(line []byte) {
	body := bytes.TrimSpace(line)
	if len(body) == 0 {
		return
	}
	if !utf8.Valid(body) || !json.Valid(body) {
		p.taint(p.pendingUnion(), "unparseable server message")
		return
	}
	if body[0] == '[' {
		var elems []json.RawMessage
		if json.Unmarshal(body, &elems) != nil {
			p.taint(p.pendingUnion(), "unparseable server batch")
			return
		}
		for _, e := range elems {
			p.observeServerElement(e)
		}
		return
	}
	p.observeServerElement(body)
}

func (p *Proxy) observeServerElement(raw []byte) {
	m, err := parseMessage(raw)
	if err != nil {
		p.taint(p.pendingUnion(), "ambiguous server message")
		return
	}
	if m.hasMethod {
		// Server->client request or notification (progress, logging,
		// sampling, ...). It may carry content produced while tool calls
		// are running, so it inherits their labels.
		if l := p.pendingUnion(); l != taint.None {
			p.taint(l, "server message "+m.method+" during pending tool calls")
		}
		return
	}
	key, ok := idKey(m.id)
	if !ok {
		p.taint(p.pendingUnion(), "server response without a valid id")
		return
	}
	p.mu.Lock()
	e, found := p.pending[key]
	if found {
		delete(p.pending, key)
	}
	p.mu.Unlock()
	if !found {
		p.taint(p.pendingUnion(), "server response with unknown id")
		return
	}
	switch e.kind {
	case kindToolCall:
		p.taintTool(e)
	case kindTaskCall:
		p.taintTool(e)
		p.recordTask(m.result, e.produces)
	case kindTaskList:
		e.produces = p.listLabels(m.result)
		p.taintTool(e)
	}
}

func (p *Proxy) pendingUnion() taint.Label {
	p.mu.Lock()
	defer p.mu.Unlock()
	var l taint.Label
	for _, e := range p.pending {
		l |= e.produces
	}
	return l
}

func (p *Proxy) taintTool(e pending) {
	added := p.cfg.Session.Add(e.produces)
	p.afterTaint(added, e.name, "result of tool "+e.name)
}

func (p *Proxy) taint(l taint.Label, why string) {
	if l == taint.None {
		return
	}
	added := p.cfg.Session.Add(l)
	p.afterTaint(added, "", why)
}

func (p *Proxy) afterTaint(added taint.Label, tool, why string) {
	if added == taint.None {
		return
	}
	if p.cfg.Store != nil {
		if err := p.cfg.Store.Publish(p.cfg.Session.Labels()); err != nil {
			p.audit(&audit.Event{Kind: audit.KindError, Reason: err.Error(), Labels: p.cfg.Session.Labels().Names()})
		}
	}
	p.audit(&audit.Event{Kind: audit.KindTaint, Tool: tool, Reason: why, Added: added.Names(), Labels: p.cfg.Session.Labels().Names(), Forward: true})
}

func (p *Proxy) syncStore() {
	if p.cfg.Store == nil {
		return
	}
	if err := p.cfg.Store.Sync(p.cfg.Session); err != nil {
		p.audit(&audit.Event{Kind: audit.KindError, Reason: "shared session sync failed, failing closed: " + err.Error(), Labels: p.cfg.Session.Labels().Names()})
	}
}

// ---- helpers ----

func (p *Proxy) writeClient(w io.Writer, b []byte) error {
	b = withNewline(b)
	p.outMu.Lock()
	defer p.outMu.Unlock()
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write client: %w", err)
	}
	return nil
}

func (p *Proxy) audit(e *audit.Event) {
	if p.cfg.Audit == nil {
		return
	}
	e.Time = p.cfg.Now()
	e.Session = p.cfg.Session.ID()
	if e.Labels == nil {
		e.Labels = p.cfg.Session.Labels().Names()
	}
	p.cfg.Audit.Log(e)
}

func withNewline(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b
	}
	out := make([]byte, len(b)+1)
	copy(out, b)
	out[len(b)] = '\n'
	return out
}
