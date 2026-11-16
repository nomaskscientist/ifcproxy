package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ifcproxy/internal/monitor"
	"ifcproxy/internal/policy"
	"ifcproxy/internal/taint"
)

// lenientMsg models a permissive server: Go struct decoding matches keys
// case-insensitively and lets the last duplicate win.
type lenientMsg struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// FuzzClientDifferential checks that whatever the proxy forwards, a lenient
// server never sees a tools/call for a tool other than the single allowed
// one ("echo"); the sink "send" must never get through in a tainted session.
func FuzzClientDifferential(f *testing.F) {
	pol, err := policy.Parse([]byte(`
tools:
  echo: {}
  send: {sink: external}
rules:
  - {tool: send, action: deny, reason: blocked}
`), "fuzz")
	if err != nil {
		f.Fatal(err)
	}
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"send"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","NAME":"send"}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}},{"jsonrpc":"2.0","id":2,"method":"TOOLS/CALL","params":{"name":"send"}}]`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","name":"send"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		if bytes.IndexByte(line, '\n') >= 0 {
			return // one message per line by construction of the framing
		}
		sess := taint.NewSession("fuzz")
		sess.Add(taint.Known)
		px, err := New(Config{Monitor: monitor.New(pol), Session: sess})
		if err != nil {
			t.Fatal(err)
		}
		fwd, _ := px.handleClientLine(context.Background(), line)
		if fwd == nil {
			return
		}
		body := bytes.TrimSpace(fwd)
		var msgs []lenientMsg
		if len(body) > 0 && body[0] == '[' {
			var raws []json.RawMessage
			if json.Unmarshal(body, &raws) != nil {
				return
			}
			for _, r := range raws {
				var m lenientMsg
				if json.Unmarshal(r, &m) == nil {
					msgs = append(msgs, m)
				}
			}
		} else {
			var m lenientMsg
			if json.Unmarshal(body, &m) == nil {
				msgs = append(msgs, m)
			}
		}
		for _, m := range msgs {
			method := strings.Map(func(r rune) rune {
				if r <= ' ' {
					return -1
				}
				return r
			}, m.Method)
			if foldKey(method) == "tools/call" && m.Params.Name != "echo" {
				t.Fatalf("forwarded a tools/call that a lenient server reads as %q(%q): %q", m.Method, m.Params.Name, fwd)
			}
		}
	})
}

// lenientTaskMsg models a permissive server reading a tasks/* request.
type lenientTaskMsg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

// FuzzTasksDifferential checks that whenever a lenient server would read a
// forwarded message as tasks/result|get|cancel|list, the proxy has recorded
// a correlatable pending entry that labels the response (unknown tasks:
// every label; listings: decided from the response). Otherwise task output
// could reach the client unlabelled.
func FuzzTasksDifferential(f *testing.F) {
	pol, err := policy.Parse([]byte("tools:\n  echo: {}\n"), "fuzz")
	if err != nil {
		f.Fatal(err)
	}
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tasks/result","params":{"taskId":"t"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"Tasks/Result","params":{"taskId":"t"}}`,
		`{"jsonrpc":"2.0","id":true,"method":"tasks/result","params":{"taskId":"t"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"TaskId":"t"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/list"}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tasks/result","params":{"taskId":"a"}},{"jsonrpc":"2.0","id":2,"method":"TASKS/GET","params":{"taskId":"b"}}]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		if bytes.IndexByte(line, '\n') >= 0 {
			return
		}
		px, err := New(Config{Monitor: monitor.New(pol), Session: taint.NewSession("fuzz")})
		if err != nil {
			t.Fatal(err)
		}
		fwd, _ := px.handleClientLine(context.Background(), line)
		if fwd == nil {
			return
		}
		body := bytes.TrimSpace(fwd)
		var raws []json.RawMessage
		if len(body) > 0 && body[0] == '[' {
			if json.Unmarshal(body, &raws) != nil {
				return
			}
		} else {
			raws = []json.RawMessage{body}
		}
		for _, r := range raws {
			var m lenientTaskMsg
			if json.Unmarshal(r, &m) != nil {
				continue
			}
			method := foldKey(strings.Map(func(c rune) rune {
				if c <= ' ' {
					return -1
				}
				return c
			}, m.Method))
			if !isTaskMethod(method) {
				continue
			}
			key, ok := idKey(m.ID)
			if !ok {
				t.Fatalf("forwarded %s with an uncorrelatable id %s: %q", method, m.ID, fwd)
			}
			px.mu.Lock()
			e, found := px.pending[key]
			px.mu.Unlock()
			switch {
			case !found:
				t.Fatalf("forwarded %s without a pending entry: %q", method, fwd)
			case method == "tasks/list" && e.kind != kindTaskList:
				t.Fatalf("tasks/list registered as kind %d: %q", e.kind, fwd)
			case method != "tasks/list" && (e.kind != kindToolCall || e.produces != taint.Known):
				t.Fatalf("%s for an unknown task not failing closed (kind %d, labels %v): %q", method, e.kind, e.produces, fwd)
			}
		}
	})
}
