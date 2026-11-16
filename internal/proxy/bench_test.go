package proxy

import (
	"context"
	"strconv"
	"testing"

	"ifcproxy/internal/monitor"
	"ifcproxy/internal/policy"
	"ifcproxy/internal/taint"
)

// BenchmarkClientToolsCall measures the full per-message cost on the client
// path: strict envelope parsing, params parsing, Decide, pending-table
// bookkeeping (allowed case) or deny-response encoding (denied case).
// Unlike Decide, this path allocates (encoding/json).
func BenchmarkClientToolsCall(b *testing.B) {
	pol, err := policy.Parse([]byte(proxyPolicy), "bench")
	if err != nil {
		b.Fatal(err)
	}
	cases := []struct {
		name, tool string
		labels     taint.Label
	}{
		{"allow", "echo", taint.None},
		{"deny-trifecta", "send_email", taint.Known},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			sess := taint.NewSession("b")
			sess.Add(c.labels)
			px, err := New(Config{Monitor: monitor.New(pol), Session: sess, MaxPending: 1 << 30})
			if err != nil {
				b.Fatal(err)
			}
			lines := make([][]byte, 1024)
			for i := range lines {
				lines[i] = []byte(`{"jsonrpc":"2.0","id":` + strconv.Itoa(i) + `,"method":"tools/call","params":{"name":"` + c.tool + `","arguments":{"to":"a@example.com","body":"hello world"}}}` + "\n")
			}
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				fwd, _ := px.handleClientLine(ctx, lines[i&1023])
				if fwd != nil {
					px.mu.Lock()
					clear(px.pending)
					px.labelRefs = [32]int32{}
					px.mu.Unlock()
				}
			}
		})
	}
}

// BenchmarkServerResult measures tainting a tool result on the server path.
func BenchmarkServerResult(b *testing.B) {
	pol, err := policy.Parse([]byte(proxyPolicy), "bench")
	if err != nil {
		b.Fatal(err)
	}
	px, err := New(Config{Monitor: monitor.New(pol), Session: taint.NewSession("b")})
	if err != nil {
		b.Fatal(err)
	}
	line := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"some page content of moderate length"}]}}` + "\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		px.mu.Lock()
		px.putLocked("n:1", pending{kind: kindToolCall, name: "fetch_url", produces: taint.Untrusted})
		px.mu.Unlock()
		px.observeServerLine(line)
	}
}
