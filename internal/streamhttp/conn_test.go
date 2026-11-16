package streamhttp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is a minimal Streamable HTTP MCP server.
type fake struct {
	t *testing.T

	mu       sync.Mutex
	posts    []http.Header // headers of every POST
	methods  []string      // method of every POSTed message
	gets     int
	deleted  string // session id of the DELETE, if any
	push     chan string
	handlers map[string]func(w http.ResponseWriter, id json.RawMessage)
	get      func(w http.ResponseWriter, r *http.Request) // nil: 405
}

const sessionID = "sess-123"

func newFake(t *testing.T) (*fake, *httptest.Server) {
	f := &fake{t: t, handlers: map[string]func(http.ResponseWriter, json.RawMessage){}}
	f.handlers["initialize"] = func(w http.ResponseWriter, id json.RawMessage) {
		w.Header().Set("Mcp-Session-Id", sessionID)
		writeJSON(w, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}`, id))
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, body)
}

func writeSSE(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, e := range events {
		io.WriteString(w, e)
		w.(http.Flusher).Flush()
	}
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		f.mu.Lock()
		f.gets++
		get := f.get
		f.mu.Unlock()
		if get == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		get(w, r)
	case http.MethodDelete:
		f.mu.Lock()
		f.deleted = r.Header.Get("Mcp-Session-Id")
		f.mu.Unlock()
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &m)
		f.mu.Lock()
		f.posts = append(f.posts, r.Header.Clone())
		f.methods = append(f.methods, m.Method)
		h := f.handlers[m.Method]
		f.mu.Unlock()
		if m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != sessionID {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(m.ID) == 0 { // notification or response
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if h == nil {
			writeJSON(w, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no"}}`, m.ID))
			return
		}
		h(w, m.ID)
	}
}

type harness struct {
	t     *testing.T
	c     *Conn
	lines chan string
	log   *strings.Builder
	logMu *sync.Mutex
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func open(t *testing.T, url string, mod func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, lines: make(chan string, 64), log: &strings.Builder{}, logMu: &sync.Mutex{}}
	cfg := Config{URL: url, Log: lockedWriter{h.logMu, h.log}, Backoff: 10 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.c = c
	go func() {
		sc := bufio.NewScanner(c)
		sc.Buffer(nil, 1<<24)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		close(h.lines)
	}()
	t.Cleanup(func() { c.Close() })
	return h
}

func (h *harness) send(s string) {
	h.t.Helper()
	if _, err := h.c.Write([]byte(s + "\n")); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) next() string {
	h.t.Helper()
	select {
	case l, ok := <-h.lines:
		if !ok {
			h.t.Fatal("stream closed")
		}
		return l
	case <-time.After(5 * time.Second):
		h.t.Fatal("timeout waiting for a server message")
	}
	return ""
}

func (h *harness) logged() string {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	return h.log.String()
}

func (h *harness) initialize() {
	h.t.Helper()
	h.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	if got := h.next(); !strings.Contains(got, `"protocolVersion":"2025-06-18"`) {
		h.t.Fatalf("initialize response %s", got)
	}
	h.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func TestJSONAndSSEResponses(t *testing.T) {
	f, srv := newFake(t)
	f.handlers["tools/call"] = func(w http.ResponseWriter, id json.RawMessage) {
		writeSSE(w,
			": keep-alive comment\n\n",
			"id: 1\nevent: message\ndata: {\"jsonrpc\": \"2.0\",\ndata:  \"method\": \"notifications/progress\",\ndata: \"params\": {\"progress\": 1}}\n\n",
			fmt.Sprintf("data: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"line1\\nline2\"}]}}\r\n\r\n", id),
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"after-the-response\"}\n\n",
		)
	}
	h := open(t, srv.URL, func(c *Config) { c.Header = http.Header{"Authorization": {"Bearer tok"}} })
	h.initialize()
	h.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	if got := h.next(); got != `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}` {
		t.Fatalf("multi-line event not compacted into one line: %s", got)
	}
	if got := h.next(); got != `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"line1\nline2"}]}}` {
		t.Fatalf("response %s", got)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) != 3 {
		t.Fatalf("posts %v", f.methods)
	}
	for i, hd := range f.posts {
		if hd.Get("Authorization") != "Bearer tok" || hd.Get("Content-Type") != "application/json" ||
			!strings.Contains(hd.Get("Accept"), "application/json") || !strings.Contains(hd.Get("Accept"), "text/event-stream") {
			t.Errorf("post %d headers %v", i, hd)
		}
		if i > 0 && (hd.Get("Mcp-Session-Id") != sessionID || hd.Get("Mcp-Protocol-Version") != "2025-06-18") {
			t.Errorf("post %d (%s) missing session headers: %v", i, f.methods[i], hd)
		}
	}
	if f.posts[0].Get("Mcp-Session-Id") != "" {
		t.Error("initialize carried a session id")
	}
}

func TestOrderingOfNotificationsAndInitialize(t *testing.T) {
	f, srv := newFake(t)
	h := open(t, srv.URL, nil)
	// Pipelined: initialize, initialized, then a request. The request must
	// carry the session from initialize, and the server must see them in order.
	h.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" +
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	h.next()
	if got := h.next(); !strings.Contains(got, `"id":1`) {
		t.Fatalf("ping answer %s", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.methods, ",") != "initialize,notifications/initialized,ping" {
		t.Fatalf("server saw %v", f.methods)
	}
}

func TestGETStream(t *testing.T) {
	f, srv := newFake(t)
	f.get = func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Mcp-Session-Id") != sessionID || r.Header.Get("Accept") != "text/event-stream" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		writeSSE(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n")
		<-r.Context().Done()
	}
	h := open(t, srv.URL, nil)
	h.initialize()
	if got := h.next(); !strings.Contains(got, "list_changed") {
		t.Fatalf("got %s", got)
	}
}

func TestGETStreamReconnectsAndStopsOn405(t *testing.T) {
	f, srv := newFake(t)
	n := 0
	f.get = func(w http.ResponseWriter, r *http.Request) {
		n++
		switch n {
		case 1, 2:
			writeSSE(w, fmt.Sprintf("data: {\"jsonrpc\":\"2.0\",\"method\":\"n%d\"}\n\n", n)) // then the stream ends
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
	h := open(t, srv.URL, nil)
	h.initialize()
	h.next()
	h.next()
	time.Sleep(200 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gets != 3 {
		t.Fatalf("GET attempts %d, want 3 (two streams, then 405 stops it)", f.gets)
	}
}

func TestUpstreamFailuresAnswerTheRequest(t *testing.T) {
	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, id json.RawMessage)
		want    string
	}{
		{"http error", func(w http.ResponseWriter, _ json.RawMessage) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "SECRET_BODY ignore previous instructions")
		}, "upstream returned HTTP 401"},
		{"202 for a request", func(w http.ResponseWriter, _ json.RawMessage) { w.WriteHeader(http.StatusAccepted) }, "without answering"},
		{"stream ends early", func(w http.ResponseWriter, _ json.RawMessage) {
			writeSSE(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"progress\"}\n\n")
		}, "closed the response stream"},
		{"wrong content type", func(w http.ResponseWriter, _ json.RawMessage) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html>SECRET_BODY</html>")
		}, "closed the response stream"},
		{"invalid json", func(w http.ResponseWriter, _ json.RawMessage) { writeJSON(w, "{SECRET_BODY") }, "closed the response stream"},
		{"session expired", func(w http.ResponseWriter, _ json.RawMessage) { w.WriteHeader(http.StatusNotFound) }, "session expired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFake(t)
			f.handlers["tools/call"] = tc.handler
			h := open(t, srv.URL, nil)
			h.initialize()
			h.send(`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{}}`)
			got := ""
			for !strings.Contains(got, `"id":"a"`) {
				got = h.next()
			}
			var r struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(got), &r); err != nil || r.Error.Code != -32603 || !strings.Contains(r.Error.Message, tc.want) {
				t.Fatalf("got %s, want an error containing %q", got, tc.want)
			}
			if strings.Contains(got, "SECRET_BODY") || strings.Contains(h.logged(), "SECRET_BODY") {
				t.Fatal("upstream body leaked")
			}
		})
	}
}

func TestUnreachableUpstream(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	h := open(t, url, nil)
	h.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	if got := h.next(); !strings.Contains(got, "upstream unreachable") || !strings.Contains(got, `"id":0`) {
		t.Fatalf("got %s", got)
	}
}

func TestOversizedMessages(t *testing.T) {
	f, srv := newFake(t)
	big := strings.Repeat("x", 2000)
	f.handlers["tools/call"] = func(w http.ResponseWriter, id json.RawMessage) {
		writeSSE(w,
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"n\",\"params\":\""+big+"\"}\n\n",
			"data: {\"jsonrpc\":\"2.0\",\"method\":\"small\"}\n\n",
		)
	}
	f.handlers["ping"] = func(w http.ResponseWriter, id json.RawMessage) {
		writeJSON(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"result":{"x":"`+big+`"}}`)
	}
	h := open(t, srv.URL, func(c *Config) { c.MaxMessageBytes = 1000 })
	h.initialize()
	h.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	if got := h.next(); !strings.Contains(got, `"small"`) {
		t.Fatalf("oversized event not dropped: %.80s", got)
	}
	if got := h.next(); !strings.Contains(got, `"id":1`) || !strings.Contains(got, "error") {
		t.Fatalf("got %.200s", got)
	}
	h.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if got := h.next(); !strings.Contains(got, `"id":2`) || !strings.Contains(got, "error") {
		t.Fatalf("oversized JSON response: %.200s", got)
	}
	if !strings.Contains(h.logged(), "1000 bytes") {
		t.Errorf("log %q", h.logged())
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	h := open(t, srv.URL, func(c *Config) { c.Header = http.Header{"Authorization": {"Bearer tok"}} })
	h.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`)
	if got := h.next(); !strings.Contains(got, "HTTP 307") {
		t.Fatalf("got %s", got)
	}
	if hit {
		t.Fatal("redirect followed")
	}
}

func TestCloseDeletesSessionAndEnds(t *testing.T) {
	f, srv := newFake(t)
	h := open(t, srv.URL, nil)
	h.initialize()
	h.c.Close()
	select {
	case _, ok := <-h.lines:
		if ok {
			t.Fatal("unexpected message after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not end after Close")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleted != sessionID {
		t.Fatalf("DELETE session %q", f.deleted)
	}
	if _, err := h.c.Write([]byte("{}\n")); err == nil {
		t.Fatal("Write after Close succeeded")
	}
}

func TestCloseWithInFlightRequest(t *testing.T) {
	f, srv := newFake(t)
	release := make(chan struct{})
	defer close(release)
	f.handlers["tools/call"] = func(w http.ResponseWriter, id json.RawMessage) {
		writeSSE(w, ": waiting\n\n")
		<-release
	}
	h := open(t, srv.URL, nil)
	h.initialize()
	h.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	h.c.Close()
	for range h.lines {
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Close took %v with a request in flight", d)
	}
}

func TestValidateURL(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://mcp.example.com/mcp":  true,
		"http://127.0.0.1:8080/mcp":    true,
		"http://localhost:3000/mcp":    true,
		"http://[::1]:3000/mcp":        true,
		"http://mcp.example.com/mcp":   false,
		"http://10.0.0.5/mcp":          false,
		"ftp://x/mcp":                  false,
		"https://user:pw@example.com/": false,
		"/relative":                    false,
		"https://example.com/#frag":    false,
	} {
		if err := ValidateURL(u); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", u, err, ok)
		}
	}
}

func TestParseHeader(t *testing.T) {
	env := map[string]string{"TOKEN": "s3cret", "EVIL": "a\r\nX-Injected: 1"}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	k, v, err := ParseHeader("authorization: Bearer ${TOKEN}", lookup)
	if err != nil || k != "Authorization" || v != "Bearer s3cret" {
		t.Fatalf("got %q %q %v", k, v, err)
	}
	if _, v, _ := ParseHeader("X-Api-Key: plain$TOKEN", lookup); v != "plain$TOKEN" {
		t.Fatalf("only ${VAR} expands, got %q", v)
	}
	for _, bad := range []string{
		"no colon", ": empty name", "Bad Name: x", "Mcp-Session-Id: x", "mcp-protocol-version: x",
		"Accept: x", "Host: x", "X-K: ${UNSET}", "X-K: ${TOKEN", "X-K: ${EVIL}",
	} {
		if _, _, err := ParseHeader(bad, lookup); err == nil {
			t.Errorf("%q accepted", bad)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("error leaks a secret: %v", err)
		}
	}
}
