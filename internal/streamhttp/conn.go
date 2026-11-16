// Package streamhttp is the client side of the MCP Streamable HTTP transport,
// shaped as a stdio server for the proxy: the proxy writes newline-delimited
// JSON-RPC messages to a Conn and reads the server's messages from it, one
// compact JSON value per line.
//
// The transport sits on the server side of the proxy. Everything it emits,
// including the errors it synthesises, passes through the proxy's server
// loop like the output of a stdio server, so labelling is unchanged.
package streamhttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	headerSession  = "Mcp-Session-Id"
	headerProtocol = "Mcp-Protocol-Version"

	// deleteTimeout bounds the best-effort session DELETE on Close.
	deleteTimeout = 2 * time.Second
	// maxBackoff caps the delay between reconnects of the GET stream.
	maxBackoff = 30 * time.Second
	// errorBodyBytes is how much of an HTTP error body is drained (never shown).
	errorBodyBytes = 4096
)

// Config configures a Conn.
type Config struct {
	URL             string        // the server's MCP endpoint (https, or http on a loopback host)
	Header          http.Header   // extra request headers, e.g. Authorization
	Client          *http.Client  // optional; must not follow redirects
	MaxMessageBytes int           // per-message limit for server messages
	Log             io.Writer     // diagnostics, one line each; optional
	Backoff         time.Duration // first GET-stream reconnect delay (default 1s)
}

// Conn is one MCP session with a Streamable HTTP server.
type Conn struct {
	cfg    Config
	url    string
	client *http.Client

	ctx    context.Context
	cancel context.CancelFunc

	pr *io.PipeReader
	pw *io.PipeWriter

	outMu sync.Mutex // serialises lines written to pw

	mu        sync.Mutex
	session   string // Mcp-Session-Id from the initialize response
	protocol  string // negotiated protocol version
	getOnce   sync.Once
	inflight  sync.WaitGroup
	partial   []byte // incomplete line written by the proxy
	closeOnce sync.Once
}

// ErrBadURL reports an unusable upstream URL.
var ErrBadURL = errors.New("upstream URL must be https, or http on a loopback host")

// ValidateURL checks that u is an absolute https URL, or http on a loopback
// host (so bearer tokens never travel in clear text over a network).
func ValidateURL(u string) error {
	p, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("upstream URL: %w", err)
	}
	if p.Host == "" || p.User != nil || p.Fragment != "" {
		return fmt.Errorf("%w: %q", ErrBadURL, u)
	}
	switch p.Scheme {
	case "https":
		return nil
	case "http":
		host := p.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrBadURL, u)
}

// reserved headers are managed by the transport.
var reserved = map[string]bool{
	"Accept": true, "Content-Type": true, "Content-Length": true, "Host": true,
	"Connection": true, "Transfer-Encoding": true, "Last-Event-Id": true,
	headerSession: true, http.CanonicalHeaderKey(headerProtocol): true,
}

// ParseHeader parses "Name: value". ${VAR} in the value is replaced by the
// environment variable VAR (lookup), so secrets need not appear on the
// command line; an unset variable is an error.
func ParseHeader(s string, lookup func(string) (string, bool)) (string, string, error) {
	name, value, ok := strings.Cut(s, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" || !validToken(name) {
		return "", "", fmt.Errorf("header %q: want \"Name: value\"", redact(s))
	}
	if reserved[http.CanonicalHeaderKey(name)] {
		return "", "", fmt.Errorf("header %s is set by ifcproxy", name)
	}
	var b strings.Builder
	rest := strings.TrimSpace(value)
	for {
		i := strings.Index(rest, "${")
		if i < 0 {
			b.WriteString(rest)
			break
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return "", "", fmt.Errorf("header %s: unterminated ${", name)
		}
		v, ok := lookup(rest[i+2 : i+j])
		if !ok {
			return "", "", fmt.Errorf("header %s: environment variable %s is not set", name, rest[i+2:i+j])
		}
		b.WriteString(rest[:i])
		b.WriteString(v)
		rest = rest[i+j+1:]
	}
	value = b.String()
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", "", fmt.Errorf("header %s: value contains a control character", name)
	}
	return http.CanonicalHeaderKey(name), value, nil
}

func validToken(s string) bool {
	for _, r := range s {
		if r > 0x7e || r <= 0x20 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}

func redact(s string) string {
	if name, _, ok := strings.Cut(s, ":"); ok {
		return name + ": …"
	}
	return "…"
}

// NewClient returns an HTTP client suitable for Conn: environment proxies,
// no redirects, no overall timeout (SSE streams are long-lived).
func NewClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{
		Transport: t,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// New returns a Conn. No request is made until the first message is written.
func New(cfg Config) (*Conn, error) {
	if err := ValidateURL(cfg.URL); err != nil {
		return nil, err
	}
	if cfg.Client == nil {
		cfg.Client = NewClient()
	}
	if cfg.MaxMessageBytes <= 0 {
		cfg.MaxMessageBytes = 16 << 20
	}
	if cfg.Log == nil {
		cfg.Log = io.Discard
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	return &Conn{cfg: cfg, url: cfg.URL, client: cfg.Client, ctx: ctx, cancel: cancel, pr: pr, pw: pw}, nil
}

// Read returns server messages, one compact JSON value per line.
func (c *Conn) Read(p []byte) (int, error) { return c.pr.Read(p) }

// Write takes newline-delimited client messages.
func (c *Conn) Write(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, io.ErrClosedPipe
	}
	c.partial = append(c.partial, p...)
	for {
		i := bytes.IndexByte(c.partial, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimSpace(c.partial[:i])
		c.partial = c.partial[i+1:]
		if len(line) > 0 {
			c.send(append([]byte(nil), line...))
		}
	}
	if len(c.partial) == 0 {
		c.partial = nil
	}
	return len(p), nil
}

// Close ends the session: in-flight requests are abandoned, the session is
// deleted on the server (best effort), and then Read returns io.EOF. Close
// does not wait for any of it, since a goroutine may be blocked delivering a
// message that nobody will read.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		go c.finish()
	})
	return nil
}

func (c *Conn) finish() {
	c.inflight.Wait()
	c.mu.Lock()
	session, protocol := c.session, c.protocol
	c.mu.Unlock()
	if session != "" {
		ctx, cancel := context.WithTimeout(context.Background(), deleteTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil)
		if err == nil {
			c.setHeaders(req, session, protocol)
			if resp, err := c.client.Do(req); err == nil {
				drain(resp)
			}
		}
		cancel()
	}
	c.pw.Close()
}

// envelope is the part of a message the transport needs.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result *struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"result"`
	Error json.RawMessage `json:"error"`
}

func (e envelope) isRequest() bool  { return e.Method != "" && len(e.ID) > 0 && string(e.ID) != "null" }
func (e envelope) isResponse() bool { return e.Method == "" && (e.Result != nil || e.Error != nil) }

// send POSTs one client message. Notifications and responses are sent
// synchronously (the server answers 202 at once), which keeps them ordered
// with respect to later requests; initialize is synchronous too, because
// every later message needs the session it creates. Other requests run
// concurrently: their responses can take as long as the tool does.
func (c *Conn) send(msg []byte) {
	var env envelope
	single := len(msg) > 0 && msg[0] == '{'
	if single {
		_ = json.Unmarshal(msg, &env)
	}
	if single && env.isRequest() && env.Method != "initialize" {
		c.inflight.Add(1)
		go func() {
			defer c.inflight.Done()
			c.post(msg, env)
		}()
		return
	}
	c.post(msg, env)
	if single && env.Method == "notifications/initialized" {
		c.getOnce.Do(func() {
			c.inflight.Add(1)
			go func() {
				defer c.inflight.Done()
				c.listen()
			}()
		})
	}
}

func (c *Conn) setHeaders(req *http.Request, session, protocol string) {
	for k, vs := range c.cfg.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if session != "" {
		req.Header.Set(headerSession, session)
	}
	if protocol != "" {
		req.Header.Set(headerProtocol, protocol)
	}
}

func (c *Conn) post(msg []byte, env envelope) {
	c.mu.Lock()
	session, protocol := c.session, c.protocol
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(msg))
	if err != nil {
		c.fail(env, "cannot build request")
		return
	}
	c.setHeaders(req, session, protocol)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := c.client.Do(req)
	if err != nil {
		if c.ctx.Err() == nil {
			c.logf("POST %s: %v", describe(env), err)
			c.fail(env, "upstream unreachable")
		}
		return
	}
	defer drain(resp)

	if env.Method == "initialize" {
		if s := resp.Header.Get(headerSession); s != "" {
			c.mu.Lock()
			c.session = s
			c.mu.Unlock()
		}
	}
	switch {
	case resp.StatusCode == http.StatusAccepted:
		if env.isRequest() {
			c.fail(env, "upstream accepted the request without answering it")
		}
		return
	case resp.StatusCode == http.StatusNotFound && session != "":
		c.logf("POST %s: HTTP 404: the upstream session has expired", describe(env))
		c.fail(env, "upstream session expired (HTTP 404); restart the client")
		return
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		c.logf("POST %s: HTTP %d", describe(env), resp.StatusCode)
		c.fail(env, fmt.Sprintf("upstream returned HTTP %d", resp.StatusCode))
		return
	}
	if !env.isRequest() && env.Method != "initialize" && !(len(msg) > 0 && msg[0] == '[') {
		return // a notification or response answered 200: nothing to deliver
	}
	answered, err := c.deliver(resp, env)
	if err != nil && c.ctx.Err() == nil {
		c.logf("POST %s: %v", describe(env), err)
	}
	if !answered && c.ctx.Err() == nil {
		c.fail(env, "upstream closed the response stream without answering")
	}
}

// deliver forwards the messages in a POST response body and reports whether
// the response to env's request was among them.
func (c *Conn) deliver(resp *http.Response, env envelope) (answered bool, err error) {
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "application/json":
		body, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.cfg.MaxMessageBytes)+1))
		if err != nil {
			return false, err
		}
		if len(body) > c.cfg.MaxMessageBytes {
			return false, fmt.Errorf("response exceeds %d bytes", c.cfg.MaxMessageBytes)
		}
		return c.emit(body, env), nil
	case "text/event-stream":
		err := c.readEvents(resp.Body, func(data []byte) bool {
			if c.emit(data, env) {
				answered = true
				return false // the stream has served its purpose
			}
			return true
		})
		return answered, err
	default:
		return false, fmt.Errorf("unexpected Content-Type %q", resp.Header.Get("Content-Type"))
	}
}

// emit writes one server message (any JSON value) as a compact line and
// reports whether it is the response to env's request.
func (c *Conn) emit(data []byte, env envelope) bool {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		c.logf("dropped a server message that is not valid JSON (%d bytes)", len(data))
		return false
	}
	var got envelope
	isResp := false
	if buf.Len() > 0 && buf.Bytes()[0] == '{' && json.Unmarshal(buf.Bytes(), &got) == nil && got.isResponse() {
		isResp = env.isRequest() && sameID(got.ID, env.ID)
		if isResp && env.Method == "initialize" && got.Result != nil && got.Result.ProtocolVersion != "" {
			c.mu.Lock()
			c.protocol = got.Result.ProtocolVersion
			c.mu.Unlock()
		}
	} else if buf.Len() > 0 && buf.Bytes()[0] == '[' {
		isResp = true // a batch response: answers whatever batch was sent
	}
	buf.WriteByte('\n')
	if c.ctx.Err() != nil {
		return isResp // closed: the client is gone
	}
	c.outMu.Lock()
	_, err := c.pw.Write(buf.Bytes())
	c.outMu.Unlock()
	if err != nil {
		c.cancel()
	}
	return isResp
}

func sameID(a, b json.RawMessage) bool {
	var x, y bytes.Buffer
	if json.Compact(&x, a) != nil || json.Compact(&y, b) != nil {
		return false
	}
	return bytes.Equal(x.Bytes(), y.Bytes())
}

// fail answers env's request with a JSON-RPC error, so the client is never
// left waiting. The text is ifcproxy's own; upstream bodies are never shown.
func (c *Conn) fail(env envelope, why string) {
	if !env.isRequest() {
		return
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      env.ID,
		"error":   map[string]any{"code": -32603, "message": "ifcproxy: " + why},
	})
	c.emit(b, envelope{})
}

// listen keeps the optional GET stream open for server-initiated messages.
func (c *Conn) listen() {
	backoff := c.cfg.Backoff
	for c.ctx.Err() == nil {
		c.mu.Lock()
		session, protocol := c.session, c.protocol
		c.mu.Unlock()
		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, c.url, nil)
		if err != nil {
			return
		}
		c.setHeaders(req, session, protocol)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := c.client.Do(req)
		if err == nil {
			mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			switch {
			case resp.StatusCode == http.StatusMethodNotAllowed:
				drain(resp)
				return // the server offers no GET stream
			case resp.StatusCode == http.StatusOK && mt == "text/event-stream":
				backoff = c.cfg.Backoff
				err = c.readEvents(resp.Body, func(data []byte) bool {
					c.emit(data, envelope{})
					return true
				})
			default:
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
				if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					drain(resp)
					c.logf("GET stream: %v; not retrying", err)
					return
				}
			}
			drain(resp)
		}
		if c.ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logf("GET stream: %v; reconnecting in %s", err, backoff)
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// readEvents parses a text/event-stream body and calls fn with the data of
// each event until fn returns false or the stream ends. Events larger than
// MaxMessageBytes are dropped.
func (c *Conn) readEvents(body io.Reader, fn func([]byte) bool) error {
	br := bufio.NewReaderSize(body, 64<<10)
	var data []byte
	hasData, tooBig := false, false
	for {
		line, err := readLine(br, c.cfg.MaxMessageBytes+64)
		if errors.Is(err, errLineTooLong) {
			tooBig = true
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(line) == 0 { // dispatch
			if tooBig {
				c.logf("dropped a server event larger than %d bytes", c.cfg.MaxMessageBytes)
			} else if hasData && len(bytes.TrimSpace(data)) > 0 {
				if !fn(data) {
					return nil
				}
			}
			data, hasData, tooBig = data[:0], false, false
			continue
		}
		field, value, _ := bytes.Cut(line, []byte(":"))
		value = bytes.TrimPrefix(value, []byte(" "))
		if string(field) != "data" || tooBig {
			continue // comments, event, id, retry
		}
		if hasData {
			data = append(data, '\n')
		}
		data = append(data, value...)
		hasData = true
		if len(data) > c.cfg.MaxMessageBytes {
			tooBig, data = true, data[:0]
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine reads one line without its terminator (LF, CRLF or CR-less LF).
// A line longer than max is consumed and reported as errLineTooLong.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	tooLong := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return nil, err
		}
		if !tooLong {
			line = append(line, chunk...)
			if len(line) > max {
				tooLong, line = true, nil
			}
		}
		if !isPrefix {
			if tooLong {
				return nil, errLineTooLong
			}
			return line, nil
		}
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errorBodyBytes))
	resp.Body.Close()
}

func describe(env envelope) string {
	switch {
	case env.Method != "" && len(env.ID) > 0:
		return env.Method + " (id " + string(env.ID) + ")"
	case env.Method != "":
		return env.Method
	case len(env.ID) > 0:
		return "response (id " + string(env.ID) + ")"
	}
	return "message"
}

func (c *Conn) logf(format string, args ...any) {
	fmt.Fprintf(c.cfg.Log, "ifcproxy: upstream: "+format+"\n", args...)
}
