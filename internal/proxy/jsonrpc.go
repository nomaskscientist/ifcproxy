package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// JSON-RPC error codes used by the proxy.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
	codeServerBusy     = -32000
)

// rpcError is a protocol-level rejection of a client message.
type rpcError struct {
	code int
	msg  string
}

func (e *rpcError) Error() string { return e.msg }

func errInvalid(msg string) *rpcError { return &rpcError{codeInvalidRequest, msg} }

// message is the envelope of one JSON-RPC message.
type message struct {
	jsonrpc   json.RawMessage
	id        json.RawMessage
	method    string
	params    json.RawMessage
	hasID     bool
	hasMethod bool
	hasResult bool
	hasError  bool
}

var envelopeKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}

// parseMessage parses a JSON-RPC envelope strictly. It rejects anything a
// different JSON parser might read differently from us: duplicate keys
// (first-wins vs last-wins), keys that collide under Unicode case folding
// (e.g. "Method" is accepted as "method" by Go's encoding/json struct
// decoding), and non-string methods.
func parseMessage(raw []byte) (message, error) {
	var m message
	err := walkObject(raw, func(key string, val json.RawMessage) error {
		switch key {
		case "jsonrpc":
			m.jsonrpc = val
		case "id":
			m.id, m.hasID = val, true
		case "method":
			var s string
			if len(val) == 0 || val[0] != '"' || json.Unmarshal(val, &s) != nil {
				return errInvalid("method must be a string")
			}
			m.method, m.hasMethod = s, true
		case "params":
			m.params = val
		case "result":
			m.hasResult = true
		case "error":
			m.hasError = true
		}
		return nil
	}, envelopeKeys)
	return m, err
}

// walkObject calls fn for every member of the JSON object raw. Keys that are
// exact duplicates, or that fold to the same key as another member or as one
// of the significant keys without being identical to it, are rejected.
func walkObject(raw []byte, fn func(key string, val json.RawMessage) error, significant []string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return &rpcError{codeParseError, "parse error"}
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errInvalid("expected a JSON object")
	}
	seen := make(map[string]string, 8)
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return &rpcError{codeParseError, "parse error"}
		}
		key, _ := kt.(string)
		fk := foldKey(key)
		if prev, dup := seen[fk]; dup {
			if prev == key {
				return errInvalid("duplicate key " + strconv.Quote(key))
			}
			return errInvalid("ambiguous keys " + strconv.Quote(prev) + " and " + strconv.Quote(key))
		}
		seen[fk] = key
		for _, s := range significant {
			if fk == s && key != s {
				return errInvalid("non-canonical key " + strconv.Quote(key) + " (expected " + strconv.Quote(s) + ")")
			}
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return &rpcError{codeParseError, "parse error"}
		}
		if err := fn(key, val); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return &rpcError{codeParseError, "parse error"}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &rpcError{codeParseError, "trailing data after JSON value"}
	}
	return nil
}

// foldKey maps s to a canonical case-folded form: every rune is replaced by
// the lower-case form of the smallest rune of its Unicode simple-folding
// orbit, so "K" (Kelvin sign), "K" and "k" all become "k", and "ſ", "S" and
// "s" become "s". ASCII strings without upper-case letters are already
// canonical.
func foldKey(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf || (s[i] >= 'A' && s[i] <= 'Z') {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b.WriteRune(unicode.ToLower(min))
	}
	return b.String()
}

// isObfuscatedToolsCall reports whether method is not exactly "tools/call"
// but would become it after case folding and removal of whitespace, control
// and format (zero-width, bidi) characters — i.e. something a lenient server
// might still dispatch as tools/call.
func isObfuscatedToolsCall(method string) bool {
	if method == "tools/call" {
		return false
	}
	var b strings.Builder
	for _, r := range method {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return foldKey(b.String()) == "tools/call"
}

// idKey returns a canonical map key for a JSON-RPC id. Numbers are
// normalised so that 1, 1.0 and 1e0 map to the same key. Only strings and
// numbers are valid ids.
func idKey(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	switch c := raw[0]; {
	case c == '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		return "s:" + s, true
	case c == '-' || (c >= '0' && c <= '9'):
		if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			return "n:" + strconv.FormatInt(n, 10), true
		}
		f, err := strconv.ParseFloat(string(raw), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return "", false
		}
		if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			return "n:" + strconv.FormatInt(int64(f), 10), true
		}
		return "f:" + strconv.FormatFloat(f, 'g', -1, 64), true
	default:
		return "", false
	}
}

// toolCall is the parsed params of a tools/call request.
type toolCall struct {
	name string
	args json.RawMessage // raw "arguments" object, or nil
}

var callParamKeys = []string{"name", "arguments", "_meta"}

func parseToolCall(params json.RawMessage) (toolCall, error) {
	var tc toolCall
	if len(params) == 0 || params[0] != '{' {
		return tc, &rpcError{codeInvalidParams, "tools/call params must be an object"}
	}
	haveName := false
	err := walkObject(params, func(key string, val json.RawMessage) error {
		switch key {
		case "name":
			if len(val) == 0 || val[0] != '"' || json.Unmarshal(val, &tc.name) != nil {
				return &rpcError{codeInvalidParams, "tools/call params.name must be a string"}
			}
			haveName = true
		case "arguments":
			if string(val) == "null" {
				return nil
			}
			if len(val) == 0 || val[0] != '{' {
				return &rpcError{codeInvalidParams, "tools/call params.arguments must be an object"}
			}
			tc.args = val
		}
		return nil
	}, callParamKeys)
	if err != nil {
		var re *rpcError
		if errors.As(err, &re) && re.code == codeInvalidRequest {
			re.code = codeInvalidParams
		}
		return tc, err
	}
	if !haveName {
		return tc, &rpcError{codeInvalidParams, "tools/call params.name is required"}
	}
	return tc, nil
}

// ---- responses generated by the proxy ----

type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErrorBody   `json:"error,omitempty"`
}

type textContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type denyMeta struct {
	Action string   `json:"action"`
	Code   string   `json:"code"`
	Rule   *int     `json:"rule,omitempty"`
	Labels []string `json:"labels"`
}

type deniedResult struct {
	Content []textContent       `json:"content"`
	IsError bool                `json:"isError"`
	Meta    map[string]denyMeta `json:"_meta"`
}

func safeID(id json.RawMessage) json.RawMessage {
	if _, ok := idKey(id); ok {
		return id
	}
	return json.RawMessage("null")
}

func marshalResponse(r rpcResponse) []byte {
	b, err := json.Marshal(r)
	if err != nil {
		// Only reachable if id were invalid JSON, which safeID prevents.
		b, _ = json.Marshal(rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"),
			Error: &rpcErrorBody{Code: -32603, Message: "ifcproxy: internal error"}})
	}
	return b
}

func errorResponse(id json.RawMessage, e *rpcError) []byte {
	return marshalResponse(rpcResponse{JSONRPC: "2.0", ID: safeID(id),
		Error: &rpcErrorBody{Code: e.code, Message: "ifcproxy: " + e.msg}})
}
