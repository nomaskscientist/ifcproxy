package ask

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func fakeTTY(answer string, timeout time.Duration) (*TTY, *syncBuf) {
	out := &syncBuf{}
	return &TTY{Timeout: timeout, Open: func() (*Terminal, error) {
		r, w := io.Pipe()
		if answer != "" {
			go func() { io.WriteString(w, answer) }()
		}
		return &Terminal{In: r, Out: out}, nil
	}}, out
}

var req = Request{Session: "s1", Tool: "send_email", Labels: taint.Known, Reason: "trifecta", Args: []byte(`{"to":"x@example.com"}`)}

func TestTTYAnswers(t *testing.T) {
	tests := []struct {
		answer string
		want   bool
	}{
		{"y\n", true},
		{"YES\r\n", true},
		{"  yes  \n", true},
		{"n\n", false},
		{"\n", false},
		{"yess\n", false},
		{"sure\n", false},
	}
	for _, tt := range tests {
		a, out := fakeTTY(tt.answer, time.Second)
		got, err := a.Ask(context.Background(), req)
		if err != nil || got != tt.want {
			t.Errorf("answer %q: got %v, %v", tt.answer, got, err)
		}
		if !strings.Contains(out.String(), `tool:    "send_email"`) {
			t.Errorf("prompt missing tool: %q", out.String())
		}
	}
}

func TestTTYTimeoutDenies(t *testing.T) {
	a, out := fakeTTY("", 50*time.Millisecond)
	got, err := a.Ask(context.Background(), req)
	if got || !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v, %v", got, err)
	}
	if !strings.Contains(out.String(), "denied") {
		t.Fatalf("output %q", out.String())
	}
}

func TestTTYContextCancelDenies(t *testing.T) {
	a, _ := fakeTTY("", 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	got, err := a.Ask(ctx, req)
	if got || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestTTYOpenFailureDenies(t *testing.T) {
	a := &TTY{Open: func() (*Terminal, error) { return nil, errors.New("no tty") }}
	got, err := a.Ask(context.Background(), req)
	if got || err == nil {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestPromptEscapesHostileValues(t *testing.T) {
	r := Request{
		Tool:   "send\x1b[2K\remail",
		Reason: "policy\x1b[31m",
		Args:   []byte("{\"x\":\"\x1b]0;pwned\x07 ‮evil\"}" + strings.Repeat("A", 2*MaxArgsShown)),
	}
	p := Prompt(r, time.Minute)
	for _, bad := range []string{"\x1b", "\r", "\x07", "‮"} {
		if strings.Contains(p, bad) {
			t.Fatalf("prompt contains raw %q: %q", bad, p)
		}
	}
	if !strings.Contains(p, "bytes total") {
		t.Fatal("long args not truncated")
	}
	if !strings.Contains(p, "auto-deny in 1m0s") {
		t.Fatal("timeout not shown")
	}
}

func TestStatic(t *testing.T) {
	if ok, _ := Static(true).Ask(context.Background(), req); !ok {
		t.Fatal("allow")
	}
	if ok, _ := Static(false).Ask(context.Background(), req); ok {
		t.Fatal("deny")
	}
}
