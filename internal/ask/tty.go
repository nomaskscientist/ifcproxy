package ask

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// MaxArgsShown is the number of argument bytes shown in a confirmation prompt.
const MaxArgsShown = 512

// ErrTimeout is returned when nobody answers within the timeout.
var ErrTimeout = errors.New("no answer before timeout")

// Terminal is a pair of streams connected to a human.
type Terminal struct {
	In  io.ReadCloser
	Out io.Writer
}

// TTY asks the human at the controlling terminal (/dev/tty, or the console
// on Windows). MCP clients own the proxy's stdin/stdout, so the terminal is
// opened separately. Questions are serialised.
type TTY struct {
	Timeout time.Duration
	Open    func() (*Terminal, error) // defaults to the controlling terminal

	mu sync.Mutex
}

// NewTTY returns a TTY asker with the given timeout (0 means wait forever).
func NewTTY(timeout time.Duration) *TTY {
	return &TTY{Timeout: timeout, Open: openTerminal}
}

// Available reports whether a terminal can be opened.
func (t *TTY) Available() error {
	term, err := t.Open()
	if err != nil {
		return err
	}
	return term.In.Close()
}

// Ask implements Asker. Anything other than "y" or "yes" is a denial.
func (t *TTY) Ask(ctx context.Context, r Request) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	term, err := t.Open()
	if err != nil {
		return false, fmt.Errorf("open terminal: %w", err)
	}
	defer term.In.Close()

	if _, err := io.WriteString(term.Out, Prompt(r, t.Timeout)); err != nil {
		return false, fmt.Errorf("write prompt: %w", err)
	}
	answer := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(term.In).ReadString('\n')
		answer <- line
	}()
	var timeout <-chan time.Time
	if t.Timeout > 0 {
		timer := time.NewTimer(t.Timeout)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case a := <-answer:
		a = strings.ToLower(strings.TrimSpace(a))
		ok := a == "y" || a == "yes"
		verdict := "denied"
		if ok {
			verdict = "allowed"
		}
		fmt.Fprintf(term.Out, "[ifcproxy] %s\n", verdict)
		return ok, nil
	case <-timeout:
		fmt.Fprintf(term.Out, "\n[ifcproxy] no answer in %s: denied\n", t.Timeout)
		return false, ErrTimeout
	case <-ctx.Done():
		fmt.Fprintf(term.Out, "\n[ifcproxy] interrupted: denied\n")
		return false, ctx.Err()
	}
}

// Prompt renders the confirmation question. Values controlled by the model
// or the server (tool name, arguments) are quoted with all control and
// non-ASCII characters escaped, so they cannot inject terminal escape
// sequences or bidi overrides that would disguise the question.
func Prompt(r Request, timeout time.Duration) string {
	args := r.Args
	truncated := ""
	if len(args) > MaxArgsShown {
		args = args[:MaxArgsShown]
		truncated = fmt.Sprintf(" … (%d bytes total)", len(r.Args))
	}
	if len(args) == 0 {
		args = []byte("{}")
	}
	wait := "no timeout"
	if timeout > 0 {
		wait = "auto-deny in " + timeout.String()
	}
	var b strings.Builder
	b.WriteString("\n[ifcproxy] a tool call needs your confirmation\n")
	fmt.Fprintf(&b, "  session: %s\n", strconv.QuoteToASCII(r.Session))
	fmt.Fprintf(&b, "  tool:    %s\n", strconv.QuoteToASCII(r.Tool))
	fmt.Fprintf(&b, "  labels:  %s\n", r.Labels)
	fmt.Fprintf(&b, "  reason:  %s\n", printable(r.Reason))
	fmt.Fprintf(&b, "  args:    %s%s\n", strconv.QuoteToASCII(string(args)), truncated)
	fmt.Fprintf(&b, "Allow? [y/N] (%s): ", wait)
	return b.String()
}

func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, s)
}
