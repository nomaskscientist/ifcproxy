// Command ifcproxy is a stdio MCP proxy that enforces an information-flow
// policy on tools/call.
//
//	ifcproxy --policy policy.yaml -- <mcp server command> [args...]
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/nomaskscientist/ifcproxy/internal/ask"
	"github.com/nomaskscientist/ifcproxy/internal/audit"
	"github.com/nomaskscientist/ifcproxy/internal/monitor"
	"github.com/nomaskscientist/ifcproxy/internal/policy"
	"github.com/nomaskscientist/ifcproxy/internal/proxy"
	"github.com/nomaskscientist/ifcproxy/internal/streamhttp"
	"github.com/nomaskscientist/ifcproxy/internal/taint"
)

const (
	shutdownGrace = 5 * time.Second // client gone or signal received -> kill
	orphanGrace   = 2 * time.Second // after a kill, how long to wait for the server's pipes to close
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type options struct {
	policyPath  string
	check       bool
	sessionID   string
	sessionFile string
	maxMessage  int
	maxPending  int
	askMode     string
	askTimeout  time.Duration
	auditPath   string
	logArgs     bool
	dryRun      bool
	version     bool
	upstream    string
	headers     []string
}

// version is set at release build time with -ldflags "-X main.version=v1.2.3".
var version = ""

// versionString reports the release version, the module version recorded by
// "go install ...@vX.Y.Z", or "devel".
func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "devel"
}

func parseFlags(args []string, stderr io.Writer) (*options, []string, error) {
	fs := flag.NewFlagSet("ifcproxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := &options{}
	fs.StringVar(&o.policyPath, "policy", "", "path to the YAML policy (required)")
	fs.BoolVar(&o.check, "check", false, "validate the policy and exit")
	fs.StringVar(&o.sessionID, "session-id", "", "session identifier for audit records (default: random)")
	fs.StringVar(&o.sessionFile, "session-file", "", "share session labels with other ifcproxy instances through this file")
	fs.IntVar(&o.maxMessage, "max-message-bytes", proxy.DefaultMaxMessageBytes, "maximum size of one JSON-RPC message")
	fs.IntVar(&o.maxPending, "max-pending", proxy.DefaultMaxPending, "maximum number of in-flight client requests")
	fs.StringVar(&o.askMode, "ask-mode", "tty", "how to resolve action: ask — tty (prompt on the controlling terminal), deny, allow")
	fs.DurationVar(&o.askTimeout, "ask-timeout", 60*time.Second, "deny an unanswered tty prompt after this long (0 = wait forever)")
	fs.StringVar(&o.auditPath, "audit", "-", "audit log (JSONL): file path, \"-\" for stderr, \"off\" to disable")
	fs.BoolVar(&o.logArgs, "log-args", false, "include tool arguments in the audit log (may contain secrets)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "decide and log, but forward every call (no enforcement)")
	fs.BoolVar(&o.version, "version", false, "print the version and exit")
	fs.StringVar(&o.upstream, "upstream", "", "MCP server URL (Streamable HTTP) instead of a server command")
	fs.Func("header", "extra upstream HTTP header \"Name: value\" (repeatable; ${VAR} reads the environment)", func(v string) error {
		o.headers = append(o.headers, v)
		return nil
	})
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: ifcproxy --policy p.yaml [flags] -- <mcp server command> [args...]\n       ifcproxy --policy p.yaml [flags] --upstream https://host/mcp [--header \"Name: value\"]...\n       ifcproxy --policy p.yaml --check\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if o.version {
		return o, nil, nil
	}
	if o.policyPath == "" {
		fs.Usage()
		return nil, nil, errors.New("--policy is required")
	}
	switch {
	case o.upstream != "" && fs.NArg() > 0:
		return nil, nil, errors.New("give either --upstream or a server command after --, not both")
	case o.upstream == "" && len(o.headers) > 0:
		return nil, nil, errors.New("--header needs --upstream")
	case o.upstream != "":
		if err := streamhttp.ValidateURL(o.upstream); err != nil {
			return nil, nil, err
		}
	case !o.check && fs.NArg() == 0:
		fs.Usage()
		return nil, nil, errors.New("missing MCP server command after -- (or --upstream URL)")
	}
	switch o.askMode {
	case "tty", "deny", "allow":
	default:
		return nil, nil, fmt.Errorf("--ask-mode must be tty, deny or allow, got %q", o.askMode)
	}
	if o.askTimeout < 0 {
		return nil, nil, errors.New("--ask-timeout must not be negative")
	}
	return o, fs.Args(), nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, cmdArgs, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 2
	}
	if o.version {
		fmt.Fprintln(stdout, "ifcproxy", versionString())
		return 0
	}
	pol, err := policy.Load(o.policyPath)
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy: invalid policy:")
		fmt.Fprintln(stderr, err)
		return 2
	}
	if o.check {
		fmt.Fprintf(stdout, "policy OK: %d tools, %d rules\n", len(pol.Tools), len(pol.Rules))
		return 0
	}

	id := o.sessionID
	if id == "" {
		id = randomID()
	}
	sess := taint.NewSession(id)
	var store *taint.Store
	if o.sessionFile != "" {
		store, err = taint.OpenStore(o.sessionFile)
		if err != nil {
			fmt.Fprintln(stderr, "ifcproxy:", err)
			return 2
		}
		defer store.Close()
		if err := store.Sync(sess); err != nil {
			fmt.Fprintln(stderr, "ifcproxy: warning:", err)
		}
	}

	var sink audit.Sink
	var childStderr io.Writer = stderr
	var childStderrCloser io.Closer
	switch o.auditPath {
	case "off":
	case "-":
		j := audit.NewJSONL(stderr)
		sink = j
		defer reportAuditLoss(j, stderr)
		// The server's stderr shares the destination: route it through a
		// writer that emits whole lines under the audit lock, so server
		// logs never split an audit record.
		lw := j.LineWriter()
		childStderr, childStderrCloser = lw, lw
	default:
		j, err := audit.OpenFile(o.auditPath)
		if err != nil {
			fmt.Fprintln(stderr, "ifcproxy:", err)
			return 2
		}
		sink = j
		defer j.Close()
		defer reportAuditLoss(j, stderr)
	}

	var asker ask.Asker
	switch o.askMode {
	case "allow":
		asker = ask.Static(true)
	case "deny":
		asker = ask.Static(false)
	default:
		tty := ask.NewTTY(o.askTimeout)
		if err := tty.Available(); err != nil && hasAsk(pol) {
			fmt.Fprintf(stderr, "ifcproxy: warning: no terminal for confirmations (%v); calls with action ask will be denied\n", err)
		}
		asker = tty
	}
	if o.dryRun {
		fmt.Fprintln(stderr, "ifcproxy: DRY RUN: decisions are logged but NOT enforced")
	}

	baseConfig := proxy.Config{
		Monitor:         monitor.New(pol),
		Session:         sess,
		Store:           store,
		Asker:           asker,
		Audit:           sink,
		DryRun:          o.dryRun,
		LogArgs:         o.logArgs,
		MaxMessageBytes: o.maxMessage,
		MaxPending:      o.maxPending,
	}
	if o.upstream != "" {
		code := runUpstream(o, baseConfig, stdin, stdout, stderr, childStderr)
		if childStderrCloser != nil {
			childStderrCloser.Close()
		}
		return code
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = childStderr
	// If descendants of the server keep stderr open after it exits, stop
	// waiting for them after this long.
	cmd.WaitDelay = orphanGrace
	setProcGroup(cmd)
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 1
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 1
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "ifcproxy: start server:", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	clientEOF := make(chan struct{})
	cfg := baseConfig
	cfg.OnClientEOF = func() { close(clientEOF) }
	px, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		_ = cmd.Process.Kill()
		return 1
	}

	stopped := make(chan struct{})
	defer close(stopped)
	killed := make(chan struct{})
	go supervise(ctx, cmd.Process, clientEOF, stopped, killed)

	runDone := make(chan error, 1)
	go func() { runDone <- px.Run(ctx, stdin, stdout, serverIn, serverOut) }()
	var runErr error
	var orphanTimeout <-chan time.Time
wait:
	for {
		select {
		case runErr = <-runDone:
			break wait
		case <-killed:
			killed = nil
			orphanTimeout = time.After(orphanGrace)
		case <-orphanTimeout:
			// The server was killed but something still holds its stdout
			// (descendants we could not reach). Do not hang the client.
			fmt.Fprintln(stderr, "ifcproxy: server output still open after the server was killed (orphaned child processes?); exiting")
			if childStderrCloser != nil {
				childStderrCloser.Close()
			}
			return 1
		}
	}
	waitErr := cmd.Wait()
	if childStderrCloser != nil {
		childStderrCloser.Close()
	}
	if runErr != nil {
		fmt.Fprintln(stderr, "ifcproxy:", runErr)
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		if runErr != nil {
			return 1
		}
		return 0
	case errors.As(waitErr, &ee):
		if ee.ExitCode() >= 0 {
			return ee.ExitCode()
		}
		return 1 // killed by a signal (possibly by us after the grace period)
	default:
		fmt.Fprintln(stderr, "ifcproxy: wait:", waitErr)
		return 1
	}
}

// supervise terminates the server (and its process tree) when the proxy is
// interrupted, or when the client has gone away and the server has not
// exited within shutdownGrace. killed is closed after a hard kill.
func supervise(ctx context.Context, proc *os.Process, clientEOF, stopped <-chan struct{}, killed chan<- struct{}) {
	var once sync.Once
	kill := func() {
		once.Do(func() {
			killTree(proc)
			close(killed)
		})
	}
	terminate := func() {
		if err := termTree(proc); err != nil {
			kill()
			return
		}
		t := time.NewTimer(shutdownGrace)
		defer t.Stop()
		select {
		case <-t.C:
			kill()
		case <-stopped:
		}
	}
	select {
	case <-ctx.Done():
		terminate()
	case <-clientEOF:
		t := time.NewTimer(shutdownGrace)
		defer t.Stop()
		select {
		case <-t.C:
			kill()
		case <-ctx.Done():
			terminate()
		case <-stopped:
		}
	case <-stopped:
	}
}

// runUpstream proxies to a Streamable HTTP server instead of a child process.
// The session ends when the client closes its output or on a signal.
func runUpstream(o *options, cfg proxy.Config, stdin io.Reader, stdout, stderr, logw io.Writer) int {
	hdr := http.Header{}
	for _, h := range o.headers {
		k, v, err := streamhttp.ParseHeader(h, os.LookupEnv)
		if err != nil {
			fmt.Fprintln(stderr, "ifcproxy:", err)
			return 2
		}
		hdr.Add(k, v)
	}
	conn, err := streamhttp.New(streamhttp.Config{
		URL:             o.upstream,
		Header:          hdr,
		MaxMessageBytes: o.maxMessage,
		Log:             logw,
	})
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 2
	}
	px, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 1
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := px.Run(ctx, stdin, stdout, conn, conn); err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		return 1
	}
	return 0
}

func hasAsk(p *policy.Policy) bool {
	for _, r := range p.Rules {
		if r.Action == policy.Ask {
			return true
		}
	}
	return false
}

func reportAuditLoss(j *audit.JSONL, stderr io.Writer) {
	if n, err := j.Err(); err != nil {
		fmt.Fprintf(stderr, "ifcproxy: warning: %d audit records lost: %v\n", n, err)
	}
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pid-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
