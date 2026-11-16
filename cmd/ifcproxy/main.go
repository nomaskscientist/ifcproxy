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
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"ifcproxy/internal/monitor"
	"ifcproxy/internal/policy"
	"ifcproxy/internal/proxy"
	"ifcproxy/internal/taint"
)

const shutdownGrace = 5 * time.Second

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
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: ifcproxy --policy p.yaml [flags] -- <mcp server command> [args...]\n       ifcproxy --policy p.yaml --check\n\nflags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if o.policyPath == "" {
		fs.Usage()
		return nil, nil, errors.New("--policy is required")
	}
	if !o.check && fs.NArg() == 0 {
		fs.Usage()
		return nil, nil, errors.New("missing MCP server command after --")
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

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = stderr
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
	cfg := proxy.Config{
		Monitor:         monitor.New(pol),
		Session:         sess,
		Store:           store,
		MaxMessageBytes: o.maxMessage,
		MaxPending:      o.maxPending,
		OnClientEOF:     func() { close(clientEOF) },
	}
	px, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "ifcproxy:", err)
		_ = cmd.Process.Kill()
		return 1
	}

	stopped := make(chan struct{})
	defer close(stopped)
	go supervise(ctx, cmd.Process, clientEOF, stopped)

	runErr := px.Run(ctx, stdin, stdout, serverIn, serverOut)
	waitErr := cmd.Wait()
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

// supervise terminates the server when the proxy is interrupted, or when the
// client has gone away and the server has not exited within shutdownGrace.
func supervise(ctx context.Context, proc *os.Process, clientEOF, stopped <-chan struct{}) {
	select {
	case <-ctx.Done():
		terminate(proc)
	case <-clientEOF:
		t := time.NewTimer(shutdownGrace)
		defer t.Stop()
		select {
		case <-t.C:
			_ = proc.Kill()
		case <-ctx.Done():
			terminate(proc)
		case <-stopped:
		}
	case <-stopped:
	}
}

// terminate asks the process to stop (SIGTERM where supported) and kills it
// after the grace period.
func terminate(proc *os.Process) {
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		_ = proc.Kill()
		return
	}
	time.AfterFunc(shutdownGrace, func() { _ = proc.Kill() })
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pid-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
