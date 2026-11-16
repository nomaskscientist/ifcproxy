package e2e

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The server ignores stdin EOF and has a descendant holding its stdout (the
// situation behind wrapper launchers like npx). After the client leaves the
// proxy must kill the whole tree and exit instead of waiting forever.
func TestOrphanedGrandchildDoesNotHangProxy(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "sleeper.pid")
	p := start(t, opts{env: []string{"FAKEMCP_IGNORE_EOF=1", "FAKEMCP_ORPHAN=1", "FAKEMCP_ORPHAN_PIDFILE=" + pidfile}})
	t0 := time.Now()
	p.stdin.Close()
	// The proxy closing its stdout means it exited (descendants of the server
	// never hold the proxy's own stdout).
	timeout := time.After(20 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-p.lines:
		case <-timeout:
			t.Fatal("proxy hung on an orphaned grandchild")
		}
	}
	t.Logf("proxy exited after %v", time.Since(t0).Round(time.Millisecond))
	b, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(5 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d still running after the proxy exited", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
