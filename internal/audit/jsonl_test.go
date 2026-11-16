package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJSONLConcurrentRecordsStayWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	j, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				rule := i
				j.Log(&Event{Time: time.Unix(0, 0).UTC(), Session: "s", Kind: KindCall, Tool: strings.Repeat("t", 100+g), Decision: "deny", Rule: &rule, Labels: []string{"untrusted"}})
			}
		}(g)
	}
	wg.Wait()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d not JSON: %v", n, err)
		}
		for _, k := range []string{"time", "session", "event", "tool", "decision", "rule", "labels", "forwarded"} {
			if _, ok := e[k]; !ok {
				t.Fatalf("line %d missing %q: %s", n, k, sc.Text())
			}
		}
		if _, ok := e["args"]; ok {
			t.Fatal("args present without being set")
		}
		n++
	}
	if n != 1600 {
		t.Fatalf("got %d records", n)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestJSONLRecordsWriteErrors(t *testing.T) {
	j := NewJSONL(failWriter{})
	j.Log(&Event{Kind: KindCall})
	j.Log(&Event{Kind: KindCall})
	n, err := j.Err()
	if err == nil || n != 2 {
		t.Fatalf("err=%v n=%d", err, n)
	}
}

// slowWriter records each Write call separately so interleaving is visible.
type chunkRecorder struct {
	mu     sync.Mutex
	chunks []string
}

func (c *chunkRecorder) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chunks = append(c.chunks, string(p))
	return len(p), nil
}

func TestLineWriterNeverSplitsRecords(t *testing.T) {
	rec := &chunkRecorder{}
	j := NewJSONL(rec)
	lw := j.LineWriter()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			j.Log(&Event{Kind: KindCall, Tool: strings.Repeat("t", 5000)})
		}
	}()
	go func() {
		defer wg.Done()
		// The server writes log lines in arbitrary fragments.
		for i := 0; i < 500; i++ {
			lw.Write([]byte("server log li"))
			lw.Write([]byte("ne " + strings.Repeat("x", 3000) + "\nnext part"))
		}
	}()
	wg.Wait()
	lw.Close()
	all := strings.Join(rec.chunks, "")
	for n, line := range strings.Split(strings.TrimSuffix(all, "\n"), "\n") {
		if strings.HasPrefix(line, "{") {
			var e map[string]any
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("line %d: audit record corrupted: %.80q", n, line)
			}
		} else if !strings.HasPrefix(line, "server log line") && !strings.HasPrefix(line, "next partserver log line") && line != "next part" {
			t.Fatalf("line %d: server output corrupted: %.80q", n, line)
		}
	}
}

func TestLineWriterFlushesLongLines(t *testing.T) {
	rec := &chunkRecorder{}
	lw := NewJSONL(rec).LineWriter()
	lw.Write([]byte(strings.Repeat("y", maxLine+1)))
	if len(rec.chunks) != 1 {
		t.Fatalf("long unterminated line not flushed: %d chunks", len(rec.chunks))
	}
}
