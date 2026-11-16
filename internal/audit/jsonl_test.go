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
