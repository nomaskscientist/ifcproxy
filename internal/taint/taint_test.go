package taint

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestParseAndString(t *testing.T) {
	tests := []struct {
		in   string
		want Label
		ok   bool
	}{
		{"untrusted", Untrusted, true},
		{"private", Private, true},
		{"Untrusted", None, false},
		{" private", None, false},
		{"", None, false},
	}
	for _, tt := range tests {
		got, ok := Parse(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("Parse(%q) = %v,%v want %v,%v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
	if s := (Untrusted | Private).String(); s != "untrusted|private" {
		t.Errorf("String = %q", s)
	}
	if s := None.String(); s != "none" {
		t.Errorf("String = %q", s)
	}
	if s := Label(1 << 7).String(); s != "unknown" {
		t.Errorf("String = %q", s)
	}
}

func TestSessionMonotonic(t *testing.T) {
	s := NewSession("x")
	if s.Labels() != None {
		t.Fatal("new session not empty")
	}
	if got := s.Add(Untrusted); got != Untrusted {
		t.Fatalf("added %v", got)
	}
	if got := s.Add(Untrusted); got != None {
		t.Fatalf("re-add reported %v", got)
	}
	if got := s.Add(Untrusted | Private); got != Private {
		t.Fatalf("added %v", got)
	}
	if s.Labels() != Known {
		t.Fatalf("labels %v", s.Labels())
	}
}

func TestSessionConcurrentAdd(t *testing.T) {
	s := NewSession("c")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var union Label
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l := Label(1 << (i % 32))
			for j := 0; j < 1000; j++ {
				if a := s.Add(l); a != None {
					mu.Lock()
					if union&a != 0 {
						t.Errorf("label %v reported as newly added twice", a)
					}
					union |= a
					mu.Unlock()
				}
				_ = s.Labels()
			}
		}(i)
	}
	wg.Wait()
	if s.Labels() != Label(0xffffffff) || union != Label(0xffffffff) {
		t.Fatalf("labels %x union %x", uint32(s.Labels()), uint32(union))
	}
}

func TestSessionAddZeroAlloc(t *testing.T) {
	s := NewSession("a")
	n := testing.AllocsPerRun(1000, func() {
		s.Add(Private)
		_ = s.Labels()
	})
	if n != 0 {
		t.Fatalf("allocs = %v", n)
	}
}

func TestStoreSharesLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess")
	a, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	sa, sb := NewSession("a"), NewSession("b")
	sa.Add(Untrusted)
	if err := a.Publish(sa.Labels()); err != nil {
		t.Fatal(err)
	}
	sb.Add(Private)
	if err := b.Publish(sb.Labels()); err != nil {
		t.Fatal(err)
	}
	if err := a.Sync(sa); err != nil {
		t.Fatal(err)
	}
	if err := b.Sync(sb); err != nil {
		t.Fatal(err)
	}
	if sa.Labels() != Known || sb.Labels() != Known {
		t.Fatalf("a=%v b=%v", sa.Labels(), sb.Labels())
	}
	// Re-publishing an already published set writes nothing.
	fi1, _ := os.Stat(path)
	if err := a.Publish(Untrusted); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(path)
	if fi1.Size() != fi2.Size() {
		t.Fatal("redundant publish wrote a record")
	}
}

func TestStoreCorruptFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess")
	if err := os.WriteFile(path, []byte("zzzzzzzz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewSession("x")
	if err := st.Sync(s); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
	if s.Labels() != Known {
		t.Fatalf("labels %v, want all known", s.Labels())
	}
}

func TestStoreIgnoresPartialRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sess")
	if err := os.WriteFile(path, []byte("00000001\n0000"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewSession("x")
	if err := st.Sync(s); err != nil {
		t.Fatal(err)
	}
	if s.Labels() != Untrusted {
		t.Fatalf("labels %v", s.Labels())
	}
}
