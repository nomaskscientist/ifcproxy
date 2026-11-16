package taint

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// recordLen is the size of one record in a shared session file:
// 8 lower-case hex digits followed by '\n'.
const recordLen = 9

// Store shares session labels between several proxy processes through an
// append-only file. Every process appends the full label set it holds after
// it grows; every process ORs all records into its own Session before it
// makes a decision. Because labels only grow, ordering between writers does
// not matter and no locking is needed beyond O_APPEND atomicity of 9-byte
// writes.
//
// A corrupted file fails closed: Sync adds every known label to the session.
type Store struct {
	mu   sync.Mutex
	f    *os.File
	off  int64
	buf  []byte
	last Label // last label set this process published
}

// OpenStore opens (creating if needed) the shared session file at path.
func OpenStore(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open session file: %w", err)
	}
	return &Store{f: f, buf: make([]byte, 0, 4096)}, nil
}

// ErrCorrupt is returned by Sync when the shared file contains a malformed record.
var ErrCorrupt = errors.New("shared session file is corrupt")

// Sync reads records appended since the previous call and merges them into s.
func (st *Store) Sync(s *Session) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	fi, err := st.f.Stat()
	if err != nil {
		s.Add(Known)
		return fmt.Errorf("stat session file: %w", err)
	}
	size := fi.Size()
	if size < st.off {
		// Truncation would let labels disappear; treat as corruption.
		s.Add(Known)
		return fmt.Errorf("%w: file shrank from %d to %d bytes", ErrCorrupt, st.off, size)
	}
	n := size - st.off
	n -= n % recordLen // only complete records
	if n == 0 {
		return nil
	}
	if int64(cap(st.buf)) < n {
		st.buf = make([]byte, n)
	}
	b := st.buf[:n]
	if _, err := st.f.ReadAt(b, st.off); err != nil && !errors.Is(err, io.EOF) {
		s.Add(Known)
		return fmt.Errorf("read session file: %w", err)
	}
	var acc Label
	for i := 0; i < len(b); i += recordLen {
		v, ok := parseRecord(b[i : i+recordLen])
		if !ok {
			s.Add(Known)
			return fmt.Errorf("%w: bad record at offset %d", ErrCorrupt, st.off+int64(i))
		}
		acc |= v
	}
	st.off += n
	s.Add(acc)
	return nil
}

// Publish appends l to the shared file if it adds anything this process has
// not already published.
func (st *Store) Publish(l Label) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.last|l == st.last {
		return nil
	}
	var rec [recordLen]byte
	const hex = "0123456789abcdef"
	for i := 0; i < 8; i++ {
		rec[i] = hex[(uint32(l)>>(28-4*i))&0xf]
	}
	rec[8] = '\n'
	if _, err := st.f.Write(rec[:]); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}
	st.last |= l
	return nil
}

// Close closes the underlying file.
func (st *Store) Close() error { return st.f.Close() }

func parseRecord(r []byte) (Label, bool) {
	if len(r) != recordLen || r[8] != '\n' {
		return None, false
	}
	var v uint32
	for _, c := range r[:8] {
		switch {
		case c >= '0' && c <= '9':
			v = v<<4 | uint32(c-'0')
		case c >= 'a' && c <= 'f':
			v = v<<4 | uint32(c-'a'+10)
		default:
			return None, false
		}
	}
	return Label(v), true
}
