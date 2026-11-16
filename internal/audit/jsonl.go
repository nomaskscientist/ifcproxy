package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// JSONL writes one JSON object per line. Each record is written with a
// single Write call under a mutex, so records never interleave.
type JSONL struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	err    error
	failed int
}

// NewJSONL writes records to w.
func NewJSONL(w io.Writer) *JSONL { return &JSONL{w: w} }

// OpenFile appends records to the file at path, creating it with mode 0600.
func OpenFile(path string) (*JSONL, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &JSONL{w: f, closer: f}, nil
}

// Log implements Sink. Write errors are remembered (see Err) rather than
// returned, so a broken audit log never blocks the proxy.
func (j *JSONL) Log(e *Event) {
	b, err := json.Marshal(e)
	if err != nil {
		b, _ = json.Marshal(struct {
			Kind  string `json:"event"`
			Error string `json:"error"`
		}{KindError, "unencodable audit event: " + err.Error()})
	}
	b = append(b, '\n')
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.w.Write(b); err != nil {
		if j.err == nil {
			j.err = err
		}
		j.failed++
	}
}

// Err returns the first write error and the number of records lost.
func (j *JSONL) Err() (lost int, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.failed, j.err
}

// Close closes the underlying file, if OpenFile created it.
func (j *JSONL) Close() error {
	if j.closer == nil {
		return nil
	}
	return j.closer.Close()
}

// maxLine bounds how much of an unterminated line LineWriter buffers before
// writing it out anyway.
const maxLine = 64 << 10

// LineWriter returns a writer for another stream that shares j's destination
// (the server's stderr when the audit log goes to stderr). It buffers input
// until a newline and writes whole lines under j's lock, so foreign output
// never splits an audit record. Close flushes an unterminated last line.
// The returned writer is meant for a single producer (exec's copy goroutine).
func (j *JSONL) LineWriter() io.WriteCloser { return &lineWriter{j: j} }

type lineWriter struct {
	j   *JSONL
	buf []byte
}

func (l *lineWriter) Write(p []byte) (int, error) {
	l.buf = append(l.buf, p...)
	if i := bytes.LastIndexByte(l.buf, '\n'); i >= 0 {
		if err := l.flush(l.buf[:i+1]); err != nil {
			return 0, err
		}
		l.buf = append(l.buf[:0], l.buf[i+1:]...)
	}
	if len(l.buf) > maxLine {
		if err := l.flush(l.buf); err != nil {
			return 0, err
		}
		l.buf = l.buf[:0]
	}
	return len(p), nil
}

func (l *lineWriter) flush(b []byte) error {
	l.j.mu.Lock()
	defer l.j.mu.Unlock()
	_, err := l.j.w.Write(b)
	return err
}

func (l *lineWriter) Close() error {
	if len(l.buf) == 0 {
		return nil
	}
	err := l.flush(append(l.buf, '\n'))
	l.buf = nil
	return err
}
