package audit

import (
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
