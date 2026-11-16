package proxy

import (
	"bufio"
	"errors"
	"io"
)

const readBufSize = 64 << 10

// lineReader splits a stream into newline-delimited messages with an upper
// bound on message size.
type lineReader struct {
	br  *bufio.Reader
	max int
	buf []byte
}

func newLineReader(r io.Reader, max int) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, readBufSize), max: max}
}

// next returns the next line including its trailing '\n' (absent for a final
// unterminated line). The returned slice is valid until the following call.
//
// If a line is longer than max bytes, next does not buffer it: it passes the
// line to overflow in chunks (the first chunk is everything read so far) and
// returns oversized=true. A final unterminated line is returned with a nil
// error; the next call returns io.EOF.
func (lr *lineReader) next(overflow func([]byte) error) (line []byte, oversized bool, err error) {
	if cap(lr.buf) > 4<<20 {
		lr.buf = nil // do not pin memory after one huge message
	}
	lr.buf = lr.buf[:0]
	for {
		chunk, rerr := lr.br.ReadSlice('\n')
		if len(lr.buf)+len(chunk) > lr.max {
			if err := overflow(lr.buf); err != nil {
				return nil, true, err
			}
			lr.buf = lr.buf[:0]
			for {
				if err := overflow(chunk); err != nil {
					return nil, true, err
				}
				if !errors.Is(rerr, bufio.ErrBufferFull) {
					break
				}
				chunk, rerr = lr.br.ReadSlice('\n')
			}
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return nil, true, rerr
			}
			return nil, true, nil
		}
		lr.buf = append(lr.buf, chunk...)
		switch {
		case rerr == nil:
			return lr.buf, false, nil
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		case errors.Is(rerr, io.EOF) && len(lr.buf) > 0:
			return lr.buf, false, nil
		default:
			return nil, false, rerr
		}
	}
}
