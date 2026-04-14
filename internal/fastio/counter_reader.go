package fastio

import (
	"errors"
	"io"
	"os"
)

var errNoDigits = errors.New("no digits in counter input")

// CounterReader reads a sysfs/procfs integer counter with minimal allocations.
// It keeps the file descriptor open and reuses a fixed-size byte buffer.
type CounterReader struct {
	path string
	f    *os.File
	buf  [64]byte
}

func NewCounterReader(path string) *CounterReader {
	cr := &CounterReader{path: path}
	_ = cr.reopen()
	return cr
}

func (cr *CounterReader) Close() error {
	if cr.f == nil {
		return nil
	}
	err := cr.f.Close()
	cr.f = nil
	return err
}

func (cr *CounterReader) Read() (uint64, error) {
	if cr.f == nil {
		if err := cr.reopen(); err != nil {
			return 0, err
		}
	}

	if _, err := cr.f.Seek(0, io.SeekStart); err != nil {
		_ = cr.Close()
		if err := cr.reopen(); err != nil {
			return 0, err
		}
		if _, err := cr.f.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
	}

	n, err := cr.f.Read(cr.buf[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	return parseUintASCII(cr.buf[:n])
}

func (cr *CounterReader) reopen() error {
	f, err := os.Open(cr.path)
	if err != nil {
		return err
	}
	cr.f = f
	return nil
}

func parseUintASCII(b []byte) (uint64, error) {
	i := 0
	for i < len(b) {
		c := b[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		i++
	}
	if i >= len(b) {
		return 0, errNoDigits
	}

	var v uint64
	digits := 0
	for i < len(b) {
		c := b[i]
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
		digits++
		i++
	}
	if digits == 0 {
		return 0, errNoDigits
	}
	return v, nil
}
