package logx

// textHandler emits one line per record:
//
//	[2026/04/14 15:30:00(UTC)][INFO ][update  ] msg key=val key2=val2
//
// UTC is fixed so logs from machines in different timezones still sort.
// Level is 5 columns and module is 8 so the prefix lines up under grep.
// Values with spaces, tabs, quotes, or '=' are double-quoted. No colour:
// the sinks are journald and a log file.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

const (
	// ModuleKey is the attr Logger.With stores. It is rendered in the
	// prefix column instead of the key=val tail.
	ModuleKey = "module"

	moduleWidth = 8
	modulePad   = "        " // moduleWidth spaces
)

type textHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	attrs []slog.Attr
	level slog.Level
}

func newTextHandler(w io.Writer, level slog.Level) *textHandler {
	return &textHandler{
		mu:    &sync.Mutex{},
		w:     w,
		level: level,
	}
}

func (h *textHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *textHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 192)
	t := r.Time.UTC()
	buf = append(buf, '[')
	buf = appendFixed(buf, t.Year(), 4)
	buf = append(buf, '/')
	buf = appendFixed(buf, int(t.Month()), 2)
	buf = append(buf, '/')
	buf = appendFixed(buf, t.Day(), 2)
	buf = append(buf, ' ')
	buf = appendFixed(buf, t.Hour(), 2)
	buf = append(buf, ':')
	buf = appendFixed(buf, t.Minute(), 2)
	buf = append(buf, ':')
	buf = appendFixed(buf, t.Second(), 2)
	buf = append(buf, "(UTC)]["...)
	buf = append(buf, levelName(r.Level)...)
	buf = append(buf, ']')

	// Record attrs override the handler's module so one call site can
	// retag a line. The first handler attr wins; the last record attr wins.
	mod := moduleAttr(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == ModuleKey {
			mod = a.Value.String()
		}
		return true
	})
	if mod == "" {
		mod = "-"
	}
	buf = append(buf, '[')
	buf = append(buf, fitWidth(mod, moduleWidth)...)
	buf = append(buf, ']', ' ')
	buf = append(buf, r.Message...)

	writeAttr := func(a slog.Attr) {
		if a.Key == ModuleKey {
			return
		}
		buf = append(buf, ' ')
		buf = append(buf, a.Key...)
		buf = append(buf, '=')
		buf = append(buf, stringifyValue(a.Value)...)
	}
	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.w.Write(buf)
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	next.attrs = append(next.attrs, h.attrs...)
	next.attrs = append(next.attrs, attrs...)
	return &next
}

// WithGroup is a no-op. The line format has no group column.
func (h *textHandler) WithGroup(string) slog.Handler { return h }

func moduleAttr(attrs []slog.Attr) string {
	for _, a := range attrs {
		if a.Key == ModuleKey {
			return a.Value.String()
		}
	}
	return ""
}

// levelName returns the 5-column name. Non-standard levels snap to the
// nearest standard one so the column never changes width.
func levelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "DEBUG"
	case l <= slog.LevelInfo:
		return "INFO "
	case l <= slog.LevelWarn:
		return "WARN "
	default:
		return "ERROR"
	}
}

// fitWidth pads s with spaces or cuts it to n bytes so the column stays put.
func fitWidth(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + modulePad[:n-len(s)]
}

func stringifyValue(v slog.Value) string {
	s := v.String()
	if !needsQuoting(s) {
		return s
	}
	return `"` + escapeQuoted(s) + `"`
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '"', '=', '\n', '\r':
			return true
		}
	}
	return false
}

// escapeQuoted keeps a value on one physical line. A raw newline inside
// quotes would still start a second log line.
func escapeQuoted(s string) string {
	if !strings.ContainsAny(s, "\"\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// appendFixed appends n in at least width digits. Negative n (a slog time
// before year 0) goes through fmt so the sign and zero-pad match %0*d.
func appendFixed(b []byte, n, width int) []byte {
	if n < 0 {
		return append(b, fmt.Sprintf("%0*d", width, n)...)
	}
	var tmp [20]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			break
		}
	}
	for len(tmp)-i < width {
		i--
		tmp[i] = '0'
	}
	return append(b, tmp[i:]...)
}

var _ slog.Handler = (*textHandler)(nil)
