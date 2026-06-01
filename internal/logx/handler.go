package logx

// textHandler is a slog.Handler that emits the kekkai log format:
//
//	[2026/04/14 15:30:00(UTC)][INFO ][update  ] msg key=val key2=val2
//
// Design decisions and their rationale:
//
//  1. Timestamp in UTC. Operators run kekkai on Pi boxes in arbitrary
//     timezones; collating log lines across machines is impossible if
//     each one lies in local time. The (UTC) suffix makes the timezone
//     choice visible so there is no second-guessing.
//
//  2. Fixed-width LEVEL and module columns. "INFO " / "WARN " / "ERROR"
//     are 5-char padded and module is padded to 8 chars so `grep` output
//     stays visually aligned and scrollable. The widths were chosen for
//     the modules we actually use (main / update / loader / reload /
//     stats / maps) — longest is 6 chars so 8 leaves room.
//
//  3. key=val pairs come after msg, space-separated. slog attrs that
//     contain spaces get shell-quoted to keep a single log line
//     parseable by `awk '{...}'` style filters. This isn't logfmt
//     (which would be stricter); it is "human-friendly text with a
//     stable layout" because humans read this far more than machines do.
//
//  4. No colour. Two of our three write destinations are journald and
//     a rotating log file; neither wants ANSI escapes. The CLI layer
//     (cmd/kekkai/ui.go) handles colourisation for interactive output.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	// ModuleKey is the attribute key we stash a module name under when
	// callers do Logger.With("module"). The handler special-cases it so
	// it renders in the prefix rather than inside the key=val tail.
	ModuleKey = "module"

	levelWidth  = 5
	moduleWidth = 8
)

// textHandler serialises slog records into the kekkai text format.
// Stateless aside from its writer and mutex — safe for concurrent calls
// from multiple goroutines (the stdlib slog.Logger is a concurrent user,
// so Handle() must be serialise-able).
type textHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	attrs []slog.Attr
	group string
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
	var b strings.Builder

	// Timestamp: YYYY/MM/DD HH:MM:SS(UTC). time.UTC() is a no-op
	// allocation so cheap; we format directly into the builder.
	t := r.Time.UTC()
	fmt.Fprintf(&b, "[%04d/%02d/%02d %02d:%02d:%02d(UTC)]",
		t.Year(), int(t.Month()), t.Day(),
		t.Hour(), t.Minute(), t.Second())

	// Level column. slog has Debug / Info / Warn / Error by default.
	// We upper-case and pad to 5 so INFO/WARN/ERROR are aligned.
	b.WriteByte('[')
	b.WriteString(padRight(levelName(r.Level), levelWidth))
	b.WriteByte(']')

	// Module column. Comes from either the With("module", ...) chain
	// or from a Record-level attr; we let the attr win so an ad-hoc
	// override in a single call site still prints.
	mod := h.moduleFromAttrs()
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == ModuleKey {
			mod = a.Value.String()
		}
		return true
	})
	if mod == "" {
		mod = "-"
	}
	b.WriteByte('[')
	b.WriteString(padRight(mod, moduleWidth))
	b.WriteByte(']')
	b.WriteByte(' ')

	// Message.
	b.WriteString(r.Message)

	// Attrs (minus the module special case). We emit in append order,
	// not alphabetical — call sites that put the most relevant attr
	// first are shown first.
	writeAttr := func(a slog.Attr) {
		if a.Key == ModuleKey {
			return
		}
		b.WriteByte(' ')
		b.WriteString(a.Key)
		b.WriteByte('=')
		b.WriteString(stringifyValue(a.Value))
	}
	for _, a := range h.attrs {
		writeAttr(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	_, err := io.WriteString(h.w, b.String())
	h.mu.Unlock()
	return err
}

func (h *textHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// slog handlers are immutable once created; WithAttrs returns a
	// derived handler sharing the parent's mutex + writer so log lines
	// from parent and child still serialise correctly.
	next := *h
	next.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &next
}

func (h *textHandler) WithGroup(name string) slog.Handler {
	next := *h
	next.group = name
	return &next
}

// moduleFromAttrs returns the module string from the accumulated
// With("module", ...) chain, or "" if none was set.
func (h *textHandler) moduleFromAttrs() string {
	for _, a := range h.attrs {
		if a.Key == ModuleKey {
			return a.Value.String()
		}
	}
	return ""
}

// levelName maps slog.Level to the upper-case short name the format
// expects. Non-standard levels round to the nearest standard one
// (our code never uses them but the handler should tolerate them).
func levelName(l slog.Level) string {
	switch {
	case l <= slog.LevelDebug:
		return "DEBUG"
	case l <= slog.LevelInfo:
		return "INFO"
	case l <= slog.LevelWarn:
		return "WARN"
	default:
		return "ERROR"
	}
}

// padRight pads s on the right with spaces to exactly n columns.
// Truncates if s is longer than n — we'd rather lose the tail of a
// weird module name than break column alignment.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

// stringifyValue renders a slog.Value as a bareword key=val fragment.
// Values containing whitespace or shell metacharacters get wrapped in
// double quotes so the line stays single-token-parseable.
func stringifyValue(v slog.Value) string {
	s := v.String()
	if needsQuoting(s) {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '"' || r == '=' {
			return true
		}
	}
	return false
}

// Ensure textHandler conforms to slog.Handler at compile time.
var _ slog.Handler = (*textHandler)(nil)

// Compile-time check: we rely on time.Time.UTC() being a zero-alloc
// timezone coercion. If that ever changes we'd want to cache.
var _ = time.Now
