// Package logx is the structured logger for kekkai-agent. It wraps
// slog with a custom text handler that produces the repo's canonical
// log line format:
//
//	[YYYY/MM/DD HH:MM:SS(UTC)][LEVEL][module] msg key=val key2=val2
//
// and writes simultaneously to stderr (picked up by journald in the
// systemd unit) and a rotated file at /var/log/kekkai/kekkai-agent.log
// (daily rotation, 7-day retention).
//
// Design intent:
//
//   - Single source of truth for log format. 44 old log.Printf call
//     sites were blending timestamp/module/level into ad-hoc string
//     prefixes like "auto-update: foo". This package makes that a
//     property of the handler rather than the call site.
//
//   - Not used by cmd/kekkai (the interactive CLI). The CLI already
//     has ui.go for coloured human-oriented output. logx is only for
//     long-running processes whose output ends up in journald or on
//     disk. Mixing the two would hurt both.
//
//   - Module tagging is a slog attribute ("module", <name>) that the
//     handler special-cases. Callers get it via Logger.With(module).
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Logger is a thin wrapper around *slog.Logger that exposes only the
// methods we actually use in kekkai-agent. Hiding the full slog
// surface keeps the call sites consistent and discourages anyone
// reaching for groups / context / handler swapping mid-flight.
type Logger struct {
	slog *slog.Logger
	// closer is the rotating file; nil when New() was given an
	// alternate writer (e.g. in tests). Close() drives it.
	closer io.Closer
}

const (
	// DefaultLogDir and DefaultBaseName are the paths New() opens for
	// the agent's on-disk log. Exported so installers (kekkai.sh) and
	// the systemd unit template can reference the same strings.
	DefaultLogDir   = "/var/log/kekkai"
	DefaultBaseName = "kekkai-agent.log"
)

// New constructs a Logger that tees writes to stderr AND to a daily-
// rotated file under /var/log/kekkai/. If the log directory cannot be
// created (e.g. running under a test or as an unprivileged user) we
// fall back to stderr-only so the agent never fails to start because
// of logging setup.
//
// The returned *Logger owns a background rotator goroutine; callers
// MUST call Close() at shutdown to stop it cleanly and release the
// file handle.
func New() *Logger {
	rf, err := newRotatingFile(DefaultLogDir, DefaultBaseName)
	if err != nil {
		// Degrade gracefully to stderr-only. We have no logger yet,
		// so this one-off stderr write is by hand.
		fmt.Fprintf(os.Stderr,
			"logx: file rotation disabled (%v); falling back to stderr-only\n", err)
		h := newTextHandler(os.Stderr, slog.LevelInfo)
		return &Logger{slog: slog.New(h)}
	}

	// MultiWriter guarantees both sinks get every line. If one write
	// errors (disk full, fd closed) the other still proceeds — slog's
	// handler does NOT propagate write errors upwards to the caller,
	// so an operator silently losing the file tail is at worst a log
	// gap rather than an agent crash.
	w := io.MultiWriter(os.Stderr, rf)
	h := newTextHandler(w, slog.LevelInfo)
	return &Logger{slog: slog.New(h), closer: rf}
}

// NewWithWriter builds a Logger backed by an explicit writer. Used by
// tests and by any future call site that wants to redirect logs (e.g.
// into a buffer for assertion). No rotation, no stderr tee.
func NewWithWriter(w io.Writer) *Logger {
	return &Logger{slog: slog.New(newTextHandler(w, slog.LevelInfo))}
}

// With returns a child Logger carrying the given module tag. This is
// the canonical way to route a subsystem's logs: agent main creates a
// root logger, each subsystem calls root.With("update") once and
// keeps the result for the life of the process.
func (l *Logger) With(module string) *Logger {
	return &Logger{
		slog:   l.slog.With(ModuleKey, module),
		closer: l.closer, // share underlying file handle, don't dup
	}
}

// Info / Warn / Error mirror slog's variadic key/value signature but
// wrap it in named methods so call sites stay compact. The variadic
// args are slog attribute pairs: ("key", val, "key2", val2, ...).
func (l *Logger) Info(msg string, kv ...any)  { l.slog.Info(msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.slog.Warn(msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.slog.Error(msg, kv...) }

// Close stops the background rotator and releases the file handle.
// Safe to call multiple times. Only the root logger created by New()
// owns the closer — child loggers from With() share it by reference,
// so calling Close() on a child is equivalent to closing the root.
func (l *Logger) Close() error {
	if l.closer == nil {
		return nil
	}
	return l.closer.Close()
}
