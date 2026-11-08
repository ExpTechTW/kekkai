// Package logx is the structured logger for kekkai-agent.
//
//	[YYYY/MM/DD HH:MM:SS(UTC)][LEVEL][module] msg key=val key2=val2
//
// Each line is written to stderr (journald) and to a daily file under
// /var/log/kekkai, kept for 7 days. The CLI does not use this package.
// Logger.With("name") sets the module column.
package logx

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Logger exposes the slog methods kekkai-agent calls.
type Logger struct {
	slog *slog.Logger
	// closer is set by New. With shares it; Close on any child closes the file.
	closer io.Closer
}

const (
	// DefaultLogDir and DefaultBaseName are the file New opens.
	// Exported so the installer and the systemd unit use the same paths.
	DefaultLogDir   = "/var/log/kekkai"
	DefaultBaseName = "kekkai-agent.log"
)

// New tees logs to stderr and a rotating file. If the directory cannot be
// created, logs go to stderr only so the agent still starts.
// Close stops the rotator.
func New() *Logger {
	rf, err := newRotatingFile(DefaultLogDir, DefaultBaseName)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"logx: file rotation disabled (%v); falling back to stderr-only\n", err)
		return &Logger{slog: slog.New(newTextHandler(os.Stderr, slog.LevelInfo))}
	}
	w := io.MultiWriter(os.Stderr, rf)
	return &Logger{slog: slog.New(newTextHandler(w, slog.LevelInfo)), closer: rf}
}

// With returns a child logger tagged with module.
func (l *Logger) With(module string) *Logger {
	return &Logger{
		slog:   l.slog.With(ModuleKey, module),
		closer: l.closer,
	}
}

func (l *Logger) Info(msg string, kv ...any)  { l.slog.Info(msg, kv...) }
func (l *Logger) Warn(msg string, kv ...any)  { l.slog.Warn(msg, kv...) }
func (l *Logger) Error(msg string, kv ...any) { l.slog.Error(msg, kv...) }

// Close stops the rotator and closes the file. Idempotent.
func (l *Logger) Close() error {
	if l.closer == nil {
		return nil
	}
	return l.closer.Close()
}
