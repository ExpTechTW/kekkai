package logx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestHandleFormat(t *testing.T) {
	if len(modulePad) != moduleWidth {
		t.Fatalf("modulePad len=%d, width=%d", len(modulePad), moduleWidth)
	}
	var buf bytes.Buffer
	h := newTextHandler(&buf, slog.LevelInfo).WithAttrs([]slog.Attr{
		slog.String(ModuleKey, "loader"),
		slog.String("k", "v"),
	})
	r := slog.NewRecord(time.Date(2026, 4, 14, 15, 30, 0, 0, time.UTC), slog.LevelInfo, "staged", 0)
	r.AddAttrs(
		slog.String(ModuleKey, "update"),
		slog.String("version", "v1"),
		slog.Int("n", 2),
		slog.String("note", "has space"),
		slog.String("q", `say "hi"`),
		slog.String("eq", "a=b"),
		slog.String("empty", ""),
		slog.String("path", "a/b"),
	)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	want := `[2026/04/14 15:30:00(UTC)][INFO ][update  ] staged k=v version=v1 n=2 note="has space" q="say \"hi\"" eq="a=b" empty="" path=a/b` + "\n"
	if got := buf.String(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestHandleLevelAndModuleWidth(t *testing.T) {
	when := time.Date(2026, 4, 14, 1, 2, 3, 0, time.UTC)
	cases := []struct {
		level slog.Level
		mod   string
		want  string
	}{
		{slog.LevelDebug, "main", "[2026/04/14 01:02:03(UTC)][DEBUG][main    ] hi\n"},
		{slog.LevelInfo, "", "[2026/04/14 01:02:03(UTC)][INFO ][-       ] hi\n"},
		{slog.LevelWarn, "abcdefghij", "[2026/04/14 01:02:03(UTC)][WARN ][abcdefgh] hi\n"},
		{slog.LevelError, "x", "[2026/04/14 01:02:03(UTC)][ERROR][x       ] hi\n"},
		{slog.LevelInfo + 1, "x", "[2026/04/14 01:02:03(UTC)][WARN ][x       ] hi\n"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		h := newTextHandler(&buf, slog.LevelDebug)
		r := slog.NewRecord(when, c.level, "hi", 0)
		if c.mod != "" {
			r.AddAttrs(slog.String(ModuleKey, c.mod))
		}
		if err := h.Handle(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		if got := buf.String(); got != c.want {
			t.Errorf("level %v mod %q\ngot  %q\nwant %q", c.level, c.mod, got, c.want)
		}
	}
}

func TestHandleUTC(t *testing.T) {
	var buf bytes.Buffer
	h := newTextHandler(&buf, slog.LevelInfo)
	loc := time.FixedZone("CST", 8*3600)
	r := slog.NewRecord(time.Date(2026, 4, 15, 7, 0, 0, 0, loc), slog.LevelInfo, "tick", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "[2026/04/14 23:00:00(UTC)]") {
		t.Fatalf("got %q", got)
	}

	buf.Reset()
	r = slog.NewRecord(time.Date(-1, 1, 2, 3, 4, 5, 0, time.UTC), slog.LevelInfo, "old", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.HasPrefix(got, "[-001/01/02 03:04:05(UTC)]") {
		t.Fatalf("got %q", got)
	}
}

func TestQuoteNewline(t *testing.T) {
	var buf bytes.Buffer
	h := newTextHandler(&buf, slog.LevelInfo)
	r := slog.NewRecord(time.Date(2026, 4, 14, 15, 30, 0, 0, time.UTC), slog.LevelInfo, "boom", 0)
	r.AddAttrs(slog.String("err", "a\nb\r"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("value broke the log line: %q", got)
	}
	if !strings.Contains(got, `err="a\nb\r"`) {
		t.Fatalf("got %q", got)
	}
}

func TestEnabled(t *testing.T) {
	h := newTextHandler(&bytes.Buffer{}, slog.LevelInfo)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("debug should be disabled")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info should be enabled")
	}
}
