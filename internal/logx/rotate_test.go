package logx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUntilNextMidnightUTC(t *testing.T) {
	cases := []struct {
		now  time.Time
		want time.Duration
	}{
		{time.Date(2026, 4, 14, 15, 30, 0, 0, time.UTC), 8*time.Hour + 30*time.Minute},
		{time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC), 12 * time.Hour},
		{time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC), 24 * time.Hour},
		{time.Date(2026, 4, 14, 23, 59, 59, 500000000, time.UTC), time.Second},
		{time.Date(2026, 4, 15, 7, 0, 0, 0, time.FixedZone("CST", 8*3600)), time.Hour},
	}
	for _, c := range cases {
		if got := untilNextMidnightUTC(c.now); got != c.want {
			t.Errorf("untilNextMidnightUTC(%s)=%s want %s", c.now, got, c.want)
		}
	}
}

func TestGCKeepsRecentAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "kekkai-agent-20200101.log")
	recent := filepath.Join(dir, "kekkai-agent-20990101.log")
	foreign := filepath.Join(dir, "notes.log")
	for _, p := range []string{old, recent, foreign} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(foreign, past, past); err != nil {
		t.Fatal(err)
	}

	rf, err := newRotatingFile(dir, "kekkai-agent.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("old rotated file still present: %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal(err)
	}
}

func TestRotateOnceArchivesOpenDay(t *testing.T) {
	dir := t.TempDir()
	rf, err := newRotatingFile(dir, "kekkai-agent.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })

	if _, err := rf.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	rf.mu.Lock()
	rf.currentDay = "20260414"
	rf.mu.Unlock()
	if err := rf.rotateOnce(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "kekkai-agent-20260414.log"))
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("archive %q err=%v", got, err)
	}
	st, err := os.Stat(filepath.Join(dir, "kekkai-agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 0 {
		t.Fatalf("active file size=%d", st.Size())
	}
}

func TestRotateOnceDoesNotClobberArchive(t *testing.T) {
	dir := t.TempDir()
	rf, err := newRotatingFile(dir, "kekkai-agent.log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rf.Close() })

	archive := filepath.Join(dir, "kekkai-agent-20260414.log")
	if err := os.WriteFile(archive, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.Write([]byte("new\n")); err != nil {
		t.Fatal(err)
	}
	rf.mu.Lock()
	rf.currentDay = "20260414"
	rf.mu.Unlock()
	if err := rf.rotateOnce(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(archive)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing archive %q err=%v", got, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "kekkai-agent-20260414.log.*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("matches=%v err=%v", matches, err)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil || string(body) != "new\n" {
		t.Fatalf("suffixed archive %q err=%v", body, err)
	}
	suffix := strings.TrimPrefix(filepath.Base(matches[0]), "kekkai-agent-20260414.log.")
	if suffix == "" || strings.Trim(suffix, "0123456789") != "" {
		t.Fatalf("suffix %q", suffix)
	}
}

func TestRotateOnceAfterCloseDoesNotReopen(t *testing.T) {
	dir := t.TempDir()
	rf, err := newRotatingFile(dir, "kekkai-agent.log")
	if err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(dir, "kekkai-agent.log")
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(active); err != nil {
		t.Fatal(err)
	}
	if err := rf.rotateOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active); !os.IsNotExist(err) {
		t.Fatalf("rotateOnce reopened %s: %v", active, err)
	}
	rf.mu.Lock()
	f := rf.f
	rf.mu.Unlock()
	if f != nil {
		t.Fatal("file handle reopened after Close")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	rf, err := newRotatingFile(dir, "kekkai-agent.log")
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rf.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}
