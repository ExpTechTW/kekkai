package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ExpTechTW/kekkai/internal/stats"
)

func TestReusePerIP(t *testing.T) {
	g := stats.Global{PktsTotal: 4, BytesTotal: 9}
	if !reusePerIP(true, 5, 5, g, g) {
		t.Fatal("idle overview should reuse the last rows")
	}
	if reusePerIP(true, 0, 5, g, g) {
		t.Fatal("a different limit must rescan")
	}
	if reusePerIP(false, 5, 5, g, g) {
		t.Fatal("a failed walk must be retried")
	}
	moved := g
	moved.PktsDropped = 1
	if reusePerIP(true, 5, 5, g, moved) {
		t.Fatal("a changed counter must rescan")
	}
}

func TestViewCacheUntilUpdate(t *testing.T) {
	m := NewModel(nil, "node", "eth0", "generic", "dev", "stable", time.Time{}, nil)
	first := m.View()
	if !strings.Contains(first, "initialising") {
		t.Fatalf("first frame: %q", first)
	}
	m.viewCache = "sentinel"
	if m.View() != "sentinel" {
		t.Fatal("View rebuilt a cached frame")
	}
	model, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	next := model.(*Model)
	if next.viewCache != "" {
		t.Fatal("Update kept the previous frame")
	}
	if got := next.View(); got == "sentinel" || !strings.Contains(got, "initialising") {
		t.Fatalf("redraw: %q", got)
	}
}
