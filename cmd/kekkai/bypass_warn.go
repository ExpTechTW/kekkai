package main

// Shared detection + rendering for the "filter is bypassed" state, used by
// `kekkai ports` and `kekkai status`. When the XDP filter isn't attached the
// box is running WIDE OPEN, so we shout about it.

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/doctor"
)

// filterBypassed reports whether the XDP filter is currently NOT protecting
// traffic, and a short reason. It catches both forms of bypass:
//   - persisted: runtime.emergency_bypass=true in config (agent never attaches)
//   - transient: `kekkai bypass on` (SIGUSR1 detaches XDP at runtime)
//
// Both leave no XDP program on the interface, so a missing attachment is the
// ground truth. `ip`-unavailable is treated as "can't tell" (no false alarm),
// falling back to the persisted config flag.
func filterBypassed(cfg *config.Config) (bool, string) {
	if cfg.Runtime.EmergencyBypass {
		return true, "runtime.emergency_bypass = true (persisted in config)"
	}
	attached, ok := doctor.XDPAttached(cfg.Interface.Name)
	if ok && !attached {
		return true, "no XDP program on " + cfg.Interface.Name +
			" — transient bypass, or the agent is stopped"
	}
	return false, ""
}

// bypassBanner renders a large, hard-to-miss warning that the filter is off.
func bypassBanner(reason string, color bool) string {
	lines := []string{
		"⚠  FILTER BYPASSED — NETWORK IS UNPROTECTED  ⚠",
		"XDP is detached: every packet is passing unfiltered.",
		reason,
		"re-enable: sudo kekkai bypass off   (or fix runtime.emergency_bypass and reload)",
	}
	if !color {
		bar := strings.Repeat("!", 64)
		return bar + "\n" + strings.Join(lines, "\n") + "\n" + bar
	}
	body := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#fecaca")).
		Render(strings.Join(lines, "\n"))
	return lipgloss.NewStyle().
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("#f43f5e")).
		Background(lipgloss.Color("#7f1d1d")).
		Padding(0, 2).
		Render(body)
}
