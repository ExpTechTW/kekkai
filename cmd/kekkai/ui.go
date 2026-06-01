package main

// Terminal detection and the small `ui*` helpers that decorate CLI output.
// Every user-facing line in this package goes through one of these helpers
// so colour precedence (NO_COLOR, non-TTY pipes) stays consistent.

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

var (
	uiTitleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a78bfa"))
	uiKeyStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#94a3b8"))
	uiErrStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f43f5e"))
	uiWarnStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f59e0b"))
	uiOKStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#22c55e"))
	uiInfoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#cbd5e1"))
)

// isTerminal reports whether f looks like a TTY and NO_COLOR is unset.
// Shared between stdout / stderr colour decisions so both streams apply
// the same NO_COLOR precedence.
func isTerminal(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func stdoutIsTerminal() bool { return isTerminal(os.Stdout) }
func stderrIsTerminal() bool { return isTerminal(os.Stderr) }

func uiErr(msg string) string {
	if !stderrIsTerminal() {
		return msg
	}
	return uiErrStyle.Render("✗ ") + msg
}

func uiWarn(msg string) string {
	if !stderrIsTerminal() {
		return msg
	}
	return uiWarnStyle.Render("! ") + msg
}

func uiOK(msg string) string {
	if !stdoutIsTerminal() {
		return msg
	}
	return uiOKStyle.Render("✓ ") + msg
}

func uiInfo(msg string) string {
	if !stdoutIsTerminal() {
		return msg
	}
	return uiInfoStyle.Render("· " + msg)
}
