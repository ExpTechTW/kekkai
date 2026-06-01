package main

// `kekkai check` — validate a config file and render a coloured summary.
//
// Previously this shelled out to `kekkai-agent -check` and piped its
// single-line "config ok" result back. We now parse directly via
// internal/config so the CLI can format the result as a proper report
// (filter summary, SSH exposure, auto-update settings, normalise log)
// instead of one stoic line. The schema validation itself still lives
// in config.LoadReadOnly — this file only presents what it returns.

import (
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"

	"github.com/ExpTechTW/kekkai/internal/config"
)

func cmdCheck(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	res, err := config.LoadReadOnly(cfgPath)
	if err != nil {
		// Validation failed — render a framed error block so it stands
		// out from the noise of previous reloads in terminal scrollback.
		renderCheckError(cfgPath, err)
		return 1
	}
	cfg := res.Config
	renderCheckSuccess(cfgPath, cfg, res)
	return 0
}

func renderCheckError(cfgPath string, err error) {
	if !stdoutIsTerminal() {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return
	}

	bar := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f43f5e")).
		Render("═══════════════════════════════════════════════")
	title := lipgloss.NewStyle().
		Bold(true).Foreground(lipgloss.Color("#f43f5e")).
		Render("  ◈ CONFIG INVALID")
	path := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748b")).Render("  " + cfgPath)
	errLine := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#fca5a5")).Render("  " + err.Error())

	fmt.Println()
	fmt.Println(bar)
	fmt.Println(title)
	fmt.Println(bar)
	fmt.Println(path)
	fmt.Println()
	fmt.Println(errLine)
	fmt.Println()
	fmt.Println(bar)
	fmt.Println()
}

func renderCheckSuccess(cfgPath string, cfg *config.Config, res *config.LoadResult) {
	if !stdoutIsTerminal() {
		// Non-TTY output stays machine-parseable — mirrors what
		// kekkai-agent -check used to print so any existing scripts
		// that pipe `kekkai check` keep working.
		if res.Migrated {
			fmt.Printf("would migrate v%d → v%d on daemon start\n",
				res.FromVersion, config.CurrentVersion)
		}
		fmt.Println("config ok")
		return
	}

	// Coloured framing to match `kekkai doctor` / `kekkai ports` style.
	bar := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#22c55e")).
		Render("═══════════════════════════════════════════════")
	title := lipgloss.NewStyle().
		Bold(true).Foreground(lipgloss.Color("#22c55e")).
		Render("  ◈ CONFIG OK")
	path := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748b")).Render("  " + cfgPath)

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8"))
	val := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e2e8f0"))
	warn := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f59e0b"))

	kv := func(k, v string) string {
		return "  " + dim.Render(fmt.Sprintf("%-18s", k)) + val.Render(v)
	}

	fmt.Println()
	fmt.Println(bar)
	fmt.Println(title)
	fmt.Println(bar)
	fmt.Println(path)
	fmt.Println()

	// Core identity.
	fmt.Println(kv("node", fmt.Sprintf("%s (region=%s)", cfg.Node.ID, cfg.Node.Region)))
	fmt.Println(kv("interface", fmt.Sprintf("%s  xdp_mode=%s", cfg.Interface.Name, cfg.Interface.XDPMode)))
	fmt.Println(kv("update", fmt.Sprintf("channel=%s", cfg.Update.Channel)))

	// Auto-update subsection — only interesting when download is enabled.
	if cfg.Update.AutoUpdateDownload != nil && *cfg.Update.AutoUpdateDownload {
		mode := "download only"
		if cfg.Update.AutoUpdateReload {
			mode = "download + auto-restart"
		}
		fmt.Println(kv("auto-update", fmt.Sprintf("%s every %dh",
			mode, cfg.Update.AutoUpdateInterval)))
	} else {
		fmt.Println(kv("auto-update", "disabled"))
	}

	// Filter summary.
	fmt.Println(kv("public tcp", formatPortList(cfg.Filter.Public.TCP)))
	fmt.Println(kv("public udp", formatPortList(cfg.Filter.Public.UDP)))
	fmt.Println(kv("private tcp", formatPortList(cfg.Filter.Private.TCP)))
	fmt.Println(kv("private udp", formatPortList(cfg.Filter.Private.UDP)))
	fmt.Println(kv("allowlist", fmt.Sprintf("%d entries", len(cfg.Filter.IngressAllowlist))))
	fmt.Println(kv("blocklist", fmt.Sprintf("%d entries", len(cfg.Filter.StaticBlocklist))))

	// SSH exposure callout — derived from security.allow_ssh_public, which
	// is the source of truth (port 22 is applied to the running filter
	// implicitly, never listed in config). Yellow when public, cyan when
	// allowlist-gated.
	var ssh string
	var sshStyle lipgloss.Style
	if cfg.SSHIsPublic() {
		ssh = "public (WIDE OPEN) — allow_ssh_public=true"
		sshStyle = warn
	} else {
		ssh = "private (allowlist-gated) — allow_ssh_public=false"
		sshStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#22d3ee"))
	}
	fmt.Println("  " + dim.Render(fmt.Sprintf("%-18s", "ssh exposure")) + sshStyle.Render(ssh))

	if res.Migrated {
		fmt.Println()
		fmt.Println("  " + warn.Render(fmt.Sprintf("would migrate v%d → v%d on daemon start",
			res.FromVersion, config.CurrentVersion)))
	}

	fmt.Println()
	fmt.Println(bar)
	fmt.Println()
}
