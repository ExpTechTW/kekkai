package main

// `kekkai ports` — print a colourised public/private port summary.
// Useful for eyeballing filter.* exposure before running `kekkai reload`.

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/ExpTechTW/kekkai/internal/config"
)

// cmdPorts prints a compact, colorized view of public/private port exposure.
func cmdPorts(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	res, err := config.LoadReadOnly(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("config: %v", err)))
		return 1
	}
	cfg := res.Config
	fmt.Println(renderPortsView(cfgPath, cfg, stdoutIsTerminal()))
	return 0
}

func renderPortsView(cfgPath string, cfg *config.Config, color bool) string {
	bypassed, reason := filterBypassed(cfg)

	if !color {
		ssh := "port 22 private (allowlist-gated) — allow_ssh_public=false"
		if cfg.SSHIsPublic() {
			ssh = "port 22 public (any source) — allow_ssh_public=true"
		}
		body := fmt.Sprintf(
			"kekkai ports  %s\nPUBLIC  tcp: %s  udp: %s\nPRIVATE tcp: %s  udp: %s\nSSH exposure: %s\ningress_allowlist entries: %d",
			cfgPath,
			formatPortList(cfg.Filter.Public.TCP),
			formatPortList(cfg.Filter.Public.UDP),
			formatPortList(cfg.Filter.Private.TCP),
			formatPortList(cfg.Filter.Private.UDP),
			ssh,
			len(cfg.Filter.IngressAllowlist),
		)
		if bypassed {
			return bypassBanner(reason, false) + "\n" + body
		}
		return body
	}

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#a78bfa")).
		Render("◈ KEKKAI PORTS")
	pathLine := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")).
		Render(cfgPath)

	pubTag := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#0b0f1a")).
		Background(lipgloss.Color("#4ade80")).
		Padding(0, 1).Render("PUBLIC")
	privTag := lipgloss.NewStyle().Bold(true).
		Foreground(lipgloss.Color("#0b0f1a")).
		Background(lipgloss.Color("#fbbf24")).
		Padding(0, 1).Render("PRIVATE")
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("#94a3b8")).Width(6)
	val := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#e2e8f0"))

	publicBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#4ade80")).
		Padding(0, 1).
		Render(strings.Join([]string{
			pubTag,
			label.Render("tcp") + val.Render(formatPortList(cfg.Filter.Public.TCP)),
			label.Render("udp") + val.Render(formatPortList(cfg.Filter.Public.UDP)),
		}, "\n"))

	privateBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#fbbf24")).
		Padding(0, 1).
		Render(strings.Join([]string{
			privTag,
			label.Render("tcp") + val.Render(formatPortList(cfg.Filter.Private.TCP)),
			label.Render("udp") + val.Render(formatPortList(cfg.Filter.Private.UDP)),
		}, "\n"))

	sshLine := "SSH exposure: port 22 private (allowlist-gated) — allow_ssh_public=false"
	sshStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#22d3ee"))
	if cfg.SSHIsPublic() {
		sshLine = "SSH exposure: port 22 public (any source) — allow_ssh_public=true"
		sshStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f43f5e"))
	}
	allowLine := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")).
		Render(fmt.Sprintf("ingress_allowlist entries: %d", len(cfg.Filter.IngressAllowlist)))

	sections := []string{
		title + "  " + pathLine,
		lipgloss.JoinHorizontal(lipgloss.Top, publicBox, " ", privateBox),
		sshStyle.Render(sshLine),
		allowLine,
	}
	if bypassed {
		sections = append([]string{bypassBanner(reason, true)}, sections...)
	}
	return strings.Join(sections, "\n")
}

func formatPortList(ports []uint16) string {
	if len(ports) == 0 {
		return "-"
	}
	cp := append([]uint16(nil), ports...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	out := make([]string, 0, len(cp))
	for _, p := range cp {
		out = append(out, strconv.FormatUint(uint64(p), 10))
	}
	return strings.Join(out, ",")
}
