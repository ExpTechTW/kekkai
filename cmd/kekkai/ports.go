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
	if !color {
		ssh := "port 22 not present in either list"
		if hasPort(cfg.Filter.Public.TCP, config.SSHPort) {
			ssh = "port 22 is in public.tcp"
		} else if hasPort(cfg.Filter.Private.TCP, config.SSHPort) {
			ssh = "port 22 is in private.tcp (allowlist-gated)"
		}
		return fmt.Sprintf(
			"kekkai ports  %s\nPUBLIC  tcp: %s  udp: %s\nPRIVATE tcp: %s  udp: %s\nSSH exposure: %s\ningress_allowlist entries: %d",
			cfgPath,
			formatPortList(cfg.Filter.Public.TCP),
			formatPortList(cfg.Filter.Public.UDP),
			formatPortList(cfg.Filter.Private.TCP),
			formatPortList(cfg.Filter.Private.UDP),
			ssh,
			len(cfg.Filter.IngressAllowlist),
		)
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

	sshLine := "SSH exposure: port 22 not present in either list"
	sshStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#94a3b8"))
	if hasPort(cfg.Filter.Public.TCP, config.SSHPort) {
		sshLine = "SSH exposure: port 22 is in public.tcp"
		sshStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#f43f5e"))
	} else if hasPort(cfg.Filter.Private.TCP, config.SSHPort) {
		sshLine = "SSH exposure: port 22 is in private.tcp (allowlist-gated)"
		sshStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#22d3ee"))
	}
	allowLine := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748b")).
		Render(fmt.Sprintf("ingress_allowlist entries: %d", len(cfg.Filter.IngressAllowlist)))

	return strings.Join([]string{
		title + "  " + pathLine,
		lipgloss.JoinHorizontal(lipgloss.Top, publicBox, " ", privateBox),
		sshStyle.Render(sshLine),
		allowLine,
	}, "\n")
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

func hasPort(list []uint16, p uint16) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}
