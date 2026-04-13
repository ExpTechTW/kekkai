// Command kekkai is the operator CLI and TUI front-end for the kekkai edge
// agent. It is intentionally separate from kekkai-agent (the long-running
// daemon): kekkai is interactive, kekkai-agent is a service.
//
// Subcommand style mirrors tools like `docker compose` / `kubectl` so
// operators can build muscle memory.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/doctor"
	"github.com/ExpTechTW/kekkai/internal/tui"
)

// version is injected at build time via -ldflags. Defaults to "dev" when
// building with plain `go build`.
var version = "dev"

const defaultConfigPath = "/etc/kekkai/kekkai.yaml"
const agentBinary = "/usr/local/bin/kekkai-agent"
const agentUnit = "kekkai-agent"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	switch cmd {
	case "status":
		os.Exit(cmdStatus(args))
	case "version", "-v", "--version":
		cmdVersion()
	case "check":
		os.Exit(runWafEdge(append([]string{"-check"}, resolveConfigArg(args)...)...))
	case "ports":
		os.Exit(cmdPorts(args))
	case "show":
		os.Exit(runWafEdge(append([]string{"-show"}, resolveConfigArg(args)...)...))
	case "backup":
		os.Exit(runWafEdge(append([]string{"-backup"}, resolveConfigArg(args)...)...))
	case "reload":
		os.Exit(cmdReload(args))
	case "reset":
		os.Exit(runWafEdge(buildResetArgs(args)...))
	case "doctor":
		os.Exit(cmdDoctor())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "kekkai: unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

// resolveConfigArg returns the [-config, path] pair to hand to kekkai-agent.
// If the user didn't pass a positional arg, we inject the default so
// `kekkai check` works like `kekkai check /etc/kekkai/kekkai.yaml`.
func resolveConfigArg(args []string) []string {
	path := defaultConfigPath
	if len(args) > 0 {
		path = args[0]
	}
	return []string{"-config", path}
}

// buildResetArgs parses `kekkai reset [path] [--iface name]` into the flag
// list consumed by `kekkai-agent -reset`. Positional arguments are
// accepted in either order as long as non-flag tokens are the config
// path.
func buildResetArgs(args []string) []string {
	path := defaultConfigPath
	iface := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--iface", "-iface", "-i":
			if i+1 < len(args) {
				iface = args[i+1]
				i++
			}
		default:
			// first non-flag arg is the config path
			path = a
		}
	}
	out := []string{"-reset", "-config", path}
	if iface != "" {
		out = append(out, "-iface", iface)
	}
	return out
}

// runWafEdge execs the daemon binary with the given flags and forwards
// its exit code. We call the existing -check/-show/-backup modes rather
// than duplicate the config-handling logic here.
func runWafEdge(args ...string) int {
	if _, err := exec.LookPath(agentBinary); err != nil {
		fmt.Fprintf(os.Stderr, "kekkai-agent binary not found at %s\n", agentBinary)
		fmt.Fprintln(os.Stderr, "is kekkai installed? run: bash scripts/bootstrap.sh")
		return 1
	}
	c := exec.Command(agentBinary, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "kekkai-agent: %v\n", err)
		return 1
	}
	return 0
}

// cmdPorts prints a compact, colorized view of public/private port exposure.
func cmdPorts(args []string) int {
	cfgPath := defaultConfigPath
	if len(args) > 0 {
		cfgPath = args[0]
	}

	res, err := config.LoadReadOnly(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
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

// cmdReload validates the config first, then triggers a daemon SIGHUP via
// systemd reload. This prevents applying a broken config.
func cmdReload(args []string) int {
	cfgPath := defaultConfigPath
	if len(args) > 0 {
		cfgPath = args[0]
	}

	// Always lint/validate before touching the running service.
	if code := runWafEdge("-check", "-config", cfgPath); code != 0 {
		fmt.Fprintln(os.Stderr, "reload aborted: config check failed")
		return code
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "reload requires root (run: sudo kekkai reload)")
		return 1
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(os.Stderr, "systemctl not found: cannot reload kekkai-agent")
		return 1
	}

	c := exec.Command("systemctl", "reload", agentUnit)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "systemctl reload %s: %v\n", agentUnit, err)
		return 1
	}

	fmt.Printf("reload requested: %s (config checked: %s)\n", agentUnit, cfgPath)
	return 0
}

// cmdStatus launches the TUI. It reads the running agent's config to
// find the interface name so the eBPF pinned map paths line up.
func cmdStatus(args []string) int {
	cfgPath := defaultConfigPath
	if len(args) > 0 {
		cfgPath = args[0]
	}

	res, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	cfg := res.Config

	src, err := tui.NewSource(cfg.Interface.Name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open eBPF maps: %v\n", err)
		return 1
	}
	defer src.Close()

	model := tui.NewModel(src, cfg.Node.ID, cfg.Interface.Name, cfg.Interface.XDPMode)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "tui: %v\n", err)
		return 1
	}
	return 0
}

// cmdDoctor runs every health check and prints a coloured report.
// Exit code 0 = healthy or warnings only, 1 = at least one error.
func cmdDoctor() int {
	r := doctor.Run()
	r.Render(os.Stdout, stdoutIsTerminal())
	return r.ExitCode()
}

// stdoutIsTerminal returns true if stdout looks like a TTY and NO_COLOR
// is not set. Kept local so the doctor package stays stdlib-only.
func stdoutIsTerminal() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func cmdVersion() {
	fmt.Printf("kekkai %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	// Also print kekkai-agent's version if available.
	if _, err := exec.LookPath(agentBinary); err == nil {
		out, err := exec.Command(agentBinary, "-check", "/dev/null").CombinedOutput()
		_ = out
		_ = err
		// kekkai-agent doesn't have -version yet; just note its presence.
		if st, err := os.Stat(agentBinary); err == nil {
			fmt.Printf("kekkai-agent present at %s (size %d bytes, modified %s)\n",
				agentBinary, st.Size(), st.ModTime().Format("2006-01-02 15:04:05"))
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `kekkai — operator CLI for the kekkai edge firewall

Usage:
  kekkai <command> [args]

Commands:
  status [config]            launch the live TUI (default: /etc/kekkai/kekkai.yaml)
  check  [config]            validate a config file (read-only; safe as non-root)
  ports  [config]            show colorized public/private port summary
  show   [config]            print the normalised config after migration
  backup [config]            write a timestamped manual backup of the config file
  reload [config]            validate config, then systemctl reload kekkai-agent
  reset  [config] [--iface]  overwrite config with a fresh default template
                             (existing file is backed up first; auto-detects iface)
  doctor                     run read-only health checks and print a report
  version                    show version information
  help                       show this message

Run reset via sudo when the config lives under /etc/kekkai.
Run doctor to diagnose common installation/runtime problems.

See COMMAND_ZH.md for the full operator handbook (in Chinese).`)
}
