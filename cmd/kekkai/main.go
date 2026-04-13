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

type colorPalette struct {
	enable bool
	reset  string
	bold   string
	dim    string
	red    string
	green  string
	yellow string
	cyan   string
}

func newColorPalette(enable bool) colorPalette {
	if !enable {
		return colorPalette{}
	}
	return colorPalette{
		enable: true,
		reset:  "\033[0m",
		bold:   "\033[1m",
		dim:    "\033[2m",
		red:    "\033[31m",
		green:  "\033[32m",
		yellow: "\033[33m",
		cyan:   "\033[36m",
	}
}

func (p colorPalette) wrap(color, s string) string {
	if !p.enable {
		return s
	}
	return color + s + p.reset
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
	c := newColorPalette(stdoutIsTerminal())

	fmt.Printf("kekkai ports  %s\n\n", cfgPath)
	fmt.Printf("%sPUBLIC%s  tcp: %s  udp: %s\n",
		c.wrap(c.green+c.bold, "PUBLIC"),
		c.reset,
		formatPortList(cfg.Filter.Public.TCP),
		formatPortList(cfg.Filter.Public.UDP))
	fmt.Printf("%sPRIVATE%s tcp: %s  udp: %s\n\n",
		c.wrap(c.yellow+c.bold, "PRIVATE"),
		c.reset,
		formatPortList(cfg.Filter.Private.TCP),
		formatPortList(cfg.Filter.Private.UDP))

	if hasPort(cfg.Filter.Public.TCP, config.SSHPort) {
		fmt.Printf("%sSSH exposure%s: port 22 is in public.tcp\n",
			c.wrap(c.red+c.bold, "SSH exposure"), c.reset)
	} else if hasPort(cfg.Filter.Private.TCP, config.SSHPort) {
		fmt.Printf("%sSSH exposure%s: port 22 is in private.tcp (allowlist-gated)\n",
			c.wrap(c.cyan+c.bold, "SSH exposure"), c.reset)
	} else {
		fmt.Printf("%sSSH exposure%s: port 22 not present in either list\n",
			c.wrap(c.dim+c.bold, "SSH exposure"), c.reset)
	}
	fmt.Printf("ingress_allowlist entries: %d\n", len(cfg.Filter.IngressAllowlist))
	return 0
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
