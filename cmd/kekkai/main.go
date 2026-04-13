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

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/tui"
)

// version is injected at build time via -ldflags. Defaults to "dev" when
// building with plain `go build`.
var version = "dev"

const defaultConfigPath = "/etc/kekkai/kekkai.yaml"
const agentBinary = "/usr/local/bin/kekkai-agent"

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
	case "show":
		os.Exit(runWafEdge(append([]string{"-show"}, resolveConfigArg(args)...)...))
	case "backup":
		os.Exit(runWafEdge(append([]string{"-backup"}, resolveConfigArg(args)...)...))
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
  status [config]     launch the live TUI (default: /etc/kekkai/kekkai.yaml)
  check  [config]     validate a config file (wrapper for kekkai-agent -check)
  show   [config]     print the normalised config (wrapper for kekkai-agent -show)
  backup [config]     write a timestamped manual backup of the config file
  version             show version information
  help                show this message

See COMMAND_ZH.md for the full operator handbook (in Chinese).`)
}
