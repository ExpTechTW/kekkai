// Command kekkai is the operator CLI and TUI front-end for the kekkai edge
// agent. It is intentionally separate from kekkai-agent (the long-running
// daemon): kekkai is interactive, kekkai-agent is a service.
//
// Subcommand style mirrors tools like `docker compose` / `kubectl` so
// operators can build muscle memory.
//
// The code is split across several sibling files in this package so each
// area of responsibility is small enough to eyeball:
//
//	main.go        — entrypoint, dispatch, usage banner
//	ui.go          — lipgloss styles and tty-aware ui* formatters
//	runner.go      — requireRoot gate, subprocess helpers, shared argv shaping
//	status.go      — read-only state surface: status / doctor / version
//	ports.go       — `kekkai ports` renderer
//	bypass.go      — `kekkai bypass on|off [--save]`
//	config_cmd.go  — `kekkai config` + `kekkai reload`
//	update.go      — `kekkai update` (delegates to kekkai.sh)
package main

import (
	"fmt"
	"os"

	"github.com/ExpTechTW/kekkai/internal/buildinfo"
)

// version is injected at build time via -ldflags:
//
//	-X main.version=YYYY.MM.DD+build.N
//
// Keep default empty so linker override works reliably.
var version string

const (
	defaultConfigPath = "/etc/kekkai/kekkai.yaml"
	agentBinary       = "/usr/local/bin/kekkai-agent"
	agentUnit         = "kekkai-agent"
	bypassUsage       = "usage: kekkai bypass on|off [--save] [config]"
)

func main() {
	if version == "" {
		version = buildinfo.DefaultVersion
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]

	// Everything except `help` / `version` requires root. The CLI is a
	// sudo-only tool on Debian/Ubuntu/Pi OS (kernel.unprivileged_bpf_disabled
	// blocks non-root bpf() even with file caps), so we fail fast with a
	// copy-pasteable sudo hint instead of letting downstream calls emit
	// cryptic EACCES.
	//
	// `version` is deliberately outside the gate: kekkai.sh's update flow
	// calls `kekkai-candidate version` to diff old vs new version strings
	// before deciding whether to restart the service. If version required
	// root, a freshly-downloaded CLI in a tmp dir (which kekkai.sh may
	// invoke while itself running under sudo's preserved env) could fail
	// that probe and leave the update result block showing "unknown".
	switch cmd {
	case "help", "-h", "--help", "version", "-v", "--version":
		// no gate
	default:
		requireRoot()
	}

	switch cmd {
	case "status":
		os.Exit(cmdStatus(args))
	case "config":
		os.Exit(cmdConfig(args))
	case "version", "-v", "--version":
		cmdVersion()
	case "check":
		os.Exit(cmdCheck(args))
	case "ports":
		os.Exit(cmdPorts(args))
	case "show":
		os.Exit(runWafEdge(append([]string{"-show"}, resolveConfigArg(args)...)...))
	case "backup":
		os.Exit(runWafEdge(append([]string{"-backup"}, resolveConfigArg(args)...)...))
	case "reload":
		os.Exit(cmdReload(args))
	case "bypass":
		os.Exit(cmdBypass(args))
	case "update":
		os.Exit(cmdUpdate(args))
	case "reset":
		os.Exit(runWafEdge(buildResetArgs(args)...))
	case "doctor":
		os.Exit(cmdDoctor())
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("kekkai: unknown command %q", cmd)))
		fmt.Fprintln(os.Stderr)
		usage()
		os.Exit(2)
	}
}

func usage() {
	if stderrIsTerminal() {
		fmt.Fprintln(os.Stderr, uiTitleStyle.Render("◈ KEKKAI CLI"))
		fmt.Fprintln(os.Stderr, uiInfoStyle.Render("operator CLI for the kekkai edge firewall"))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, uiKeyStyle.Render("Usage:"))
		fmt.Fprintln(os.Stderr, "  sudo kekkai <command> [args]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, uiWarn("always run with sudo for cross-host consistency"))
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, uiKeyStyle.Render("Commands:"))
		fmt.Fprintln(os.Stderr, "  status [config]            launch the live TUI")
		fmt.Fprintln(os.Stderr, "  config [config]            open config in nano, then auto-reload")
		fmt.Fprintln(os.Stderr, "  check  [config]            validate a config file (read-only)")
		fmt.Fprintln(os.Stderr, "  ports  [config]            show colorized public/private port summary")
		fmt.Fprintln(os.Stderr, "  show   [config]            print the normalised config after migration")
		fmt.Fprintln(os.Stderr, "  backup [config]            write a timestamped manual backup")
		fmt.Fprintln(os.Stderr, "  reload [config]            validate config, then systemctl reload")
		fmt.Fprintln(os.Stderr, "  bypass on|off [--save]     toggle emergency bypass")
		fmt.Fprintln(os.Stderr, "  update [--force]           run installer update flow (--force = cross-channel latest, bypass downgrade guard)")
		fmt.Fprintln(os.Stderr, "  reset  [config] [--iface]  overwrite config with a fresh default template")
		fmt.Fprintln(os.Stderr, "  doctor                     run read-only health checks and print a report")
		fmt.Fprintln(os.Stderr, "  version                    show version information")
		fmt.Fprintln(os.Stderr, "  help                       show this message")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, uiInfoStyle.Render("See COMMAND_ZH.md for the full operator handbook."))
		return
	}

	fmt.Fprintln(os.Stderr, `kekkai — operator CLI for the kekkai edge firewall

Usage:
  sudo kekkai <command> [args]

Always run kekkai with sudo. On Debian/Ubuntu/Pi OS the kernel sysctl
kernel.unprivileged_bpf_disabled blocks non-root bpf() regardless of caps,
so the CLI needs root to open pinned eBPF maps.

Commands:
  status [config]            launch the live TUI
  config [config]            open config in nano, then auto-reload
  check  [config]            validate a config file (read-only)
  ports  [config]            show colorized public/private port summary
  show   [config]            print the normalised config after migration
  backup [config]            write a timestamped manual backup
  reload [config]            validate config, then systemctl reload
  bypass on|off [--save]     toggle emergency bypass
  update [--force]           run installer update flow (--force = cross-channel latest, bypass downgrade guard)
  reset  [config] [--iface]  overwrite config with a fresh default template
                             (existing file is backed up first)
  doctor                     run read-only health checks and print a report
  version                    show version information
  help                       show this message

Run "sudo kekkai doctor" to diagnose common installation/runtime problems.

See COMMAND_ZH.md for the full operator handbook (in Chinese).`)
}
