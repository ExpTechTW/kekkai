package main

// Shared execution helpers: requireRoot gate, subprocess runner, arg
// shaping for the kekkai-agent daemon modes, and the shell-quoting used
// by the copy-pasteable "retry with sudo" hint.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// requireRoot prints a clear error and exits 1 if euid != 0. kekkai CLI is
// designed for sudo-only use (kernel.unprivileged_bpf_disabled on Debian/
// Ubuntu/Pi OS blocks non-root bpf() regardless of caps), so we fail fast
// with a copy-pasteable sudo hint rather than letting downstream calls
// emit cryptic permission-denied errors.
func requireRoot() {
	if os.Geteuid() == 0 {
		return
	}
	// Rebuild the full invocation so the user can copy the "retry with"
	// line verbatim — including any trailing flags / config paths.
	cmdline := "sudo kekkai"
	for _, a := range os.Args[1:] {
		cmdline += " " + shellQuote(a)
	}
	fmt.Fprintln(os.Stderr, uiErr("kekkai must run as root"))
	fmt.Fprintln(os.Stderr, uiInfoStyle.Render("retry with: "+cmdline))
	os.Exit(1)
}

// shellQuote wraps an argument in single quotes if it contains anything
// other than the POSIX "portable filename character set". Keeps the
// suggested command pasteable even when args have spaces or globs.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
			!(r >= '0' && r <= '9') && r != '_' && r != '-' &&
			r != '.' && r != '/' && r != ':' && r != '=' && r != ',' {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runCommand wires a subprocess to the CLI's own stdio and forwards its
// exit code. The `op` label is only used for error wrapping when the
// command fails before exec (e.g. binary not found).
func runCommand(c *exec.Cmd, op string) int {
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", op, err)
		return 1
	}
	return 0
}

// runWafEdge execs the daemon binary with the given flags and forwards
// its exit code. We call the existing -check/-show/-backup modes rather
// than duplicate the config-handling logic here.
func runWafEdge(args ...string) int {
	if _, err := exec.LookPath(agentBinary); err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("kekkai-agent binary not found at %s", agentBinary)))
		fmt.Fprintln(os.Stderr, uiWarn("is kekkai installed? run: bash scripts/bootstrap.sh"))
		return 1
	}
	c := exec.Command(agentBinary, args...)
	return runCommand(c, "kekkai-agent")
}

func firstArgOrDefault(args []string, def string) string {
	if len(args) == 0 {
		return def
	}
	return args[0]
}

// resolveConfigArg returns the [-config, path] pair to hand to kekkai-agent.
// If the user didn't pass a positional arg, we inject the default so
// `kekkai check` works like `kekkai check /etc/kekkai/kekkai.yaml`.
func resolveConfigArg(args []string) []string {
	return []string{"-config", firstArgOrDefault(args, defaultConfigPath)}
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
