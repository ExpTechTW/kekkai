package main

// Commands that touch /etc/kekkai/kekkai.yaml directly:
// - cmdConfig prints how to edit + reload safely (it does NOT launch an editor).
// - cmdReload runs an offline -check pass and then signals the daemon.
//
// Plus tiny filesystem helpers kept local to these two commands.

import (
	"fmt"
	"os"
	"os/exec"
)

// cmdConfig prints how to safely edit and reload the config. It deliberately
// does NOT launch an editor.
//
// The old behaviour (`exec nano <path>` while running as root via sudo) was a
// local privilege-escalation vector: most editors can spawn a shell (nano
// ^R^X, vi :!sh, …), so anyone allowed to run `sudo kekkai config` could get
// a root shell. Editing is delegated to `sudoedit`, which runs the editor as
// the invoking *user* on a temp copy and writes back as root — an editor
// shell-escape there only yields the user's own shell, not root.
func cmdConfig(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)
	fmt.Println(uiInfo("config file: " + cfgPath))
	fmt.Println(uiInfo("edit safely (the editor runs as you, not root):"))
	fmt.Println("    sudoedit " + cfgPath)
	fmt.Println(uiInfo("then apply:"))
	fmt.Println("    sudo kekkai reload")
	fmt.Println()
	// Show the current on-disk config's validity so the operator sees its state.
	return runWafEdge("-check", "-config", cfgPath)
}

// cmdReload validates the config first, then triggers a daemon SIGHUP via
// systemd reload. This prevents applying a broken config.
func cmdReload(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	// Always lint/validate before touching the running service.
	if code := runWafEdge("-check", "-config", cfgPath); code != 0 {
		fmt.Fprintln(os.Stderr, uiErr("reload aborted: config check failed"))
		return code
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(os.Stderr, uiErr("systemctl not found: cannot reload kekkai-agent"))
		return 1
	}

	c := exec.Command("systemctl", "reload", agentUnit)
	if code := runCommand(c, "systemctl reload "+agentUnit); code != 0 {
		return code
	}

	fmt.Println(uiOK(fmt.Sprintf("reload requested: %s (config checked: %s)", agentUnit, cfgPath)))
	return 0
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
