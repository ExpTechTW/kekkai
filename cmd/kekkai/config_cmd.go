package main

// Commands that touch /etc/kekkai/kekkai.yaml directly:
// - cmdConfig opens the file in nano and auto-reloads on successful save.
// - cmdReload runs an offline -check pass and then signals the daemon.
//
// Plus tiny filesystem helpers kept local to these two commands.

import (
	"fmt"
	"os"
	"os/exec"
)

// cmdConfig opens config in nano and reloads the agent after editor exit.
// Root is already enforced by requireRoot() in main dispatch.
func cmdConfig(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	nanoPath, err := exec.LookPath("nano")
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr("nano not found; install nano first"))
		return 1
	}

	editorCmd := exec.Command(nanoPath, cfgPath)
	if code := runCommand(editorCmd, "edit config with nano"); code != 0 {
		return code
	}

	// Reuse existing reload flow (includes config check).
	return cmdReload([]string{cfgPath})
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
