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
// Non-root users are transparently escalated with sudo when needed.
func cmdConfig(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	nanoPath, err := exec.LookPath("nano")
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr("nano not found; install nano first"))
		return 1
	}

	editorArgs := []string{nanoPath, cfgPath}
	editorCmd := exec.Command(editorArgs[0], editorArgs[1:]...)
	if os.Geteuid() != 0 && !isWritableByCurrentUser(cfgPath) {
		editorCmd = exec.Command("sudo", editorArgs...)
	}
	if code := runCommand(editorCmd, "edit config with nano"); code != 0 {
		return code
	}

	// Reuse existing reload flow (includes config check).
	if os.Geteuid() == 0 {
		return cmdReload([]string{cfgPath})
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("resolve executable for reload: %v", err)))
		return 1
	}
	return runCommand(exec.Command("sudo", exe, "reload", cfgPath), "sudo reload after config edit")
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

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, uiErr("reload requires root (run: sudo kekkai reload)"))
		return 1
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

func isWritableByCurrentUser(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
