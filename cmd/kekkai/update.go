package main

// `kekkai update` — delegates to kekkai.sh so the full install/rollback
// logic lives in exactly one place (shell). This file is just a locator
// for that script plus a thin exec wrapper.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// cmdUpdate delegates to kekkai.sh so update logic stays in one place
// (release asset fetch + rollback-safe restart).
func cmdUpdate(args []string) int {
	script, searched := resolveUpdateScript()
	if script == "" {
		fmt.Fprintln(os.Stderr, uiErr("kekkai update requires kekkai.sh"))
		fmt.Fprintln(os.Stderr, uiWarn("run from repository root, or set KEKKAI_REPO=/path/to/waf-go"))
		fmt.Fprintln(os.Stderr, uiKeyStyle.Render("searched:"))
		for _, p := range searched {
			fmt.Fprintf(os.Stderr, "  %s\n", uiInfoStyle.Render("- "+p))
		}
		return 1
	}

	// kekkai update pulls prebuilt release assets from GitHub — no git /
	// SSH key required, so we just run kekkai.sh under the current (root)
	// uid. requireRoot() above guarantees we're already root.
	cmdArgs := append([]string{script, "update"}, args...)
	c := exec.Command("bash", cmdArgs...)
	return runCommand(c, fmt.Sprintf("run %s update", script))
}

// resolveUpdateScript walks a list of candidate paths for `kekkai.sh` and
// returns the first one that exists. The full candidate list is returned
// separately so the error message can show what was searched when nothing
// matches.
func resolveUpdateScript() (string, []string) {
	var candidates []string

	if p := strings.TrimSpace(os.Getenv("KEKKAI_SCRIPT")); p != "" {
		candidates = append(candidates, p)
	}
	if repo := strings.TrimSpace(os.Getenv("KEKKAI_REPO")); repo != "" {
		candidates = append(candidates, filepath.Join(repo, "kekkai.sh"))
	}
	// Common default clone location (legacy / dev).
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		candidates = append(candidates, filepath.Join(home, "kekkai", "kekkai.sh"))
	}
	// When running as root via sudo, also look in the invoking user's home.
	if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" {
		candidates = append(candidates, filepath.Join("/home", sudoUser, "kekkai", "kekkai.sh"))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, "kekkai.sh"))
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "kekkai.sh"),
			filepath.Join(exeDir, "..", "kekkai.sh"),
		)
	}

	seen := make(map[string]struct{}, len(candidates))
	searched := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if p == "" {
			continue
		}
		abs, err := filepath.Abs(p)
		if err == nil {
			p = abs
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		searched = append(searched, p)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, searched
		}
	}
	return "", searched
}
