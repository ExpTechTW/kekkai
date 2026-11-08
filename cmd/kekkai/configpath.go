package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// configRoot is the only directory a root-run kekkai CLI may read or write
// config files from. Passwordless sudo covers only the safe subcommands, but
// update/reset/backup still run as root after a password, so a config
// argument has to be confined here rather than trusted.
const configRoot = "/etc/kekkai"

// mustConfigPath returns path unchanged when the process is not root.
// As root it accepts only a .yaml/.yml file directly inside configRoot and
// exits 1 otherwise. forReset selects the error wording; missing files
// (reset creates them) are resolved from the parent directory.
func mustConfigPath(path string, forReset bool) string {
	if os.Geteuid() != 0 {
		return path
	}
	resolved, err := confineConfigPath(path, configRoot, forReset)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(err.Error()))
		os.Exit(1)
	}
	return resolved
}

// confineConfigPath accepts path only when, after Abs + Clean + EvalSymlinks,
// it is a direct child of root and ends in .yaml or .yml. Existing files are
// symlink-resolved at the leaf. A path that does not exist yet (reset, or a
// check of a missing file) resolves the parent directory so a symlink cannot
// point the write outside root.
func confineConfigPath(path, root string, forReset bool) (string, error) {
	kind := "config"
	if forReset {
		kind = "reset"
	}
	if path == "" {
		return "", fmt.Errorf("refusing %s path: empty", kind)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("refusing %s path %q: %w", kind, path, err)
	}
	clean := filepath.Clean(abs)
	root = filepath.Clean(root)

	resolved, err := resolveConfinedPath(clean)
	if err != nil {
		return "", fmt.Errorf("refusing %s path %q: %w", kind, path, err)
	}
	resolved = filepath.Clean(resolved)
	if filepath.Dir(resolved) != root {
		return "", fmt.Errorf("refusing %s path %q: must be a .yaml or .yml file directly inside %s", kind, path, root)
	}
	base := filepath.Base(resolved)
	if base == "." || base == ".." {
		return "", fmt.Errorf("refusing %s path %q: must be a .yaml or .yml file directly inside %s", kind, path, root)
	}
	ext := filepath.Ext(resolved)
	if ext != ".yaml" && ext != ".yml" {
		return "", fmt.Errorf("refusing %s path %q: must end in .yaml or .yml", kind, path)
	}
	return resolved, nil
}

func resolveConfinedPath(clean string) (string, error) {
	st, err := os.Lstat(clean)
	if err == nil {
		if st.IsDir() {
			return "", fmt.Errorf("%s is a directory", clean)
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return "", err
		}
		if rst, rerr := os.Lstat(resolved); rerr == nil && rst.IsDir() {
			return "", fmt.Errorf("%s is a directory", resolved)
		}
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}

	parent := filepath.Dir(clean)
	base := filepath.Base(clean)
	if base == "." || base == ".." {
		return "", fmt.Errorf("invalid file name %q", base)
	}
	pst, perr := os.Lstat(parent)
	if perr != nil {
		if os.IsNotExist(perr) {
			// Parent is not on disk yet. The lexical path is checked
			// against the config root by the caller. reset's agent
			// creates the directory; other commands surface a normal
			// open error for a missing file.
			return clean, nil
		}
		return "", perr
	}
	if !pst.IsDir() && pst.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("parent %s is not a directory", parent)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, base), nil
}
