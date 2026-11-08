package main

// `kekkai update` delegates to the installed kekkai.sh so the install and
// rollback logic lives in exactly one place. The script path is fixed:
// a root-owned regular file at /usr/local/bin/kekkai.sh. Environment
// variables, the home directory, and the working directory are not
// searched — those locations are writable by the user who can sudo kekkai
// without a password.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const updateScriptPath = "/usr/local/bin/kekkai.sh"

// cmdUpdate runs /usr/local/bin/kekkai.sh update after checking that the
// script and its directory are root-owned and not group/world-writable.
func cmdUpdate(args []string) int {
	if err := verifyUpdateScript(updateScriptPath, 0); err != nil {
		fmt.Fprintln(os.Stderr, uiErr(err.Error()))
		fmt.Fprintln(os.Stderr, "developers can still run `bash kekkai.sh update` directly")
		return 1
	}

	cmdArgs := append([]string{updateScriptPath, "update"}, args...)
	c := exec.Command("bash", cmdArgs...)
	return runCommand(c, "run /usr/local/bin/kekkai.sh update")
}

// verifyUpdateScript reports whether path is a regular file (not a symlink)
// owned by rootUID, not group/world-writable, living in a directory with
// the same owner and mode constraints. rootUID is injectable so tests can
// use a temp directory without running as uid 0.
func verifyUpdateScript(path string, rootUID int) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("kekkai update requires %s: %w", path, err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file owned by uid %d, not a symlink", path, rootUID)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or world-writable", path)
	}
	uid, err := fileOwnerUID(st)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if uid != rootUID {
		return fmt.Errorf("%s must be owned by uid %d", path, rootUID)
	}

	dir := filepath.Dir(path)
	dst, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("kekkai update script directory: %w", err)
	}
	if dst.Mode()&os.ModeSymlink != 0 || !dst.IsDir() {
		return fmt.Errorf("%s must be a real directory owned by uid %d", dir, rootUID)
	}
	if dst.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or world-writable", dir)
	}
	dirUID, err := fileOwnerUID(dst)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	if dirUID != rootUID {
		return fmt.Errorf("%s must be owned by uid %d", dir, rootUID)
	}
	return nil
}

func fileOwnerUID(info os.FileInfo) (int, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, fmt.Errorf("cannot read owner uid")
	}
	return int(st.Uid), nil
}
