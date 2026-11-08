package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
)

// BackupKind is one of the three distinct triggers for a config backup.
// Each kind has its own filename suffix so operators can tell at a glance
// why a file was written.
type BackupKind string

const (
	// BackupKindUpdate is written automatically when a config migration
	// (version bump) rewrites the on-disk file.
	BackupKindUpdate BackupKind = "update_backup"

	// BackupKindAuto is written by SIGHUP reload when the new config
	// differs from the one currently in memory.
	BackupKindAuto BackupKind = "auto_backup"

	// BackupKindManual is written by the operator via `kekkai-agent -backup`.
	BackupKindManual BackupKind = "backup"

	// BackupRetention is the number of files per kind retained on disk.
	// Older backups are garbage-collected after a successful write.
	BackupRetention = 10
)

// timestampFormat produces ISO8601 basic format (no colons, safe for
// filenames across filesystems): 20060102T150405
const timestampFormat = "20060102T150405"

// backupNow is the clock used to name backup files. Tests pin it so an
// O_EXCL collision can be set up without racing the wall clock.
var backupNow = time.Now

// BackupFile copies the current on-disk config to a sibling file named
// `<basename>.<kind>.<timestamp>`. After writing, it prunes files of the
// same kind beyond BackupRetention.
//
// Returns the absolute path of the backup written. If `src` does not
// exist, returns an error without touching the filesystem.
func BackupFile(src string, kind BackupKind) (string, error) {
	return backupFile(src, kind)
}

// backupFile is the unexported entry point used by Load() and tests.
func backupFile(src string, kind BackupKind) (string, error) {
	data, err := readRegularFile(src)
	if err != nil {
		return "", err
	}
	ts := backupNow().UTC().Format(timestampFormat)
	dst := fmt.Sprintf("%s.%s.%s", src, kind, ts)
	if err := writeExclusive(dst, data); err != nil {
		return "", err
	}
	if err := gcBackups(src, kind, BackupRetention); err != nil {
		// The copy is already durable. Pruning old files must not fail
		// the backup or a migration that is waiting on this path.
		warnBackup(fmt.Sprintf("backup %s written but old-backup gc failed: %v", dst, err))
	}
	return dst, nil
}

// warnBackup reports a non-fatal backup problem. Tests replace it.
var warnBackup = func(msg string) {
	fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
}

// readBackupDir lists a backup directory. Tests replace it.
var readBackupDir = os.ReadDir

// readRegularFile refuses symlinks (and anything else that is not a
// regular file) and opens the source with O_NOFOLLOW so a swap between
// the check and the read cannot retarget the copy.
func readRegularFile(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to back up symlink %s", path)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to back up non-regular file %s", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read source: %w", err)
	}
	return data, nil
}

// writeExclusive creates dst as a new file. O_EXCL|O_NOFOLLOW refuses an
// existing path and a symlink, so a planted link cannot redirect the
// root write. Mode is 0600.
func writeExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write backup: %w", werr)
	}
	if cerr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write backup: %w", cerr)
	}
	return nil
}

// AutoBackupIfChanged compares the new config against the old one and
// writes an auto_backup if they differ. It is the caller's responsibility
// to invoke this before overwriting `src`. No-op if the structs match.
//
// Returns the backup path (empty if no backup was needed) and any error.
func AutoBackupIfChanged(src string, oldCfg, newCfg *Config) (string, error) {
	if oldCfg == nil || newCfg == nil {
		return "", nil
	}
	if reflect.DeepEqual(oldCfg, newCfg) {
		return "", nil
	}
	return backupFile(src, BackupKindAuto)
}

// gcBackups removes oldest backups of a given kind beyond `keep`. The
// filename is expected to sort lexicographically by timestamp because we
// use ISO8601 basic format.
func gcBackups(src string, kind BackupKind, keep int) error {
	if keep <= 0 {
		return nil
	}
	dir := filepath.Dir(src)
	base := filepath.Base(src)
	prefix := fmt.Sprintf("%s.%s.", base, kind)

	entries, err := readBackupDir(dir)
	if err != nil {
		return err
	}
	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), prefix) {
			matches = append(matches, e.Name())
		}
	}
	if len(matches) <= keep {
		return nil
	}
	sort.Strings(matches) // ascending → oldest first
	toRemove := matches[:len(matches)-keep]
	for _, name := range toRemove {
		_ = os.Remove(filepath.Join(dir, name))
	}
	return nil
}
