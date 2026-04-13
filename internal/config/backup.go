package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("read source: %w", err)
	}
	ts := time.Now().UTC().Format(timestampFormat)
	dst := fmt.Sprintf("%s.%s.%s", src, kind, ts)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	if err := gcBackups(src, kind, BackupRetention); err != nil {
		// GC failure is non-fatal; the backup itself succeeded.
		return dst, fmt.Errorf("backup written but gc failed: %w", err)
	}
	return dst, nil
}

// AutoBackupIfChanged compares the new config against the old one (after
// Normalize) and writes an auto_backup if they differ. It is the caller's
// responsibility to invoke this before overwriting `src`. No-op if the
// structs match.
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

	entries, err := os.ReadDir(dir)
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
