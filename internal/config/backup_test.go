package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupExclusiveRefusesExistingAndSymlink(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kekkai.yaml")
	if err := os.WriteFile(src, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	fixed := time.Date(2026, 11, 8, 1, 2, 3, 0, time.UTC)
	prev := backupNow
	backupNow = func() time.Time { return fixed }
	t.Cleanup(func() { backupNow = prev })

	dst := src + "." + string(BackupKindManual) + "." + fixed.UTC().Format(timestampFormat)

	if err := os.WriteFile(dst, []byte("KEEP"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := backupFile(src, BackupKindManual); err == nil {
		t.Fatal("expected O_EXCL to refuse an existing destination")
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "KEEP" {
		t.Fatalf("existing destination changed: %q err=%v", got, err)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(dir, "outside")
	if err := os.WriteFile(outside, []byte("SAFE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := backupFile(src, BackupKindManual); err == nil {
		t.Fatal("expected symlink destination to be refused")
	}
	got, err = os.ReadFile(outside)
	if err != nil || string(got) != "SAFE" {
		t.Fatalf("symlink target changed: %q err=%v", got, err)
	}
	if err := os.Remove(dst); err != nil {
		t.Fatal(err)
	}

	linkSrc := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(src, linkSrc); err != nil {
		t.Fatal(err)
	}
	if _, err := backupFile(linkSrc, BackupKindManual); err == nil {
		t.Fatal("expected symlink source to be refused")
	}

	written, err := backupFile(src, BackupKindManual)
	if err != nil {
		t.Fatal(err)
	}
	if written != dst {
		t.Fatalf("backup path = %s, want %s", written, dst)
	}
	st, err := os.Stat(written)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %#o, want 0600", st.Mode().Perm())
	}
	body, err := os.ReadFile(written)
	if err != nil || string(body) != "secret" {
		t.Fatalf("backup body = %q err=%v", body, err)
	}
	if _, err := backupFile(src, BackupKindManual); err == nil {
		t.Fatal("expected a second backup in the same second to hit O_EXCL")
	}
	body, err = os.ReadFile(written)
	if err != nil || string(body) != "secret" {
		t.Fatalf("backup overwritten after O_EXCL: %q err=%v", body, err)
	}
}

func TestBackupGCErrorDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kekkai.yaml")
	if err := os.WriteFile(src, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	prevRead := readBackupDir
	prevWarn := warnBackup
	readBackupDir = func(string) ([]os.DirEntry, error) {
		return nil, errors.New("disk")
	}
	var warned string
	warnBackup = func(msg string) { warned = msg }
	t.Cleanup(func() {
		readBackupDir = prevRead
		warnBackup = prevWarn
	})

	dst, err := backupFile(src, BackupKindManual)
	if err != nil {
		t.Fatalf("gc error failed the backup: %v", err)
	}
	body, err := os.ReadFile(dst)
	if err != nil || string(body) != "secret" {
		t.Fatalf("backup body %q err=%v", body, err)
	}
	if !strings.Contains(warned, "gc failed") || !strings.Contains(warned, dst) {
		t.Fatalf("warning %q", warned)
	}
}
