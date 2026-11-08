package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyUpdateScript(t *testing.T) {
	uid := os.Getuid()

	t.Run("accepts regular file owned by expected uid", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("rejects other owner", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid+1); err == nil {
			t.Fatal("expected owner mismatch")
		}
	})

	t.Run("rejects group writable", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o775); err != nil {
			t.Fatal(err)
		}
		// WriteFile applies the process umask, so force the mode.
		if err := os.Chmod(script, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid); err == nil {
			t.Fatal("expected group-writable file to be rejected")
		}
	})

	t.Run("rejects world writable", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(script, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid); err == nil {
			t.Fatal("expected world-writable file to be rejected")
		}
	})

	t.Run("rejects symlink", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "link.sh")
		if err := os.Symlink(script, link); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(link, uid); err == nil {
			t.Fatal("expected symlink to be rejected")
		}
	})

	t.Run("rejects world writable directory", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid); err == nil {
			t.Fatal("expected world-writable directory to be rejected")
		}
	})

	t.Run("rejects group writable directory", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(script, uid); err == nil {
			t.Fatal("expected group-writable directory to be rejected")
		}
	})

	t.Run("rejects symlink directory", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "real")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(real, "kekkai.sh")
		if err := os.WriteFile(script, []byte("#!/bin/bash\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		linkDir := filepath.Join(dir, "linkdir")
		if err := os.Symlink(real, linkDir); err != nil {
			t.Fatal(err)
		}
		if err := verifyUpdateScript(filepath.Join(linkDir, "kekkai.sh"), uid); err == nil {
			t.Fatal("expected symlink directory to be rejected")
		}
	})
}
