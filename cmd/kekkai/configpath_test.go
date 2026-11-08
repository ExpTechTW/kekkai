package main

import (
	"os"
	"path/filepath"
	"testing"
)

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestConfineConfigPath(t *testing.T) {
	base := canonicalTempDir(t)
	root := filepath.Join(base, "kekkai")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.yaml"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok.yml"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nope.txt"), []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(root, "escape.yaml")); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "inner.yaml"), []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redir")); err != nil {
		t.Fatal(err)
	}

	got, err := confineConfigPath(filepath.Join(root, "ok.yaml"), root, false)
	if err != nil {
		t.Fatalf("inside yaml: %v", err)
	}
	if got != filepath.Join(root, "ok.yaml") {
		t.Fatalf("inside yaml resolved to %s", got)
	}
	if _, err := confineConfigPath(filepath.Join(root, "ok.yml"), root, false); err != nil {
		t.Fatalf("inside yml: %v", err)
	}

	cases := []struct {
		name     string
		path     string
		forReset bool
	}{
		{"outside", filepath.Join(outside, "secret.yaml"), false},
		{"dotdot", filepath.Join(root, "..", "outside", "secret.yaml"), false},
		{"dotdot missing", filepath.Join(root, "..", "nope.yaml"), true},
		{"symlink escape", filepath.Join(root, "escape.yaml"), false},
		{"wrong extension", filepath.Join(root, "nope.txt"), false},
		{"uppercase extension", filepath.Join(root, "OK.YAML"), false},
		{"nested", filepath.Join(nested, "inner.yaml"), false},
		{"parent symlink", filepath.Join(root, "redir", "new.yaml"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := confineConfigPath(tc.path, root, tc.forReset); err == nil {
				t.Fatalf("confineConfigPath(%q) accepted", tc.path)
			}
		})
	}

	fresh := filepath.Join(root, "new.yaml")
	got, err = confineConfigPath(fresh, root, true)
	if err != nil {
		t.Fatalf("reset missing file: %v", err)
	}
	if got != fresh {
		t.Fatalf("reset missing file resolved to %s", got)
	}

	// A symlink that stays inside the config directory is confined to its target.
	if err := os.Symlink(filepath.Join(root, "ok.yaml"), filepath.Join(root, "alias.yaml")); err != nil {
		t.Fatal(err)
	}
	got, err = confineConfigPath(filepath.Join(root, "alias.yaml"), root, false)
	if err != nil {
		t.Fatalf("internal symlink: %v", err)
	}
	if got != filepath.Join(root, "ok.yaml") {
		t.Fatalf("internal symlink resolved to %s", got)
	}
}
