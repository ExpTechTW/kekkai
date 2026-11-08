package config

import (
	"strings"
	"testing"
)

func TestMigrateIfNeeded(t *testing.T) {
	cfg, migrated, err := migrateIfNeeded([]byte("version: 3\nnode:\n  id: edge\n"), CurrentVersion)
	if err != nil || migrated || cfg.Node.ID != "edge" || cfg.Version != CurrentVersion {
		t.Fatalf("current: cfg=%+v migrated=%v err=%v", cfg, migrated, err)
	}

	cfg, migrated, err = migrateIfNeeded([]byte("node:\n  id: edge\n"), 0)
	if err != nil || migrated || cfg.Node.ID != "edge" || cfg.Version != 0 {
		t.Fatalf("versionless: cfg=%+v migrated=%v err=%v", cfg, migrated, err)
	}

	old := []byte("version: 2\nsecurity:\n  allow_ssh_public: false\n  enforce_ssh_private: true\n")
	cfg, migrated, err = migrateIfNeeded(old, 2)
	if err != nil || !migrated || cfg.Version != CurrentVersion || cfg.Security.AllowSSHPublic {
		t.Fatalf("v2: cfg=%+v migrated=%v err=%v", cfg, migrated, err)
	}

	cfg, migrated, err = migrateIfNeeded([]byte("version: 1\nsecurity:\n  allow_ssh_public: true\n"), 1)
	if err != nil || !migrated || cfg.Version != CurrentVersion || !cfg.Security.AllowSSHPublic {
		t.Fatalf("v1: cfg=%+v migrated=%v err=%v", cfg, migrated, err)
	}

	_, _, err = migrateIfNeeded([]byte("version: 3\nnot_a_field: true\n"), CurrentVersion)
	if err == nil {
		t.Fatal("current schema accepted an unknown field")
	}
	_, _, err = migrateIfNeeded([]byte("version: 3\nsecurity:\n  enforce_ssh_private: true\n"), CurrentVersion)
	if err == nil {
		t.Fatal("current schema accepted a removed field")
	}
	if _, _, err = migrateIfNeeded([]byte("version: 2\nnot_a_field: true\n"), 2); err != nil {
		t.Fatal(err)
	}

	for _, v := range []int{-1, CurrentVersion + 1} {
		_, _, err = migrateIfNeeded([]byte("version: 1\n"), v)
		if err == nil || !strings.Contains(err.Error(), "unsupported config version") {
			t.Fatalf("version %d: %v", v, err)
		}
	}
}
