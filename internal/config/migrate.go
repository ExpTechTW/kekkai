package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// migrateIfNeeded parses data as schema fromVersion.
//
// v2 → v3 dropped security.enforce_ssh_private. allow_ssh_public already
// meant the same thing, so the value is kept and the removed key is ignored.
// Version 0 and the current version are strict (a typo is an unknown field).
// Older versions parse leniently and then the version field is bumped so
// Load can rewrite the file.
func migrateIfNeeded(data []byte, fromVersion int) (*Config, bool, error) {
	strict := true
	migrated := false
	switch {
	case fromVersion == 0 || fromVersion == CurrentVersion:
	case fromVersion > 0 && fromVersion < CurrentVersion:
		strict = false
		migrated = true
	default:
		return nil, false, fmt.Errorf(
			"unsupported config version: %d (this build supports v%d)",
			fromVersion, CurrentVersion)
	}
	cfg, err := parseConfig(data, strict)
	if err != nil {
		return nil, false, err
	}
	if migrated {
		cfg.Version = CurrentVersion
	}
	return cfg, migrated, nil
}

// parseConfig decodes one document. strict rejects unknown keys.
func parseConfig(data []byte, strict bool) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if strict {
		dec.KnownFields(true)
	}
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &c, nil
}
