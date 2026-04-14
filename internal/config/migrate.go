package config

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// migrateIfNeeded parses an on-disk config and converts it to the current
// schema if it carries an older version.
//
// v1 -> v2 currently has no field-level semantic break; we only bump the
// version marker so newer binaries can persist canonical config with new
// commented/defaulted keys.
func migrateIfNeeded(data []byte, fromVersion int) (*Config, bool, error) {
	if fromVersion == 0 || fromVersion == CurrentVersion {
		cfg, err := parseCurrent(data)
		if err != nil {
			return nil, false, err
		}
		return cfg, false, nil
	}

	if fromVersion > 0 && fromVersion < CurrentVersion {
		// Backward-compatible migration path: parse with current struct, then
		// bump the version marker so Load() can back up + rewrite canonical
		// config in the current schema shape.
		cfg, err := parseCurrent(data)
		if err != nil {
			return nil, false, err
		}
		cfg.Version = CurrentVersion
		return cfg, true, nil
	}

	return nil, false, fmt.Errorf(
		"unsupported config version: %d (this build supports v%d)",
		fromVersion, CurrentVersion)
}

// parseCurrent decodes a current-schema document using strict field
// matching. Unknown keys are a hard error so typos surface immediately.
func parseCurrent(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &c, nil
}
