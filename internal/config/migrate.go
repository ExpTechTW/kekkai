package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// migrateIfNeeded parses an on-disk config and converts it to the current
// schema if it carries an older version.
//
// v2 -> v3 dropped security.enforce_ssh_private, folding its meaning into
// the single security.allow_ssh_public flag. There is no field-level value
// to translate: a v1/v2 file's allow_ssh_public carries over verbatim
// (false there meant "22 stays private", which is exactly what false means
// in v3), and the now-removed enforce_ssh_private key is simply ignored by
// the lenient parse and dropped when Load() rewrites the canonical file.
func migrateIfNeeded(data []byte, fromVersion int) (*Config, bool, error) {
	if fromVersion == 0 || fromVersion == CurrentVersion {
		// Current-version (or version-less) docs are parsed strictly so
		// typos surface as a hard "unknown field" error.
		cfg, err := parseConfig(data, true)
		if err != nil {
			return nil, false, err
		}
		return cfg, false, nil
	}

	if fromVersion > 0 && fromVersion < CurrentVersion {
		// Backward-compatible migration path. Parse leniently so keys that
		// existed in older schemas but were removed since (e.g. v2's
		// enforce_ssh_private) are ignored rather than rejected by the
		// strict decoder. Then bump the version marker so Load() backs up +
		// rewrites canonical config in the current schema shape, dropping
		// the dead keys from disk.
		cfg, err := parseConfig(data, false)
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

// parseConfig decodes a config document. When strict is true unknown keys
// are a hard error (so typos surface immediately); when false they are
// tolerated, which the migration path relies on to drop keys removed in
// newer schema versions.
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
