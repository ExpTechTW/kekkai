package config

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// migrateIfNeeded parses an on-disk config and converts it to the current
// schema if it carries an older version. Since the project hasn't shipped
// a real schema break yet, there is nothing to migrate — every document
// must declare `version: 1` (or omit version, which is treated as 1) and
// is parsed as-is.
//
// When a real v1→v2 migration lands later, this is the place to:
//  1. Parse the old document with a historic struct.
//  2. Build a Values from it (see template.go).
//  3. Return Render(values) as the migrated YAML (comments preserved).
//  4. Have the caller write that to disk + backup the original.
func migrateIfNeeded(data []byte, fromVersion int) (*Config, bool, error) {
	switch fromVersion {
	case 0, CurrentVersion:
		cfg, err := parseCurrent(data)
		if err != nil {
			return nil, false, err
		}
		return cfg, false, nil
	default:
		return nil, false, fmt.Errorf(
			"unsupported config version: %d (this build supports v%d)",
			fromVersion, CurrentVersion)
	}
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
