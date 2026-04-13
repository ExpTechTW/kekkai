package config

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// migrateIfNeeded converts an older on-disk schema into the current one.
//
// Version semantics:
//
//	v1  — flat schema (M3 era): node_id / region / iface / stats_path /
//	      perip_max_entries / static_blocklist
//	v2  — current nested schema
//
// Missing or zero `version` is interpreted as v1. Versions newer than
// CurrentVersion are rejected by the caller (Validate). Downgrades are
// not supported — roll back by restoring an older backup file by hand.
func migrateIfNeeded(data []byte, fromVersion int) (*Config, bool, error) {
	switch fromVersion {
	case 0, 1:
		cfg, err := migrateV1ToV2(data)
		if err != nil {
			return nil, false, fmt.Errorf("migrate v1→v2: %w", err)
		}
		return cfg, true, nil
	case CurrentVersion:
		cfg, err := parseCurrent(data)
		if err != nil {
			return nil, false, err
		}
		return cfg, false, nil
	default:
		return nil, false, fmt.Errorf("unsupported config version: %d (max %d)", fromVersion, CurrentVersion)
	}
}

// parseCurrent decodes a v2 document using strict field matching. Unknown
// keys are a hard error so typos can't silently become no-ops.
func parseCurrent(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &c, nil
}

// v1Config mirrors the historic M3 schema. Kept here as the single source
// of truth for migration; do not reuse elsewhere.
type v1Config struct {
	NodeID          string   `yaml:"node_id"`
	Region          string   `yaml:"region"`
	Iface           string   `yaml:"iface"`
	StatsPath       string   `yaml:"stats_path"`
	PerIPMaxEntries uint32   `yaml:"perip_max_entries"`
	StaticBlocklist []string `yaml:"static_blocklist"`
}

// migrateV1ToV2 reads a flat v1 document and rewrites it into the nested
// v2 schema. Fields that didn't exist in v1 (filter.public, filter.private,
// ingress_allowlist, security.*) are left at their conservative defaults:
//
//   - filter.public.tcp:  [80, 443]    (typical public web ports)
//   - filter.public.udp:  []
//   - filter.private.tcp: []           (security.enforce_ssh_private adds 22)
//   - filter.private.udp: []
//   - ingress_allowlist:  []           (Validate will refuse to start)
//
// The intentionally restrictive defaults force the user to edit the
// post-migration file before the agent will run. Safer than guessing.
func migrateV1ToV2(data []byte) (*Config, error) {
	var v1 v1Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// Do NOT set KnownFields here: a v1 file necessarily contains fields
	// we've removed, plus we want to tolerate extra keys gracefully.
	if err := dec.Decode(&v1); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse v1 yaml: %w", err)
	}

	out := &Config{
		Version: CurrentVersion,
		Node: NodeConfig{
			ID:     v1.NodeID,
			Region: v1.Region,
		},
		Interface: InterfaceConfig{
			Name:    v1.Iface,
			XDPMode: DefaultXDPMode,
		},
		Runtime: RuntimeConfig{
			EmergencyBypass: false,
			PerIPTableSize:  v1.PerIPMaxEntries,
		},
		Observability: ObservabilityConfig{
			StatsFile: v1.StatsPath,
		},
		Filter: FilterConfig{
			Public: PortGroup{
				TCP: []uint16{80, 443},
				UDP: []uint16{},
			},
			Private: PortGroup{
				TCP: []uint16{},
				UDP: []uint16{},
			},
			IngressAllowlist: []string{},
			StaticBlocklist:  append([]string{}, v1.StaticBlocklist...),
		},
		// Security defaults: enforce_ssh_private=true (via Normalize),
		// allow_ssh_public=false.
	}
	return out, nil
}
