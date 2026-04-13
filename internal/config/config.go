// Package config loads the edge agent configuration from YAML, migrates
// older versions, applies defaults, and validates the result.
//
// The on-disk schema is versioned. New installs use the current version
// (CurrentVersion). Older versions are automatically migrated on load;
// the previous file is backed up with a timestamp suffix before the new
// form is written. See migrate.go and backup.go for details.
//
// Validation runs both on startup and on every SIGHUP reload. Invalid
// configs keep the previous state intact — the agent never drops into a
// half-applied filter.
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CurrentVersion is the schema version this build writes and expects.
const CurrentVersion = 2

const (
	DefaultStatsFile      = "/var/run/waf-go/stats.txt"
	DefaultPerIPTableSize = 65536
	DefaultXDPMode        = "generic"
	SSHPort               = uint16(22)
)

// Config is the root document.
type Config struct {
	// Version is the schema version. Missing or 1 triggers migration.
	Version int `yaml:"version"`

	Node          NodeConfig          `yaml:"node"`
	Interface     InterfaceConfig     `yaml:"interface"`
	Runtime       RuntimeConfig       `yaml:"runtime"`
	Observability ObservabilityConfig `yaml:"observability"`
	Security      SecurityConfig      `yaml:"security"`
	Filter        FilterConfig        `yaml:"filter"`
}

type NodeConfig struct {
	ID     string `yaml:"id"`
	Region string `yaml:"region"`
}

type InterfaceConfig struct {
	Name    string `yaml:"name"`
	XDPMode string `yaml:"xdp_mode"` // generic | driver | offload
}

type RuntimeConfig struct {
	EmergencyBypass bool   `yaml:"emergency_bypass"`
	PerIPTableSize  uint32 `yaml:"perip_table_size"`
}

type ObservabilityConfig struct {
	StatsFile string `yaml:"stats_file"`
}

// SecurityConfig carries opt-in / opt-out toggles that protect the agent
// itself from foot-guns like accidentally locking SSH out.
type SecurityConfig struct {
	// EnforceSSHPrivate forces port 22 into filter.private.tcp on startup
	// (and each reload). If the user hasn't listed 22 anywhere, it is
	// auto-added to private.tcp. Works together with ingress_allowlist to
	// guarantee SSH is never accidentally exposed.
	EnforceSSHPrivate *bool `yaml:"enforce_ssh_private"`

	// AllowSSHPublic lets the user intentionally place port 22 in
	// filter.public.tcp. Without this flag, 22 in public.tcp is a fatal
	// validation error. With it, 22 is allowed in public.tcp but emits a
	// loud WARNING at startup and on every reload.
	AllowSSHPublic bool `yaml:"allow_ssh_public"`
}

// EnforceSSHPrivateValue returns the effective value, defaulting to true
// when the field is absent from the config file.
func (s SecurityConfig) EnforceSSHPrivateValue() bool {
	if s.EnforceSSHPrivate == nil {
		return true
	}
	return *s.EnforceSSHPrivate
}

type FilterConfig struct {
	Public           PortGroup `yaml:"public"`
	Private          PortGroup `yaml:"private"`
	IngressAllowlist []string  `yaml:"ingress_allowlist"`
	StaticBlocklist  []string  `yaml:"static_blocklist"`
}

type PortGroup struct {
	TCP []uint16 `yaml:"tcp"`
	UDP []uint16 `yaml:"udp"`
}

// LoadResult carries the loaded config and any side-effects of loading
// (migrations, backups) so main.go can log them.
type LoadResult struct {
	Config       *Config
	Migrated     bool   // true if version was bumped during load
	FromVersion  int    // version found on disk
	BackupPath   string // non-empty if a migration backup was written
	Normalized   bool   // true if Normalize() auto-added anything
	NormalizeLog []string
}

// Load is the high-level entry point. It reads the file, parses the
// version, migrates if needed (writing a backup first), applies defaults,
// validates, normalizes, and returns the result.
//
// On migration the on-disk file is rewritten to the new schema and the
// previous contents are saved to edge.yaml.update_backup.<ts>.
func Load(path string) (*LoadResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	fromVersion, err := peekVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("peek version: %w", err)
	}

	cfg, migrated, err := migrateIfNeeded(raw, fromVersion)
	if err != nil {
		return nil, err
	}

	res := &LoadResult{
		Config:      cfg,
		Migrated:    migrated,
		FromVersion: fromVersion,
	}

	// If we migrated, persist the new form and back up the original.
	if migrated {
		backupPath, err := backupFile(path, BackupKindUpdate)
		if err != nil {
			return nil, fmt.Errorf("migration backup: %w", err)
		}
		res.BackupPath = backupPath

		newBytes, err := Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("marshal migrated config: %w", err)
		}
		if err := writeAtomic(path, newBytes, 0o644); err != nil {
			return nil, fmt.Errorf("write migrated config: %w", err)
		}
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	logs := cfg.Normalize()
	if len(logs) > 0 {
		res.Normalized = true
		res.NormalizeLog = logs
		// Re-validate after normalization to catch any issues the
		// auto-inserted values might introduce (they shouldn't, but belt
		// and braces).
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("post-normalize validation: %w", err)
		}
	}
	return res, nil
}

// Parse decodes a byte slice into a Config and runs the full validate +
// normalize pipeline. Used by the -check and -show CLI flags and by tests.
// It does NOT touch the filesystem.
func Parse(data []byte) (*Config, error) {
	fromVersion, err := peekVersion(data)
	if err != nil {
		return nil, err
	}
	cfg, _, err := migrateIfNeeded(data, fromVersion)
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, err := func() ([]string, error) {
		logs := cfg.Normalize()
		if err := cfg.Validate(); err != nil {
			return logs, fmt.Errorf("post-normalize validation: %w", err)
		}
		return logs, nil
	}(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Marshal serialises a Config back to YAML. The output is always in the
// current schema version with stable field ordering.
func Marshal(cfg *Config) ([]byte, error) {
	out := *cfg
	out.Version = CurrentVersion
	var buf strings.Builder
	enc := yaml.NewEncoder(stringBuilderWriter{&buf})
	enc.SetIndent(2)
	if err := enc.Encode(&out); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

type stringBuilderWriter struct{ sb *strings.Builder }

func (w stringBuilderWriter) Write(p []byte) (int, error) {
	return w.sb.Write(p)
}

// peekVersion extracts just the top-level `version:` field so we know what
// migration path (if any) to run.
func peekVersion(data []byte) (int, error) {
	var probe struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil && !errors.Is(err, io.EOF) {
		// Not a fatal error — we also hit this on empty files.
		// The caller's migration will surface any parse issues.
		return 0, nil
	}
	return probe.Version, nil
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	if c.Node.ID == "" {
		h, _ := os.Hostname()
		c.Node.ID = h
	}
	if c.Node.Region == "" {
		c.Node.Region = "default"
	}
	if c.Interface.XDPMode == "" {
		c.Interface.XDPMode = DefaultXDPMode
	}
	if c.Runtime.PerIPTableSize == 0 {
		c.Runtime.PerIPTableSize = DefaultPerIPTableSize
	}
	if c.Observability.StatsFile == "" {
		c.Observability.StatsFile = DefaultStatsFile
	}
}

// Validate enforces the schema rules. Called after every Load and after
// every Normalize.
func (c *Config) Validate() error {
	if c.Version != 0 && c.Version > CurrentVersion {
		return fmt.Errorf("config version %d is newer than agent supports (max %d)", c.Version, CurrentVersion)
	}
	if c.Interface.Name == "" {
		return errors.New("interface.name is required")
	}
	switch c.Interface.XDPMode {
	case "generic", "driver", "offload":
	default:
		return fmt.Errorf("interface.xdp_mode: invalid %q (want generic|driver|offload)", c.Interface.XDPMode)
	}

	tcpSeen, udpSeen := map[uint16]string{}, map[uint16]string{}
	registerProto := func(list []uint16, bucket map[uint16]string, label string) error {
		for _, p := range list {
			if p == 0 {
				return fmt.Errorf("%s: port 0 is invalid", label)
			}
			if prev, ok := bucket[p]; ok {
				return fmt.Errorf("port %d appears in both %s and %s", p, prev, label)
			}
			bucket[p] = label
		}
		return nil
	}
	if err := registerProto(c.Filter.Public.TCP, tcpSeen, "filter.public.tcp"); err != nil {
		return err
	}
	if err := registerProto(c.Filter.Private.TCP, tcpSeen, "filter.private.tcp"); err != nil {
		return err
	}
	if err := registerProto(c.Filter.Public.UDP, udpSeen, "filter.public.udp"); err != nil {
		return err
	}
	if err := registerProto(c.Filter.Private.UDP, udpSeen, "filter.private.udp"); err != nil {
		return err
	}

	if _, err := ParsePrefixes(c.Filter.IngressAllowlist); err != nil {
		return fmt.Errorf("filter.ingress_allowlist: %w", err)
	}
	if _, err := ParsePrefixes(c.Filter.StaticBlocklist); err != nil {
		return fmt.Errorf("filter.static_blocklist: %w", err)
	}

	// --- SSH safety rules -------------------------------------------------

	sshInPublic := containsPort(c.Filter.Public.TCP, SSHPort)
	sshInPrivate := containsPort(c.Filter.Private.TCP, SSHPort)

	if sshInPublic && !c.Security.AllowSSHPublic {
		return errors.New(
			"filter.public.tcp contains 22 but security.allow_ssh_public is false — " +
				"set security.allow_ssh_public: true to override, or move 22 to filter.private.tcp")
	}
	if sshInPublic && sshInPrivate {
		return errors.New("port 22 cannot appear in both filter.public.tcp and filter.private.tcp")
	}

	// If SSH is protected by private.tcp but the allowlist is empty we
	// would lock out every caller. Refuse to start.
	if sshInPrivate && len(c.Filter.IngressAllowlist) == 0 {
		return errors.New(
			"filter.private.tcp contains 22 but filter.ingress_allowlist is empty — " +
				"this would lock SSH out. add your management network to ingress_allowlist")
	}
	return nil
}

// Normalize applies schema-level transformations the user shouldn't have
// to write by hand — notably auto-adding port 22 to private.tcp when
// security.enforce_ssh_private is set. Returns human-readable log lines
// describing each change.
func (c *Config) Normalize() []string {
	var logs []string
	if c.Security.EnforceSSHPrivateValue() {
		inPublic := containsPort(c.Filter.Public.TCP, SSHPort)
		inPrivate := containsPort(c.Filter.Private.TCP, SSHPort)
		if !inPublic && !inPrivate {
			c.Filter.Private.TCP = append(c.Filter.Private.TCP, SSHPort)
			logs = append(logs,
				"auto-added port 22 to filter.private.tcp (security.enforce_ssh_private=true)")
		}
	}
	return logs
}

// ResolveInterface fetches the *net.Interface for the configured name.
func (c *Config) ResolveInterface() (*net.Interface, error) {
	return net.InterfaceByName(c.Interface.Name)
}

// ParsePrefixes converts a list of strings (CIDR or bare IP) into
// netip.Prefix values. Bare addresses are treated as /32 (IPv4).
func ParsePrefixes(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, s := range entries {
		p, err := ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// ParsePrefix accepts either "1.2.3.4" (→ /32) or "1.2.3.0/24".
func ParsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func containsPort(list []uint16, p uint16) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}

// writeAtomic writes `data` to `path` via a temporary sibling file and
// rename, so readers never observe a partial file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
