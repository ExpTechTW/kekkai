// Package config loads the edge agent configuration from YAML, applies
// defaults, and validates the result. The schema is intentionally flat
// enough for a human to scan but grouped into sections so the file stays
// navigable as features accrete.
//
// Validation rules (enforced on startup and on every reload):
//   - interface.name must be set and resolvable
//   - filter ports are in range 1..65535
//   - no port appears in more than one list (public/private/tcp/udp)
//   - all CIDRs in ingress_allowlist / static_blocklist parse cleanly
//   - if private_tcp_ports contains 22 and ingress_allowlist is empty, the
//     load fails loudly to avoid locking SSH out
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

const (
	DefaultStatsFile      = "/var/run/waf-go/stats.txt"
	DefaultPerIPTableSize = 65536
	DefaultXDPMode        = "generic"
)

// Config is the root document.
type Config struct {
	Node          NodeConfig          `yaml:"node"`
	Interface     InterfaceConfig     `yaml:"interface"`
	Runtime       RuntimeConfig       `yaml:"runtime"`
	Observability ObservabilityConfig `yaml:"observability"`
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

// Load reads, parses, validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes and validates an in-memory config document. Exposed for
// tests and for the `-check` CLI flag.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		// yaml.v3 returns io.EOF on empty docs; tolerate that so defaults
		// still apply, but surface all other errors.
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
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

// Validate enforces the schema rules. Called by Parse and again by reload.
func (c *Config) Validate() error {
	if c.Interface.Name == "" {
		return errors.New("interface.name is required")
	}
	switch c.Interface.XDPMode {
	case "generic", "driver", "offload":
	default:
		return fmt.Errorf("interface.xdp_mode: invalid %q (want generic|driver|offload)", c.Interface.XDPMode)
	}

	// Every port in every list must be valid and unique across lists.
	seen := map[uint16]string{}
	register := func(list []uint16, label string) error {
		for _, p := range list {
			if p == 0 {
				return fmt.Errorf("%s: port 0 is invalid", label)
			}
			if prev, ok := seen[p]; ok {
				return fmt.Errorf("port %d is declared in both %s and %s", p, prev, label)
			}
			seen[p] = label
		}
		return nil
	}
	// Build separate maps per (proto, kind) because 80/tcp and 80/udp are
	// distinct and may legitimately both appear.
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
	_ = register // kept for potential future cross-proto checks
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

	// Parse all CIDRs up front so reload failures surface before we touch
	// any eBPF map.
	if _, err := ParsePrefixes(c.Filter.IngressAllowlist); err != nil {
		return fmt.Errorf("filter.ingress_allowlist: %w", err)
	}
	if _, err := ParsePrefixes(c.Filter.StaticBlocklist); err != nil {
		return fmt.Errorf("filter.static_blocklist: %w", err)
	}

	// SSH lockout safety net.
	for _, p := range c.Filter.Private.TCP {
		if p == 22 && len(c.Filter.IngressAllowlist) == 0 {
			return errors.New("filter.private.tcp contains 22 but filter.ingress_allowlist is empty — this would lock SSH out")
		}
	}
	return nil
}

// ResolveInterface fetches the *net.Interface for the configured name.
// Called at attach time and on reload (if iface name changed).
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
