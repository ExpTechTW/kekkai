package config

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed default.yaml
var defaultTemplate string

// DefaultTemplate returns the raw, un-rendered template. Exposed mostly
// for tests and for tooling that wants to inspect the canonical form.
func DefaultTemplate() string { return defaultTemplate }

// Values is the data used to render the default template. Every field is
// optional — empty values fall back to conservative defaults so the
// output is always valid YAML.
type Values struct {
	NodeID     string
	NodeRegion string

	InterfaceName    string
	InterfaceXDPMode string

	EmergencyBypass bool
	PerIPTableSize  uint32

	StatsFile string

	EnforceSSHPrivate bool
	AllowSSHPublic    bool

	PublicTCP        []uint16
	PublicUDP        []uint16
	PrivateTCP       []uint16
	PrivateUDP       []uint16
	AllowICMP        bool
	AllowARP         bool
	UDPEphemeralMin  uint16
	IngressAllowlist []string
	StaticBlocklist  []string
}

// DefaultValues returns the conservative defaults used by `kekkai reset`
// when there is no prior config to carry over. Callers override whichever
// fields they have better information for (hostname, detected iface, ...).
func DefaultValues() Values {
	return Values{
		NodeRegion:        "default",
		InterfaceXDPMode:  DefaultXDPMode,
		EmergencyBypass:   false,
		PerIPTableSize:    DefaultPerIPTableSize,
		StatsFile:         DefaultStatsFile,
		EnforceSSHPrivate: true,
		AllowSSHPublic:    false,
		AllowICMP:         true,
		AllowARP:          true,
		UDPEphemeralMin:   EPHEMERALPortMin,
		PublicTCP:         []uint16{80, 443},
	}
}

// Render substitutes v into the embedded template and returns a YAML
// document. Placeholders unfilled by v fall back to hard defaults so the
// result always parses (modulo validation errors like empty allowlist).
func Render(v Values) string {
	if v.NodeRegion == "" {
		v.NodeRegion = "default"
	}
	if v.InterfaceXDPMode == "" {
		v.InterfaceXDPMode = DefaultXDPMode
	}
	if v.PerIPTableSize == 0 {
		v.PerIPTableSize = DefaultPerIPTableSize
	}
	if v.StatsFile == "" {
		v.StatsFile = DefaultStatsFile
	}
	if v.UDPEphemeralMin == 0 {
		v.UDPEphemeralMin = EPHEMERALPortMin
	}

	out := defaultTemplate
	replace := func(placeholder, value string) {
		out = strings.ReplaceAll(out, placeholder, value)
	}
	// replaceLine substitutes a placeholder that owns its own line.
	// When the value is empty the entire line (including its trailing
	// newline) is removed so the output doesn't grow stray blank lines
	// for empty list fields.
	replaceLine := func(placeholder, value string) {
		if value == "" {
			out = strings.ReplaceAll(out, placeholder+"\n", "")
			return
		}
		replace(placeholder, value)
	}

	replace("__NODE_ID__", v.NodeID)
	replace("__NODE_REGION__", v.NodeRegion)
	replace("__INTERFACE_NAME__", v.InterfaceName)
	replace("__INTERFACE_XDP_MODE__", v.InterfaceXDPMode)
	replace("__RUNTIME_EMERGENCY_BYPASS__", boolYAML(v.EmergencyBypass))
	replace("__RUNTIME_PERIP_TABLE_SIZE__", strconv.FormatUint(uint64(v.PerIPTableSize), 10))
	replace("__OBSERVABILITY_STATS_FILE__", v.StatsFile)
	replace("__SECURITY_ENFORCE_SSH_PRIVATE__", boolYAML(v.EnforceSSHPrivate))
	replace("__SECURITY_ALLOW_SSH_PUBLIC__", boolYAML(v.AllowSSHPublic))
	replace("__FILTER_ALLOW_ICMP__", boolYAML(v.AllowICMP))
	replace("__FILTER_ALLOW_ARP__", boolYAML(v.AllowARP))
	replace("__FILTER_UDP_EPHEMERAL_MIN__", strconv.FormatUint(uint64(v.UDPEphemeralMin), 10))

	// List placeholders sit on their own line. Render each as a block
	// sequence with 6 spaces of indent (4 for the key's indent + 2 for
	// the "- " prefix) so the template's layout stays consistent.
	// Empty lists collapse the whole line so the rendered YAML doesn't
	// grow a stray blank line between the `tcp:` key and the next one.
	replaceLine("__FILTER_PUBLIC_TCP__", uint16List(v.PublicTCP, "      "))
	replaceLine("__FILTER_PUBLIC_UDP__", uint16List(v.PublicUDP, "      "))
	replaceLine("__FILTER_PRIVATE_TCP__", uint16List(v.PrivateTCP, "      "))
	replaceLine("__FILTER_PRIVATE_UDP__", uint16List(v.PrivateUDP, "      "))
	replaceLine("__FILTER_INGRESS_ALLOWLIST__", stringList(v.IngressAllowlist, "    "))
	replaceLine("__FILTER_STATIC_BLOCKLIST__", stringList(v.StaticBlocklist, "    "))

	return out
}

// boolYAML formats a bool the way YAML expects (`true` / `false`).
func boolYAML(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// uint16List renders a []uint16 as a block sequence. Empty slices render
// to an empty string so the key becomes `tcp:` alone (nil in YAML).
func uint16List(items []uint16, indent string) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range items {
		fmt.Fprintf(&b, "%s- %d", indent, v)
		if i < len(items)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// stringList renders a []string as a block sequence, same conventions.
func stringList(items []string, indent string) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range items {
		fmt.Fprintf(&b, "%s- %s", indent, v)
		if i < len(items)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
