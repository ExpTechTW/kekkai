package config

import (
	_ "embed"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultTemplate string

// Values is the data used to render the default template. Every field is
// optional — empty values fall back to conservative defaults so the
// output is always valid YAML.
type Values struct {
	Version int

	NodeID     string
	NodeRegion string

	InterfaceName    string
	InterfaceXDPMode string
	UpdateChannel    string

	AutoUpdateDownload bool
	AutoUpdateReload   bool
	AutoUpdateInterval int

	EmergencyBypass bool
	PerIPTableSize  uint32

	StatsFile string

	AllowSSHPublic bool

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
		Version:            CurrentVersion,
		NodeRegion:         "default",
		InterfaceXDPMode:   DefaultXDPMode,
		UpdateChannel:      DefaultUpdateChannel,
		AutoUpdateDownload: DefaultAutoUpdateDownload,
		AutoUpdateReload:   false,
		AutoUpdateInterval: DefaultAutoUpdateInterval,
		EmergencyBypass:    false,
		PerIPTableSize:     DefaultPerIPTableSize,
		StatsFile:          DefaultStatsFile,
		AllowSSHPublic:     true,
		AllowICMP:          true,
		AllowARP:           true,
		UDPEphemeralMin:    DefaultUDPEphemeralMin,
		// 22 is intentionally NOT listed — allow_ssh_public:true applies it
		// to the running filter implicitly. We never write 22 into config.
		PublicTCP:        []uint16{80, 443},
		IngressAllowlist: []string{"192.168.0.0/16"},
	}
}

// Render substitutes v into the embedded template and returns a YAML
// document. Placeholders unfilled by v fall back to hard defaults so the
// result always parses (modulo validation errors like empty allowlist).
func Render(v Values) string {
	if v.Version <= 0 {
		v.Version = CurrentVersion
	}
	if v.NodeRegion == "" {
		v.NodeRegion = "default"
	}
	if v.InterfaceXDPMode == "" {
		v.InterfaceXDPMode = DefaultXDPMode
	}
	if v.UpdateChannel == "" {
		v.UpdateChannel = DefaultUpdateChannel
	}
	if v.AutoUpdateInterval == 0 {
		v.AutoUpdateInterval = DefaultAutoUpdateInterval
	}
	if v.PerIPTableSize == 0 {
		v.PerIPTableSize = DefaultPerIPTableSize
	}
	if v.StatsFile == "" {
		v.StatsFile = DefaultStatsFile
	}
	if v.UDPEphemeralMin == 0 {
		v.UDPEphemeralMin = DefaultUDPEphemeralMin
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

	replace("__VERSION__", strconv.Itoa(v.Version))
	replace("__NODE_ID__", yamlScalar(v.NodeID))
	replace("__NODE_REGION__", yamlScalar(v.NodeRegion))
	replace("__INTERFACE_NAME__", yamlScalar(v.InterfaceName))
	replace("__INTERFACE_XDP_MODE__", yamlScalar(v.InterfaceXDPMode))
	replace("__UPDATE_CHANNEL__", yamlScalar(v.UpdateChannel))
	replace("__AUTO_UPDATE_DOWNLOAD__", boolStr(v.AutoUpdateDownload))
	replace("__AUTO_UPDATE_RELOAD__", boolStr(v.AutoUpdateReload))
	replace("__AUTO_UPDATE_INTERVAL__", strconv.Itoa(v.AutoUpdateInterval))
	replace("__RUNTIME_EMERGENCY_BYPASS__", boolStr(v.EmergencyBypass))
	replace("__RUNTIME_PERIP_TABLE_SIZE__", strconv.FormatUint(uint64(v.PerIPTableSize), 10))
	replace("__OBSERVABILITY_STATS_FILE__", yamlScalar(v.StatsFile))
	replace("__SECURITY_ALLOW_SSH_PUBLIC__", boolStr(v.AllowSSHPublic))
	replace("__FILTER_ALLOW_ICMP__", boolStr(v.AllowICMP))
	replace("__FILTER_ALLOW_ARP__", boolStr(v.AllowARP))
	replace("__FILTER_UDP_EPHEMERAL_MIN__", strconv.FormatUint(uint64(v.UDPEphemeralMin), 10))

	// List placeholders own their line. Indent is the template's nesting
	// (6 under public/private, 4 under filter). An empty list drops the
	// line so `tcp:` is not followed by a blank line.
	replaceLine("__FILTER_PUBLIC_TCP__", blockList(v.PublicTCP, "      ", uintText))
	replaceLine("__FILTER_PUBLIC_UDP__", blockList(v.PublicUDP, "      ", uintText))
	replaceLine("__FILTER_PRIVATE_TCP__", blockList(v.PrivateTCP, "      ", uintText))
	replaceLine("__FILTER_PRIVATE_UDP__", blockList(v.PrivateUDP, "      ", uintText))
	replaceLine("__FILTER_INGRESS_ALLOWLIST__", blockList(v.IngressAllowlist, "    ", yamlScalar))
	replaceLine("__FILTER_STATIC_BLOCKLIST__", blockList(v.StaticBlocklist, "    ", yamlScalar))

	return out
}

func uintText(n uint16) string {
	return strconv.FormatUint(uint64(n), 10)
}

// blockList renders items as a YAML block sequence. Empty input is empty
// so the caller can delete the placeholder line.
func blockList[T any](items []T, indent string, scalar func(T) string) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	for i, item := range items {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(indent)
		b.WriteString("- ")
		b.WriteString(scalar(item))
	}
	return b.String()
}

// yamlScalar emits s as a YAML scalar that cannot break out of the value
// position. When yaml.v3 would round-trip the plain form unchanged, s is
// returned as-is so existing safe values stay byte-identical. Anything
// else is double-quoted with escapes.
func yamlScalar(s string) string {
	if plainYAMLRoundTrip(s) {
		return s
	}
	return yamlDoubleQuoted(s)
}

func plainYAMLRoundTrip(s string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("v: "+s+"\n"), &root); err != nil {
		return false
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		return false
	}
	mapping := root.Content[0]
	if mapping.Kind != yaml.MappingNode || len(mapping.Content) != 2 {
		return false
	}
	key, val := mapping.Content[0], mapping.Content[1]
	if key.Kind != yaml.ScalarNode || key.Value != "v" {
		return false
	}
	if val.Kind != yaml.ScalarNode || val.Tag != "!!str" || val.Style != 0 || val.Value != s {
		return false
	}
	encoded, err := yaml.Marshal(&yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: s,
	})
	if err != nil {
		return false
	}
	return strings.TrimSuffix(string(encoded), "\n") == s
}

func yamlDoubleQuoted(s string) string {
	encoded, err := yaml.Marshal(&yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: s,
		Style: yaml.DoubleQuotedStyle,
	})
	if err != nil {
		return strconv.Quote(s)
	}
	out := strings.TrimSuffix(string(encoded), "\n")
	if strings.Contains(out, "\n") || !strings.HasPrefix(out, `"`) {
		return strconv.Quote(s)
	}
	return out
}
