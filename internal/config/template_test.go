package config

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRender_UsesCurrentVersionByDefault(t *testing.T) {
	out := Render(DefaultValues())
	want := fmt.Sprintf("version: %d", CurrentVersion)
	if !strings.Contains(out, want) {
		t.Fatalf("rendered template missing %q:\n%s", want, out)
	}
}

func TestValuesFromConfig_UsesCurrentVersionWhenUnset(t *testing.T) {
	cfg := &Config{
		Version: 0,
	}
	v := ValuesFromConfig(cfg)
	if v.Version != CurrentVersion {
		t.Fatalf("ValuesFromConfig version=%d, want %d", v.Version, CurrentVersion)
	}
}

func TestValuesFromConfig_DefaultsAutoUpdateDownloadToTrueWhenUnset(t *testing.T) {
	cfg := &Config{
		Update: UpdateConfig{
			AutoUpdateDownload: nil,
		},
	}
	v := ValuesFromConfig(cfg)
	if !v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig AutoUpdateDownload=false, want true")
	}
}

func TestValuesFromConfig_PreservesAutoUpdateDownloadFalse(t *testing.T) {
	disabled := false
	cfg := &Config{
		Update: UpdateConfig{
			AutoUpdateDownload: &disabled,
		},
	}
	v := ValuesFromConfig(cfg)
	if v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig AutoUpdateDownload=true, want false")
	}
}

func TestValuesFromConfig_NilConfigFallsBackToDefaults(t *testing.T) {
	v := ValuesFromConfig(nil)
	if v.Version != CurrentVersion {
		t.Fatalf("ValuesFromConfig(nil) version=%d, want %d", v.Version, CurrentVersion)
	}
	if !v.AutoUpdateDownload {
		t.Fatalf("ValuesFromConfig(nil) AutoUpdateDownload=false, want true")
	}
	if v.InterfaceXDPMode != DefaultXDPMode {
		t.Fatalf("ValuesFromConfig(nil) InterfaceXDPMode=%q, want %q", v.InterfaceXDPMode, DefaultXDPMode)
	}
	if v.UDPEphemeralMin != DefaultUDPEphemeralMin {
		t.Fatalf("ValuesFromConfig(nil) UDPEphemeralMin=%d, want %d", v.UDPEphemeralMin, DefaultUDPEphemeralMin)
	}
}

func TestRender_ExistingSafeLinesUnchanged(t *testing.T) {
	out := Render(DefaultValues())
	for _, line := range []string{
		fmt.Sprintf("version: %d\n", CurrentVersion),
		"  region: default\n",
		"  xdp_mode: generic\n",
		"  channel: release\n",
		"  auto_update_download: true\n",
		"  auto_update_reload: false\n",
		"  auto_update_interval: 1\n",
		"  emergency_bypass: false\n",
		"  perip_table_size: 65536\n",
		"  stats_file: /var/run/kekkai/stats.txt\n",
		"  allow_ssh_public: true\n",
		"  allow_icmp: true\n",
		"  allow_arp: true\n",
		"  udp_ephemeral_min: 32768\n",
		"      - 80\n",
		"      - 443\n",
		"    - 192.168.0.0/16\n",
	} {
		if !strings.Contains(out, line) {
			t.Errorf("default render missing %q", line)
		}
	}
}

func TestYAMLScalar_SafeValuesStayPlain(t *testing.T) {
	for _, s := range []string{
		"default", "generic", "release", "pre-release",
		"/var/run/kekkai/stats.txt", "192.168.0.0/16", "eth0",
		"2001:db8::/32", "edge-01",
	} {
		if got := yamlScalar(s); got != s {
			t.Fatalf("yamlScalar(%q) = %q, want plain", s, got)
		}
	}
}

func TestRender_NodeIDRoundTripNoExtraKeys(t *testing.T) {
	cases := []string{
		"edge\n  evil: true",
		"node # not-a-comment",
		"id: injected",
		"edge\n  evil: true # note: injected",
	}
	for _, id := range cases {
		v := DefaultValues()
		v.NodeID = id
		v.InterfaceName = "eth0"
		out := Render(v)
		cfg, err := Parse([]byte(out))
		if err != nil {
			t.Fatalf("Parse node id %q: %v\n%s", id, err, out)
		}
		if cfg.Node.ID != id {
			t.Fatalf("node id = %q, want %q\n%s", cfg.Node.ID, id, out)
		}
		if cfg.Node.Region != "default" {
			t.Fatalf("region = %q after node id %q\n%s", cfg.Node.Region, id, out)
		}
		if cfg.Interface.Name != "eth0" || cfg.Interface.XDPMode != DefaultXDPMode {
			t.Fatalf("interface changed for node id %q: %+v\n%s", id, cfg.Interface, out)
		}
		assertNoInjectedKeys(t, out)
	}
}

func TestRender_ListEntryDoesNotCreateKeys(t *testing.T) {
	v := DefaultValues()
	v.InterfaceName = "eth0"
	v.NodeID = "edge-01"
	v.StaticBlocklist = []string{"203.0.113.4\n  evil: true", "198.51.100.0/24 # comment", "10.0.0.1: extra"}
	out := Render(v)
	assertNoInjectedKeys(t, out)

	dec := yaml.NewDecoder(strings.NewReader(out))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("strict decode: %v\n%s", err, out)
	}
	if len(cfg.Filter.StaticBlocklist) != len(v.StaticBlocklist) {
		t.Fatalf("blocklist len = %d, want %d\n%s", len(cfg.Filter.StaticBlocklist), len(v.StaticBlocklist), out)
	}
	for i, want := range v.StaticBlocklist {
		if cfg.Filter.StaticBlocklist[i] != want {
			t.Fatalf("blocklist[%d] = %q, want %q\n%s", i, cfg.Filter.StaticBlocklist[i], want, out)
		}
	}
}

func assertNoInjectedKeys(t *testing.T, doc string) {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, doc)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		t.Fatalf("document shape %#v", root.Kind)
	}
	top := mappingKeys(root.Content[0])
	wantTop := []string{"version", "node", "interface", "update", "runtime", "observability", "security", "filter"}
	if strings.Join(top, ",") != strings.Join(wantTop, ",") {
		t.Fatalf("top-level keys = %v, want %v\n%s", top, wantTop, doc)
	}
	node := mappingValue(root.Content[0], "node")
	if node == nil {
		t.Fatalf("missing node key\n%s", doc)
	}
	if got := strings.Join(mappingKeys(node), ","); got != "id,region" {
		t.Fatalf("node keys = %q, want id,region\n%s", got, doc)
	}
}

func mappingKeys(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	return keys
}

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func TestValuesFromConfig_DefaultsNilBoolPointers(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{
			AllowICMP: nil,
			AllowARP:  nil,
		},
	}
	v := ValuesFromConfig(cfg)
	if !v.AllowICMP {
		t.Fatalf("ValuesFromConfig AllowICMP=false, want true")
	}
	if !v.AllowARP {
		t.Fatalf("ValuesFromConfig AllowARP=false, want true")
	}
}
