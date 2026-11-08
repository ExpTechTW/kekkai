package loader

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/ExpTechTW/kekkai/internal/maps"
)

// TestBPFObjectMatchesGoLayout loads the data-plane object and checks that
// every map and program the loader names is present, with the key and value
// sizes the Go structs marshal to. KEKKAI_BPF_OBJ overrides the object path;
// the default is the embedded object, which is a 4-byte placeholder in this
// repo until a real build replaces it.
func TestBPFObjectMatchesGoLayout(t *testing.T) {
	obj := programBytes
	if p := os.Getenv("KEKKAI_BPF_OBJ"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		obj = b
	}
	if len(obj) == 4 {
		t.Skip("bpf object is a 4-byte placeholder")
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}

	for _, name := range []string{progNameXDP, progNameTCEgress} {
		if spec.Programs[name] == nil {
			t.Errorf("program %s missing (have %s)", name, strings.Join(progNames(spec), ", "))
		}
	}

	checks := []struct {
		name       string
		key, value int
	}{
		{mapBlocklist, binary.Size(maps.LPMKey{}), binary.Size(uint8(0))},
		{mapAllowlist, binary.Size(maps.LPMKey{}), binary.Size(uint8(0))},
		{mapPorts, binary.Size(maps.PortKey{}), binary.Size(uint8(0))},
		{mapRuntimeCfg, binary.Size(uint32(0)), binary.Size(uint32(0))},
		{mapStats, binary.Size(uint32(0)), binary.Size(maps.StatsCounters{})},
		{mapPerIP, binary.Size(maps.PerIPKey{}), binary.Size(maps.PerIPStat{})},
	}
	for _, c := range checks {
		m := spec.Maps[c.name]
		if m == nil {
			t.Errorf("map %s missing (have %s)", c.name, strings.Join(mapNames(spec), ", "))
			continue
		}
		if int(m.KeySize) != c.key || int(m.ValueSize) != c.value {
			t.Errorf("map %s key/value size %d/%d, want %d/%d",
				c.name, m.KeySize, m.ValueSize, c.key, c.value)
		}
		if c.name == mapPerIP && m.Type != ebpf.LRUCPUHash {
			t.Errorf("map %s type %s, want %s", c.name, m.Type, ebpf.LRUCPUHash)
		}
	}
}

func progNames(spec *ebpf.CollectionSpec) []string {
	out := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		out = append(out, name)
	}
	return out
}

func mapNames(spec *ebpf.CollectionSpec) []string {
	out := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		out = append(out, name)
	}
	return out
}
