package maps

import (
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	// RuntimeFlagAllowICMP mirrors RT_ALLOW_ICMP (bit 0) in bpf/xdp_filter.c.
	RuntimeFlagAllowICMP uint32 = 1
	// RuntimeFlagAllowARP mirrors RT_ALLOW_ARP (bit 1) in bpf/xdp_filter.c.
	RuntimeFlagAllowARP uint32 = 2
	// RuntimeFlagEgressSeed mirrors RT_EGRESS_SEED (bit 2). Set only while
	// the TC egress program is attached.
	RuntimeFlagEgressSeed uint32 = 4
)

// RuntimeCfg wraps the runtime_cfg array. Index 0 holds the RT_* flags.
type RuntimeCfg struct {
	m *ebpf.Map
}

func NewRuntimeCfg(m *ebpf.Map) *RuntimeCfg {
	return &RuntimeCfg{m: m}
}

// Sync writes flags into slot 0.
func (r *RuntimeCfg) Sync(flags uint32) error {
	if err := r.m.Update(uint32(0), flags, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("runtime_cfg update: %w", err)
	}
	return nil
}
