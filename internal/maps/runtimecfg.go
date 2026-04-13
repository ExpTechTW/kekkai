package maps

import (
	"fmt"

	"github.com/cilium/ebpf"
)

const (
	// RuntimeFlagAllowICMP mirrors enum in bpf/xdp_filter.c.
	RuntimeFlagAllowICMP = uint32(1 << 0)
	// RuntimeFlagAllowARP mirrors enum in bpf/xdp_filter.c.
	RuntimeFlagAllowARP = uint32(1 << 1)
)

type RuntimeCfg struct {
	m *ebpf.Map
}

type RuntimeCfgValue struct {
	Initialized     uint32
	Flags           uint32
	UDPEphemeralMin uint16
	Pad             uint16
}

func NewRuntimeCfg(m *ebpf.Map) *RuntimeCfg {
	return &RuntimeCfg{m: m}
}

func (r *RuntimeCfg) Sync(v RuntimeCfgValue) error {
	key := uint32(0)
	if err := r.m.Update(key, v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("runtime_cfg_v4 update: %w", err)
	}
	return nil
}
