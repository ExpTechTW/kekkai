package maps

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
)

// DynBlockVal mirrors `struct dyn_block_val` in bpf/xdp_filter.c. It stores
// an absolute expiry (in ktime ns from bpf_ktime_get_ns) and a reason code
// so operators can correlate dynamic drops back to their source.
type DynBlockVal struct {
	UntilNS uint64
	Reason  uint8
	_       [7]uint8
}

// Reason codes — keep in sync with M6 auto-ban logic and NATS consumer.
const (
	ReasonUnknown     uint8 = 0
	ReasonRateLimit   uint8 = 1
	ReasonCorePush    uint8 = 2
	ReasonManual      uint8 = 3
)

// DynBlocklist wraps an LRU_HASH map keyed on __u32 src IPv4 (network byte
// order). Entries expire when `UntilNS` is in the past; eBPF checks this on
// lookup, so expired entries cost nothing and get naturally pruned by LRU.
type DynBlocklist struct {
	m         *ebpf.Map
	ktimeBase time.Time // wall time we sampled bpf_ktime_get_ns() at start
	ktimeNS   uint64    // ktime value at sample point
}

func NewDynBlocklist(m *ebpf.Map) *DynBlocklist {
	return &DynBlocklist{m: m}
}

// SetClockBase calibrates the bpf_ktime_get_ns base. Call it once after
// loading the collection; ideally with a sample returned from the kernel.
// If we never calibrate we fall back to time.Since(process start) which is
// close enough for TTLs measured in seconds.
func (d *DynBlocklist) SetClockBase(wall time.Time, ktimeNS uint64) {
	d.ktimeBase = wall
	d.ktimeNS = ktimeNS
}

// Add inserts a dynamic block. addr must be IPv4. ttl is the wall-clock
// duration the block should last. reason is one of the Reason* constants.
func (d *DynBlocklist) Add(addr netip.Addr, ttl time.Duration, reason uint8) error {
	if !addr.Is4() {
		return fmt.Errorf("dyn blocklist: ipv6 not supported: %s", addr)
	}
	key := addrToKey(addr)
	val := DynBlockVal{
		UntilNS: d.expiryKtime(ttl),
		Reason:  reason,
	}
	if err := d.m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("dyn blocklist add %s: %w", addr, err)
	}
	return nil
}

// Delete removes a dynamic block immediately. Used for manual unblock.
func (d *DynBlocklist) Delete(addr netip.Addr) error {
	if !addr.Is4() {
		return fmt.Errorf("dyn blocklist: ipv6 not supported: %s", addr)
	}
	key := addrToKey(addr)
	if err := d.m.Delete(&key); err != nil {
		return fmt.Errorf("dyn blocklist delete %s: %w", addr, err)
	}
	return nil
}

// expiryKtime converts a wall-clock TTL to an absolute bpf_ktime_get_ns
// value. If the clock base was never set we approximate by assuming the
// process just started and its ktime is 0 — inaccurate for long-lived
// agents but safe (TTLs may skew by a few seconds, never produce negatives).
func (d *DynBlocklist) expiryKtime(ttl time.Duration) uint64 {
	if d.ktimeBase.IsZero() {
		return uint64(ttl.Nanoseconds())
	}
	elapsed := time.Since(d.ktimeBase).Nanoseconds()
	return d.ktimeNS + uint64(elapsed) + uint64(ttl.Nanoseconds())
}

func addrToKey(addr netip.Addr) uint32 {
	b := addr.As4()
	// XDP stores saddr in network byte order. cilium/ebpf copies the Go
	// value verbatim, so we pack the bytes into a uint32 that, when
	// serialised in little-endian (host order), produces the expected
	// wire-order layout.
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
