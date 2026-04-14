package config

// Field-by-field diff for Config structs.
//
// Used by the agent's reload path to log exactly which fields changed
// when SIGHUP is delivered, so the operator can see at a glance "this
// reload added 8080 to public.tcp and nothing else" rather than a
// vague "reload ok".
//
// Design choices worth calling out:
//
//   1. Hand-written, NOT reflect-based. The config struct is small
//      (seven sections, ~20 fields total) and stable enough that the
//      duplication is tolerable. Reflect would fire on internal pointer
//      fields like *bool vs bool oddities, hidden YAML aliases, and
//      the helper methods (EnforceSSHPrivateValue) would be invisible
//      to it. Explicit beats clever here.
//
//   2. Every diff line is plain text that the logger emits as a
//      `change="..."` attr. The format mirrors how humans describe
//      diffs: "public.tcp added=[8080] removed=[]" or
//      "runtime.emergency_bypass false → true". No JSON.
//
//   3. Empty return = identity reload. Callers can cheaply test
//      `if len(diffs) == 0` to decide whether to log a "noop" line or
//      an actual change summary.

import (
	"fmt"
	"sort"
)

// DiffConfigs returns a slice of human-readable change lines describing
// every field that differs between old and new. Empty slice means the
// two configs are struct-equivalent (nil / empty considered equal to
// each other where that makes sense).
//
// Order is deterministic: sections are walked in the same order as the
// struct definition, which also matches the YAML file layout.
func DiffConfigs(old, newCfg *Config) []string {
	if old == nil || newCfg == nil {
		return nil
	}
	var out []string

	// node
	out = appendScalarDiff(out, "node.id", old.Node.ID, newCfg.Node.ID)
	out = appendScalarDiff(out, "node.region", old.Node.Region, newCfg.Node.Region)

	// interface
	out = appendScalarDiff(out, "interface.name", old.Interface.Name, newCfg.Interface.Name)
	out = appendScalarDiff(out, "interface.xdp_mode", old.Interface.XDPMode, newCfg.Interface.XDPMode)

	// update
	out = appendScalarDiff(out, "update.channel", old.Update.Channel, newCfg.Update.Channel)
	out = appendBoolPtrDiff(out, "update.auto_update_download",
		old.Update.AutoUpdateDownload, newCfg.Update.AutoUpdateDownload)
	out = appendScalarDiff(out, "update.auto_update_reload",
		boolStr(old.Update.AutoUpdateReload), boolStr(newCfg.Update.AutoUpdateReload))
	out = appendScalarDiff(out, "update.auto_update_interval",
		fmt.Sprintf("%d", old.Update.AutoUpdateInterval),
		fmt.Sprintf("%d", newCfg.Update.AutoUpdateInterval))

	// runtime
	out = appendScalarDiff(out, "runtime.emergency_bypass",
		boolStr(old.Runtime.EmergencyBypass), boolStr(newCfg.Runtime.EmergencyBypass))
	out = appendScalarDiff(out, "runtime.perip_table_size",
		fmt.Sprintf("%d", old.Runtime.PerIPTableSize),
		fmt.Sprintf("%d", newCfg.Runtime.PerIPTableSize))

	// observability
	out = appendScalarDiff(out, "observability.stats_file",
		old.Observability.StatsFile, newCfg.Observability.StatsFile)

	// security — EnforceSSHPrivate is a pointer with a "default-true"
	// getter, so compare via the getter to match the on-disk truth.
	out = appendScalarDiff(out, "security.enforce_ssh_private",
		boolStr(old.Security.EnforceSSHPrivateValue()),
		boolStr(newCfg.Security.EnforceSSHPrivateValue()))
	out = appendScalarDiff(out, "security.allow_ssh_public",
		boolStr(old.Security.AllowSSHPublic), boolStr(newCfg.Security.AllowSSHPublic))

	// filter — the port groups and IP lists are what operators edit
	// most often, so format them as added / removed sets rather than
	// "a → b" which would be unreadable for long lists.
	out = appendPortDiff(out, "filter.public.tcp", old.Filter.Public.TCP, newCfg.Filter.Public.TCP)
	out = appendPortDiff(out, "filter.public.udp", old.Filter.Public.UDP, newCfg.Filter.Public.UDP)
	out = appendPortDiff(out, "filter.private.tcp", old.Filter.Private.TCP, newCfg.Filter.Private.TCP)
	out = appendPortDiff(out, "filter.private.udp", old.Filter.Private.UDP, newCfg.Filter.Private.UDP)
	out = appendBoolPtrDiff(out, "filter.allow_icmp", old.Filter.AllowICMP, newCfg.Filter.AllowICMP)
	out = appendBoolPtrDiff(out, "filter.allow_arp", old.Filter.AllowARP, newCfg.Filter.AllowARP)
	out = appendScalarDiff(out, "filter.udp_ephemeral_min",
		fmt.Sprintf("%d", old.Filter.UDPEphemeralMin),
		fmt.Sprintf("%d", newCfg.Filter.UDPEphemeralMin))
	out = appendStringListDiff(out, "filter.ingress_allowlist",
		old.Filter.IngressAllowlist, newCfg.Filter.IngressAllowlist)
	out = appendStringListDiff(out, "filter.static_blocklist",
		old.Filter.StaticBlocklist, newCfg.Filter.StaticBlocklist)

	return out
}

// appendScalarDiff records a change if before != after. Caller passes
// already-stringified values; the helper only cares about equality and
// formatting.
func appendScalarDiff(out []string, path, before, after string) []string {
	if before == after {
		return out
	}
	return append(out, fmt.Sprintf("%s %s → %s", path, quoteIfEmpty(before), quoteIfEmpty(after)))
}

// appendBoolPtrDiff handles the *bool pattern (nil = "unset" vs explicit
// true/false). Useful because the effective value of *bool fields
// depends on defaults the loader applies post-parse.
func appendBoolPtrDiff(out []string, path string, before, after *bool) []string {
	if boolPtrEqual(before, after) {
		return out
	}
	return append(out, fmt.Sprintf("%s %s → %s", path, boolPtrStr(before), boolPtrStr(after)))
}

// appendPortDiff records added / removed ports in set semantics.
// Order within the set is normalised (sorted ascending) so the log
// reads cleanly regardless of how the YAML listed them.
func appendPortDiff(out []string, path string, before, after []uint16) []string {
	addedPorts, removedPorts := diffUint16Sets(before, after)
	if len(addedPorts) == 0 && len(removedPorts) == 0 {
		return out
	}
	return append(out, fmt.Sprintf("%s added=%v removed=%v", path, addedPorts, removedPorts))
}

// appendStringListDiff handles CIDR / IP lists (ingress_allowlist,
// static_blocklist) with the same added / removed set semantics.
func appendStringListDiff(out []string, path string, before, after []string) []string {
	addedStrs, removedStrs := diffStringSets(before, after)
	if len(addedStrs) == 0 && len(removedStrs) == 0 {
		return out
	}
	return append(out, fmt.Sprintf("%s added=%v removed=%v", path, addedStrs, removedStrs))
}

// diffUint16Sets returns (added, removed) where:
//   - added = elements in after but not in before
//   - removed = elements in before but not in after
// Both slices are sorted ascending for readability.
func diffUint16Sets(before, after []uint16) (added, removed []uint16) {
	bset := make(map[uint16]struct{}, len(before))
	for _, v := range before {
		bset[v] = struct{}{}
	}
	aset := make(map[uint16]struct{}, len(after))
	for _, v := range after {
		aset[v] = struct{}{}
	}
	for v := range aset {
		if _, ok := bset[v]; !ok {
			added = append(added, v)
		}
	}
	for v := range bset {
		if _, ok := aset[v]; !ok {
			removed = append(removed, v)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i] < added[j] })
	sort.Slice(removed, func(i, j int) bool { return removed[i] < removed[j] })
	return added, removed
}

// diffStringSets is the string variant. Kept separate from diffUint16Sets
// because Go generics would save five lines at the cost of making every
// reader check the instantiation.
func diffStringSets(before, after []string) (added, removed []string) {
	bset := make(map[string]struct{}, len(before))
	for _, v := range before {
		bset[v] = struct{}{}
	}
	aset := make(map[string]struct{}, len(after))
	for _, v := range after {
		aset[v] = struct{}{}
	}
	for v := range aset {
		if _, ok := bset[v]; !ok {
			added = append(added, v)
		}
	}
	for v := range bset {
		if _, ok := aset[v]; !ok {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// boolPtrEqual treats nil as a distinct third state from true/false.
// Matches the config loader semantics where nil means "fall through to
// default" — a user explicitly setting false is NOT equivalent to
// omitting the field.
func boolPtrEqual(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func boolPtrStr(b *bool) string {
	if b == nil {
		return "unset"
	}
	if *b {
		return "true"
	}
	return "false"
}

// quoteIfEmpty renders empty strings visibly as "" so a line like
// `node.id  → edge-01` doesn't leave the reader guessing whether the
// old value was blank or the formatter dropped it.
func quoteIfEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}
