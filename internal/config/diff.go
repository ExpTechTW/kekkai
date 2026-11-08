package config

// Field-by-field diff for reload logs. Hand-written so pointer-bool fields
// stay a third state (nil is "unset", which is not false) and so the lines
// match the way operators read a change: "path before → after", or
// "path added=[...] removed=[...]" for lists. An empty result means none
// of the compared fields differ.

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
)

// DiffConfigs lists human-readable changes from old to newCfg.
// Nil arguments yield nil. Order follows the config struct.
func DiffConfigs(old, newCfg *Config) []string {
	if old == nil || newCfg == nil {
		return nil
	}
	var out []string

	out = appendScalarDiff(out, "node.id", old.Node.ID, newCfg.Node.ID)
	out = appendScalarDiff(out, "node.region", old.Node.Region, newCfg.Node.Region)

	out = appendScalarDiff(out, "interface.name", old.Interface.Name, newCfg.Interface.Name)
	out = appendScalarDiff(out, "interface.xdp_mode", old.Interface.XDPMode, newCfg.Interface.XDPMode)

	out = appendScalarDiff(out, "update.channel", old.Update.Channel, newCfg.Update.Channel)
	out = appendBoolPtrDiff(out, "update.auto_update_download",
		old.Update.AutoUpdateDownload, newCfg.Update.AutoUpdateDownload)
	out = appendBoolDiff(out, "update.auto_update_reload",
		old.Update.AutoUpdateReload, newCfg.Update.AutoUpdateReload)
	out = appendIntDiff(out, "update.auto_update_interval",
		old.Update.AutoUpdateInterval, newCfg.Update.AutoUpdateInterval)

	out = appendBoolDiff(out, "runtime.emergency_bypass",
		old.Runtime.EmergencyBypass, newCfg.Runtime.EmergencyBypass)
	out = appendUintDiff(out, "runtime.perip_table_size",
		uint64(old.Runtime.PerIPTableSize), uint64(newCfg.Runtime.PerIPTableSize))

	out = appendScalarDiff(out, "observability.stats_file",
		old.Observability.StatsFile, newCfg.Observability.StatsFile)

	out = appendBoolDiff(out, "security.allow_ssh_public",
		old.Security.AllowSSHPublic, newCfg.Security.AllowSSHPublic)

	out = appendSetDiff(out, "filter.public.tcp", old.Filter.Public.TCP, newCfg.Filter.Public.TCP)
	out = appendSetDiff(out, "filter.public.udp", old.Filter.Public.UDP, newCfg.Filter.Public.UDP)
	out = appendSetDiff(out, "filter.private.tcp", old.Filter.Private.TCP, newCfg.Filter.Private.TCP)
	out = appendSetDiff(out, "filter.private.udp", old.Filter.Private.UDP, newCfg.Filter.Private.UDP)
	out = appendBoolPtrDiff(out, "filter.allow_icmp", old.Filter.AllowICMP, newCfg.Filter.AllowICMP)
	out = appendBoolPtrDiff(out, "filter.allow_arp", old.Filter.AllowARP, newCfg.Filter.AllowARP)
	out = appendUintDiff(out, "filter.udp_ephemeral_min",
		uint64(old.Filter.UDPEphemeralMin), uint64(newCfg.Filter.UDPEphemeralMin))
	out = appendSetDiff(out, "filter.ingress_allowlist",
		old.Filter.IngressAllowlist, newCfg.Filter.IngressAllowlist)
	out = appendSetDiff(out, "filter.static_blocklist",
		old.Filter.StaticBlocklist, newCfg.Filter.StaticBlocklist)

	return out
}

func appendScalarDiff(out []string, path, before, after string) []string {
	if before == after {
		return out
	}
	return append(out, fmt.Sprintf("%s %s → %s", path, quoteIfEmpty(before), quoteIfEmpty(after)))
}

func appendBoolDiff(out []string, path string, before, after bool) []string {
	if before == after {
		return out
	}
	return appendScalarDiff(out, path, boolStr(before), boolStr(after))
}

func appendIntDiff(out []string, path string, before, after int) []string {
	if before == after {
		return out
	}
	return appendScalarDiff(out, path, strconv.Itoa(before), strconv.Itoa(after))
}

func appendUintDiff(out []string, path string, before, after uint64) []string {
	if before == after {
		return out
	}
	return appendScalarDiff(out, path, strconv.FormatUint(before, 10), strconv.FormatUint(after, 10))
}

func appendBoolPtrDiff(out []string, path string, before, after *bool) []string {
	if boolPtrEqual(before, after) {
		return out
	}
	return append(out, fmt.Sprintf("%s %s → %s", path, boolPtrStr(before), boolPtrStr(after)))
}

func appendSetDiff[T cmp.Ordered](out []string, path string, before, after []T) []string {
	added, removed := diffSet(before, after)
	if len(added) == 0 && len(removed) == 0 {
		return out
	}
	return append(out, fmt.Sprintf("%s added=%v removed=%v", path, added, removed))
}

func diffSet[T cmp.Ordered](before, after []T) (added, removed []T) {
	bset := make(map[T]struct{}, len(before))
	for _, v := range before {
		bset[v] = struct{}{}
	}
	aset := make(map[T]struct{}, len(after))
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
	slices.Sort(added)
	slices.Sort(removed)
	return added, removed
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// boolPtrEqual treats nil as distinct from both true and false.
// Nil means "fall through to the default"; an explicit false does not.
func boolPtrEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func boolPtrStr(b *bool) string {
	if b == nil {
		return "unset"
	}
	return boolStr(*b)
}

func quoteIfEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}
