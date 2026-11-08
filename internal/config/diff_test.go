package config

import (
	"strings"
	"testing"
)

func TestDiffConfigs(t *testing.T) {
	if DiffConfigs(nil, &Config{}) != nil || DiffConfigs(&Config{}, nil) != nil {
		t.Fatal("nil config should not diff")
	}

	base := &Config{
		Node:      NodeConfig{ID: "a", Region: "default"},
		Interface: InterfaceConfig{Name: "eth0", XDPMode: "generic"},
		Update:    UpdateConfig{Channel: "release", AutoUpdateInterval: 1},
		Runtime:   RuntimeConfig{PerIPTableSize: 65536},
		Filter: FilterConfig{
			Public:           PortGroup{TCP: []uint16{443, 80, 80}},
			IngressAllowlist: []string{"10.0.0.0/8"},
			UDPEphemeralMin:  32768,
		},
	}
	same := *base
	same.Filter.Public.TCP = []uint16{80, 443}
	if got := DiffConfigs(base, &same); len(got) != 0 {
		t.Fatalf("set-equal ports differed: %v", got)
	}

	on := true
	off := false
	if !boolPtrEqual(&on, &on) || boolPtrEqual(&on, nil) || boolPtrEqual(&on, &off) {
		t.Fatal("boolPtrEqual")
	}
	other := true
	if !boolPtrEqual(&on, &other) {
		t.Fatal("equal true pointers")
	}

	next := *base
	next.Node.ID = ""
	next.Node.Region = "edge"
	next.Update.AutoUpdateDownload = &off
	next.Update.AutoUpdateInterval = 2
	next.Runtime.EmergencyBypass = true
	next.Runtime.PerIPTableSize = 128
	next.Filter.Public.TCP = []uint16{80, 8080}
	next.Filter.AllowICMP = &on
	next.Filter.IngressAllowlist = []string{"192.168.0.0/16", "10.0.0.0/8"}
	next.Filter.UDPEphemeralMin = 1024

	got := DiffConfigs(base, &next)
	want := []string{
		`node.id a → ""`,
		`node.region default → edge`,
		`update.auto_update_download unset → false`,
		`update.auto_update_interval 1 → 2`,
		`runtime.emergency_bypass false → true`,
		`runtime.perip_table_size 65536 → 128`,
		`filter.public.tcp added=[8080] removed=[443]`,
		`filter.allow_icmp unset → true`,
		`filter.udp_ephemeral_min 32768 → 1024`,
		`filter.ingress_allowlist added=[192.168.0.0/16] removed=[]`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
