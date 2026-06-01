package doctor

import (
	"strings"
	"testing"
)

func TestParseKernelMajorMinor(t *testing.T) {
	tests := []struct {
		rel          string
		major, minor int
		ok           bool
		tcxOK        bool // whether >= 6.6 (TCX egress supported)
	}{
		{"5.15.0-179-generic\n", 5, 15, true, false},
		{"6.8.0-31-generic", 6, 8, true, true},
		{"6.6.0", 6, 6, true, true},
		{"6.5.0-14-generic", 6, 5, true, false},
		{"7.0.1", 7, 0, true, true},
		{"garbage", 0, 0, false, false},
		{"6", 0, 0, false, false},
		{"x.y.z", 0, 0, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.rel, func(t *testing.T) {
			major, minor, ok := parseKernelMajorMinor(tt.rel)
			if ok != tt.ok || major != tt.major || minor != tt.minor {
				t.Fatalf("parseKernelMajorMinor(%q) = (%d,%d,%v), want (%d,%d,%v)",
					tt.rel, major, minor, ok, tt.major, tt.minor, tt.ok)
			}
			if !ok {
				return
			}
			// Mirror the <6.6 gate used by checkKernel.
			tcxOK := !(major < 6 || (major == 6 && minor < 6))
			if tcxOK != tt.tcxOK {
				t.Fatalf("%q: tcxOK=%v, want %v", tt.rel, tcxOK, tt.tcxOK)
			}
		})
	}
}

func TestParseOSReleaseIDs(t *testing.T) {
	const ubuntu = `NAME="Ubuntu"
ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=jammy`
	id, like := parseOSReleaseIDs(ubuntu)
	if id != "ubuntu" || like != "debian" {
		t.Fatalf("got id=%q id_like=%q, want ubuntu/debian", id, like)
	}
	// Quoted ID_LIKE with multiple families.
	id, like = parseOSReleaseIDs("ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")
	if id != "rocky" || like != "rhel centos fedora" {
		t.Fatalf("got id=%q id_like=%q", id, like)
	}
}

func TestCountRXQueues(t *testing.T) {
	tests := []struct {
		names []string
		want  int
	}{
		{[]string{"rx-0", "tx-0", "rx-1", "tx-1"}, 2},
		{[]string{"rx-0"}, 1},                                 // single queue → warn case
		{[]string{"rx-0", "rx-1", "rx-2", "rx-3", "tx-0"}, 4}, // multi-queue → ok case
		{[]string{"tx-0", "tx-1"}, 0},                         // no rx dirs
		{nil, 0},
	}
	for _, tt := range tests {
		if got := countRXQueues(tt.names); got != tt.want {
			t.Errorf("countRXQueues(%v) = %d, want %d", tt.names, got, tt.want)
		}
	}
}

func TestKernelUpgradeCommandFor(t *testing.T) {
	tests := []struct {
		id, idLike string
		wantSub    string
	}{
		{"ubuntu", "debian", "linux-generic-hwe-22.04"},
		{"debian", "", "-backports"},
		{"raspbian", "debian", "-backports"}, // matched via ID_LIKE
		{"fedora", "", "dnf upgrade --refresh kernel"},
		{"rocky", "rhel centos fedora", "ELRepo"},
		{"arch", "", "pacman -Syu linux"},
		{"manjaro", "arch", "pacman -Syu linux"}, // ID_LIKE=arch
		{"opensuse-leap", "suse opensuse", "zypper"},
		{"alpine", "", "apk add linux-lts"},
		{"voidlinux", "", "see your distro's docs"}, // unknown fallback
		{"", "", "see your distro's docs"},          // os-release missing
	}
	for _, tt := range tests {
		t.Run(tt.id+"/"+tt.idLike, func(t *testing.T) {
			got := kernelUpgradeCommandFor(tt.id, tt.idLike)
			if !strings.Contains(got, tt.wantSub) {
				t.Fatalf("kernelUpgradeCommandFor(%q,%q) = %q, want substring %q",
					tt.id, tt.idLike, got, tt.wantSub)
			}
		})
	}
}
