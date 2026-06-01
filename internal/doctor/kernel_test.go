package doctor

import "testing"

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
