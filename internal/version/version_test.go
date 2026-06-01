package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		ok   bool
	}{
		// Canonical CI tag (with leading v).
		{"v2026.04.14+build.9", Version{2026, 4, 14, 9}, true},
		// -ldflags form (no leading v).
		{"2026.04.14+build.25", Version{2026, 4, 14, 25}, true},
		// Whitespace tolerated.
		{"  v2026.04.14+build.1  ", Version{2026, 4, 14, 1}, true},
		// Large build number.
		{"v2026.12.31+build.9999", Version{2026, 12, 31, 9999}, true},

		// Rejects.
		{"", Version{}, false},
		{"v2026.04.14", Version{}, false},              // missing +build.N
		{"v2026.04.14+build.", Version{}, false},       // empty build
		{"v2026.4.14+build.9", Version{}, false},       // month not zero-padded
		{"2026.04.14+build.9+extra", Version{}, false}, // trailing garbage
		{"20260414+build.9", Version{}, false},         // legacy YYYYMMDD (never shipped)
		{"dev-abc123", Version{}, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q) ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("Parse(%q) = %+v want %+v", c.in, got, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v2026.04.14+build.24", "v2026.04.14+build.25", -1}, // the bug that motivated this package
		{"v2026.04.14+build.25", "v2026.04.14+build.24", 1},
		{"v2026.04.14+build.24", "v2026.04.14+build.24", 0},
		{"v2026.04.14+build.9", "v2026.04.14+build.18", -1},  // numeric not lexicographic
		{"v2026.04.14+build.99", "v2026.04.15+build.1", -1},  // day rolls
		{"v2026.04.30+build.99", "v2026.05.01+build.1", -1},  // month rolls
		{"v2026.12.31+build.99", "v2027.01.01+build.1", -1},  // year rolls
	}
	for _, c := range cases {
		a, okA := Parse(c.a)
		b, okB := Parse(c.b)
		if !okA || !okB {
			t.Fatalf("setup failure: Parse(%q)=%v Parse(%q)=%v", c.a, okA, c.b, okB)
		}
		if got := Compare(a, b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewer(t *testing.T) {
	older, _ := Parse("v2026.04.14+build.24")
	newer, _ := Parse("v2026.04.14+build.25")
	if !IsNewer(newer, older) {
		t.Error("build.25 should be newer than build.24")
	}
	if IsNewer(older, newer) {
		t.Error("build.24 should not be newer than build.25")
	}
	if IsNewer(older, older) {
		t.Error("equal versions should not be 'newer'")
	}
}
