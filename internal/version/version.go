// Package version parses and compares kekkai release versions.
//
//	[v]YYYY.MM.DD+build.N
//
// The leading v is optional. kekkai.sh and ci-release.yml duplicate this
// rule and have to stay in lock-step with Parse.
package version

import (
	"strconv"
	"strings"
)

// Version is a parsed release id. The zero value is invalid; use Parse's bool.
type Version struct {
	Year, Month, Day, Build int
}

const (
	versionDateLen   = len("YYYY.MM.DD") // 10
	versionBuildMark = "+build."
)

// Parse accepts a trimmed `[v]YYYY.MM.DD+build.N` string.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 0 && s[0] == 'v' {
		s = s[1:]
	}
	markAt := versionDateLen
	if len(s) < markAt+len(versionBuildMark)+1 ||
		s[4] != '.' || s[7] != '.' ||
		s[markAt:markAt+len(versionBuildMark)] != versionBuildMark {
		return Version{}, false
	}
	year, ok := fixedDigits(s[0:4])
	if !ok {
		return Version{}, false
	}
	month, ok := fixedDigits(s[5:7])
	if !ok {
		return Version{}, false
	}
	day, ok := fixedDigits(s[8:10])
	if !ok {
		return Version{}, false
	}
	build, ok := atoiDigits(s[markAt+len(versionBuildMark):])
	if !ok {
		return Version{}, false
	}
	return Version{Year: year, Month: month, Day: day, Build: build}, true
}

func fixedDigits(s string) (int, bool) {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

func atoiDigits(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	// Atoi rejects values that do not fit in int, matching the old parser.
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Compare returns -1, 0, or +1. Order is year, month, day, build.
func Compare(a, b Version) int {
	av := [...]int{a.Year, a.Month, a.Day, a.Build}
	bv := [...]int{b.Year, b.Month, b.Day, b.Build}
	for i := range av {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

// IsNewer reports whether candidate is strictly newer than installed.
func IsNewer(candidate, installed Version) bool {
	return Compare(candidate, installed) > 0
}
