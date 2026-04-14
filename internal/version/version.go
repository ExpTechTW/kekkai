// Package version parses and compares kekkai release version strings.
//
// kekkai tags are emitted by .github/workflows/ci-release.yml in a fixed
// shape:
//
//	v<YYYY>.<MM>.<DD>+build.<N>
//
// The leading `v` is optional — CI publishes with it, `-X main.version=...`
// ldflags pass it without. Anything else is rejected.
//
// This package is the single source of truth for version comparison across
// Go code. kekkai.sh (bash) and .github/workflows/ci-release.yml (python)
// contain sibling implementations that MUST stay semantically identical;
// if the parsing rule changes here, those two need to be updated in lock
// step. There are no unit tests enforcing this — it is a manual contract.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

// regex captures (year, month, day, build). The leading `v` and the
// `build.` literal are stripped so the four groups are pure integers.
var regex = regexp.MustCompile(`^v?(\d{4})\.(\d{2})\.(\d{2})\+build\.(\d+)$`)

// Version is a parsed kekkai release identifier. The zero value is an
// invalid version; always check the bool returned by Parse.
type Version struct {
	Year, Month, Day, Build int
}

// Parse extracts a Version from a tag string. Returns false for any input
// that does not match the canonical `[v]YYYY.MM.DD+build.N` shape.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}
	m := regex.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var v Version
	for i, dst := range []*int{&v.Year, &v.Month, &v.Day, &v.Build} {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return Version{}, false
		}
		*dst = n
	}
	return v, true
}

// Compare returns -1 / 0 / +1 for a < b, a == b, a > b respectively.
// Comparison is lexicographic across (year, month, day, build).
func Compare(a, b Version) int {
	switch {
	case a.Year != b.Year:
		return sign(a.Year - b.Year)
	case a.Month != b.Month:
		return sign(a.Month - b.Month)
	case a.Day != b.Day:
		return sign(a.Day - b.Day)
	case a.Build != b.Build:
		return sign(a.Build - b.Build)
	}
	return 0
}

// IsNewer reports whether candidate is strictly newer than installed.
// Used by update flows to gate whether a fetched release should replace
// the currently running binary.
func IsNewer(candidate, installed Version) bool {
	return Compare(candidate, installed) > 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
