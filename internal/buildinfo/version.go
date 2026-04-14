package buildinfo

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionRaw string

// DefaultVersion is the repository's single-source version value.
var DefaultVersion = strings.TrimSpace(versionRaw)
