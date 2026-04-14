package config

// CurrentVersion is the schema version this build writes and expects.
// v2 is backward-compatible with v1 via migrateIfNeeded().
const CurrentVersion = 2

const (
	DefaultStatsFile       = "/var/run/kekkai/stats.txt"
	DefaultPerIPTableSize  = 65536
	DefaultXDPMode         = "generic"
	DefaultUpdateChannel   = "release"
	DefaultUDPEphemeralMin = uint16(32768)

	// Auto-update defaults. Download is on by default so fresh installs
	// always pick up release fixes without operator action; reload stays
	// off so nobody gets surprised by an agent self-restart.
	DefaultAutoUpdateDownload = true
	DefaultAutoUpdateInterval = 1 // hours

	SSHPort = uint16(22)
)
