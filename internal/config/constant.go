package config

// CurrentVersion is the schema version this build writes and expects.
// Not yet bumped — the project has not shipped a breaking schema change.
// The field is reserved so older agents can refuse to load future formats
// and future agents know when to run migration.
const CurrentVersion = 1

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
