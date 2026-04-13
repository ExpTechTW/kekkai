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
	DefaultUDPEphemeralMin = uint16(32768)

	SSHPort = uint16(22)
)
