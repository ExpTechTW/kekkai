package config

import "fmt"

// ValidateInterfaceName applies Linux interface-name rules (IFNAMSIZ is 16
// including the trailing NUL). The name must be 1–15 bytes drawn from
// [A-Za-z0-9._@:-], and "." / ".." are rejected because they are path
// components, not device names.
func ValidateInterfaceName(name string) error {
	if name == "." || name == ".." {
		return fmt.Errorf("invalid interface name %q", name)
	}
	if len(name) < 1 || len(name) > 15 {
		return fmt.Errorf("invalid interface name %q: must be 1–15 bytes", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '@' || c == ':' || c == '-':
		default:
			return fmt.Errorf("invalid interface name %q", name)
		}
	}
	return nil
}
