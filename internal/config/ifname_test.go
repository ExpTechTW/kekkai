package config

import "testing"

func TestValidateInterfaceName(t *testing.T) {
	ok := []string{"eth0", "eth0.10", "br-lan", "wlan0", "veth0@if2", "enp0s1", "a", "123456789012345"}
	for _, name := range ok {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("ValidateInterfaceName(%q) unexpected error: %v", name, err)
		}
	}

	bad := []string{"", ".", "..", "has space", "eth0\nname: evil", "eth/0", "eth0*", "1234567890123456", "名前"}
	for _, name := range bad {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("ValidateInterfaceName(%q) accepted invalid name", name)
		}
	}
}
