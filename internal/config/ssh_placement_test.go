package config

import (
	"strings"
	"testing"
)

// baseValidConfig returns a minimal config that passes Validate once
// applyDefaults has run, so individual tests only set the SSH-relevant
// fields they care about.
func baseValidConfig() *Config {
	c := &Config{}
	c.applyDefaults()
	c.Interface.Name = "eth0"
	c.Filter.IngressAllowlist = []string{"192.168.0.0/16"}
	return c
}

func TestValidate_SSHPlacementMatchesAllowSSHPublic(t *testing.T) {
	tests := []struct {
		name        string
		allowPublic bool
		publicTCP   []uint16
		privateTCP  []uint16
		wantErr     string // substring; "" means expect success
	}{
		{
			name:        "public flag, 22 in private contradicts",
			allowPublic: true,
			privateTCP:  []uint16{22},
			wantErr:     "filter.private.tcp contains 22 but security.allow_ssh_public is true",
		},
		{
			name:        "private flag, 22 in public contradicts",
			allowPublic: false,
			publicTCP:   []uint16{22},
			wantErr:     "filter.public.tcp contains 22 but security.allow_ssh_public is false",
		},
		{
			name:        "public flag, 22 in public agrees",
			allowPublic: true,
			publicTCP:   []uint16{22},
		},
		{
			name:        "private flag, 22 in private agrees",
			allowPublic: false,
			privateTCP:  []uint16{22},
		},
		{
			name:        "22 in both groups rejected by generic check",
			allowPublic: true,
			publicTCP:   []uint16{22},
			privateTCP:  []uint16{22},
			wantErr:     "port 22 appears in both",
		},
		{
			name:        "22 unlisted is fine under either flag",
			allowPublic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			c.Security.AllowSSHPublic = tt.allowPublic
			c.Filter.Public.TCP = tt.publicTCP
			c.Filter.Private.TCP = tt.privateTCP

			err := c.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("Validate() = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestEffectiveTCP_PlacesSSHImplicitlyWithoutMutatingConfig(t *testing.T) {
	t.Run("public flag: 22 implicit in public, not in config", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = true
		c.Filter.Public.TCP = []uint16{80}

		if !containsPort(c.EffectivePublicTCP(), SSHPort) {
			t.Fatalf("EffectivePublicTCP missing 22: %v", c.EffectivePublicTCP())
		}
		if containsPort(c.EffectivePrivateTCP(), SSHPort) {
			t.Fatalf("EffectivePrivateTCP unexpectedly has 22: %v", c.EffectivePrivateTCP())
		}
		// The config struct must stay untouched — 22 is never persisted.
		if containsPort(c.Filter.Public.TCP, SSHPort) {
			t.Fatalf("config Filter.Public.TCP was mutated: %v", c.Filter.Public.TCP)
		}
	})

	t.Run("private flag: 22 implicit in private, not in config", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = false

		if !containsPort(c.EffectivePrivateTCP(), SSHPort) {
			t.Fatalf("EffectivePrivateTCP missing 22: %v", c.EffectivePrivateTCP())
		}
		if containsPort(c.EffectivePublicTCP(), SSHPort) {
			t.Fatalf("EffectivePublicTCP unexpectedly has 22: %v", c.EffectivePublicTCP())
		}
		if containsPort(c.Filter.Private.TCP, SSHPort) {
			t.Fatalf("config Filter.Private.TCP was mutated: %v", c.Filter.Private.TCP)
		}
	})

	t.Run("no duplicate when user already listed 22 in agreeing group", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = true
		c.Filter.Public.TCP = []uint16{22, 443}

		eff := c.EffectivePublicTCP()
		n := 0
		for _, p := range eff {
			if p == SSHPort {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("EffectivePublicTCP has %d copies of 22, want 1: %v", n, eff)
		}
	})

	t.Run("SSHIsPublic tracks the flag", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = true
		if !c.SSHIsPublic() {
			t.Fatal("SSHIsPublic()=false, want true")
		}
		c.Security.AllowSSHPublic = false
		if c.SSHIsPublic() {
			t.Fatal("SSHIsPublic()=true, want false")
		}
	})
}
