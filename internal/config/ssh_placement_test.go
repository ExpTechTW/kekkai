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

func TestNormalize_PlacesSSHPerAllowSSHPublic(t *testing.T) {
	t.Run("public flag adds 22 to public.tcp", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = true
		c.Normalize()
		if !containsPort(c.Filter.Public.TCP, SSHPort) {
			t.Fatalf("Normalize did not add 22 to public.tcp: %v", c.Filter.Public.TCP)
		}
		if containsPort(c.Filter.Private.TCP, SSHPort) {
			t.Fatalf("22 unexpectedly added to private.tcp: %v", c.Filter.Private.TCP)
		}
	})

	t.Run("private flag adds 22 to private.tcp", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = false
		c.Normalize()
		if !containsPort(c.Filter.Private.TCP, SSHPort) {
			t.Fatalf("Normalize did not add 22 to private.tcp: %v", c.Filter.Private.TCP)
		}
		if containsPort(c.Filter.Public.TCP, SSHPort) {
			t.Fatalf("22 unexpectedly added to public.tcp: %v", c.Filter.Public.TCP)
		}
	})

	t.Run("already listed in agreeing group is untouched", func(t *testing.T) {
		c := baseValidConfig()
		c.Security.AllowSSHPublic = true
		c.Filter.Public.TCP = []uint16{22, 443}
		logs := c.Normalize()
		if len(logs) != 0 {
			t.Fatalf("Normalize logged changes for already-placed 22: %v", logs)
		}
		if got := len(c.Filter.Public.TCP); got != 2 {
			t.Fatalf("public.tcp len = %d, want 2 (no duplicate 22): %v", got, c.Filter.Public.TCP)
		}
	})
}
