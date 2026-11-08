package config

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/ExpTechTW/kekkai/internal/maps"
)

func TestValidatePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		allow   []string
		block   []string
		wantErr string
	}{
		{name: "v4 cidr", allow: []string{"10.0.0.0/8"}},
		{name: "v4 bare", allow: []string{"192.168.1.10"}},
		{name: "v4 host bits masked", allow: []string{"10.1.2.3/16"}},
		{name: "v6 cidr", allow: []string{"2001:db8::/32"}},
		{name: "v6 bare", allow: []string{"2001:db8::1"}},
		{name: "mapped treated as v4", allow: []string{"::ffff:192.168.0.0/112"}},
		{name: "mapped host bits", block: []string{"::ffff:1.2.3.255/120"}},
		{
			name:    "mapped shorter than /96",
			allow:   []string{"::ffff:1.2.3.0/95"},
			wantErr: "shorter than /96",
		},
		{
			name:    "v4 prefix too long",
			allow:   []string{"1.2.3.4/33"},
			wantErr: "filter.ingress_allowlist",
		},
		{
			name:    "v6 prefix too long",
			allow:   []string{"2001:db8::/129"},
			wantErr: "filter.ingress_allowlist",
		},
		{
			name:    "garbage",
			block:   []string{"not-a-prefix"},
			wantErr: "filter.static_blocklist",
		},
		{
			name:    "zone",
			allow:   []string{"fe80::1%eth0"},
			wantErr: "zone",
		},
		{
			name:    "zone with length",
			allow:   []string{"fe80::1%eth0/64"},
			wantErr: "filter.ingress_allowlist",
		},
		{
			name:    "empty",
			allow:   []string{""},
			wantErr: "filter.ingress_allowlist",
		},
		{
			name:    "v6 ::/0 covers ipv4",
			block:   []string{"::/0"},
			wantErr: "also covers IPv4",
		},
		{
			name:    "v6 ::/64 covers ipv4",
			allow:   []string{"::/64"},
			wantErr: "also covers IPv4",
		},
		{name: "global unicast", allow: []string{"2000::/3"}},
		{name: "link local", allow: []string{"fe80::/10"}},
		{name: "v6 loopback", allow: []string{"::1/128"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			if tt.allow != nil {
				c.Filter.IngressAllowlist = tt.allow
			}
			if tt.block != nil {
				c.Filter.StaticBlocklist = tt.block
			}
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate err %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParsePrefixCanonical(t *testing.T) {
	v4, err := ParsePrefix("1.2.3.255/24")
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := ParsePrefix("::ffff:1.2.3.0/120")
	if err != nil {
		t.Fatal(err)
	}
	if v4 != mapped {
		t.Fatalf("v4 %s and mapped %s normalised differently", v4, mapped)
	}
	if v4.Bits() != 120 || v4.Addr() != netip.MustParseAddr("::ffff:1.2.3.0") {
		t.Fatalf("canonical prefix %s", v4)
	}

	bare, err := ParsePrefix("2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	if bare.Bits() != 128 || bare.Addr() != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("bare v6 %s", bare)
	}

	// The key the agent will insert is the one Validate accepted.
	key, err := maps.KeyFromPrefix(v4)
	if err != nil {
		t.Fatal(err)
	}
	again, err := maps.KeyFromPrefix(mapped)
	if err != nil {
		t.Fatal(err)
	}
	if key != again || key.Prefixlen != 120 {
		t.Fatalf("keys differ or prefixlen %d", key.Prefixlen)
	}
}

func TestValidatePortMapCapacity(t *testing.T) {
	// 4095 explicit TCP ports plus the implicit SSH port is exactly the map.
	c := baseValidConfig()
	c.Security.AllowSSHPublic = false
	c.Filter.Public.TCP = seqPorts(23, 4095) // 23..4117, no 22
	if err := c.Validate(); err != nil {
		t.Fatalf("4096 with implicit ssh: %v", err)
	}

	// One more UDP port does not fit.
	c.Filter.Public.UDP = []uint16{53}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "ports map") {
		t.Fatalf("capacity err %v", err)
	}

	// 4096 public TCP ports that already include nothing extra when SSH is
	// listed and allow_ssh_public agrees: still exactly the map.
	ok := baseValidConfig()
	ok.Security.AllowSSHPublic = true
	ports := seqPorts(1, maps.PortsMaxEntries) // 1..4096, includes 22
	ok.Filter.Public.TCP = ports
	if err := ok.Validate(); err != nil {
		t.Fatalf("exactly %d: %v", maps.PortsMaxEntries, err)
	}
}

func seqPorts(start, n int) []uint16 {
	out := make([]uint16, n)
	for i := range out {
		out[i] = uint16(start + i)
	}
	return out
}
