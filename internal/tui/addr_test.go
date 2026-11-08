package tui

import (
	"strings"
	"testing"

	"github.com/ExpTechTW/kekkai/internal/stats"
)

func TestAddrColumnFitsTerminal(t *testing.T) {
	if w := addrColumnWidth(80); w >= addrColMax || w < 8 {
		t.Fatalf("80-col addr width %d", w)
	}
	if w := addrColumnWidth(200); w != addrColMax {
		t.Fatalf("wide addr width %d", w)
	}
	if addrColumnWidth(0) != 16 {
		t.Fatalf("unset width %d", addrColumnWidth(0))
	}

	full := "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	if len(full) != addrColMax {
		t.Fatalf("fixture len %d", len(full))
	}
	narrow := addrColumnWidth(80)
	got := truncateMiddle(full, narrow)
	if !strings.Contains(got, "…") || len([]rune(got)) != narrow {
		t.Fatalf("%q runes=%d width=%d", got, len([]rune(got)), narrow)
	}
	if truncateMiddle("1.2.3.4", narrow) != "1.2.3.4" {
		t.Fatal("ipv4 address was truncated")
	}
	if truncateMiddle(full, addrColMax) != full {
		t.Fatal("full address was truncated at 39 columns")
	}
}

func TestIPv6Share(t *testing.T) {
	if ipv6Share(stats.Global{}) != "0%" {
		t.Fatal("empty mix")
	}
	got := ipv6Share(stats.Global{PktsTCP: 50, PktsUDP: 50, PktsIPv6: 25})
	if got != "25.0%" {
		t.Fatalf("share %s", got)
	}
}
