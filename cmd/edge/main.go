// Command waf-edge is the edge agent binary. It loads the XDP data plane
// program, wires the blocklist and stats subsystems, and blocks on SIGINT /
// SIGTERM. All cross-cutting orchestration lives in run(); main() only parses
// flags.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/signal"
	"syscall"

	"github.com/YuYu1015/waf-go/internal/config"
	"github.com/YuYu1015/waf-go/internal/loader"
	"github.com/YuYu1015/waf-go/internal/maps"
	"github.com/YuYu1015/waf-go/internal/stats"
)

func main() {
	cfgPath := flag.String("config", "/etc/waf-go/edge.yaml", "path to edge config")
	flag.Parse()

	if err := run(*cfgPath); err != nil {
		log.Fatalf("waf-edge: %v", err)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	log.Printf("waf-edge starting node=%s region=%s iface=%s", cfg.NodeID, cfg.Region, cfg.Iface)

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("lookup iface %s: %w", cfg.Iface, err)
	}

	ld := loader.New(cfg.Iface)
	if err := ld.Attach(iface.Index); err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}
	defer ld.Close()
	log.Printf("xdp attached to %s (ifindex=%d)", cfg.Iface, iface.Index)

	if _, err := openBlocklist(ld, cfg.StaticBlocklist); err != nil {
		return err
	}

	reader, err := openStats(ld, cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := reader.Run(ctx.Done()); err != nil {
			log.Printf("stats reader: %v", err)
		}
	}()
	log.Printf("stats writing to %s (watch -n 1 cat %s)", cfg.StatsPath, cfg.StatsPath)

	<-ctx.Done()
	log.Printf("shutting down")
	<-done
	return nil
}

// openBlocklist wraps the eBPF LPM trie map and seeds it with the static
// CIDRs from config. Each entry may be a bare address (→ /32) or a CIDR.
func openBlocklist(ld *loader.Loader, entries []string) (*maps.Blocklist, error) {
	m, err := ld.BlocklistMap()
	if err != nil {
		return nil, fmt.Errorf("blocklist map: %w", err)
	}
	bl := maps.NewBlocklist(m)

	added := 0
	for _, s := range entries {
		p, err := parsePrefix(s)
		if err != nil {
			log.Printf("static blocklist: skip %q: %v", s, err)
			continue
		}
		if err := bl.Add(p); err != nil {
			return nil, fmt.Errorf("static blocklist add %s: %w", p, err)
		}
		added++
	}
	log.Printf("static blocklist loaded: %d entries", added)
	return bl, nil
}

// openStats wires the two eBPF stat maps into a decoupled reader that writes
// /var/run/waf-go/stats.txt on a fixed cadence.
func openStats(ld *loader.Loader, cfg *config.Config) (*stats.Reader, error) {
	globalMap, err := ld.StatsMap()
	if err != nil {
		return nil, fmt.Errorf("stats map: %w", err)
	}
	peripMap, err := ld.PerIPMap()
	if err != nil {
		return nil, fmt.Errorf("perip map: %w", err)
	}
	return stats.NewReader(globalMap, peripMap, cfg.NodeID, cfg.Iface, cfg.StatsPath), nil
}

// parsePrefix accepts either "1.2.3.4" (→ /32) or "1.2.3.0/24".
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
