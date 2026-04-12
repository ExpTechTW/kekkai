package main

import (
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/YuYu1015/waf-go/internal/config"
	"github.com/YuYu1015/waf-go/internal/loader"
	wafmaps "github.com/YuYu1015/waf-go/internal/maps"
)

func main() {
	cfgPath := flag.String("config", "/etc/waf-go/edge.yaml", "path to edge config")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("waf-edge starting node=%s region=%s iface=%s", cfg.NodeID, cfg.Region, cfg.Iface)

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		log.Fatalf("lookup iface %s: %v", cfg.Iface, err)
	}

	ld := loader.New(cfg.Iface)
	if err := ld.Attach(iface.Index); err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer ld.Close()
	log.Printf("xdp attached to %s (ifindex=%d)", cfg.Iface, iface.Index)

	rawMap, err := ld.BlocklistMap()
	if err != nil {
		log.Fatalf("blocklist map: %v", err)
	}
	bl := wafmaps.NewBlocklist(rawMap)

	if err := loadStaticBlocklist(bl, cfg.StaticBlocklist); err != nil {
		log.Fatalf("static blocklist: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}

func loadStaticBlocklist(bl *wafmaps.Blocklist, entries []string) error {
	added := 0
	for _, s := range entries {
		p, err := parsePrefix(s)
		if err != nil {
			log.Printf("static blocklist: skip %q: %v", s, err)
			continue
		}
		if err := bl.Add(p); err != nil {
			return err
		}
		added++
	}
	log.Printf("static blocklist loaded: %d entries", added)
	return nil
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
