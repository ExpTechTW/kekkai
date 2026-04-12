package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/YuYu1015/waf-go/internal/config"
	"github.com/YuYu1015/waf-go/internal/loader"
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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("shutting down")
}
