// Command waf-edge is the edge agent binary.
//
// Responsibilities:
//   - Load XDP program, install maps, attach to configured interface
//     (or stay in emergency bypass).
//   - Seed maps from config (ports, allowlist, blocklist).
//   - Run stats reader which publishes /var/run/waf-go/stats.txt.
//   - Reload config on SIGHUP; validate first, apply as a diff to maps.
//   - `-check <path>` mode validates a config without attaching anything.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/YuYu1015/waf-go/internal/config"
	"github.com/YuYu1015/waf-go/internal/loader"
	wafmaps "github.com/YuYu1015/waf-go/internal/maps"
	"github.com/YuYu1015/waf-go/internal/stats"
)

func main() {
	cfgPath := flag.String("config", "/etc/waf-go/edge.yaml", "path to edge config")
	check := flag.Bool("check", false, "validate config and exit (non-zero on error)")
	flag.Parse()

	if *check {
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("config ok")
		return
	}

	if err := run(*cfgPath); err != nil {
		log.Fatalf("waf-edge: %v", err)
	}
}

// agent bundles all the subsystems main() wires together so reload can
// touch each map through a single handle.
type agent struct {
	cfg       *config.Config
	cfgPath   string
	loader    *loader.Loader
	mu        sync.Mutex
	blocklist *wafmaps.PrefixSet
	allowlist *wafmaps.PrefixSet
	pubTCP    *wafmaps.PortSet
	pubUDP    *wafmaps.PortSet
	privTCP   *wafmaps.PortSet
	privUDP   *wafmaps.PortSet
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	log.Printf("waf-edge starting node=%s region=%s iface=%s xdp_mode=%s bypass=%v",
		cfg.Node.ID, cfg.Node.Region, cfg.Interface.Name, cfg.Interface.XDPMode, cfg.Runtime.EmergencyBypass)

	iface, err := cfg.ResolveInterface()
	if err != nil {
		return fmt.Errorf("lookup iface %s: %w", cfg.Interface.Name, err)
	}

	ld := loader.New(cfg.Interface.Name)
	if err := ld.Attach(iface.Index, loader.Options{
		PerIPMaxEntries: cfg.Runtime.PerIPTableSize,
		XDPMode:         cfg.Interface.XDPMode,
		EmergencyBypass: cfg.Runtime.EmergencyBypass,
	}); err != nil {
		return fmt.Errorf("attach xdp: %w", err)
	}
	defer ld.Close()
	if cfg.Runtime.EmergencyBypass {
		log.Printf("emergency bypass ENABLED: eBPF loaded but not attached to %s", cfg.Interface.Name)
	} else {
		log.Printf("xdp attached to %s (ifindex=%d)", cfg.Interface.Name, iface.Index)
	}

	a := &agent{cfg: cfg, cfgPath: cfgPath, loader: ld}
	if err := a.openMaps(); err != nil {
		return err
	}
	if err := a.applyFilter(cfg); err != nil {
		return fmt.Errorf("apply filter: %w", err)
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
	log.Printf("stats writing to %s (watch -n 1 cat %s)",
		cfg.Observability.StatsFile, cfg.Observability.StatsFile)

	// SIGHUP → reload
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := a.reload(); err != nil {
				log.Printf("reload failed (keeping previous config): %v", err)
				continue
			}
			log.Printf("reload ok")
		}
	}()

	<-ctx.Done()
	signal.Stop(hup)
	close(hup)
	log.Printf("shutting down")
	<-done
	return nil
}

// openMaps grabs handles once; wrappers hold onto them for the lifetime of
// the agent so reload is a pure Sync diff without reopening.
func (a *agent) openMaps() error {
	get := func(name string, fn func() (*wafmaps.PrefixSet, error)) (*wafmaps.PrefixSet, error) {
		return fn()
	}
	_ = get // placeholder — below uses named locals for clarity

	blMap, err := a.loader.BlocklistMap()
	if err != nil {
		return fmt.Errorf("blocklist map: %w", err)
	}
	alMap, err := a.loader.AllowlistMap()
	if err != nil {
		return fmt.Errorf("allowlist map: %w", err)
	}
	ptcp, err := a.loader.PublicTCPMap()
	if err != nil {
		return fmt.Errorf("public tcp map: %w", err)
	}
	pudp, err := a.loader.PublicUDPMap()
	if err != nil {
		return fmt.Errorf("public udp map: %w", err)
	}
	prtcp, err := a.loader.PrivateTCPMap()
	if err != nil {
		return fmt.Errorf("private tcp map: %w", err)
	}
	prudp, err := a.loader.PrivateUDPMap()
	if err != nil {
		return fmt.Errorf("private udp map: %w", err)
	}

	a.blocklist = wafmaps.NewPrefixSet(blMap, "blocklist")
	a.allowlist = wafmaps.NewPrefixSet(alMap, "allowlist")
	a.pubTCP = wafmaps.NewPortSet(ptcp, "public_tcp")
	a.pubUDP = wafmaps.NewPortSet(pudp, "public_udp")
	a.privTCP = wafmaps.NewPortSet(prtcp, "private_tcp")
	a.privUDP = wafmaps.NewPortSet(prudp, "private_udp")
	return nil
}

// applyFilter syncs all six filter maps from the given config in one shot.
// Used both for initial seed and for reload.
func (a *agent) applyFilter(cfg *config.Config) error {
	allowlist, err := config.ParsePrefixes(cfg.Filter.IngressAllowlist)
	if err != nil {
		return err
	}
	blocklist, err := config.ParsePrefixes(cfg.Filter.StaticBlocklist)
	if err != nil {
		return err
	}
	if err := a.allowlist.Sync(allowlist); err != nil {
		return err
	}
	if err := a.blocklist.Sync(blocklist); err != nil {
		return err
	}
	if err := a.pubTCP.Sync(cfg.Filter.Public.TCP); err != nil {
		return err
	}
	if err := a.pubUDP.Sync(cfg.Filter.Public.UDP); err != nil {
		return err
	}
	if err := a.privTCP.Sync(cfg.Filter.Private.TCP); err != nil {
		return err
	}
	if err := a.privUDP.Sync(cfg.Filter.Private.UDP); err != nil {
		return err
	}
	log.Printf("filter applied: public tcp=%v udp=%v  private tcp=%v udp=%v  allowlist=%d  blocklist=%d",
		cfg.Filter.Public.TCP, cfg.Filter.Public.UDP,
		cfg.Filter.Private.TCP, cfg.Filter.Private.UDP,
		len(cfg.Filter.IngressAllowlist), len(cfg.Filter.StaticBlocklist))
	return nil
}

// reload re-reads the config file, validates it, applies filter diffs, and
// toggles emergency bypass if it changed. On any error the previous state
// is preserved.
func (a *agent) reload() error {
	newCfg, err := config.Load(a.cfgPath)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Interface.Name and Runtime.PerIPTableSize cannot hot reload — they
	// require tearing down and recreating the collection. Reject those.
	if newCfg.Interface.Name != a.cfg.Interface.Name {
		return fmt.Errorf("interface.name change requires restart (was %s, now %s)",
			a.cfg.Interface.Name, newCfg.Interface.Name)
	}
	if newCfg.Runtime.PerIPTableSize != a.cfg.Runtime.PerIPTableSize {
		return fmt.Errorf("runtime.perip_table_size change requires restart (was %d, now %d)",
			a.cfg.Runtime.PerIPTableSize, newCfg.Runtime.PerIPTableSize)
	}
	if newCfg.Interface.XDPMode != a.cfg.Interface.XDPMode {
		return fmt.Errorf("interface.xdp_mode change requires restart (was %s, now %s)",
			a.cfg.Interface.XDPMode, newCfg.Interface.XDPMode)
	}

	if err := a.applyFilter(newCfg); err != nil {
		return err
	}

	// Toggle emergency bypass if it changed.
	if newCfg.Runtime.EmergencyBypass != a.cfg.Runtime.EmergencyBypass {
		if err := a.loader.SetBypass(newCfg.Runtime.EmergencyBypass); err != nil {
			return fmt.Errorf("bypass toggle: %w", err)
		}
		if newCfg.Runtime.EmergencyBypass {
			log.Printf("reload: emergency bypass ENABLED (XDP detached)")
		} else {
			log.Printf("reload: emergency bypass DISABLED (XDP re-attached)")
		}
	}

	a.cfg = newCfg
	return nil
}

// openStats wires the two eBPF stat maps into a decoupled reader that
// writes the snapshot file on a fixed cadence.
func openStats(ld *loader.Loader, cfg *config.Config) (*stats.Reader, error) {
	globalMap, err := ld.StatsMap()
	if err != nil {
		return nil, fmt.Errorf("stats map: %w", err)
	}
	peripMap, err := ld.PerIPMap()
	if err != nil {
		return nil, fmt.Errorf("perip map: %w", err)
	}
	return stats.NewReader(globalMap, peripMap, cfg.Node.ID, cfg.Interface.Name, cfg.Observability.StatsFile), nil
}
