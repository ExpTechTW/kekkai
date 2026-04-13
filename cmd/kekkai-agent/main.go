// Command kekkai-agent is the edge agent binary.
//
// Responsibilities:
//   - Load XDP program, install maps, attach to configured interface
//     (or stay in emergency bypass).
//   - Seed maps from config (ports, allowlist, blocklist).
//   - Run stats reader which publishes /var/run/kekkai/stats.txt.
//   - Reload config on SIGHUP; validate first, apply as a diff to maps,
//     auto-backup the previous config if it differed.
//   - Offer offline CLI modes: -check, -show, -backup.
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

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/loader"
	kmaps "github.com/ExpTechTW/kekkai/internal/maps"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

func main() {
	cfgPath := flag.String("config", "/etc/kekkai/kekkai.yaml", "path to edge config")
	check := flag.Bool("check", false, "validate config and exit (non-zero on error)")
	show := flag.Bool("show", false, "print the normalised config after migration and exit")
	backup := flag.Bool("backup", false, "write a timestamped manual backup of -config and exit")
	flag.Parse()

	// Mutually exclusive run modes.
	modeCount := 0
	for _, b := range []bool{*check, *show, *backup} {
		if b {
			modeCount++
		}
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "-check, -show, and -backup are mutually exclusive")
		os.Exit(2)
	}

	switch {
	case *check:
		os.Exit(runCheck(*cfgPath))
	case *show:
		os.Exit(runShow(*cfgPath))
	case *backup:
		os.Exit(runBackup(*cfgPath))
	}

	if err := run(*cfgPath); err != nil {
		log.Fatalf("kekkai-agent: %v", err)
	}
}

// runCheck validates a config file without attaching anything.
func runCheck(path string) int {
	res, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	if res.Migrated {
		fmt.Printf("migrated v%d → v%d (backup: %s)\n",
			res.FromVersion, config.CurrentVersion, res.BackupPath)
	}
	for _, line := range res.NormalizeLog {
		fmt.Printf("normalize: %s\n", line)
	}
	fmt.Println("config ok")
	return 0
}

// runShow prints the fully normalised config (post-migrate, post-default,
// post-normalize) to stdout. Useful for "what is the agent actually seeing".
func runShow(path string) int {
	res, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	out, err := config.Marshal(res.Config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		return 1
	}
	if _, err := os.Stdout.Write(out); err != nil {
		return 1
	}
	return 0
}

// runBackup writes a manual timestamped backup of the config file.
func runBackup(path string) int {
	dst, err := config.BackupFile(path, config.BackupKindManual)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup failed: %v\n", err)
		return 1
	}
	fmt.Printf("backup written: %s\n", dst)
	return 0
}

// agent bundles all the subsystems main() wires together so reload can
// touch each map through a single handle.
type agent struct {
	cfg       *config.Config
	cfgPath   string
	loader    *loader.Loader
	mu        sync.Mutex
	blocklist *kmaps.PrefixSet
	allowlist *kmaps.PrefixSet
	pubTCP    *kmaps.PortSet
	pubUDP    *kmaps.PortSet
	privTCP   *kmaps.PortSet
	privUDP   *kmaps.PortSet
}

func run(cfgPath string) error {
	res, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg := res.Config

	if res.Migrated {
		log.Printf("config migrated v%d → v%d (backup: %s)",
			res.FromVersion, config.CurrentVersion, res.BackupPath)
	}
	for _, line := range res.NormalizeLog {
		log.Printf("normalize: %s", line)
	}
	warnIfSSHPublic(cfg)

	log.Printf("kekkai-agent starting node=%s region=%s iface=%s xdp_mode=%s bypass=%v",
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

	a.blocklist = kmaps.NewPrefixSet(blMap, "blocklist")
	a.allowlist = kmaps.NewPrefixSet(alMap, "allowlist")
	a.pubTCP = kmaps.NewPortSet(ptcp, "public_tcp")
	a.pubUDP = kmaps.NewPortSet(pudp, "public_udp")
	a.privTCP = kmaps.NewPortSet(prtcp, "private_tcp")
	a.privUDP = kmaps.NewPortSet(prudp, "private_udp")
	return nil
}

// applyFilter syncs all six filter maps from the given config in one shot.
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

// reload re-reads the config file, validates it, auto-backs up the
// previous state if the new struct differs, applies filter diffs, and
// toggles emergency bypass if it changed. Any error preserves the
// previous state.
func (a *agent) reload() error {
	res, err := config.Load(a.cfgPath)
	if err != nil {
		return err
	}
	newCfg := res.Config

	a.mu.Lock()
	defer a.mu.Unlock()

	// Reject changes that can't hot-reload before touching anything.
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

	// Auto-backup if the struct actually changed. Safe to run even on
	// failure below — the backup is of the previous good state.
	if backupPath, bErr := config.AutoBackupIfChanged(a.cfgPath, a.cfg, newCfg); bErr != nil {
		log.Printf("auto-backup warning: %v", bErr)
	} else if backupPath != "" {
		log.Printf("auto-backup written: %s", backupPath)
	}

	for _, line := range res.NormalizeLog {
		log.Printf("normalize: %s", line)
	}
	warnIfSSHPublic(newCfg)

	if err := a.applyFilter(newCfg); err != nil {
		return err
	}

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

// warnIfSSHPublic shouts into the log whenever SSH is intentionally
// exposed via security.allow_ssh_public. Three lines so nobody misses it.
func warnIfSSHPublic(cfg *config.Config) {
	if !cfg.Security.AllowSSHPublic {
		return
	}
	for _, p := range cfg.Filter.Public.TCP {
		if p == config.SSHPort {
			log.Printf("=========================================================")
			log.Printf("SECURITY WARNING: SSH (port 22) is in filter.public.tcp")
			log.Printf("=========================================================")
			return
		}
	}
}

// openStats wires the two eBPF stat maps into a decoupled reader.
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
