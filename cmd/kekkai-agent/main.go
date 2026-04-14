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
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/loader"
	kmaps "github.com/ExpTechTW/kekkai/internal/maps"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

func main() {
	cfgPath := flag.String("config", "/etc/kekkai/kekkai.yaml", "path to edge config")
	managedCfgPath := flag.String("managed-config", "", "path to agent-managed last-known-good config (default: <config>.agent.yaml)")
	check := flag.Bool("check", false, "validate config and exit (non-zero on error)")
	show := flag.Bool("show", false, "print the normalised config after migration and exit")
	backup := flag.Bool("backup", false, "write a timestamped manual backup of -config and exit")
	reset := flag.Bool("reset", false, "overwrite -config with a fresh default template (backs up any existing file)")
	resetIface := flag.String("iface", "", "network interface for -reset (auto-detected if empty)")
	flag.Parse()

	// Mutually exclusive run modes.
	modeCount := 0
	for _, b := range []bool{*check, *show, *backup, *reset} {
		if b {
			modeCount++
		}
	}
	if modeCount > 1 {
		fmt.Fprintln(os.Stderr, "-check, -show, -backup, and -reset are mutually exclusive")
		os.Exit(2)
	}

	switch {
	case *check:
		os.Exit(runCheck(*cfgPath))
	case *show:
		os.Exit(runShow(*cfgPath))
	case *backup:
		os.Exit(runBackup(*cfgPath))
	case *reset:
		os.Exit(runReset(*cfgPath, *resetIface))
	}

	if err := run(*cfgPath, resolveManagedConfigPath(*cfgPath, *managedCfgPath)); err != nil {
		log.Fatalf("kekkai-agent: %v", err)
	}
}

func resolveManagedConfigPath(cfgPath, managed string) string {
	if managed != "" {
		return managed
	}
	return cfgPath + ".agent.yaml"
}

// runCheck validates a config file without touching the filesystem.
// Uses LoadReadOnly so a v1→v2 migration is simulated in memory and the
// on-disk file is never rewritten — non-root users can check safely.
func runCheck(path string) int {
	res, err := config.LoadReadOnly(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	if res.Migrated {
		fmt.Printf("would migrate v%d → v%d on daemon start\n",
			res.FromVersion, config.CurrentVersion)
	}
	for _, line := range res.NormalizeLog {
		fmt.Printf("normalize: %s\n", line)
	}
	fmt.Println("config ok")
	return 0
}

// runShow prints the fully normalised config (post-migrate, post-default,
// post-normalize) to stdout. Read-only — never writes the filesystem.
func runShow(path string) int {
	res, err := config.LoadReadOnly(path)
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

// runReset writes a fresh default config template to path. Any existing
// file is first copied to <path>.backup.<ts> (manual backup kind) so the
// user can always roll back. Requires root to write under /etc/kekkai.
//
// If iface is empty we try to auto-detect the default-route interface so
// the template is immediately useful; callers can still override with
// -iface at the command line.
func runReset(path, iface string) int {
	if iface == "" {
		iface = detectDefaultIface()
	}
	if iface == "" {
		fmt.Fprintln(os.Stderr, "reset: could not auto-detect interface; pass -iface <name>")
		return 1
	}

	// Backup existing file (if any) before overwriting.
	if _, err := os.Stat(path); err == nil {
		dst, err := config.BackupFile(path, config.BackupKindManual)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reset: failed to back up existing config: %v\n", err)
			return 1
		}
		fmt.Printf("existing config backed up: %s\n", dst)
	}

	if err := os.MkdirAll(filepathDir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "reset: mkdir: %v\n", err)
		return 1
	}

	hostname, _ := os.Hostname()
	values := config.DefaultValues()
	values.NodeID = hostname
	if values.NodeID == "" {
		values.NodeID = "edge-01"
	}
	values.InterfaceName = iface
	rendered := config.Render(values)
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "reset: write: %v\n", err)
		return 1
	}
	fmt.Printf("default config written: %s\n", path)
	fmt.Printf("iface=%s — review filter.ingress_allowlist before starting the agent\n", iface)
	return 0
}

// detectDefaultIface reads /proc/net/route and returns the interface the
// default route uses, or "" on failure.
func detectDefaultIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range splitLines(string(data)) {
		fields := splitFields(line)
		// Iface Destination Gateway Flags ...
		// Destination == 00000000 means default route.
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// filepathDir is a trivial split to avoid importing path/filepath for
// one call. Kept local so the rest of this file can stay small.
func filepathDir(p string) string {
	i := len(p) - 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return p[:i]
}

func splitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitFields(s string) []string {
	out := []string{}
	start := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		space := c == ' ' || c == '\t'
		if space {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// agent bundles all the subsystems main() wires together so reload can
// touch each map through a single handle.
type agent struct {
	cfg       *config.Config
	cfgPath   string
	mcfgPath  string
	loader    *loader.Loader
	mu        sync.Mutex
	blocklist *kmaps.PrefixSet
	allowlist *kmaps.PrefixSet
	pubTCP    *kmaps.PortSet
	pubUDP    *kmaps.PortSet
	privTCP   *kmaps.PortSet
	privUDP   *kmaps.PortSet
	runtime   *kmaps.RuntimeCfg
}

func run(cfgPath, managedCfgPath string) error {
	res, source, err := loadStartupConfig(cfgPath, managedCfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	cfg := res.Config
	log.Printf("config source: %s", source)

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

	a := &agent{cfg: cfg, cfgPath: cfgPath, mcfgPath: managedCfgPath, loader: ld}
	if err := a.openMaps(); err != nil {
		return err
	}
	if err := a.applyFilter(cfg); err != nil {
		return fmt.Errorf("apply filter: %w", err)
	}
	if err := persistManagedConfig(managedCfgPath, cfg); err != nil {
		log.Printf("managed config persist warning: %v", err)
	} else {
		log.Printf("managed config updated: %s", managedCfgPath)
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

	// SIGUSR1/SIGUSR2 → temporary bypass toggle (not persisted to config).
	bypassSig := make(chan os.Signal, 1)
	signal.Notify(bypassSig, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range bypassSig {
			switch sig {
			case syscall.SIGUSR1:
				if err := a.setBypassRuntime(true, "signal"); err != nil {
					log.Printf("temporary bypass enable failed: %v", err)
				}
			case syscall.SIGUSR2:
				if err := a.setBypassRuntime(false, "signal"); err != nil {
					log.Printf("temporary bypass disable failed: %v", err)
				}
			}
		}
	}()

	<-ctx.Done()
	signal.Stop(hup)
	close(hup)
	signal.Stop(bypassSig)
	close(bypassSig)
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
	rcfg, err := a.loader.RuntimeCfgMap()
	if err != nil {
		return fmt.Errorf("runtime cfg map: %w", err)
	}

	a.blocklist = kmaps.NewPrefixSet(blMap, "blocklist")
	a.allowlist = kmaps.NewPrefixSet(alMap, "allowlist")
	a.pubTCP = kmaps.NewPortSet(ptcp, "public_tcp")
	a.pubUDP = kmaps.NewPortSet(pudp, "public_udp")
	a.privTCP = kmaps.NewPortSet(prtcp, "private_tcp")
	a.privUDP = kmaps.NewPortSet(prudp, "private_udp")
	a.runtime = kmaps.NewRuntimeCfg(rcfg)
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
	flags := uint32(0)
	if cfg.Filter.AllowICMP != nil && *cfg.Filter.AllowICMP {
		flags |= kmaps.RuntimeFlagAllowICMP
	}
	if cfg.Filter.AllowARP != nil && *cfg.Filter.AllowARP {
		flags |= kmaps.RuntimeFlagAllowARP
	}
	if err := a.runtime.Sync(kmaps.RuntimeCfgValue{
		Initialized:     1,
		Flags:           flags,
		UDPEphemeralMin: cfg.Filter.UDPEphemeralMin,
	}); err != nil {
		return err
	}
	log.Printf("filter applied: public tcp=%v udp=%v  private tcp=%v udp=%v  allowlist=%d  blocklist=%d",
		cfg.Filter.Public.TCP, cfg.Filter.Public.UDP,
		cfg.Filter.Private.TCP, cfg.Filter.Private.UDP,
		len(cfg.Filter.IngressAllowlist), len(cfg.Filter.StaticBlocklist))
	log.Printf("runtime policy: allow_icmp=%v allow_arp=%v udp_ephemeral_min=%d",
		cfg.Filter.AllowICMP != nil && *cfg.Filter.AllowICMP,
		cfg.Filter.AllowARP != nil && *cfg.Filter.AllowARP,
		cfg.Filter.UDPEphemeralMin)
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
	if err := persistManagedConfig(a.mcfgPath, newCfg); err != nil {
		log.Printf("managed config persist warning: %v", err)
	} else {
		log.Printf("managed config updated: %s", a.mcfgPath)
	}
	return nil
}

// setBypassRuntime toggles emergency bypass in-memory only. It intentionally
// does not write user config or managed config, so the state is ephemeral.
func (a *agent) setBypassRuntime(bypass bool, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cfg.Runtime.EmergencyBypass == bypass {
		log.Printf("temporary bypass unchanged: bypass=%v reason=%s", bypass, reason)
		return nil
	}
	if err := a.loader.SetBypass(bypass); err != nil {
		return fmt.Errorf("bypass toggle: %w", err)
	}
	a.cfg.Runtime.EmergencyBypass = bypass
	if bypass {
		log.Printf("temporary bypass ENABLED (reason=%s, not persisted)", reason)
	} else {
		log.Printf("temporary bypass DISABLED (reason=%s, not persisted)", reason)
	}
	return nil
}

func loadStartupConfig(cfgPath, managedCfgPath string) (*config.LoadResult, string, error) {
	if st, err := os.Stat(managedCfgPath); err == nil && !st.IsDir() {
		res, mErr := config.Load(managedCfgPath)
		if mErr == nil {
			return res, "managed (" + managedCfgPath + ")", nil
		}
		log.Printf("managed config invalid (%s): %v", managedCfgPath, mErr)
		log.Printf("falling back to user config: %s", cfgPath)
	}

	res, err := config.Load(cfgPath)
	if err != nil {
		return nil, "", err
	}
	return res, "user (" + cfgPath + ")", nil
}

func persistManagedConfig(path string, cfg *config.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := config.Marshal(cfg)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
