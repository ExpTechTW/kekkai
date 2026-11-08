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
	"strings"
	"sync"
	"syscall"

	"github.com/ExpTechTW/kekkai/internal/buildinfo"
	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/loader"
	"github.com/ExpTechTW/kekkai/internal/logx"
	kmaps "github.com/ExpTechTW/kekkai/internal/maps"
	"github.com/ExpTechTW/kekkai/internal/stats"
)

// version is injected at build time via -ldflags:
//
//	-X main.version=YYYY.MM.DD+build.N
//
// Keep default empty so linker override works reliably.
var version string

func main() {
	if version == "" {
		version = buildinfo.DefaultVersion
	}

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
	if err := config.ValidateInterfaceName(iface); err != nil {
		fmt.Fprintf(os.Stderr, "reset: %v\n", err)
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

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
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
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// Iface Destination Gateway Flags ...
		// Destination == 00000000 means default route.
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// agent bundles all the subsystems main() wires together so reload can
// touch each map through a single handle.
//
// log is the module-scoped ("main") logger; subsystems like autoupdate
// make their own children via log.With("update"). Sharing the root
// logger across goroutines is safe — logx serialises writes internally.
type agent struct {
	cfg          *config.Config
	cfgPath      string
	mcfgPath     string
	loader       *loader.Loader
	log          *logx.Logger
	root         *logx.Logger // kept separately so Close() at shutdown stops rotation
	mu           sync.Mutex
	blocklist    *kmaps.PrefixSet
	allowlist    *kmaps.PrefixSet
	ports        *kmaps.PortTable
	runtime      *kmaps.RuntimeCfg
	egressWarned bool
}

func run(cfgPath, managedCfgPath string) error {
	// Build the root logger FIRST so every subsequent event — including
	// config load failures — goes through the same stream that journald
	// and the rotated file are already capturing. If file rotation
	// cannot be set up (disk full, permission), logx.New() degrades to
	// stderr-only rather than erroring out.
	root := logx.New()
	mainLog := root.With("main")
	mainLog.Info("agent starting", "pid", os.Getpid(), "version", version)

	res, source, err := loadStartupConfig(cfgPath, managedCfgPath)
	if err != nil {
		mainLog.Error("config load failed", "path", cfgPath, "err", err.Error())
		_ = root.Close()
		return fmt.Errorf("config: %w", err)
	}
	cfg := res.Config
	mainLog.Info("config loaded", "source", source, "path", cfgPath)

	if res.Migrated {
		mainLog.Info("config migrated",
			"from_version", res.FromVersion,
			"to_version", config.CurrentVersion,
			"backup", res.BackupPath)
	}
	warnIfSSHPublic(cfg, mainLog)

	mainLog.Info("kekkai-agent config summary",
		"node", cfg.Node.ID,
		"region", cfg.Node.Region,
		"iface", cfg.Interface.Name,
		"xdp_mode", cfg.Interface.XDPMode,
		"bypass", cfg.Runtime.EmergencyBypass)

	iface, err := cfg.ResolveInterface()
	if err != nil {
		mainLog.Error("resolve iface", "iface", cfg.Interface.Name, "err", err.Error())
		_ = root.Close()
		return fmt.Errorf("lookup iface %s: %w", cfg.Interface.Name, err)
	}

	loaderLog := root.With("loader")
	ld := loader.New(cfg.Interface.Name)
	// Load maps with nothing attached, fill them, then attach. That closes
	// the window where XDP would run against empty maps.
	if err := ld.Attach(iface.Index, loader.Options{
		PerIPMaxEntries: cfg.Runtime.PerIPTableSize,
		XDPMode:         cfg.Interface.XDPMode,
		EmergencyBypass: true,
	}); err != nil {
		loaderLog.Error("xdp attach failed", "iface", cfg.Interface.Name, "err", err.Error())
		_ = root.Close()
		return fmt.Errorf("attach xdp: %w", err)
	}
	defer ld.Close()

	a := &agent{
		cfg:      cfg,
		cfgPath:  cfgPath,
		mcfgPath: managedCfgPath,
		loader:   ld,
		log:      root.With("reload"),
		root:     root,
	}
	defer func() { _ = root.Close() }()

	mapsLog := root.With("maps")
	if err := a.openMaps(); err != nil {
		mapsLog.Error("open maps failed", "err", err.Error())
		return err
	}
	mapsLog.Info("maps opened")

	if err := a.applyFilter(cfg); err != nil {
		mapsLog.Error("apply filter failed", "err", err.Error())
		return fmt.Errorf("apply filter: %w", err)
	}
	if cfg.Runtime.EmergencyBypass {
		loaderLog.Warn("emergency bypass enabled — eBPF loaded but not attached",
			"iface", cfg.Interface.Name)
	} else {
		if err := ld.SetBypass(false); err != nil {
			loaderLog.Error("xdp attach failed", "iface", cfg.Interface.Name, "err", err.Error())
			return fmt.Errorf("attach xdp: %w", err)
		}
		// applyFilter ran while the TC link was down, so EGRESS_SEED was clear.
		if err := a.syncRuntimeFlags(cfg); err != nil {
			loaderLog.Error("runtime flags after attach failed", "err", err.Error())
			return fmt.Errorf("runtime flags: %w", err)
		}
		a.warnEgressDegraded()
		loaderLog.Info("xdp attached",
			"iface", cfg.Interface.Name,
			"ifindex", iface.Index,
			"mode", cfg.Interface.XDPMode,
			"egress", ld.EgressActive())
	}
	mapsLog.Info("initial filter applied",
		"public_tcp", len(cfg.Filter.Public.TCP),
		"public_udp", len(cfg.Filter.Public.UDP),
		"private_tcp", len(cfg.Filter.Private.TCP),
		"private_udp", len(cfg.Filter.Private.UDP),
		"allowlist", len(cfg.Filter.IngressAllowlist),
		"blocklist", len(cfg.Filter.StaticBlocklist))

	if err := persistManagedConfig(managedCfgPath, cfg); err != nil {
		mainLog.Warn("managed config persist failed", "path", managedCfgPath, "err", err.Error())
	} else {
		mainLog.Info("managed config updated", "path", managedCfgPath)
	}

	statsLog := root.With("stats")
	reader, err := openStats(ld, cfg)
	if err != nil {
		statsLog.Error("stats reader init failed", "err", err.Error())
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		statsLog.Info("stats reader started", "file", cfg.Observability.StatsFile)
		if err := reader.Run(ctx.Done()); err != nil {
			statsLog.Error("stats reader exited with error", "err", err.Error())
		} else {
			statsLog.Info("stats reader stopped")
		}
	}()

	// SIGHUP → reload
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			a.log.Info("signal received", "signal", "SIGHUP", "action", "reload")
			if err := a.reload(); err != nil {
				a.log.Error("reload failed (keeping previous config)", "err", err.Error())
				continue
			}
			a.log.Info("reload ok")
		}
	}()

	// SIGUSR1/SIGUSR2 → temporary bypass toggle (not persisted to config).
	bypassLog := root.With("bypass")
	bypassSig := make(chan os.Signal, 1)
	signal.Notify(bypassSig, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range bypassSig {
			switch sig {
			case syscall.SIGUSR1:
				bypassLog.Info("signal received", "signal", "SIGUSR1", "action", "bypass_on")
				if err := a.setBypassRuntime(true, "signal"); err != nil {
					bypassLog.Error("temporary bypass enable failed", "err", err.Error())
				}
			case syscall.SIGUSR2:
				bypassLog.Info("signal received", "signal", "SIGUSR2", "action", "bypass_off")
				if err := a.setBypassRuntime(false, "signal"); err != nil {
					bypassLog.Error("temporary bypass disable failed", "err", err.Error())
				}
			}
		}
	}()

	// Background release poller. No-op when auto_update_download=false.
	go a.runAutoUpdate(ctx, version, root.With("update"))

	<-ctx.Done()
	mainLog.Info("shutdown signal received", "action", "stopping goroutines")
	signal.Stop(hup)
	close(hup)
	signal.Stop(bypassSig)
	close(bypassSig)
	mainLog.Info("waiting for stats reader to drain")
	<-done
	mainLog.Info("agent shutdown complete")
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
	ports, err := a.loader.PortsMap()
	if err != nil {
		return fmt.Errorf("ports map: %w", err)
	}
	rcfg, err := a.loader.RuntimeCfgMap()
	if err != nil {
		return fmt.Errorf("runtime cfg map: %w", err)
	}

	a.blocklist = kmaps.NewPrefixSet(blMap, "blocklist")
	a.allowlist = kmaps.NewPrefixSet(alMap, "allowlist")
	a.ports = kmaps.NewPortTable(ports, "ports")
	a.runtime = kmaps.NewRuntimeCfg(rcfg)
	return nil
}

// applyFilter syncs allowlist, blocklist, ports, and runtime flags.
// Prefixes are parsed and normalised before any map is touched, so a bad
// string leaves the running filter as it was.
func (a *agent) applyFilter(cfg *config.Config) error {
	allowlist, err := config.ParsePrefixes(cfg.Filter.IngressAllowlist)
	if err != nil {
		return err
	}
	blocklist, err := config.ParsePrefixes(cfg.Filter.StaticBlocklist)
	if err != nil {
		return err
	}
	// Effective*TCP fold in the implicit SSH port (22) per
	// security.allow_ssh_public. The port is applied to the running filter
	// only — it is never written back to the config file.
	pubTCP := cfg.EffectivePublicTCP()
	privTCP := cfg.EffectivePrivateTCP()
	pubUDP := cfg.Filter.Public.UDP
	privUDP := cfg.Filter.Private.UDP
	flags := runtimeFlags(cfg, a.loader.EgressActive())

	if err := a.allowlist.Sync(allowlist); err != nil {
		return err
	}
	if err := a.blocklist.Sync(blocklist); err != nil {
		return err
	}
	if err := a.ports.Sync(pubTCP, pubUDP, privTCP, privUDP); err != nil {
		return err
	}
	if err := a.runtime.Sync(flags); err != nil {
		return err
	}
	a.log.Info("filter applied",
		"public_tcp", fmt.Sprintf("%v", pubTCP),
		"public_udp", fmt.Sprintf("%v", pubUDP),
		"private_tcp", fmt.Sprintf("%v", privTCP),
		"private_udp", fmt.Sprintf("%v", privUDP),
		"allowlist", len(cfg.Filter.IngressAllowlist),
		"blocklist", len(cfg.Filter.StaticBlocklist))
	a.logRuntimeFlags(flags)
	return nil
}

// runtimeFlags is the runtime_cfg word: ICMP and ARP come from cfg, and
// EGRESS_SEED is set only while the TC egress program is attached.
func runtimeFlags(cfg *config.Config, egressActive bool) uint32 {
	var flags uint32
	if cfg.Filter.AllowICMP != nil && *cfg.Filter.AllowICMP {
		flags |= kmaps.RuntimeFlagAllowICMP
	}
	if cfg.Filter.AllowARP != nil && *cfg.Filter.AllowARP {
		flags |= kmaps.RuntimeFlagAllowARP
	}
	if egressActive {
		flags |= kmaps.RuntimeFlagEgressSeed
	}
	return flags
}

func (a *agent) syncRuntimeFlags(cfg *config.Config) error {
	flags := runtimeFlags(cfg, a.loader.EgressActive())
	if err := a.runtime.Sync(flags); err != nil {
		return err
	}
	a.logRuntimeFlags(flags)
	return nil
}

func (a *agent) logRuntimeFlags(flags uint32) {
	a.log.Info("runtime policy applied",
		"allow_icmp", flags&kmaps.RuntimeFlagAllowICMP != 0,
		"allow_arp", flags&kmaps.RuntimeFlagAllowARP != 0,
		"egress_seed", flags&kmaps.RuntimeFlagEgressSeed != 0)
}

// warnEgressDegraded logs once per process when XDP is attached and the TC
// egress program is not. DHCP replies stay open and UDP return traffic is
// not seeded until egress is available.
func (a *agent) warnEgressDegraded() {
	if a.egressWarned || a.cfg.Runtime.EmergencyBypass || a.loader.EgressActive() {
		return
	}
	a.egressWarned = true
	a.root.With("loader").Warn("XDP is attached but TC egress is not; DHCP and UDP return traffic are degraded")
}

// rollbackFilter re-applies the previous config after a partial update.
// Both the original error and a failed rollback are logged.
func (a *agent) rollbackFilter(cause error) {
	if rerr := a.applyFilter(a.cfg); rerr != nil {
		a.log.Error("apply failed and previous config could not be restored",
			"err", cause.Error(),
			"rollback_err", rerr.Error())
		return
	}
	a.log.Error("apply failed; previous config restored", "err", cause.Error())
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

	// Emit a field-by-field diff of the running vs new config so the
	// operator sees exactly what changed during this reload. Done
	// before the backup/apply steps so the log ordering tells a story:
	// "we saw these changes → backed up old → applied new".
	diffs := config.DiffConfigs(a.cfg, newCfg)
	for _, line := range diffs {
		a.log.Info("config diff", "change", line)
	}
	if len(diffs) == 0 {
		a.log.Info("config reload noop — no struct changes")
	}

	// Auto-backup if the struct actually changed. Safe to run even on
	// failure below — the backup is of the previous good state.
	if backupPath, bErr := config.AutoBackupIfChanged(a.cfgPath, a.cfg, newCfg); bErr != nil {
		a.log.Warn("auto-backup failed", "err", bErr.Error())
	} else if backupPath != "" {
		a.log.Info("auto-backup written", "path", backupPath)
	}

	warnIfSSHPublic(newCfg, a.log)

	if err := a.applyFilter(newCfg); err != nil {
		a.rollbackFilter(err)
		return err
	}

	if newCfg.Runtime.EmergencyBypass != a.cfg.Runtime.EmergencyBypass {
		if err := a.loader.SetBypass(newCfg.Runtime.EmergencyBypass); err != nil {
			a.rollbackFilter(err)
			return fmt.Errorf("bypass toggle: %w", err)
		}
		// The link state changed after applyFilter computed EGRESS_SEED.
		if err := a.syncRuntimeFlags(newCfg); err != nil {
			if berr := a.loader.SetBypass(a.cfg.Runtime.EmergencyBypass); berr != nil {
				a.log.Error("runtime flag sync failed and bypass rollback failed",
					"err", err.Error(),
					"rollback_err", berr.Error())
			}
			a.rollbackFilter(err)
			return fmt.Errorf("runtime flags: %w", err)
		}
		if newCfg.Runtime.EmergencyBypass {
			a.log.Warn("emergency bypass enabled via reload", "xdp", "detached")
		} else {
			a.log.Info("emergency bypass disabled via reload", "xdp", "reattached",
				"egress", a.loader.EgressActive())
		}
	}

	a.cfg = newCfg
	a.warnEgressDegraded()
	if err := persistManagedConfig(a.mcfgPath, newCfg); err != nil {
		a.log.Warn("managed config persist failed", "path", a.mcfgPath, "err", err.Error())
	} else {
		a.log.Info("managed config updated", "path", a.mcfgPath)
	}
	return nil
}

// setBypassRuntime toggles emergency bypass in-memory only. It intentionally
// does not write user config or managed config, so the state is ephemeral.
func (a *agent) setBypassRuntime(bypass bool, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cfg.Runtime.EmergencyBypass == bypass {
		a.log.Info("temporary bypass unchanged", "bypass", bypass, "reason", reason)
		return nil
	}
	if err := a.loader.SetBypass(bypass); err != nil {
		return fmt.Errorf("bypass toggle: %w", err)
	}
	prev := a.cfg.Runtime.EmergencyBypass
	a.cfg.Runtime.EmergencyBypass = bypass
	if err := a.syncRuntimeFlags(a.cfg); err != nil {
		a.cfg.Runtime.EmergencyBypass = prev
		if berr := a.loader.SetBypass(prev); berr != nil {
			a.log.Error("runtime flag sync failed and bypass rollback failed",
				"err", err.Error(),
				"rollback_err", berr.Error())
		} else if ferr := a.syncRuntimeFlags(a.cfg); ferr != nil {
			a.log.Error("runtime flag sync failed and flag rollback failed",
				"err", err.Error(),
				"rollback_err", ferr.Error())
		}
		return fmt.Errorf("runtime flags: %w", err)
	}
	a.warnEgressDegraded()
	if bypass {
		a.log.Warn("temporary bypass enabled", "reason", reason, "persisted", false)
	} else {
		a.log.Info("temporary bypass disabled", "reason", reason, "persisted", false,
			"egress", a.loader.EgressActive())
	}
	return nil
}

func loadStartupConfig(cfgPath, managedCfgPath string) (*config.LoadResult, string, error) {
	if st, err := os.Stat(managedCfgPath); err == nil && !st.IsDir() {
		res, mErr := config.Load(managedCfgPath)
		if mErr == nil {
			return res, "managed (" + managedCfgPath + ")", nil
		}
		// No logger here — loadStartupConfig runs before the logger is
		// built. Stderr is journald-visible so this still lands in
		// `journalctl -u kekkai-agent`.
		fmt.Fprintf(os.Stderr, "managed config invalid (%s): %v\n", managedCfgPath, mErr)
		fmt.Fprintf(os.Stderr, "falling back to user config: %s\n", cfgPath)
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

// warnIfSSHPublic shouts into the log whenever SSH is exposed to the public
// internet. SSH-is-public is fully determined by security.allow_ssh_public
// (Validate enforces that 22 can't sit in the contradicting group), so the
// flag alone is the trigger. WARN level so it lands in the MOTD-reachable
// slice of journal output.
func warnIfSSHPublic(cfg *config.Config, l *logx.Logger) {
	if cfg.SSHIsPublic() {
		l.Warn("SECURITY: SSH (port 22) is reachable from any source",
			"security.allow_ssh_public", true)
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
