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
//   -X main.version=YYYY.MM.DD+build.N
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
	cfg       *config.Config
	cfgPath   string
	mcfgPath  string
	loader    *loader.Loader
	log       *logx.Logger
	root      *logx.Logger // kept separately so Close() at shutdown stops rotation
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
	for _, line := range res.NormalizeLog {
		mainLog.Info("config normalize", "change", line)
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
	if err := ld.Attach(iface.Index, loader.Options{
		PerIPMaxEntries: cfg.Runtime.PerIPTableSize,
		XDPMode:         cfg.Interface.XDPMode,
		EmergencyBypass: cfg.Runtime.EmergencyBypass,
	}); err != nil {
		loaderLog.Error("xdp attach failed", "iface", cfg.Interface.Name, "err", err.Error())
		_ = root.Close()
		return fmt.Errorf("attach xdp: %w", err)
	}
	defer ld.Close()
	if cfg.Runtime.EmergencyBypass {
		loaderLog.Warn("emergency bypass enabled — eBPF loaded but not attached",
			"iface", cfg.Interface.Name)
	} else {
		loaderLog.Info("xdp attached",
			"iface", cfg.Interface.Name,
			"ifindex", iface.Index,
			"mode", cfg.Interface.XDPMode)
	}

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
	a.log.Info("filter applied",
		"public_tcp", fmt.Sprintf("%v", cfg.Filter.Public.TCP),
		"public_udp", fmt.Sprintf("%v", cfg.Filter.Public.UDP),
		"private_tcp", fmt.Sprintf("%v", cfg.Filter.Private.TCP),
		"private_udp", fmt.Sprintf("%v", cfg.Filter.Private.UDP),
		"allowlist", len(cfg.Filter.IngressAllowlist),
		"blocklist", len(cfg.Filter.StaticBlocklist))
	a.log.Info("runtime policy applied",
		"allow_icmp", cfg.Filter.AllowICMP != nil && *cfg.Filter.AllowICMP,
		"allow_arp", cfg.Filter.AllowARP != nil && *cfg.Filter.AllowARP,
		"udp_ephemeral_min", cfg.Filter.UDPEphemeralMin)
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

	for _, line := range res.NormalizeLog {
		a.log.Info("config normalize", "change", line)
	}
	warnIfSSHPublic(newCfg, a.log)

	if err := a.applyFilter(newCfg); err != nil {
		return err
	}

	if newCfg.Runtime.EmergencyBypass != a.cfg.Runtime.EmergencyBypass {
		if err := a.loader.SetBypass(newCfg.Runtime.EmergencyBypass); err != nil {
			return fmt.Errorf("bypass toggle: %w", err)
		}
		if newCfg.Runtime.EmergencyBypass {
			a.log.Warn("emergency bypass enabled via reload", "xdp", "detached")
		} else {
			a.log.Info("emergency bypass disabled via reload", "xdp", "reattached")
		}
	}

	a.cfg = newCfg
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
	a.cfg.Runtime.EmergencyBypass = bypass
	if bypass {
		a.log.Warn("temporary bypass enabled", "reason", reason, "persisted", false)
	} else {
		a.log.Info("temporary bypass disabled", "reason", reason, "persisted", false)
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

// warnIfSSHPublic shouts into the log whenever SSH is intentionally
// exposed via security.allow_ssh_public. WARN level so it lands in the
// MOTD-reachable slice of journal output.
func warnIfSSHPublic(cfg *config.Config, l *logx.Logger) {
	if !cfg.Security.AllowSSHPublic {
		return
	}
	for _, p := range cfg.Filter.Public.TCP {
		if p == config.SSHPort {
			l.Warn("SECURITY: SSH (port 22) is in filter.public.tcp",
				"security.allow_ssh_public", true)
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
