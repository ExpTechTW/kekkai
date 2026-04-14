package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/ExpTechTW/kekkai/internal/config"
)

// Paths the agent uses. Kept in one place so any future rename is a
// single-point edit.
const (
	agentBinaryPath = "/usr/local/bin/kekkai-agent"
	cliBinaryPath   = "/usr/local/bin/kekkai"
	rollbackPath    = "/usr/local/bin/kekkai-agent.prev"
	defaultCfgPath  = "/etc/kekkai/kekkai.yaml"
	systemdUnit     = "kekkai-agent.service"
	systemdUnitPath = "/etc/systemd/system/kekkai-agent.service"
	bpffsPinRoot    = "/sys/fs/bpf/kekkai"
	defaultStatsDir = "/var/run/kekkai"
)

// Run executes the full check battery and returns the Runner for
// rendering. Error checks never panic — each Check swallows its own
// failures and reports them as a StatusError result.
func Run() *Runner {
	r := New()

	checkBinaries(r)
	cfg := checkConfig(r)
	checkSystemd(r)
	checkKernel(r)
	checkNetwork(r, cfg)
	checkPermissions(r)
	checkRuntime(r, cfg)

	return r
}

// ---------- binaries ------------------------------------------------------

func checkBinaries(r *Runner) {
	sec := r.Section("binaries")

	sec.Add(binaryResult("kekkai-agent (daemon)", agentBinaryPath))
	sec.Add(binaryResult("kekkai (CLI)", cliBinaryPath))

	if _, err := os.Stat(rollbackPath); err == nil {
		sec.Add(Result{
			Status: StatusOK,
			Title:  "rollback snapshot",
			Detail: fmt.Sprintf("%s present", rollbackPath),
		})
	}
}

func binaryResult(title, path string) Result {
	st, err := os.Stat(path)
	if err != nil {
		return Result{
			Status:      StatusError,
			Title:       title,
			Detail:      "missing at " + path,
			Suggestions: []string{"run: bash ./kekkai.sh install"},
		}
	}
	sum, _ := sha256File(path)
	detail := fmt.Sprintf("%s · %s", humanSize(st.Size()), st.ModTime().Format("2006-01-02 15:04"))
	if sum != "" {
		detail += " · sha " + sum[:12]
	}
	return Result{Status: StatusOK, Title: title, Detail: detail}
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------- config -------------------------------------------------------

// checkConfig returns the loaded config (or nil) so downstream sections
// can cross-reference it.
func checkConfig(r *Runner) *config.Config {
	sec := r.Section("config")

	if _, err := os.Stat(defaultCfgPath); err != nil {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "config file",
			Detail:      "missing at " + defaultCfgPath,
			Suggestions: []string{"run: sudo kekkai reset"},
		})
		return nil
	}
	sec.Add(Result{
		Status: StatusOK,
		Title:  "config file",
		Detail: defaultCfgPath,
	})

	res, err := config.LoadReadOnly(defaultCfgPath)
	if err != nil {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "validation",
			Detail:      err.Error(),
			Suggestions: []string{"run: kekkai check (for details)"},
		})
		return nil
	}
	cfg := res.Config

	if res.Migrated {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "schema version",
			Detail: fmt.Sprintf("v%d on disk, will migrate to v%d on next daemon start", res.FromVersion, config.CurrentVersion),
			Suggestions: []string{
				"sudo systemctl restart kekkai-agent  (to apply migration)",
			},
		})
	} else {
		sec.Add(Result{
			Status: StatusOK,
			Title:  "schema version",
			Detail: fmt.Sprintf("v%d (current)", cfg.Version),
		})
	}

	// Validation passed in LoadReadOnly already, so we just surface a "ok".
	sec.Add(Result{
		Status: StatusOK,
		Title:  "validation",
		Detail: "schema ok, ports unique, CIDRs parse",
	})

	// Security sanity checks.
	hasSSHPrivate := false
	for _, p := range cfg.Filter.Private.TCP {
		if p == 22 {
			hasSSHPrivate = true
			break
		}
	}
	hasSSHPublic := false
	for _, p := range cfg.Filter.Public.TCP {
		if p == 22 {
			hasSSHPublic = true
			break
		}
	}

	switch {
	case hasSSHPublic:
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "SSH exposure",
			Detail: "port 22 in filter.public.tcp — accessible from anywhere",
			Suggestions: []string{
				"consider moving 22 to filter.private.tcp and setting an allowlist",
			},
		})
	case hasSSHPrivate && len(cfg.Filter.IngressAllowlist) == 0:
		sec.Add(Result{
			Status:      StatusError,
			Title:       "SSH allowlist",
			Detail:      "private.tcp contains 22 but ingress_allowlist is empty",
			Suggestions: []string{"add your management network to filter.ingress_allowlist"},
		})
	case hasSSHPrivate:
		sec.Add(Result{
			Status: StatusOK,
			Title:  "SSH allowlist",
			Detail: fmt.Sprintf("%d allowlist entries gate port 22", len(cfg.Filter.IngressAllowlist)),
		})
	}

	// Interface existence — only on Linux.
	if runtime.GOOS == "linux" && cfg.Interface.Name != "" {
		if _, err := net.InterfaceByName(cfg.Interface.Name); err != nil {
			sec.Add(Result{
				Status:      StatusError,
				Title:       "interface",
				Detail:      fmt.Sprintf("%s: %v", cfg.Interface.Name, err),
				Suggestions: []string{"check: ip -br link", "update interface.name in config"},
			})
		} else {
			sec.Add(Result{
				Status: StatusOK,
				Title:  "interface",
				Detail: fmt.Sprintf("%s (xdp_mode=%s)", cfg.Interface.Name, cfg.Interface.XDPMode),
			})
		}
	}

	return cfg
}

// ---------- systemd ------------------------------------------------------

func checkSystemd(r *Runner) {
	sec := r.Section("systemd")

	if _, err := exec.LookPath("systemctl"); err != nil {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "systemctl",
			Detail: "not available on this host",
		})
		return
	}

	if _, err := os.Stat(systemdUnitPath); err != nil {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "unit file",
			Detail:      "missing at " + systemdUnitPath,
			Suggestions: []string{"run: bash ./kekkai.sh repair"},
		})
		return
	}
	sec.Add(Result{
		Status: StatusOK,
		Title:  "unit file",
		Detail: systemdUnitPath,
	})

	if systemctlIs("is-enabled", systemdUnit) {
		sec.Add(Result{Status: StatusOK, Title: "enabled at boot", Detail: "yes"})
	} else {
		sec.Add(Result{
			Status:      StatusWarn,
			Title:       "enabled at boot",
			Detail:      "no",
			Suggestions: []string{"sudo systemctl enable kekkai-agent"},
		})
	}

	if systemctlIs("is-active", systemdUnit) {
		// Uptime via show --property=ActiveEnterTimestamp
		since := systemctlShow(systemdUnit, "ActiveEnterTimestamp")
		detail := "running"
		if since != "" {
			detail += " · since " + since
		}
		sec.Add(Result{Status: StatusOK, Title: "runtime", Detail: detail})
	} else {
		state := systemctlShow(systemdUnit, "ActiveState")
		sec.Add(Result{
			Status: StatusError,
			Title:  "runtime",
			Detail: "inactive (" + state + ")",
			Suggestions: []string{
				"sudo systemctl restart kekkai-agent",
				"journalctl -u kekkai-agent -n 50 --no-pager",
			},
		})
	}
}

func systemctlIs(subcmd, unit string) bool {
	cmd := exec.Command("systemctl", subcmd, "--quiet", unit)
	return cmd.Run() == nil
}

func systemctlShow(unit, prop string) string {
	out, err := exec.Command("systemctl", "show", "--property="+prop, "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------- kernel / bpf -------------------------------------------------

func checkKernel(r *Runner) {
	sec := r.Section("kernel / ebpf")

	if runtime.GOOS != "linux" {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "os",
			Detail: runtime.GOOS + " — kekkai only runs on linux",
		})
		return
	}

	// Kernel version.
	if data, err := os.ReadFile("/proc/version"); err == nil {
		line := strings.TrimSpace(string(data))
		// Full line is verbose; keep first 70 chars.
		if len(line) > 70 {
			line = line[:70] + "…"
		}
		sec.Add(Result{Status: StatusOK, Title: "kernel version", Detail: line})
	}

	// BTF.
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		sec.Add(Result{Status: StatusOK, Title: "BTF", Detail: "/sys/kernel/btf/vmlinux present"})
	} else {
		sec.Add(Result{
			Status: StatusOK, // kekkai doesn't need BTF — informational only
			Title:  "BTF",
			Detail: "not available (OK — kekkai doesn't need CO-RE)",
		})
	}

	// bpffs mount.
	if mounts, err := os.ReadFile("/proc/mounts"); err == nil {
		if strings.Contains(string(mounts), " bpf ") || strings.Contains(string(mounts), " type bpf ") {
			sec.Add(Result{Status: StatusOK, Title: "bpffs", Detail: "mounted at /sys/fs/bpf"})
		} else {
			sec.Add(Result{
				Status:      StatusError,
				Title:       "bpffs",
				Detail:      "not mounted",
				Suggestions: []string{"sudo mount -t bpf bpf /sys/fs/bpf"},
			})
		}
	}

	// Pinned maps.
	if entries, err := os.ReadDir(bpffsPinRoot); err == nil {
		sec.Add(Result{
			Status: StatusOK,
			Title:  "pinned maps",
			Detail: fmt.Sprintf("%d entries in %s", len(entries), bpffsPinRoot),
		})
	} else {
		sec.Add(Result{
			Status:      StatusWarn,
			Title:       "pinned maps",
			Detail:      bpffsPinRoot + " missing — is the agent running?",
			Suggestions: []string{"sudo systemctl start kekkai-agent"},
		})
	}
}

// ---------- network ------------------------------------------------------

func checkNetwork(r *Runner, cfg *config.Config) {
	if runtime.GOOS != "linux" || cfg == nil {
		return
	}
	sec := r.Section("network")

	iface := cfg.Interface.Name

	// Driver.
	if driver := ethtoolDriver(iface); driver != "" {
		if nativeCapable(driver) {
			sec.Add(Result{
				Status: StatusOK,
				Title:  "NIC driver",
				Detail: driver + " (supports native XDP)",
			})
		} else {
			sec.Add(Result{
				Status: StatusWarn,
				Title:  "NIC driver",
				Detail: driver + " — native XDP not supported, using generic mode",
			})
		}
	}

	// XDP attachment.
	if xdpAttached(iface) {
		sec.Add(Result{Status: StatusOK, Title: "XDP attachment", Detail: "program attached to " + iface})
	} else {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "XDP attachment",
			Detail: "no XDP program detected on " + iface,
			Suggestions: []string{
				"if the daemon is running, this may just be generic mode and ip link doesn't expose it",
				"check: journalctl -u kekkai-agent -n 30",
			},
		})
	}

	// tx sysfs counters.
	txBytes := sysfsTxPath(iface, "tx_bytes")
	if _, err := os.Stat(txBytes); err == nil {
		sec.Add(Result{Status: StatusOK, Title: "sysfs counters", Detail: "tx_bytes readable"})
	} else {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "sysfs counters",
			Detail: "tx_bytes missing for " + iface,
		})
	}
}

func ethtoolDriver(iface string) string {
	out, err := exec.Command("ethtool", "-i", iface).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "driver:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "driver:"))
		}
	}
	return ""
}

func nativeCapable(driver string) bool {
	native := map[string]bool{
		"ixgbe":     true,
		"i40e":      true,
		"ice":       true,
		"mlx5_core": true,
		"ena":       true,
		"bnxt_en":   true,
		"virtio_net": false, // technically has native, but varies
	}
	return native[driver]
}

func xdpAttached(iface string) bool {
	out, err := exec.Command("ip", "-o", "link", "show", "dev", iface).Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "xdp")
}

func sysfsTxPath(iface, metric string) string {
	return filepath.Join("/sys/class/net", iface, "statistics", metric)
}

// ---------- permissions --------------------------------------------------

// checkPermissions verifies the bits that still vary when doctor is already
// running as root: bpffs mount, agent-pinned maps, and whether the pinned
// stats map is actually openable via bpf_obj_get. Non-root / setcap / sysctl
// checks were dropped when the CLI became sudo-only — doctor is gated by
// requireRoot() in cmd/kekkai, so euid is always 0 here.
func checkPermissions(r *Runner) {
	sec := r.Section("permissions")

	if _, err := os.Stat("/sys/fs/bpf"); err == nil {
		sec.Add(Result{Status: StatusOK, Title: "/sys/fs/bpf", Detail: "mounted"})
	} else {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "/sys/fs/bpf",
			Detail:      err.Error(),
			Suggestions: []string{"sudo mount -t bpf bpf /sys/fs/bpf"},
		})
	}

	if _, err := os.Stat(bpffsPinRoot); err == nil {
		sec.Add(Result{
			Status: StatusOK,
			Title:  "pin root",
			Detail: bpffsPinRoot + " present",
		})
	} else {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "pin root",
			Detail:      err.Error(),
			Suggestions: []string{"is the agent running? sudo systemctl start kekkai-agent"},
		})
		return
	}

	// Informational: passwordless sudo drop-in. Doesn't affect the running
	// doctor process (it already has root) — we surface it so the operator
	// knows whether their *next* `sudo kekkai ...` will prompt for a password.
	if entries, err := filepath.Glob("/etc/sudoers.d/kekkai-cli-*"); err == nil && len(entries) > 0 {
		sec.Add(Result{
			Status: StatusOK,
			Title:  "sudo NOPASSWD",
			Detail: filepath.Base(entries[0]),
		})
	} else {
		sec.Add(Result{
			Status: StatusWarn,
			Title:  "sudo NOPASSWD",
			Detail: "no kekkai sudoers drop-in — sudo will prompt for password",
			Suggestions: []string{
				"bash ./kekkai.sh repair",
			},
		})
	}

	// Load-bearing check: actually open the pinned stats map via bpf_obj_get.
	// If this fails with EACCES even as root, the kernel's BPF LSM or
	// unprivileged_bpf_disabled is in an unusual state worth investigating.
	statsPin := filepath.Join(bpffsPinRoot, "stats")
	if _, err := os.Stat(statsPin); err != nil {
		sec.Add(Result{
			Status:      StatusError,
			Title:       "pinned stats map",
			Detail:      "missing at " + statsPin,
			Suggestions: []string{"sudo systemctl restart kekkai-agent"},
		})
		return
	}
	m, err := ebpf.LoadPinnedMap(statsPin, nil)
	if err != nil {
		sec.Add(Result{
			Status: StatusError,
			Title:  "pinned stats map open",
			Detail: err.Error(),
			Suggestions: []string{
				"sudo systemctl status kekkai-agent",
				"sudo journalctl -u kekkai-agent -n 50",
			},
		})
		return
	}
	_ = m.Close()
	sec.Add(Result{
		Status: StatusOK,
		Title:  "pinned stats map",
		Detail: "openable",
	})
}

func statusFor(ok bool) Status {
	if ok {
		return StatusOK
	}
	return StatusWarn
}

// ---------- runtime ------------------------------------------------------

func checkRuntime(r *Runner, cfg *config.Config) {
	sec := r.Section("runtime")

	statsFile := defaultStatsDir + "/stats.txt"
	if cfg != nil && cfg.Observability.StatsFile != "" {
		statsFile = cfg.Observability.StatsFile
	}
	st, err := os.Stat(statsFile)
	if err != nil {
		sec.Add(Result{
			Status:      StatusWarn,
			Title:       "stats file",
			Detail:      "missing at " + statsFile,
			Suggestions: []string{"is the agent running? sudo systemctl start kekkai-agent"},
		})
		return
	}

	age := time.Since(st.ModTime())
	ageStr := fmtAge(age)
	status := StatusOK
	if age > 5*time.Second {
		status = StatusWarn
	}
	if age > 30*time.Second {
		status = StatusError
	}
	sec.Add(Result{
		Status: status,
		Title:  "stats file",
		Detail: fmt.Sprintf("%s · updated %s ago", statsFile, ageStr),
	})

	// Lightweight peek at stats content — look for dropped counts.
	if data, err := os.ReadFile(statsFile); err == nil && len(data) > 0 {
		drops := extractStat(string(data), "packets dropped :")
		if drops != "" {
			sec.Add(Result{
				Status: StatusOK,
				Title:  "packets dropped",
				Detail: drops,
			})
		}
	}
}

func fmtAge(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

// extractStat does a dumb line search for a stats.txt row like
// "  packets dropped :         1,234" and returns the trimmed value.
func extractStat(body, label string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, label) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// Suppress unused-import warnings when building on non-linux (where
// some helpers above are referenced but never executed).
var _ = strconv.Itoa
