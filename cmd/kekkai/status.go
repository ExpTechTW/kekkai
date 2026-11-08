package main

// Read-only commands that surface daemon / installation state:
// status (live TUI), doctor (health report), version (build info).

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ExpTechTW/kekkai/internal/config"
	"github.com/ExpTechTW/kekkai/internal/doctor"
	"github.com/ExpTechTW/kekkai/internal/tui"
)

// cmdStatus launches the TUI. It reads the running agent's config to
// find the interface name so the eBPF pinned map paths line up.
func cmdStatus(args []string) int {
	cfgPath := firstArgOrDefault(args, defaultConfigPath)

	res, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("config: %v", err)))
		return 1
	}
	cfg := res.Config

	src, err := tui.NewSource(cfg.Interface.Name)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("open eBPF maps: %v", err)))
		return 1
	}
	defer src.Close()

	// `ip link` is a process spawn. The banner still tracks attach state,
	// but not on every 1s frame.
	var poll bypassPoll
	model := tui.NewModel(
		src,
		cfg.Node.ID,
		cfg.Interface.Name,
		cfg.Interface.XDPMode,
		version,
		cfg.Update.Channel,
		readAgentActiveSince(),
		func() bool { return poll.bypassed(cfg) },
	)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("tui: %v", err)))
		return 1
	}
	return 0
}

// cmdDoctor runs every health check and prints a coloured report.
// Exit code 0 = healthy or warnings only, 1 = at least one error.
func cmdDoctor() int {
	r := doctor.Run()
	r.Render(os.Stdout, stdoutIsTerminal())
	return r.ExitCode()
}

func cmdVersion() {
	if stdoutIsTerminal() {
		fmt.Println(uiTitleStyle.Render("◈ KEKKAI VERSION"))
		fmt.Printf("%s %s\n", uiKeyStyle.Render("kekkai"), uiInfoStyle.Render(fmt.Sprintf("%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)))
	} else {
		fmt.Printf("kekkai %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	}
	if st, err := os.Stat(agentBinary); err == nil {
		msg := fmt.Sprintf("present at %s (size %d bytes, modified %s)",
			agentBinary, st.Size(), st.ModTime().Format("2006-01-02 15:04:05"))
		if stdoutIsTerminal() {
			fmt.Printf("%s %s\n", uiKeyStyle.Render("kekkai-agent"), uiInfoStyle.Render(msg))
		} else {
			fmt.Printf("kekkai-agent %s\n", msg)
		}
	}
}

// bypassPoll caches the `ip link` probe. Spawning it on every TUI frame
// was a steady source of wakeups; the banner still updates within a few
// seconds, and a persisted emergency_bypass flag is reported immediately.
type bypassPoll struct {
	mu      sync.Mutex
	checked time.Time
	on      bool
}

func (p *bypassPoll) bypassed(cfg *config.Config) bool {
	if cfg.Runtime.EmergencyBypass {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.checked.IsZero() && time.Since(p.checked) < 5*time.Second {
		return p.on
	}
	p.checked = time.Now()
	attached, ok := doctor.XDPAttached(cfg.Interface.Name)
	p.on = ok && !attached
	return p.on
}

// readAgentActiveSince returns when the agent unit last became active, so the
// TUI shows the agent's uptime rather than the status session's. Returns zero
// time when it can't be determined; the TUI then falls back to session time.
//
// systemd exposes ActiveEnterTimestamp (a human string) and
// ActiveEnterTimestampMonotonic (microseconds since boot). There is no
// realtime "...USec" property — querying it returns empty, and uptime then
// silently falls back to session time. The monotonic value plus /proc/uptime
// gives how long the agent has been up, anchored to wall-clock now.
func readAgentActiveSince() time.Time {
	out, err := exec.Command(
		"systemctl",
		"show",
		"--property=ActiveEnterTimestampMonotonic",
		"--value",
		agentUnit+".service",
	).Output()
	if err != nil {
		return time.Time{}
	}
	startUsec, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || startUsec <= 0 {
		return time.Time{}
	}
	bootElapsed, err := readProcUptime()
	if err != nil {
		return time.Time{}
	}
	agentUp := bootElapsed - time.Duration(startUsec)*time.Microsecond
	if agentUp < 0 {
		agentUp = 0
	}
	return time.Now().Add(-agentUp)
}

// readProcUptime returns seconds-since-boot (the first field of /proc/uptime)
// as a Duration.
func readProcUptime() (time.Duration, error) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	return parseProcUptime(string(b))
}

// parseProcUptime parses the first whitespace-delimited float of /proc/uptime
// content into a Duration. Pure so it can be unit-tested.
func parseProcUptime(content string) (time.Duration, error) {
	fields := strings.Fields(content)
	if len(fields) == 0 {
		return 0, fmt.Errorf("empty /proc/uptime")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(secs * float64(time.Second)), nil
}
