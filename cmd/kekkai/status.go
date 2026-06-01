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

	model := tui.NewModel(
		src,
		cfg.Node.ID,
		cfg.Interface.Name,
		cfg.Interface.XDPMode,
		version,
		cfg.Update.Channel,
		readAgentActiveSince(),
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
	// Also print kekkai-agent's version if available.
	if _, err := exec.LookPath(agentBinary); err == nil {
		// kekkai-agent doesn't have a -version flag yet; just note its
		// presence and file metadata. We ignore the -check invocation's
		// output here — it's purely a liveness probe against /dev/null.
		_, _ = exec.Command(agentBinary, "-check", "/dev/null").CombinedOutput()
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
}

// readAgentActiveSince tries to read systemd's active-enter timestamp for the
// running agent unit. Returns zero time when systemctl is unavailable or when
// the property can't be parsed.
func readAgentActiveSince() time.Time {
	out, err := exec.Command(
		"systemctl",
		"show",
		"--property=ActiveEnterTimestampUSec",
		"--value",
		agentUnit,
	).Output()
	if err != nil {
		return time.Time{}
	}
	usec, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || usec <= 0 {
		return time.Time{}
	}
	return time.Unix(0, usec*int64(time.Microsecond))
}
