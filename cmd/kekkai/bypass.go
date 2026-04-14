package main

// `kekkai bypass on|off [--save]` — flip runtime.emergency_bypass on the
// running daemon, optionally persisting through a reload.
//
// - Default (no --save): transient signal via systemctl kill -SIGUSR1/2.
// - With --save: manual backup → rewrite config → cmdReload.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ExpTechTW/kekkai/internal/config"
)

type parsedBypassArgs struct {
	wantBypass bool
	save       bool
	cfgPath    string
}

func cmdBypass(args []string) int {
	p, err := parseBypassArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(err.Error()))
		return 2
	}
	if p.save {
		return cmdBypassSave(p.wantBypass, p.cfgPath)
	}
	return cmdBypassTemporary(p.wantBypass)
}

func parseBypassArgs(args []string) (parsedBypassArgs, error) {
	if len(args) < 1 {
		return parsedBypassArgs{}, fmt.Errorf(bypassUsage)
	}
	p := parsedBypassArgs{cfgPath: defaultConfigPath}
	switch args[0] {
	case "on":
		p.wantBypass = true
	case "off":
		p.wantBypass = false
	default:
		return parsedBypassArgs{}, fmt.Errorf(bypassUsage)
	}
	for _, a := range args[1:] {
		switch a {
		case "--save":
			p.save = true
		default:
			if strings.HasPrefix(a, "-") {
				return parsedBypassArgs{}, fmt.Errorf("unknown flag: %s", a)
			}
			p.cfgPath = a
		}
	}
	return p, nil
}

func cmdBypassTemporary(wantBypass bool) int {
	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(os.Stderr, uiErr("systemctl not found: cannot signal kekkai-agent"))
		return 1
	}

	sig := "SIGUSR2"
	action := "disabled"
	if wantBypass {
		sig = "SIGUSR1"
		action = "enabled"
	}
	c := exec.Command("systemctl", "kill", "-s", sig, agentUnit)
	if code := runCommand(c, fmt.Sprintf("systemctl kill -s %s %s", sig, agentUnit)); code != 0 {
		return code
	}

	fmt.Println(uiOK(fmt.Sprintf("temporary bypass %s (not saved)", action)))
	fmt.Fprintln(os.Stderr, uiWarn("temporary bypass state is ephemeral; use --save to persist"))
	return 0
}

func cmdBypassSave(wantBypass bool, cfgPath string) int {
	res, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("config: %v", err)))
		return 1
	}
	cfg := res.Config
	if cfg.Runtime.EmergencyBypass == wantBypass {
		fmt.Println(uiInfo(fmt.Sprintf("config already has runtime.emergency_bypass=%v", wantBypass)))
		return cmdReload([]string{cfgPath})
	}

	if backupPath, err := config.BackupFile(cfgPath, config.BackupKindManual); err == nil {
		fmt.Println(uiOK(fmt.Sprintf("backup written: %s", backupPath)))
	} else {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("backup failed: %v", err)))
		return 1
	}

	cfg.Runtime.EmergencyBypass = wantBypass
	b, err := config.Marshal(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("marshal: %v", err)))
		return 1
	}
	if err := writeFileAtomic(cfgPath, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, uiErr(fmt.Sprintf("write config: %v", err)))
		return 1
	}
	if code := cmdReload([]string{cfgPath}); code != 0 {
		return code
	}

	fmt.Println(uiOK(fmt.Sprintf("persisted runtime.emergency_bypass=%v in %s", wantBypass, cfgPath)))
	return 0
}
