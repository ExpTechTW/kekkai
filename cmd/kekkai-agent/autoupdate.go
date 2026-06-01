package main

// Background auto-update poller for the running kekkai-agent.
//
// Policy (all knobs live under `update:` in kekkai.yaml):
//
//   auto_update_download=false → this goroutine exits immediately (no-op).
//   auto_update_download=true  → every auto_update_interval hours, hit the
//                                GitHub Releases API, compare to running
//                                version, and if strictly newer, download
//                                the two binaries to /var/lib/kekkai/staged/
//                                as "staged". Running binaries stay put.
//   auto_update_reload=true    → after a successful stage, delegate to
//                                kekkai.sh `update` in a detached session.
//                                kekkai.sh will install + systemctl restart
//                                us; our current pid gets killed as part
//                                of that restart, so the detached child is
//                                the one that actually drives it.
//
// Failure handling writes a human-readable explanation to
// /var/lib/kekkai/auto_update_error.txt (the "state file"). The MOTD
// script reads that file at SSH login so the next operator sees the
// error without having to dig through journalctl. Successful runs
// unlink the state file so the warning goes away.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/ExpTechTW/kekkai/internal/logx"
	kver "github.com/ExpTechTW/kekkai/internal/version"
)

const (
	autoUpdateStateDir      = "/var/lib/kekkai"
	autoUpdateStagedDir     = "/var/lib/kekkai/staged"
	autoUpdateErrorFile     = "/var/lib/kekkai/auto_update_error.txt"
	autoUpdateLastRunFile   = "/var/lib/kekkai/auto_update_last_run.txt"
	autoUpdateScriptPath    = "/usr/local/bin/kekkai.sh"
	autoUpdateReleasesAPI   = "https://api.github.com/repos/ExpTechTW/kekkai/releases"
	autoUpdateHTTPTimeout   = 10 * time.Second
	autoUpdateStartupDelay  = 30 * time.Second
	autoUpdateUserAgent     = "kekkai-agent/auto-update"
	autoUpdateMaxReleaseLen = 4 << 20 // 4 MiB cap on API JSON just in case
)

// runAutoUpdate is the entry point from main's goroutine fan-out. Returns
// when ctx is cancelled. Never panics — any unexpected failure is logged
// and the next tick retries.
//
// The logger is passed in (not taken from a.log) because the main.go
// goroutine-launching site already knows it wants the "update" module
// and it's cleaner to make that explicit than have autoupdate.go call
// a.root.With("update") itself.
func (a *agent) runAutoUpdate(ctx context.Context, currentVersion string, log *logx.Logger) {
	cfg := a.cfg.Update
	if cfg.AutoUpdateDownload == nil || !*cfg.AutoUpdateDownload {
		log.Info("auto-update disabled", "reason", "auto_update_download=false")
		return
	}
	interval := time.Duration(cfg.AutoUpdateInterval) * time.Hour
	if interval <= 0 {
		interval = time.Hour
	}

	log.Info("auto-update enabled",
		"interval", interval.String(),
		"channel", cfg.Channel,
		"reload", cfg.AutoUpdateReload)

	// First tick after a short warm-up so the agent's main loop has a
	// chance to fully bring up maps / stats reader before we hammer the
	// network. Subsequent ticks follow the configured interval.
	select {
	case <-ctx.Done():
		return
	case <-time.After(autoUpdateStartupDelay):
	}
	a.tickAutoUpdate(ctx, currentVersion, log)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("auto-update poller stopping", "reason", "context cancelled")
			return
		case <-t.C:
			a.tickAutoUpdate(ctx, currentVersion, log)
		}
	}
}

// tickAutoUpdate runs one poll-and-maybe-apply cycle. Splits the work
// into narrow phases so errors attribute cleanly in the state file.
func (a *agent) tickAutoUpdate(ctx context.Context, currentVersion string, log *logx.Logger) {
	cfg := a.cfg.Update
	if err := os.MkdirAll(autoUpdateStateDir, 0o755); err != nil {
		log.Error("mkdir state dir failed", "path", autoUpdateStateDir, "err", err.Error())
		return
	}

	log.Info("auto-update tick start",
		"running", currentVersion,
		"channel", cfg.Channel)

	cur, curOK := kver.Parse(currentVersion)
	// If the running binary doesn't parse (e.g. dev build), we can't make
	// a safe "newer" decision — bail quietly so we don't accidentally
	// trample a dev build with a release.
	if !curOK {
		log.Warn("auto-update skip — running version not parseable",
			"version", currentVersion)
		writeLastRun("skipped", "running version not parseable: "+currentVersion)
		return
	}

	latestTag, agentURL, cliURL, err := fetchLatestRelease(ctx, cfg.Channel)
	if err != nil {
		a.recordAutoUpdateError("fetch_failed", latestTag, err.Error())
		log.Error("fetch release metadata failed", "channel", cfg.Channel, "err", err.Error())
		return
	}
	log.Info("fetched release metadata", "channel", cfg.Channel, "latest", latestTag)

	latest, latestOK := kver.Parse(latestTag)
	if !latestOK {
		a.recordAutoUpdateError("parse_failed", latestTag,
			"GitHub returned tag "+latestTag+" which does not match the expected YYYY.MM.DD+build.N format")
		log.Error("parse latest tag failed", "tag", latestTag)
		return
	}
	if !kver.IsNewer(latest, cur) {
		// Already up-to-date is the happy path — clear any stale error
		// from a previous failed tick and refresh last-run timestamp.
		_ = os.Remove(autoUpdateErrorFile)
		writeLastRun("up-to-date", latestTag)
		log.Info("auto-update already up-to-date",
			"running", currentVersion,
			"latest", latestTag)
		return
	}

	log.Info("auto-update newer release available",
		"running", currentVersion,
		"latest", latestTag)

	if err := os.MkdirAll(autoUpdateStagedDir, 0o755); err != nil {
		a.recordAutoUpdateError("mkdir_staged", latestTag, err.Error())
		log.Error("mkdir staged dir failed", "path", autoUpdateStagedDir, "err", err.Error())
		return
	}
	// "Only keep the latest" — wipe any prior staged binaries before
	// writing the new pair. Use RemoveAll so we don't accumulate leftover
	// files from previous runs / interrupted downloads.
	if entries, err := os.ReadDir(autoUpdateStagedDir); err == nil {
		for _, e := range entries {
			_ = os.Remove(filepath.Join(autoUpdateStagedDir, e.Name()))
		}
	}

	stagedAgent := filepath.Join(autoUpdateStagedDir, "kekkai-agent")
	stagedCLI := filepath.Join(autoUpdateStagedDir, "kekkai")

	log.Info("downloading agent binary", "url", agentURL, "dst", stagedAgent)
	if err := downloadTo(ctx, agentURL, stagedAgent); err != nil {
		a.recordAutoUpdateError("download_agent", latestTag, err.Error())
		log.Error("download agent failed", "err", err.Error())
		return
	}

	log.Info("downloading cli binary", "url", cliURL, "dst", stagedCLI)
	if err := downloadTo(ctx, cliURL, stagedCLI); err != nil {
		a.recordAutoUpdateError("download_cli", latestTag, err.Error())
		log.Error("download cli failed", "err", err.Error())
		return
	}

	// Write a version marker so kekkai.sh / doctor can identify what's
	// sitting in staged without having to exec the binary.
	_ = os.WriteFile(filepath.Join(autoUpdateStagedDir, "VERSION"),
		[]byte(latestTag+"\n"), 0o644)

	log.Info("auto-update staged", "tag", latestTag, "dir", autoUpdateStagedDir)

	if !cfg.AutoUpdateReload {
		// Download-only mode. Record the staged version so operators
		// can see it via `kekkai doctor` and decide when to apply.
		writeLastRun("staged", latestTag)
		_ = os.Remove(autoUpdateErrorFile)
		log.Info("auto-update done (download-only)",
			"action", "operator must run `sudo kekkai update` to apply",
			"tag", latestTag)
		return
	}

	// Reload mode: delegate to kekkai.sh. That script already knows how
	// to install + systemctl restart, and it is the single source of
	// truth for update flow. We detach the child so it survives our own
	// process being killed by the restart it is about to trigger.
	log.Info("auto-update launching reload", "tag", latestTag, "script", autoUpdateScriptPath)
	if err := launchDetachedUpdate(latestTag, log); err != nil {
		a.recordAutoUpdateError("launch_update", latestTag, err.Error())
		log.Error("launch detached update failed", "err", err.Error())
		return
	}
	// At this point we've handed off; no further work for this tick.
	// The child will stream its output to systemd-journal via stderr.
	writeLastRun("applying", latestTag)
}

// fetchLatestRelease calls the Releases API, picks the right tag for the
// requested channel, and returns (tag, agent_asset_url, cli_asset_url).
func fetchLatestRelease(ctx context.Context, channel string) (string, string, string, error) {
	url := autoUpdateReleasesAPI + "/latest"
	if channel == "pre-release" {
		url = autoUpdateReleasesAPI + "?per_page=30"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", autoUpdateUserAgent)

	client := &http.Client{Timeout: autoUpdateHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, autoUpdateMaxReleaseLen))
	if err != nil {
		return "", "", "", err
	}

	pick, err := selectReleaseFromJSON(body, channel)
	if err != nil {
		return "", "", "", err
	}
	// Asset matching mirrors kekkai.sh: pick the asset whose name ends
	// with the current GOOS-GOARCH. `kekkai` must not accidentally match
	// `kekkai-agent` — we check that prefix explicitly.
	wantOSArch := runtime.GOOS + "-" + runtime.GOARCH
	var agentURL, cliURL string
	for _, asset := range pick.Assets {
		name := asset.Name
		if !endsWith(name, wantOSArch) {
			continue
		}
		if startsWith(name, "kekkai-agent") {
			agentURL = asset.DownloadURL
		} else if startsWith(name, "kekkai") {
			cliURL = asset.DownloadURL
		}
	}
	if agentURL == "" || cliURL == "" {
		return pick.TagName, "", "", fmt.Errorf("release %s has no %s assets", pick.TagName, wantOSArch)
	}
	return pick.TagName, agentURL, cliURL, nil
}

// releaseAsset / releaseBody mirror the subset of the GitHub Releases API
// that we need. JSON tags spell out the few fields we read.
type releaseAsset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

type releaseBody struct {
	TagName    string         `json:"tag_name"`
	Prerelease bool           `json:"prerelease"`
	Draft      bool           `json:"draft"`
	Assets     []releaseAsset `json:"assets"`
}

// selectReleaseFromJSON returns the relevant release for the given channel.
// - release channel: the /latest endpoint returns a single object.
// - pre-release channel: the list endpoint returns an array; we pick the
//   max-version prerelease (NOT the API's default created_at order,
//   which has been observed to be unstable for republished tags).
func selectReleaseFromJSON(body []byte, channel string) (*releaseBody, error) {
	if channel == "release" {
		var r releaseBody
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("parse /latest: %w", err)
		}
		return &r, nil
	}

	var list []releaseBody
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse release list: %w", err)
	}
	var best *releaseBody
	var bestVer kver.Version
	for i := range list {
		r := &list[i]
		if r.Draft || !r.Prerelease {
			continue
		}
		v, ok := kver.Parse(r.TagName)
		if !ok {
			continue
		}
		if best == nil || kver.Compare(v, bestVer) > 0 {
			best = r
			bestVer = v
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no pre-release found in release list")
	}
	return best, nil
}

// downloadTo pulls url to dst with a streaming copy and chmod +x on
// success. Truncates dst on retry.
func downloadTo(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", autoUpdateUserAgent)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d fetching %s", resp.StatusCode, url)
	}

	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// launchDetachedUpdate forks kekkai.sh update into a new session so that
// when the script restarts kekkai-agent (killing us) the script itself
// keeps running until it completes or errors.
func launchDetachedUpdate(targetVersion string, log *logx.Logger) error {
	if _, err := os.Stat(autoUpdateScriptPath); err != nil {
		return fmt.Errorf("%s not found: %w", autoUpdateScriptPath, err)
	}

	// Pipe child output into a small buffered tail file so the next
	// operator can see what happened even though the parent (us) gets
	// killed mid-run. Best effort — we don't block on failures here.
	logOut, err := os.Create(filepath.Join(autoUpdateStateDir, "auto_update_child.log"))
	if err != nil {
		return err
	}

	cmd := exec.Command("bash", autoUpdateScriptPath, "update")
	cmd.Stdout = logOut
	cmd.Stderr = logOut
	// Setsid puts the child in its own session so signals delivered to
	// our process group (which systemd sends on unit restart) don't
	// reach it. Without this, `systemctl restart kekkai-agent` would
	// kill our child too and nothing would drive the update to completion.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		logOut.Close()
		return err
	}
	// Release the child — we deliberately do NOT Wait(), because we
	// expect to be killed before it finishes.
	go func() {
		_ = cmd.Wait()
		logOut.Close()
	}()
	log.Info("detached update child launched",
		"target", targetVersion,
		"pid", cmd.Process.Pid,
		"log", filepath.Join(autoUpdateStateDir, "auto_update_child.log"))
	return nil
}

// recordAutoUpdateError persists a machine-readable failure summary for
// the MOTD script and `kekkai doctor` to surface. Intentionally only
// takes the agent receiver (not a logger) because callers already log
// via the passed-in *logx.Logger right next to their recordAutoUpdateError
// invocation — this function's sole job is writing the state file.
func (a *agent) recordAutoUpdateError(kind, targetVersion, detail string) {
	_ = os.MkdirAll(autoUpdateStateDir, 0o755)
	body := fmt.Sprintf("timestamp=%s\nkind=%s\ntarget_version=%s\nlast_error=%s\n",
		time.Now().UTC().Format(time.RFC3339), kind, targetVersion, detail)
	// No logger here — any failure on this path cannot be reported
	// through logx without a logger reference. Writing to stderr still
	// reaches journald; it just won't be pretty-formatted.
	if err := os.WriteFile(autoUpdateErrorFile, []byte(body), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "auto-update: write error file: %v\n", err)
	}
	writeLastRun("failed", targetVersion+" ("+kind+")")
}

// writeLastRun drops a short "what happened on the last poll" line into
// a sibling state file. doctor reads this to show status even when
// nothing is broken.
func writeLastRun(state, detail string) {
	line := fmt.Sprintf("timestamp=%s\nstate=%s\ndetail=%s\n",
		time.Now().UTC().Format(time.RFC3339), state, detail)
	_ = os.WriteFile(autoUpdateLastRunFile, []byte(line), 0o644)
}

// Tiny local helpers to avoid pulling in strings just for these two.
// The pattern set is bounded so an inline byte walk is cheaper and
// clearer than strings.HasPrefix for this file's uses.
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

