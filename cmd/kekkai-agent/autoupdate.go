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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

	rel, err := fetchLatestRelease(ctx, cfg.Channel)
	if err != nil {
		a.recordAutoUpdateError("fetch_failed", rel.Tag, err.Error())
		log.Error("fetch release metadata failed", "channel", cfg.Channel, "err", err.Error())
		return
	}
	latestTag := rel.Tag
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

	for _, raw := range []string{rel.AgentURL, rel.CLIURL, rel.SumsURL} {
		if err := validateDownloadURL(raw); err != nil {
			a.recordAutoUpdateError("download_url", latestTag, err.Error())
			log.Error("refusing download url", "err", err.Error())
			return
		}
	}

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
	agentPart := stagedAgent + ".part"
	cliPart := stagedCLI + ".part"
	sumsPart := filepath.Join(autoUpdateStagedDir, "SHA256SUMS")

	discard := func() {
		removePaths(agentPart, cliPart, sumsPart, stagedAgent, stagedCLI)
	}

	log.Info("downloading SHA256SUMS", "url", rel.SumsURL)
	if err := downloadPart(ctx, rel.SumsURL, sumsPart, 0o640); err != nil {
		discard()
		a.recordAutoUpdateError("download_sums", latestTag, err.Error())
		log.Error("download SHA256SUMS failed", "err", err.Error())
		return
	}

	log.Info("downloading agent binary", "url", rel.AgentURL, "dst", stagedAgent)
	if err := downloadPart(ctx, rel.AgentURL, agentPart, 0o755); err != nil {
		discard()
		a.recordAutoUpdateError("download_agent", latestTag, err.Error())
		log.Error("download agent failed", "err", err.Error())
		return
	}

	log.Info("downloading cli binary", "url", rel.CLIURL, "dst", stagedCLI)
	if err := downloadPart(ctx, rel.CLIURL, cliPart, 0o755); err != nil {
		discard()
		a.recordAutoUpdateError("download_cli", latestTag, err.Error())
		log.Error("download cli failed", "err", err.Error())
		return
	}

	// Verify before the final rename. A missing entry or a mismatch
	// discards the partial download and leaves the running binaries alone.
	if err := verifySHA256File(agentPart, rel.AgentName, sumsPart); err != nil {
		discard()
		a.recordAutoUpdateError("checksum", latestTag, err.Error())
		log.Error("agent checksum failed", "err", err.Error())
		return
	}
	if err := verifySHA256File(cliPart, rel.CLIName, sumsPart); err != nil {
		discard()
		a.recordAutoUpdateError("checksum", latestTag, err.Error())
		log.Error("cli checksum failed", "err", err.Error())
		return
	}
	if err := os.Rename(agentPart, stagedAgent); err != nil {
		discard()
		a.recordAutoUpdateError("stage_rename", latestTag, err.Error())
		log.Error("rename staged agent failed", "err", err.Error())
		return
	}
	if err := os.Rename(cliPart, stagedCLI); err != nil {
		discard()
		a.recordAutoUpdateError("stage_rename", latestTag, err.Error())
		log.Error("rename staged cli failed", "err", err.Error())
		return
	}
	_ = os.Remove(sumsPart)

	// Write a version marker so kekkai.sh / doctor can identify what's
	// sitting in staged without having to exec the binary.
	_ = os.WriteFile(filepath.Join(autoUpdateStagedDir, "VERSION"),
		[]byte(latestTag+"\n"), 0o640)

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

// fetchedRelease is the subset of a GitHub release the stager needs.
// SumsURL points at the SHA256SUMS asset for the same release as the
// binaries. AgentName and CLIName are the names listed in that file.
type fetchedRelease struct {
	Tag       string
	AgentURL  string
	AgentName string
	CLIURL    string
	CLIName   string
	SumsURL   string
}

// fetchLatestRelease calls the Releases API and picks the right tag for
// the requested channel, plus the platform binaries and SHA256SUMS.
func fetchLatestRelease(ctx context.Context, channel string) (fetchedRelease, error) {
	url := autoUpdateReleasesAPI + "/latest"
	if channel == "pre-release" {
		url = autoUpdateReleasesAPI + "?per_page=30"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetchedRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", autoUpdateUserAgent)

	client := &http.Client{Timeout: autoUpdateHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fetchedRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fetchedRelease{}, fmt.Errorf("http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, autoUpdateMaxReleaseLen))
	if err != nil {
		return fetchedRelease{}, err
	}

	pick, err := selectReleaseFromJSON(body, channel)
	if err != nil {
		return fetchedRelease{}, err
	}
	// Asset matching mirrors kekkai.sh: pick the asset whose name ends
	// with the current GOOS-GOARCH. `kekkai` must not accidentally match
	// `kekkai-agent` — we check that prefix explicitly.
	wantOSArch := runtime.GOOS + "-" + runtime.GOARCH
	out := fetchedRelease{Tag: pick.TagName}
	for _, asset := range pick.Assets {
		name := asset.Name
		if name == "SHA256SUMS" && asset.DownloadURL != "" {
			out.SumsURL = asset.DownloadURL
			continue
		}
		if !strings.HasSuffix(name, wantOSArch) {
			continue
		}
		// kekkai-agent is checked before kekkai. The shorter prefix also
		// matches the agent asset, so the order is the match.
		if strings.HasPrefix(name, "kekkai-agent") {
			out.AgentURL = asset.DownloadURL
			out.AgentName = name
		} else if strings.HasPrefix(name, "kekkai") {
			out.CLIURL = asset.DownloadURL
			out.CLIName = name
		}
	}
	if out.AgentURL == "" || out.CLIURL == "" {
		return out, fmt.Errorf("release %s has no %s assets", pick.TagName, wantOSArch)
	}
	if out.SumsURL == "" {
		return out, fmt.Errorf("release %s is missing SHA256SUMS", pick.TagName)
	}
	return out, nil
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
//   - release channel: the /latest endpoint returns a single object.
//   - pre-release channel: the list endpoint returns an array; we pick the
//     max-version prerelease (NOT the API's default created_at order,
//     which has been observed to be unstable for republished tags).
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

// downloadPart pulls url to dst. The caller renames dst into place only
// after SHA256SUMS matches. mode is 0755 for binaries and 0640 for the
// checksum file and other metadata.
func downloadPart(ctx context.Context, rawURL, dst string, mode os.FileMode) error {
	if err := validateDownloadURL(rawURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", autoUpdateUserAgent)

	resp, err := newAssetClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d fetching %s", resp.StatusCode, rawURL)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

// validateDownloadURL allows only the GitHub hosts that actually serve
// release assets. Every redirect hop is checked the same way.
func validateDownloadURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid download url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing download url %q: https required", raw)
	}
	switch strings.ToLower(u.Hostname()) {
	case "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com":
		return nil
	default:
		return fmt.Errorf("refusing download url host %q", u.Hostname())
	}
}

func newAssetClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return validateDownloadURL(req.URL.String())
		},
	}
}

// verifySHA256File checks path against the sha256sum-format entry for
// assetName. A missing line or a mismatched digest is an error.
func verifySHA256File(path, assetName, sumsPath string) error {
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if len(bytes.TrimSpace(sums)) == 0 {
		return fmt.Errorf("SHA256SUMS is empty; refusing to stage unverified files")
	}
	expect, ok := lookupSHA256(sums, assetName)
	if !ok {
		return fmt.Errorf("SHA256SUMS has no entry for %s", assetName)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expect) {
		return fmt.Errorf("checksum mismatch for %s", assetName)
	}
	return nil
}

// lookupSHA256 finds name in a sha256sum file. Lines are "<hex><whitespace><filename>"
// or "<hex> *<filename>" (text mode).
func lookupSHA256(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields[0]) != 64 {
			continue
		}
		fn := strings.TrimPrefix(fields[1], "*")
		if fn == name {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

func removePaths(paths ...string) {
	for _, p := range paths {
		if p == "" {
			continue
		}
		_ = os.Remove(p)
	}
}

// launchDetachedUpdate starts `kekkai.sh update`, which replaces the
// binaries and restarts kekkai-agent (killing us), so it must outlive us.
//
// The preferred path asks pid 1 for a transient unit via systemd-run. A
// child of ours cannot do the job: it inherits this unit's sandbox
// (ProtectSystem=strict leaves /usr/local/bin and /etc/systemd read-only)
// and its cgroup, which `systemctl restart` kills wholesale regardless of
// Setsid. The direct child below is only a fallback for hosts without
// systemd-run.
func launchDetachedUpdate(targetVersion string, log *logx.Logger) error {
	if _, err := os.Stat(autoUpdateScriptPath); err != nil {
		return fmt.Errorf("%s not found: %w", autoUpdateScriptPath, err)
	}
	childLog := filepath.Join(autoUpdateStateDir, "auto_update_child.log")

	if sr, err := exec.LookPath("systemd-run"); err == nil {
		unit := fmt.Sprintf("kekkai-update-%d", time.Now().Unix())
		out, err := exec.Command(sr,
			"--unit="+unit, "--collect", "--no-block",
			"--service-type=oneshot",
			"--property=StandardOutput=append:"+childLog,
			"--property=StandardError=append:"+childLog,
			"/bin/bash", autoUpdateScriptPath, "update",
		).CombinedOutput()
		if err == nil {
			log.Info("update unit started", "target", targetVersion, "unit", unit, "log", childLog)
			return nil
		}
		log.Warn("systemd-run failed; falling back to a direct child",
			"err", err.Error(), "output", strings.TrimSpace(string(out)))
	}

	// Pipe child output into a small buffered tail file so the next
	// operator can see what happened even though the parent (us) gets
	// killed mid-run. Best effort — we don't block on failures here.
	logOut, err := os.OpenFile(childLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
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
		"log", childLog)
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
	if err := os.WriteFile(autoUpdateErrorFile, []byte(body), 0o640); err != nil {
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
	_ = os.WriteFile(autoUpdateLastRunFile, []byte(line), 0o640)
}
