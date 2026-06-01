package logx

// Daily log-file rotation and 7-day TTL GC for kekkai-agent's
// persistent log at /var/log/kekkai/kekkai-agent.log.
//
// The file layout is:
//
//	kekkai-agent.log              ← the active file (always this name)
//	kekkai-agent-20260414.log     ← yesterday's, renamed at 00:00 UTC
//	kekkai-agent-20260413.log     ← older still
//	...                           ← deleted once mtime > 7 days
//
// Keeping the active file's name stable lets anyone do a trivial
// `tail -F /var/log/kekkai/kekkai-agent.log` and never chase a suffix.
// The rotator goroutine acquires the shared writer mutex during the
// rename/open dance so no log line can leak across file boundaries.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// rotateRetention is how long old daily files are kept. Matches
	// the spec: 7 days, hard-coded. Not a config knob on purpose — an
	// operator noticing a problem should have at least a week of
	// context without having to pre-plan.
	rotateRetention = 7 * 24 * time.Hour

	// Filename glob used for GC. We ONLY touch files matching this
	// pattern so accidentally putting `/etc/passwd` in the log dir
	// cannot cause harm.
	rotateFilenameGlob = "kekkai-agent-*.log"
)

// rotatingFile is an io.Writer that transparently swaps its underlying
// *os.File at 00:00 UTC each day. Multi-writer fan-out is done at a
// layer above — this struct only cares about one file.
type rotatingFile struct {
	dir        string    // /var/log/kekkai
	baseName   string    // kekkai-agent.log
	mu         sync.Mutex
	f          *os.File
	currentDay string    // "20260414", set on Open
	stop       chan struct{}
}

// newRotatingFile opens (or creates) dir/base and starts the rotator
// goroutine. Caller is responsible for Close()ing at shutdown so the
// goroutine exits cleanly.
func newRotatingFile(dir, base string) (*rotatingFile, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir %s: %w", dir, err)
	}
	rf := &rotatingFile{
		dir:      dir,
		baseName: base,
		stop:     make(chan struct{}),
	}
	if err := rf.openCurrent(); err != nil {
		return nil, err
	}
	// GC once at startup — if the box was off for a month this cleans
	// out the dead history before we add today's first line to it.
	rf.gc()
	go rf.runRotator()
	return rf, nil
}

// Write passes through to the active file under the mutex. This is
// what slog.Handler ends up calling on every log line.
func (rf *rotatingFile) Write(p []byte) (int, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.f == nil {
		return 0, os.ErrClosed
	}
	return rf.f.Write(p)
}

// Close shuts the rotator goroutine and closes the active file.
// Idempotent — multiple calls after the first are no-ops.
func (rf *rotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	select {
	case <-rf.stop:
		// already closed
	default:
		close(rf.stop)
	}
	if rf.f == nil {
		return nil
	}
	err := rf.f.Close()
	rf.f = nil
	return err
}

// openCurrent (re)opens dir/base for append. Holds rf.mu during the
// swap so concurrent Write calls are safe.
func (rf *rotatingFile) openCurrent() error {
	path := filepath.Join(rf.dir, rf.baseName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", path, err)
	}
	rf.f = f
	rf.currentDay = time.Now().UTC().Format("20060102")
	return nil
}

// runRotator wakes at every midnight UTC. On wake it:
//  1. renames the active file to kekkai-agent-<yesterday>.log
//  2. opens a fresh kekkai-agent.log
//  3. runs gc to delete anything older than rotateRetention
//
// Cancellation is handled by the stop channel; Close() triggers an
// immediate exit without one last rotation.
func (rf *rotatingFile) runRotator() {
	for {
		wait := untilNextMidnightUTC(time.Now())
		select {
		case <-rf.stop:
			return
		case <-time.After(wait):
			if err := rf.rotateOnce(); err != nil {
				// Use stderr directly — we can't log through ourselves
				// right now, the file is mid-swap. This is extremely
				// rare; when it happens you want to see it loud.
				fmt.Fprintf(os.Stderr, "logx: rotate failed: %v\n", err)
			}
			rf.gc()
		}
	}
}

// rotateOnce does the actual rename + reopen under the mutex.
func (rf *rotatingFile) rotateOnce() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	// Close the current handle before renaming on the off chance the
	// filesystem serves open-file semantics we don't expect (ext4 is
	// fine with it; NFS is not, and someone WILL put /var/log on NFS).
	if rf.f != nil {
		_ = rf.f.Close()
		rf.f = nil
	}

	active := filepath.Join(rf.dir, rf.baseName)
	// Archive under the *previous* day's name — if the timer fires at
	// 00:00:00.001 we still want yesterday as the suffix. Use the
	// stored currentDay rather than computing from "now".
	archive := filepath.Join(rf.dir,
		fmt.Sprintf("kekkai-agent-%s.log", rf.currentDay))

	if _, err := os.Stat(active); err == nil {
		// If the archive name is somehow already taken (e.g. someone
		// restarted kekkai at exactly 00:00:00 twice), append a marker
		// so we never lose the previous day's content.
		if _, err := os.Stat(archive); err == nil {
			archive = archive + "." + fmt.Sprintf("%d", time.Now().UnixNano())
		}
		if err := os.Rename(active, archive); err != nil {
			return fmt.Errorf("rename %s → %s: %w", active, archive, err)
		}
	}

	return rf.openCurrent()
}

// gc deletes rotated files older than rotateRetention. Errors are
// logged to stderr and ignored — we'd rather keep rotating than die
// because one stale file had weird perms.
func (rf *rotatingFile) gc() {
	pattern := filepath.Join(rf.dir, rotateFilenameGlob)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logx: gc glob: %v\n", err)
		return
	}
	cutoff := time.Now().Add(-rotateRetention)
	for _, p := range matches {
		// Extra safety: only touch files whose base name starts with
		// the expected prefix. Glob is lax about * matching weird
		// characters in some locales.
		if !strings.HasPrefix(filepath.Base(p), "kekkai-agent-") {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.ModTime().Before(cutoff) {
			_ = os.Remove(p)
		}
	}
}

// untilNextMidnightUTC returns the duration from now until the next
// 00:00:00 UTC. Clamped at 1s if the calculation somehow returned
// <= 0 (clock skew, leap second, etc).
func untilNextMidnightUTC(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	d := next.Sub(u)
	if d < time.Second {
		return time.Second
	}
	return d
}
