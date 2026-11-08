package logx

// Daily rotation for /var/log/kekkai/kekkai-agent.log.
//
//	kekkai-agent.log           active file; the name stays put so tail -F works
//	kekkai-agent-YYYYMMDD.log  previous days, removed once mtime is over 7 days
//
// Rename and reopen run under the writer mutex so a line cannot split across
// two files. Retention is fixed: a week of context should be on disk without
// a config knob.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	rotateRetention    = 7 * 24 * time.Hour
	rotateFilenameGlob = "kekkai-agent-*.log"
)

type rotatingFile struct {
	dir        string
	baseName   string
	mu         sync.Mutex
	f          *os.File
	currentDay string // YYYYMMDD of the open file; the archive suffix uses this, not "now"
	stop       chan struct{}
}

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
	rf.gc()
	go rf.runRotator()
	return rf, nil
}

func (rf *rotatingFile) Write(p []byte) (int, error) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.f == nil {
		return 0, os.ErrClosed
	}
	return rf.f.Write(p)
}

func (rf *rotatingFile) Close() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	select {
	case <-rf.stop:
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

// openCurrent replaces rf.f. The caller must keep Write out until it returns.
func (rf *rotatingFile) openCurrent() error {
	path := filepath.Join(rf.dir, rf.baseName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", path, err)
	}
	rf.f = f
	rf.currentDay = time.Now().UTC().Format("20060102")
	return nil
}

func (rf *rotatingFile) runRotator() {
	timer := time.NewTimer(untilNextMidnightUTC(time.Now()))
	defer timer.Stop()
	for {
		select {
		case <-rf.stop:
			return
		case <-timer.C:
			if err := rf.rotateOnce(); err != nil {
				fmt.Fprintf(os.Stderr, "logx: rotate failed: %v\n", err)
			}
			rf.gc()
			timer.Reset(untilNextMidnightUTC(time.Now()))
		}
	}
}

func (rf *rotatingFile) rotateOnce() error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	// Close may have won the race after the timer fired and before this
	// lock. Reopening here would leak a file the caller already released.
	select {
	case <-rf.stop:
		return nil
	default:
	}

	// Close first. NFS will not rename a file that still has an open fd.
	if rf.f != nil {
		_ = rf.f.Close()
		rf.f = nil
	}

	active := filepath.Join(rf.dir, rf.baseName)
	archive := filepath.Join(rf.dir, "kekkai-agent-"+rf.currentDay+".log")
	if _, err := os.Stat(active); err == nil {
		if _, err := os.Stat(archive); err == nil {
			archive += "." + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		if err := os.Rename(active, archive); err != nil {
			return fmt.Errorf("rename %s → %s: %w", active, archive, err)
		}
	}
	return rf.openCurrent()
}

// gc removes rotated files older than rotateRetention. A failure is logged
// and ignored so rotation itself keeps going.
func (rf *rotatingFile) gc() {
	matches, err := filepath.Glob(filepath.Join(rf.dir, rotateFilenameGlob))
	if err != nil {
		fmt.Fprintf(os.Stderr, "logx: gc glob: %v\n", err)
		return
	}
	cutoff := time.Now().Add(-rotateRetention)
	for _, p := range matches {
		// Glob is not a substitute for a prefix check on every platform.
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

// untilNextMidnightUTC is at least one second. A zero or negative wait
// (clock step, leap second) would spin the rotator.
func untilNextMidnightUTC(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	d := next.Sub(u)
	if d < time.Second {
		return time.Second
	}
	return d
}
