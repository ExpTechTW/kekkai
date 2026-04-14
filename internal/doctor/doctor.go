// Package doctor implements read-only health checks for a running kekkai
// installation. It powers the `kekkai doctor` CLI command.
//
// Every check returns a Result with a status (OK / Warn / Error), a one
// line message, and optional remediation hints. Checks never write any
// file, never start/stop services, never attach/detach XDP — doctor is
// strictly observational.
package doctor

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ExpTechTW/kekkai/internal/buildinfo"
)

// Status is the traffic-light value for a single check.
type Status int

const (
	StatusOK Status = iota
	StatusWarn
	StatusError
)

func (s Status) Symbol() string {
	switch s {
	case StatusOK:
		return "✓"
	case StatusWarn:
		return "⚠"
	case StatusError:
		return "✗"
	}
	return "?"
}

// Result is what every check returns.
type Result struct {
	Status      Status
	Title       string   // short label, e.g. "kernel version"
	Detail      string   // one-line human text
	Suggestions []string // optional remediation lines
}

// Section groups related checks under a common heading in the final
// report. Sections run in insertion order and their checks run in
// insertion order within the section.
type Section struct {
	Name    string
	Results []Result
}

// Runner accumulates sections and drives their execution.
type Runner struct {
	sections []*Section
}

func New() *Runner { return &Runner{} }

// Section appends a new section and returns it for chaining.
func (r *Runner) Section(name string) *Section {
	s := &Section{Name: name}
	r.sections = append(r.sections, s)
	return s
}

func (s *Section) Add(result Result) { s.Results = append(s.Results, result) }

// Summary counts check outcomes across every section.
type Summary struct {
	OK    int
	Warn  int
	Error int
}

func (r *Runner) Summary() Summary {
	var s Summary
	for _, sec := range r.sections {
		for _, res := range sec.Results {
			switch res.Status {
			case StatusOK:
				s.OK++
			case StatusWarn:
				s.Warn++
			case StatusError:
				s.Error++
			}
		}
	}
	return s
}

// Render writes a formatted, colourised report to w.
func (r *Runner) Render(w io.Writer, colour bool) {
	p := newPalette(colour)
	fmt.Fprintln(w, p.title("  ◈ KEKKAI doctor  結界 ·  diagnostic report"))
	fmt.Fprintln(w, p.dim(fmt.Sprintf("  kekkai %s · %s/%s",
		buildinfo.DefaultVersion, runtime.GOOS, runtime.GOARCH)))
	fmt.Fprintln(w, p.dim("  ---------------------------------------------"))
	fmt.Fprintln(w)

	for _, sec := range r.sections {
		fmt.Fprintf(w, "  %s %s\n", p.section("○"), p.sectionName(sec.Name))
		for _, res := range sec.Results {
			sym := res.Status.Symbol()
			var line string
			switch res.Status {
			case StatusOK:
				line = p.ok(fmt.Sprintf("    %s  %-28s %s", sym, res.Title, res.Detail))
			case StatusWarn:
				line = p.warn(fmt.Sprintf("    %s  %-28s %s", sym, res.Title, res.Detail))
			case StatusError:
				line = p.errCol(fmt.Sprintf("    %s  %-28s %s", sym, res.Title, res.Detail))
			}
			fmt.Fprintln(w, line)
			for _, s := range res.Suggestions {
				fmt.Fprintf(w, "       %s %s\n", p.dim("→"), p.dim(s))
			}
		}
		fmt.Fprintln(w)
	}

	sum := r.Summary()
	total := sum.OK + sum.Warn + sum.Error
	fmt.Fprintln(w, p.dim("  ---------------------------------------------"))
	status := p.ok("healthy")
	if sum.Error > 0 {
		status = p.errCol("issues detected")
	} else if sum.Warn > 0 {
		status = p.warn("warnings present")
	}
	fmt.Fprintf(w, "  %s  %d checks · %s%d ok%s · %s%d warn%s · %s%d error%s\n",
		status, total,
		p.okCode, sum.OK, p.reset,
		p.warnCode, sum.Warn, p.reset,
		p.errCode, sum.Error, p.reset,
	)
	fmt.Fprintln(w)
}

// ExitCode reflects the highest-severity check: 0 for healthy or warnings
// only, 1 if any check failed. Keeping warnings as success matches the
// typical `docker info` / `brew doctor` convention.
func (r *Runner) ExitCode() int {
	if r.Summary().Error > 0 {
		return 1
	}
	return 0
}

// ---------- colour palette ------------------------------------------------

type palette struct {
	reset                        string
	okCode, warnCode, errCode    string
	titleCode, dimCode, sectCode string
	enabled                      bool
}

func newPalette(enable bool) palette {
	if !enable {
		return palette{enabled: false}
	}
	return palette{
		enabled:   true,
		reset:     "\x1b[0m",
		okCode:    "\x1b[1;32m",
		warnCode:  "\x1b[1;33m",
		errCode:   "\x1b[1;31m",
		titleCode: "\x1b[1;35m",
		dimCode:   "\x1b[2m",
		sectCode:  "\x1b[1;36m",
	}
}

func (p palette) wrap(code, s string) string {
	if !p.enabled {
		return s
	}
	return code + s + p.reset
}

func (p palette) ok(s string) string          { return p.wrap(p.okCode, s) }
func (p palette) warn(s string) string        { return p.wrap(p.warnCode, s) }
func (p palette) errCol(s string) string      { return p.wrap(p.errCode, s) }
func (p palette) title(s string) string       { return p.wrap(p.titleCode, s) }
func (p palette) dim(s string) string         { return p.wrap(p.dimCode, s) }
func (p palette) section(s string) string     { return p.wrap(p.sectCode, s) }
func (p palette) sectionName(s string) string { return p.wrap(p.sectCode, strings.ToUpper(s)) }

// ---------- check utilities (used by platform-specific files) ------------

// fileInfo returns a short "size, modified" description or an empty
// string if the file doesn't exist.
func fileInfo(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("(%s, %s)", humanSize(st.Size()), filepath.Base(path))
}

func humanSize(n int64) string {
	const (
		k = 1024
		m = k * 1024
		g = m * 1024
	)
	switch {
	case n >= g:
		return fmt.Sprintf("%.1f GiB", float64(n)/g)
	case n >= m:
		return fmt.Sprintf("%.1f MiB", float64(n)/m)
	case n >= k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	return fmt.Sprintf("%d B", n)
}
