package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Page identifies the currently-visible screen.
type Page int

const (
	PageOverview Page = iota
	PageDetail
	PageTopN
	PageCharts
	pageCount
)

// Model is the Bubble Tea state machine. It polls the Source on a fixed
// cadence, holds the latest two snapshots for rate calculation, and tracks
// which page is active plus any per-page cursor state.
type Model struct {
	src  *Source
	page Page

	// last two snapshots for delta computation
	prev *Snapshot
	cur  *Snapshot

	// UI state
	width, height int
	topCursor     int  // selected row index on PageTopN
	paused        bool // `p` freezes the display
	ppsHist       []float64
	dpsHist       []float64
	tcpHist       []float64
	udpHist       []float64
	icmpHist      []float64

	// startup metadata
	startedAt time.Time
	nodeID    string
	iface     string
	xdpMode   string
	errMsg    string // non-fatal error from the last tick
}

// NewModel wires a Source to a Model. The Source is owned by the Model
// and closed when the program exits.
func NewModel(src *Source, nodeID, iface, xdpMode string) *Model {
	return &Model{
		src:       src,
		page:      PageOverview,
		startedAt: time.Now(),
		nodeID:    nodeID,
		iface:     iface,
		xdpMode:   xdpMode,
		ppsHist:   make([]float64, 0, 120),
		dpsHist:   make([]float64, 0, 120),
		tcpHist:   make([]float64, 0, 120),
		udpHist:   make([]float64, 0, 120),
		icmpHist:  make([]float64, 0, 120),
	}
}

// tickMsg triggers a source read.
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// readMsg carries the latest Snapshot from the background read goroutine.
// (Currently Read is fast enough to do on the main tick.)
type readMsg struct {
	snap Snapshot
	err  error
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		m.doRead(),
	)
}

func (m *Model) doRead() tea.Cmd {
	return func() tea.Msg {
		snap, err := m.src.Read(m.prev)
		return readMsg{snap: snap, err: err}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		if m.paused {
			return m, tickCmd()
		}
		return m, tea.Batch(tickCmd(), m.doRead())

	case readMsg:
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			return m, nil
		}
		m.errMsg = ""
		// Promote current to prev, keep a copy of the new snapshot so
		// rate math is correct on the next tick.
		if m.cur != nil {
			p := *m.cur
			m.prev = &p
		}
		s := msg.snap
		m.cur = &s
		m.pushHistory(s)
		// Clamp top cursor after data changes.
		if m.cur != nil && m.topCursor >= len(m.cur.Top) {
			m.topCursor = len(m.cur.Top) - 1
			if m.topCursor < 0 {
				m.topCursor = 0
			}
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "1":
		m.page = PageOverview
	case "2":
		m.page = PageDetail
	case "3":
		m.page = PageTopN
	case "4":
		m.page = PageCharts
	case "tab":
		m.page = (m.page + 1) % pageCount
	case "shift+tab":
		m.page = (m.page + pageCount - 1) % pageCount

	case "p":
		m.paused = !m.paused

	case "up", "k":
		if m.page == PageTopN && m.topCursor > 0 {
			m.topCursor--
		}
	case "down", "j":
		if m.page == PageTopN && m.cur != nil && m.topCursor < len(m.cur.Top)-1 {
			m.topCursor++
		}
	case "home", "g":
		if m.page == PageTopN {
			m.topCursor = 0
		}
	case "end", "G":
		if m.page == PageTopN && m.cur != nil {
			m.topCursor = len(m.cur.Top) - 1
			if m.topCursor < 0 {
				m.topCursor = 0
			}
		}
	}
	return m, nil
}

func (m *Model) pushHistory(s Snapshot) {
	m.ppsHist = pushSeries(m.ppsHist, s.PPS, 120)
	m.dpsHist = pushSeries(m.dpsHist, s.DPS, 120)
	m.tcpHist = pushSeries(m.tcpHist, s.PpsTCP, 120)
	m.udpHist = pushSeries(m.udpHist, s.PpsUDP, 120)
	m.icmpHist = pushSeries(m.icmpHist, s.PpsICMP, 120)
}

func pushSeries(series []float64, v float64, max int) []float64 {
	if v < 0 {
		v = 0
	}
	series = append(series, v)
	if len(series) > max {
		copy(series, series[len(series)-max:])
		series = series[:max]
	}
	return series
}

// uptime formats how long the TUI itself has been running. The agent
// uptime is not directly visible to kekkai (maps are pinned but have no
// start timestamp), so this is "session uptime" which is good enough for
// an operator glancing at the screen.
func (m *Model) uptime() string {
	d := time.Since(m.startedAt).Truncate(time.Second)
	return fmt.Sprintf("%s", d)
}
