package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ExpTechTW/kekkai/internal/version"
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

// Model is the Bubble Tea state machine. It polls the Source once a second,
// keeps the latest snapshot for the next rate sample, and tracks which page
// is active plus any per-page cursor state.
type Model struct {
	src  *Source
	page Page

	cur *Snapshot

	// UI state
	width, height int
	topCursor     int  // selected row index on PageTopN
	paused        bool // `p` freezes the display
	ppsHist       []float64
	dpsHist       []float64
	tcpHist       []float64
	udpHist       []float64
	icmpHist      []float64
	udpFlowHist   []float64

	// startup metadata
	agentStartedAt   time.Time
	sessionStartedAt time.Time
	nodeID           string
	iface            string
	xdpMode          string
	version          string
	updateChannel    string
	updateState      string // checking | up-to-date | update-available | n/a | error
	updateLatest     string
	updateHint       string
	errMsg           string // non-fatal error from the last tick
	reading          bool   // a source read is already in flight
	beat             bool   // banner glyph, flipped once per tick
	viewCache        string // last frame; dropped on every Update so a tick still redraws

	// bypassCheck reports whether the XDP filter is currently NOT attached
	// (emergency bypass on, or agent detached). Re-run every tick so the
	// banner appears/clears live. nil => never bypassed.
	bypassCheck func() bool
	bypassed    bool
}

// NewModel wires a Source to a Model. The Source is owned by the Model
// and closed when the program exits.
func NewModel(
	src *Source,
	nodeID, iface, xdpMode, version, updateChannel string,
	agentStartedAt time.Time,
	bypassCheck func() bool,
) *Model {
	return &Model{
		src:              src,
		page:             PageOverview,
		agentStartedAt:   agentStartedAt,
		sessionStartedAt: time.Now(),
		nodeID:           nodeID,
		iface:            iface,
		xdpMode:          xdpMode,
		version:          version,
		updateChannel:    updateChannel,
		bypassCheck:      bypassCheck,
		updateState:      "checking",
		ppsHist:          make([]float64, 0, 120),
		dpsHist:          make([]float64, 0, 120),
		tcpHist:          make([]float64, 0, 120),
		udpHist:          make([]float64, 0, 120),
		icmpHist:         make([]float64, 0, 120),
		udpFlowHist:      make([]float64, 0, 120),
	}
}

// tickMsg triggers a source read.
type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

type updateCheckMsg struct {
	state  string
	latest string
	hint   string
}

func (m *Model) Init() tea.Cmd {
	m.reading = true
	return tea.Batch(
		tickCmd(),
		m.doRead(),
		m.doUpdateCheck(),
		m.doBypassCheck(),
	)
}

// bypassMsg carries the latest filter-attachment state.
type bypassMsg bool

func (m *Model) doBypassCheck() tea.Cmd {
	return func() tea.Msg {
		if m.bypassCheck == nil {
			return bypassMsg(false)
		}
		return bypassMsg(m.bypassCheck())
	}
}

// readMsg carries the latest Snapshot from the background read goroutine.
type readMsg struct {
	snap  Snapshot
	err   error
	limit int // per-IP limit this read used; < 0 means the walk was skipped
}

// perIPLimit is how many per-IP rows the current page needs.
// Negative skips the map walk. Zero keeps every row for scrolling.
func (m *Model) perIPLimit() int {
	switch m.page {
	case PageOverview:
		return 5
	case PageTopN:
		return 0
	default:
		return -1
	}
}

func (m *Model) doRead() tea.Cmd {
	limit := m.perIPLimit()
	var base Snapshot
	hasBase := m.cur != nil
	if hasBase {
		base = *m.cur
		base.Top = nil
	}
	return func() tea.Msg {
		var p *Snapshot
		if hasBase {
			p = &base
		}
		snap, err := m.src.Read(p, limit)
		return readMsg{snap: snap, err: err, limit: limit}
	}
}

func (m *Model) kickRead() tea.Cmd {
	if m.paused || m.reading {
		return nil
	}
	m.reading = true
	return m.doRead()
}

func (m *Model) doUpdateCheck() tea.Cmd {
	return func() tea.Msg {
		state, latest, hint := checkUpdateStatus(m.updateChannel, m.version)
		return updateCheckMsg{state: state, latest: latest, hint: hint}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m.viewCache = ""
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
		m.beat = !m.beat
		if m.reading {
			return m, tea.Batch(tickCmd(), m.doBypassCheck())
		}
		m.reading = true
		return m, tea.Batch(tickCmd(), m.doBypassCheck(), m.doRead())

	case bypassMsg:
		m.bypassed = bool(msg)
		return m, nil

	case readMsg:
		m.reading = false
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			return m, m.followRead(msg.limit)
		}
		m.errMsg = ""
		s := msg.snap
		// A page that does not list sources keeps the rows already on screen
		// so switching back does not flash empty for a frame.
		if msg.limit < 0 && m.cur != nil {
			s.Top = m.cur.Top
		}
		m.cur = &s
		m.pushHistory(s)
		if m.topCursor >= len(m.cur.Top) {
			m.topCursor = len(m.cur.Top) - 1
			if m.topCursor < 0 {
				m.topCursor = 0
			}
		}
		return m, m.followRead(msg.limit)

	case updateCheckMsg:
		m.updateState = msg.state
		m.updateLatest = msg.latest
		m.updateHint = msg.hint
		return m, nil
	}
	return m, nil
}

// followRead starts another read when the one that just finished was for
// a different page than the one now on screen.
func (m *Model) followRead(limit int) tea.Cmd {
	if m.paused || limit == m.perIPLimit() {
		return nil
	}
	m.reading = true
	return m.doRead()
}

func (m *Model) switchPage(p Page) (tea.Model, tea.Cmd) {
	if m.page == p {
		return m, nil
	}
	m.page = p
	return m, m.kickRead()
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "1":
		return m.switchPage(PageOverview)
	case "2":
		return m.switchPage(PageDetail)
	case "3":
		return m.switchPage(PageTopN)
	case "4":
		return m.switchPage(PageCharts)
	case "tab":
		return m.switchPage((m.page + 1) % pageCount)
	case "shift+tab":
		return m.switchPage((m.page + pageCount - 1) % pageCount)

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
	m.udpFlowHist = pushSeries(m.udpFlowHist, s.PpsUDPFlow, 120)
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

// uptime prefers agent runtime. cmd/kekkai status derives it from systemd's
// ActiveEnterTimestampMonotonic plus /proc/uptime (there is no realtime
// USec property). If unavailable, fall back to TUI session time so
// non-systemd/manual runs still show a useful counter.
func (m *Model) uptime() string {
	startAt := m.agentStartedAt
	if startAt.IsZero() {
		startAt = m.sessionStartedAt
	}
	d := time.Since(startAt).Truncate(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}

func checkUpdateStatus(channel, current string) (state, latest, hint string) {
	channel = strings.TrimSpace(channel)
	if channel == "" {
		channel = "release"
	}
	switch channel {
	case "release", "pre-release":
	default:
		return "error", "", "unsupported update channel: " + channel
	}

	tag, err := fetchLatestReleaseTag(channel)
	if err != nil {
		return "error", "", "check failed: " + err.Error()
	}
	if tag == "" {
		return "error", "", "check failed: empty release tag"
	}

	curVer, curOK := version.Parse(current)
	latestVer, latestOK := version.Parse(tag)
	if !curOK || !latestOK {
		return "n/a", tag, "local version has unknown format; latest release=" + tag
	}
	if version.IsNewer(latestVer, curVer) {
		return "update-available", tag, "new release available"
	}
	return "up-to-date", tag, "already latest"
}

func fetchLatestReleaseTag(channel string) (string, error) {
	const base = "https://api.github.com/repos/ExpTechTW/kekkai/releases"
	url := base + "/latest"
	if channel == "pre-release" {
		url = base + "?per_page=20"
	}

	client := &http.Client{Timeout: 3500 * time.Millisecond}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("http %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if channel == "release" {
		var r struct {
			TagName string `json:"tag_name"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return "", err
		}
		return strings.TrimSpace(r.TagName), nil
	}

	var rs []struct {
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		TagName    string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rs); err != nil {
		return "", err
	}
	for _, r := range rs {
		if r.Draft || !r.Prerelease {
			continue
		}
		return strings.TrimSpace(r.TagName), nil
	}
	return "", fmt.Errorf("no pre-release found")
}
