package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ExpTechTW/kekkai/internal/stats"
)

// ---------- palette --------------------------------------------------------
//
// The TUI is themed as a "magical barrier security console" — saturated
// cyan/violet with scarlet alert accents. Every colour lives here so a
// single edit changes the whole look.

var (
	// Base
	cBg     = lipgloss.Color("#0b0f1a") // near-black navy
	cFg     = lipgloss.Color("#e2e8f0") // slate-200
	cDim    = lipgloss.Color("#475569") // slate-600
	cSubtle = lipgloss.Color("#64748b") // slate-500

	// Accent — barrier glow
	cBarrier  = lipgloss.Color("#8b5cf6") // violet-500
	cBarrier2 = lipgloss.Color("#a78bfa") // violet-400
	cCyan     = lipgloss.Color("#22d3ee") // cyan-400
	cMagenta  = lipgloss.Color("#e879f9") // fuchsia-400

	// Semantic
	cPass     = lipgloss.Color("#4ade80") // green-400
	cWarn     = lipgloss.Color("#fbbf24") // amber-400
	cAlert    = lipgloss.Color("#fb923c") // orange-400
	cDanger   = lipgloss.Color("#f43f5e") // rose-500
	cCritical = lipgloss.Color("#dc2626") // red-600
)

// ---------- text styles ----------------------------------------------------

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(cBarrier2).
			Bold(true)

	dimStyle = lipgloss.NewStyle().Foreground(cDim)
	fgStyle  = lipgloss.NewStyle().Foreground(cFg)

	passStyle     = lipgloss.NewStyle().Foreground(cPass).Bold(true)
	dropStyle     = lipgloss.NewStyle().Foreground(cDanger).Bold(true)
	warnStyle     = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	alertStyle    = lipgloss.NewStyle().Foreground(cAlert).Bold(true)
	criticalStyle = lipgloss.NewStyle().Foreground(cCritical).Bold(true).Blink(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBarrier).
			Padding(0, 1)

	boxAlert = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(cDanger).
			Padding(0, 1)

	labelStyle = lipgloss.NewStyle().
			Foreground(cSubtle).
			Width(18)

	valueStyle = lipgloss.NewStyle().
			Foreground(cCyan).
			Bold(true)

	tabActive = lipgloss.NewStyle().
			Foreground(cBg).
			Background(cBarrier).
			Bold(true).
			Padding(0, 2)

	tabInactive = lipgloss.NewStyle().
			Foreground(cDim).
			Padding(0, 2)

	footerStyle = lipgloss.NewStyle().
			Foreground(cSubtle).
			BorderTop(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(cBarrier).
			Padding(0, 1)

	kanjiStyle = lipgloss.NewStyle().
			Foreground(cMagenta).
			Bold(true)
)

// ---------- entry ---------------------------------------------------------

func (m *Model) View() string {
	if m.cur == nil && m.errMsg == "" {
		return "\n  " + titleStyle.Render("◈ KEKKAI") + "  " +
			dimStyle.Render("initialising barrier...") + "\n\n"
	}

	var body string
	switch m.page {
	case PageOverview:
		body = m.viewOverview()
	case PageDetail:
		body = m.viewDetail()
	case PageTopN:
		body = m.viewTopN()
	}

	return strings.Join([]string{
		m.viewBanner(),
		m.viewHeader(),
		m.viewTabs(),
		body,
		m.viewFooter(),
	}, "\n")
}

// ---------- chrome --------------------------------------------------------

// viewBanner renders the top branded banner. The banner colour and status
// label both shift based on current threat level so there's an unmistakable
// visual cue when something is wrong.
func (m *Model) viewBanner() string {
	t := m.threatLevel()

	// Heartbeat glyph pulses once per tick; even a stopped agent breathes.
	beat := "●"
	if time.Now().UnixMilli()/500%2 == 0 {
		beat = "◉"
	}

	statusGlyph := passStyle.Render(beat)
	statusText := "BARRIER ACTIVE"
	bannerColor := cBarrier

	if m.paused {
		statusGlyph = warnStyle.Render("◌")
		statusText = "PAUSED"
		bannerColor = cWarn
	}
	switch t {
	case threatElevated:
		bannerColor = cAlert
	case threatHigh:
		bannerColor = cDanger
	case threatCritical:
		bannerColor = cCritical
		statusGlyph = criticalStyle.Render("◆")
		statusText = "THREAT CRITICAL"
	}

	left := lipgloss.NewStyle().Foreground(bannerColor).Bold(true).
		Render("◈ KEKKAI")
	kanji := kanjiStyle.Render("結界")
	sub := lipgloss.NewStyle().Foreground(cCyan).Italic(true).
		Render("· edge barrier console ·")
	status := lipgloss.NewStyle().Foreground(bannerColor).Bold(true).
		Render(statusText)

	return fmt.Sprintf(" %s  %s  %s   %s %s",
		left, kanji, sub, statusGlyph, status)
}

func (m *Model) viewHeader() string {
	meta := fmt.Sprintf("node=%s  iface=%s  xdp=%s  uptime=%s",
		m.nodeID, m.iface, m.xdpMode, m.uptime())
	return " " + dimStyle.Render(meta)
}

func (m *Model) viewTabs() string {
	tabs := []string{"[1] Overview", "[2] Detail", "[3] Top-N"}
	out := make([]string, 3)
	for i, t := range tabs {
		if Page(i) == m.page {
			out[i] = tabActive.Render(t)
		} else {
			out[i] = tabInactive.Render(t)
		}
	}
	return " " + lipgloss.JoinHorizontal(lipgloss.Top, out...)
}

func (m *Model) viewFooter() string {
	help := "[1/2/3] page  [Tab] cycle  [p] pause  [↑↓] scroll  [q] quit"
	if m.errMsg != "" {
		help = criticalStyle.Render("⚠ "+m.errMsg) + "   " + help
	}
	return footerStyle.Render(help)
}

// ---------- threat level --------------------------------------------------

type threat int

const (
	threatCalm threat = iota
	threatElevated
	threatHigh
	threatCritical
)

// threatLevel maps current drop rate (pps) to a named threat level. The
// thresholds are opinionated — tune if they turn out to be too jumpy.
func (m *Model) threatLevel() threat {
	if m.cur == nil {
		return threatCalm
	}
	switch {
	case m.cur.DPS >= 1000:
		return threatCritical
	case m.cur.DPS >= 100:
		return threatHigh
	case m.cur.DPS >= 10:
		return threatElevated
	}
	return threatCalm
}

func (t threat) label() string {
	switch t {
	case threatCritical:
		return "CRITICAL"
	case threatHigh:
		return "HIGH"
	case threatElevated:
		return "ELEVATED"
	}
	return "CALM"
}

func (t threat) style() lipgloss.Style {
	switch t {
	case threatCritical:
		return criticalStyle
	case threatHigh:
		return dropStyle
	case threatElevated:
		return alertStyle
	}
	return passStyle
}

// ---------- gauge ---------------------------------------------------------

// gauge renders a horizontal bar using block glyphs. Saturates at `max`.
func gauge(value, max float64, width int, fill lipgloss.Color) string {
	if max <= 0 {
		max = 1
	}
	ratio := value / max
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * float64(width))
	empty := width - filled
	f := lipgloss.NewStyle().Foreground(fill).Render(strings.Repeat("▰", filled))
	e := lipgloss.NewStyle().Foreground(cDim).Render(strings.Repeat("▱", empty))
	return f + e
}

// ---------- pages ---------------------------------------------------------

func (m *Model) viewOverview() string {
	s := m.cur
	if s == nil {
		return "\n"
	}
	g := s.Global

	t := m.threatLevel()
	threatBadge := t.style().Render(fmt.Sprintf(" ◆ THREAT %s ", t.label()))

	const maxPPS = 10000.0
	rxGauge := gauge(s.PPS, maxPPS, 22, cCyan)
	dropGauge := gauge(s.DPS, maxPPS, 22, cDanger)

	rxBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◈ RX · XDP ingress"),
		labelStyle.Render("pps total") + valueStyle.Render(fmtNum(s.PPS)),
		"  " + rxGauge,
		labelStyle.Render("pps dropped") + dropStyle.Render(fmtNum(s.DPS)),
		"  " + dropGauge,
		labelStyle.Render("rx total") + valueStyle.Render(humanBits(s.BpsTotal)),
		labelStyle.Render("rx dropped") + dropStyle.Render(humanBits(s.BpsDropped)),
	}, "\n"))

	txBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◈ TX · kernel"),
		labelStyle.Render("tx bps") + valueStyle.Render(humanBits(s.TxBps)),
		labelStyle.Render("tx pps") + valueStyle.Render(fmtNum(s.TxPps)),
		labelStyle.Render("tx total") + fgStyle.Render(humanBytes(s.TxBytes)),
		"",
		dimStyle.Render("(not filtered by XDP)"),
	}, "\n"))

	protoBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◈ Protocol rate"),
		labelStyle.Render("tcp") + valueStyle.Render(fmtNum(s.PpsTCP)+" pps"),
		labelStyle.Render("udp") + valueStyle.Render(fmtNum(s.PpsUDP)+" pps"),
		labelStyle.Render("icmp") + valueStyle.Render(fmtNum(s.PpsICMP)+" pps"),
		"",
		dimStyle.Render(fmt.Sprintf("total: tcp=%s  udp=%s",
			fmtU(g.PktsTCP), fmtU(g.PktsUDP))),
	}, "\n"))

	dropBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◆ Drops (since start)"),
		labelStyle.Render("blocklist") + dropStyle.Render(fmtU(g.DropBlocklist)),
		labelStyle.Render("dyn blocklist") + dropStyle.Render(fmtU(g.DropDynBlock)),
		labelStyle.Render("not allowed") + dropStyle.Render(fmtU(g.DropNotAllowed)),
		labelStyle.Render("no policy") + dropStyle.Render(fmtU(g.DropNoPolicy)),
		labelStyle.Render("non-ipv4") + dropStyle.Render(fmtU(g.DropNonIPv4)),
	}, "\n"))

	topBox := renderTopBox(s, 5, -1)

	row1 := lipgloss.JoinHorizontal(lipgloss.Top, rxBox, " ", txBox, " ", protoBox)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, dropBox, " ", topBox)

	return "\n " + threatBadge + "\n\n" + row1 + "\n" + row2 + "\n"
}

func (m *Model) viewDetail() string {
	s := m.cur
	if s == nil {
		return "\n"
	}
	g := s.Global

	countersBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◆ Counters (since start)"),
		labelStyle.Render("packets total") + valueStyle.Render(fmtU(g.PktsTotal)),
		labelStyle.Render("packets passed") + passStyle.Render(fmtU(g.PktsPassed)),
		labelStyle.Render("packets dropped") + dropStyle.Render(fmtU(g.PktsDropped)),
		labelStyle.Render("bytes total") + valueStyle.Render(humanBytes(g.BytesTotal)),
		labelStyle.Render("bytes dropped") + dropStyle.Render(humanBytes(g.BytesDropped)),
	}, "\n"))

	protoBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◆ Protocols"),
		labelStyle.Render("tcp") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsTCP), humanBytes(g.BytesTCP))),
		labelStyle.Render("udp") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsUDP), humanBytes(g.BytesUDP))),
		labelStyle.Render("icmp") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsICMP), humanBytes(g.BytesICMP))),
		labelStyle.Render("other l4") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsOtherL4), humanBytes(g.BytesOtherL4))),
	}, "\n"))

	dropsBox := boxAlert.Render(strings.Join([]string{
		titleStyle.Render("▼ Drops by reason"),
		labelStyle.Render("non-ipv4") + dropStyle.Render(fmtU(g.DropNonIPv4)),
		labelStyle.Render("malformed") + dropStyle.Render(fmtU(g.DropMalformed)),
		labelStyle.Render("blocklist") + dropStyle.Render(fmtU(g.DropBlocklist)),
		labelStyle.Render("dyn blocklist") + dropStyle.Render(fmtU(g.DropDynBlock)),
		labelStyle.Render("not allowed") + dropStyle.Render(fmtU(g.DropNotAllowed)),
		labelStyle.Render("no policy") + dropStyle.Render(fmtU(g.DropNoPolicy)),
	}, "\n"))

	passesBox := boxStyle.BorderForeground(cPass).Render(strings.Join([]string{
		titleStyle.Render("▲ Passes by reason"),
		labelStyle.Render("return tcp (ACK)") + passStyle.Render(fmtU(g.PassReturnTCP)),
		labelStyle.Render("return udp (eph)") + passStyle.Render(fmtU(g.PassReturnUDP)),
		labelStyle.Render("return icmp") + passStyle.Render(fmtU(g.PassReturnICMP)),
		labelStyle.Render("ip fragment") + passStyle.Render(fmtU(g.PassFragment)),
		labelStyle.Render("public tcp") + passStyle.Render(fmtU(g.PassPublicTCP)),
		labelStyle.Render("public udp") + passStyle.Render(fmtU(g.PassPublicUDP)),
		labelStyle.Render("private tcp") + passStyle.Render(fmtU(g.PassPrivateTCP)),
		labelStyle.Render("private udp") + passStyle.Render(fmtU(g.PassPrivateUDP)),
	}, "\n"))

	col1 := lipgloss.JoinVertical(lipgloss.Left, countersBox, protoBox)
	col2 := lipgloss.JoinVertical(lipgloss.Left, dropsBox, passesBox)
	return "\n" + lipgloss.JoinHorizontal(lipgloss.Top, col1, " ", col2) + "\n"
}

func (m *Model) viewTopN() string {
	s := m.cur
	if s == nil {
		return "\n"
	}
	maxRows := m.height - 8
	if maxRows < 5 {
		maxRows = 5
	}
	box := renderTopBox(s, maxRows, m.topCursor)
	hint := dimStyle.Render(fmt.Sprintf("  %d entries in perip table  |  ↑↓ scroll  home/end jump  ",
		len(s.Top)))
	return "\n" + box + "\n" + hint + "\n"
}

// ---------- helpers -------------------------------------------------------

func renderTopBox(s *Snapshot, limit, cursor int) string {
	header := fmt.Sprintf("  %-3s %-16s %-14s %-14s %-10s %-5s %s",
		"#", "SRC_IP", "PKTS", "BYTES", "DROPPED", "PROTO", "STATUS")

	rows := []string{
		titleStyle.Render("◈ Top source IPs"),
		dimStyle.Render(header),
	}
	if len(s.Top) == 0 {
		rows = append(rows, dimStyle.Render("  (no traffic yet)"))
	}
	shown := len(s.Top)
	if limit > 0 && shown > limit {
		shown = limit
	}
	for i := 0; i < shown; i++ {
		e := s.Top[i]
		var status string
		if e.Blocked {
			status = dropStyle.Render("▼ BLOCK")
		} else {
			status = passStyle.Render("▲ pass ")
		}
		line := fmt.Sprintf("  %-3d %-16s %-14s %-14s %-10s %-5s %s",
			i+1,
			FormatAddr(e.Addr),
			fmtU(e.Pkts),
			humanBytes(e.Bytes),
			fmtU(e.PktsDropped),
			protoName(e.Proto),
			status,
		)
		if i == cursor {
			line = lipgloss.NewStyle().
				Background(cBarrier).
				Foreground(cBg).
				Bold(true).
				Render(line)
		}
		rows = append(rows, line)
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// ---------- formatting (shared with internal/stats) -----------------------

func fmtU(v uint64) string       { return stats.FormatCount(v) }
func fmtNum(v float64) string    { return stats.FormatRate(v) }
func humanBits(v float64) string { return stats.HumanBits(v) }
func humanBytes(v uint64) string { return stats.HumanBytes(v) }
func protoName(p uint8) string   { return stats.ProtoName(p) }
