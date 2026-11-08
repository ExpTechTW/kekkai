package tui

import (
	"fmt"
	"strings"

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
	criticalStyle = lipgloss.NewStyle().Foreground(cCritical).Bold(true)

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

	sparkBlocks = []rune("▁▂▃▄▅▆▇█")

	// Foreground styles built once. View used to allocate a new style on
	// every gauge, sparkline, and banner, which showed up as UI jank.
	boldBarrier  = lipgloss.NewStyle().Foreground(cBarrier).Bold(true)
	boldWarn     = lipgloss.NewStyle().Foreground(cWarn).Bold(true)
	boldAlert    = lipgloss.NewStyle().Foreground(cAlert).Bold(true)
	boldDanger   = lipgloss.NewStyle().Foreground(cDanger).Bold(true)
	boldCritical = lipgloss.NewStyle().Foreground(cCritical).Bold(true)
	subStyle     = lipgloss.NewStyle().Foreground(cCyan).Italic(true)
	labelNarrow  = labelStyle.Width(10)

	fillCyan    = lipgloss.NewStyle().Foreground(cCyan)
	fillDanger  = lipgloss.NewStyle().Foreground(cDanger)
	fillPass    = lipgloss.NewStyle().Foreground(cPass)
	fillWarn    = lipgloss.NewStyle().Foreground(cWarn)
	fillMagenta = lipgloss.NewStyle().Foreground(cMagenta)
	fillBarrier = lipgloss.NewStyle().Foreground(cBarrier)
	fillDim     = lipgloss.NewStyle().Foreground(cDim)

	rowSelected = lipgloss.NewStyle().Background(cBarrier).Foreground(cBg).Bold(true)

	bypassBodyStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#fecaca"))
	bypassBoxStyle  = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(cCritical).
			Background(lipgloss.Color("#7f1d1d")).
			Padding(0, 2)
)

// ---------- entry ---------------------------------------------------------

func (m *Model) View() string {
	if m.viewCache != "" {
		return m.viewCache
	}
	m.viewCache = m.renderView()
	return m.viewCache
}

func (m *Model) renderView() string {
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
	case PageCharts:
		body = m.viewCharts()
	}

	sections := []string{
		m.viewBanner(),
		m.viewHeader(),
		m.viewTabs(),
		body,
		m.viewFooter(),
	}
	if m.bypassed {
		sections = append([]string{m.viewBypassBanner()}, sections...)
	}
	return strings.Join(sections, "\n")
}

// viewBypassBanner is the unmissable red strip shown when the XDP filter is
// not attached — every packet is passing unfiltered.
func (m *Model) viewBypassBanner() string {
	body := bypassBodyStyle.Render("⚠  FILTER BYPASSED — NETWORK UNPROTECTED  ⚠\n" +
		"XDP is detached on " + m.iface + "; every packet passes unfiltered.\n" +
		"re-enable: sudo kekkai bypass off")
	return bypassBoxStyle.Render(body)
}

// ---------- chrome --------------------------------------------------------

// viewBanner renders the top branded banner. The banner colour and status
// label both shift based on current threat level so there's an unmistakable
// visual cue when something is wrong.
func (m *Model) viewBanner() string {
	t := m.threatLevel()

	beat := "●"
	if m.beat {
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

	left := boldFG(bannerColor).Render("◈ KEKKAI")
	kanji := kanjiStyle.Render("結界")
	sub := subStyle.Render("· edge barrier console ·")
	status := boldFG(bannerColor).Render(statusText)

	return fmt.Sprintf(" %s  %s  %s   %s %s",
		left, kanji, sub, statusGlyph, status)
}

func (m *Model) viewHeader() string {
	meta := fmt.Sprintf("node=%s  iface=%s  xdp=%s  uptime=%s",
		m.nodeID, m.iface, m.xdpMode, m.uptime())
	update := m.renderUpdateStatus()
	return " " + dimStyle.Render(meta) + "\n " + update
}

func (m *Model) viewTabs() string {
	tabs := []string{"[1] Overview", "[2] Detail", "[3] Top-N", "[4] Charts"}
	out := make([]string, len(tabs))
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
	help := "[1/2/3/4] page  [Tab] cycle  [p] pause  [↑↓] scroll  [q] quit"
	if m.errMsg != "" {
		help = criticalStyle.Render("⚠ "+m.errMsg) + "   " + help
	}
	return footerStyle.Render(help)
}

func (m *Model) renderUpdateStatus() string {
	base := fmt.Sprintf("version=%s  channel=%s", m.version, m.updateChannel)
	switch m.updateState {
	case "checking":
		return dimStyle.Render(base + "  update=checking...")
	case "up-to-date":
		return passStyle.Render(base + "  update=up-to-date (" + m.updateLatest + ")")
	case "update-available":
		return warnStyle.Render(base + "  update=available (" + m.updateLatest + ")")
	case "n/a":
		if m.updateHint != "" {
			return dimStyle.Render(base + "  update=n/a · " + m.updateHint)
		}
		return dimStyle.Render(base + "  update=n/a")
	case "error":
		if m.updateHint != "" {
			return alertStyle.Render(base + "  update=error · " + m.updateHint)
		}
		return alertStyle.Render(base + "  update=error")
	default:
		return dimStyle.Render(base + "  update=unknown")
	}
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

// Overview gauges are 22 cells. The glyph strings are built once; a wider
// bar falls back to Repeat.
const gaugeSlots = 22

var (
	gaugeOn  = strings.Repeat("▰", gaugeSlots)
	gaugeOff = strings.Repeat("▱", gaugeSlots)
)

// gauge renders a horizontal bar using block glyphs. Saturates at `max`.
func gauge(value, max float64, width int, fill lipgloss.Style) string {
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
	return fill.Render(gaugePart(gaugeOn, "▰", filled)) + fillDim.Render(gaugePart(gaugeOff, "▱", empty))
}

func gaugePart(cached, glyph string, n int) string {
	if n <= 0 {
		return ""
	}
	if n*len(glyph) <= len(cached) {
		return cached[:n*len(glyph)]
	}
	return strings.Repeat(glyph, n)
}

func boldFG(c lipgloss.Color) lipgloss.Style {
	switch c {
	case cWarn:
		return boldWarn
	case cAlert:
		return boldAlert
	case cDanger:
		return boldDanger
	case cCritical:
		return boldCritical
	default:
		return boldBarrier
	}
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
	rxGauge := gauge(s.PPS, maxPPS, 22, fillCyan)
	dropGauge := gauge(s.DPS, maxPPS, 22, fillDanger)

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
		labelStyle.Render("udp flow") + valueStyle.Render(fmtNum(s.PpsUDPFlow)+" pps"),
		labelStyle.Render("ipv6 share") + valueStyle.Render(ipv6Share(g)),
		"",
		dimStyle.Render(fmt.Sprintf("total: tcp=%s  udp=%s",
			fmtU(g.PktsTCP), fmtU(g.PktsUDP))),
	}, "\n"))

	dropBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◆ Drops (since start)"),
		labelStyle.Render("non-ip") + dropStyle.Render(fmtU(g.DropNonIP)),
		labelStyle.Render("malformed") + dropStyle.Render(fmtU(g.DropMalformed)),
		labelStyle.Render("blocklist") + dropStyle.Render(fmtU(g.DropBlocklist)),
		labelStyle.Render("not allowed") + dropStyle.Render(fmtU(g.DropNotAllowed)),
		labelStyle.Render("no policy") + dropStyle.Render(fmtU(g.DropNoPolicy)),
	}, "\n"))

	topBox := renderTopBox(s, 5, -1, m.width)

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
		labelStyle.Render("other") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsOther), humanBytes(g.BytesOther))),
		labelStyle.Render("ipv6") + valueStyle.Render(
			fmt.Sprintf("pkts=%-12s bytes=%s", fmtU(g.PktsIPv6), humanBytes(g.BytesIPv6))),
	}, "\n"))

	dropsBox := boxAlert.Render(strings.Join([]string{
		titleStyle.Render("▼ Drops by reason"),
		labelStyle.Render("non-ip") + dropStyle.Render(fmtU(g.DropNonIP)),
		labelStyle.Render("malformed") + dropStyle.Render(fmtU(g.DropMalformed)),
		labelStyle.Render("blocklist") + dropStyle.Render(fmtU(g.DropBlocklist)),
		labelStyle.Render("not allowed") + dropStyle.Render(fmtU(g.DropNotAllowed)),
		labelStyle.Render("no policy") + dropStyle.Render(fmtU(g.DropNoPolicy)),
	}, "\n"))

	passesBox := boxStyle.BorderForeground(cPass).Render(strings.Join([]string{
		titleStyle.Render("▲ Passes by reason"),
		labelStyle.Render("arp") + passStyle.Render(fmtU(g.PassARP)),
		labelStyle.Render("ip fragment") + passStyle.Render(fmtU(g.PassFragment)),
		labelStyle.Render("tcp established") + passStyle.Render(fmtU(g.PassTCPEst)),
		labelStyle.Render("udp flow") + passStyle.Render(fmtU(g.PassUDPFlow)),
		labelStyle.Render("udp flow pps") + passStyle.Render(fmtNum(s.PpsUDPFlow)),
		labelStyle.Render("dhcp") + passStyle.Render(fmtU(g.PassDHCP)),
		labelStyle.Render("icmp") + passStyle.Render(fmtU(g.PassICMP)),
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
	box := renderTopBox(s, maxRows, m.topCursor, m.width)
	hint := dimStyle.Render(fmt.Sprintf("  %d entries in perip table  |  ↑↓ scroll  home/end jump  ",
		len(s.Top)))
	return "\n" + box + "\n" + hint + "\n"
}

func (m *Model) viewCharts() string {
	s := m.cur
	if s == nil {
		return "\n"
	}
	w := m.width - 28
	if w < 32 {
		w = 32
	}
	if w > 96 {
		w = 96
	}

	trafficBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◈ Traffic trend (last 120s)"),
		renderSeriesLine("pps total ", m.ppsHist, w, fillCyan, s.PPS),
		renderSeriesLine("pps drop  ", m.dpsHist, w, fillDanger, s.DPS),
		dimStyle.Render("left=old  right=now"),
	}, "\n"))

	protoBox := boxStyle.Render(strings.Join([]string{
		titleStyle.Render("◈ Protocol trend (last 120s)"),
		renderSeriesLine("tcp pps   ", m.tcpHist, w, fillPass, s.PpsTCP),
		renderSeriesLine("udp pps   ", m.udpHist, w, fillWarn, s.PpsUDP),
		renderSeriesLine("icmp pps  ", m.icmpHist, w, fillMagenta, s.PpsICMP),
		renderSeriesLine("udp flow  ", m.udpFlowHist, w, fillBarrier, s.PpsUDPFlow),
		dimStyle.Render("adaptive scale per line"),
	}, "\n"))

	return "\n" + trafficBox + "\n" + protoBox + "\n"
}

// ---------- helpers -------------------------------------------------------

func renderTopBox(s *Snapshot, limit, cursor, termWidth int) string {
	addrW := addrColumnWidth(termWidth)
	header := fmt.Sprintf("  %-3s %-*s %-14s %-14s %-10s %-5s %s",
		"#", addrW, "SRC_IP", "PKTS", "BYTES", "DROPPED", "PROTO", "STATUS")

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
		line := fmt.Sprintf("  %-3d %-*s %-14s %-14s %-10s %-5s %s",
			i+1,
			addrW,
			truncateMiddle(FormatAddr(e.Addr), addrW),
			fmtU(e.Pkts),
			humanBytes(e.Bytes),
			fmtU(e.PktsDropped),
			protoName(e.Proto),
			status,
		)
		if i == cursor {
			line = rowSelected.Render(line)
		}
		rows = append(rows, line)
	}
	return boxStyle.Render(strings.Join(rows, "\n"))
}

// ---------- formatting (shared with internal/stats) -----------------------

// addrColMax is a full IPv6 textual address ("ffff:...:ffff", 39 columns).
const addrColMax = 39

// addrColumnWidth sizes the SRC_IP column so the row, the rounded border,
// and the one-cell padding stay inside the terminal. A full address is used
// when it fits; otherwise the caller truncates it.
func addrColumnWidth(termWidth int) int {
	const chrome = 4 // left/right border + Padding(0, 1)
	const fixed = 61 // visual columns in the row besides the address
	if termWidth <= 0 {
		return 16
	}
	w := termWidth - chrome - fixed
	if w > addrColMax {
		return addrColMax
	}
	if w < 8 {
		return 8
	}
	return w
}

// truncateMiddle shortens s to width columns with a single-column ellipsis
// in the middle. Addresses are ASCII, so byte slices match columns.
func truncateMiddle(s string, width int) string {
	if width <= 0 || len(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	keep := width - 1
	left := keep / 2
	right := keep - left
	return s[:left] + "…" + s[len(s)-right:]
}

// ipv6Share is PktsIPv6 over the IP protocol mix. Those counters increment
// only for IP packets, and the IPv6 counters only when the family is IPv6.
func ipv6Share(g stats.Global) string {
	den := g.PktsTCP + g.PktsUDP + g.PktsICMP + g.PktsOther
	if den == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", float64(g.PktsIPv6)*100/float64(den))
}

func fmtU(v uint64) string       { return stats.FormatCount(v) }
func fmtNum(v float64) string    { return stats.FormatRate(v) }
func humanBits(v float64) string { return stats.HumanBits(v) }
func humanBytes(v uint64) string { return stats.HumanBytes(v) }
func protoName(p uint8) string   { return stats.ProtoName(p) }

func renderSeriesLine(label string, series []float64, width int, color lipgloss.Style, latest float64) string {
	graph := sparkline(series, width, color)
	val := valueStyle.Render(fmtNum(latest))
	return labelNarrow.Render(label) + graph + "  " + val
}

func sparkline(series []float64, width int, color lipgloss.Style) string {
	if width <= 0 {
		return ""
	}
	if len(series) == 0 {
		return dimStyle.Render(strings.Repeat("·", width))
	}
	// Downsample to requested width. Charts page caps width at 96, so use a
	// fixed stack buffer in steady-state to avoid per-frame heap allocations.
	var sampledFixed [96]float64
	sampled := sampledFixed[:0]
	if width <= len(sampledFixed) {
		sampled = sampledFixed[:width]
	} else {
		sampled = make([]float64, width)
	}
	if len(series) <= width {
		start := width - len(series)
		for i := 0; i < start; i++ {
			sampled[i] = 0
		}
		copy(sampled[start:], series)
	} else {
		for i := 0; i < width; i++ {
			src := int(float64(i) * float64(len(series)-1) / float64(width-1))
			sampled[i] = series[src]
		}
	}
	maxV := 0.0
	for _, v := range sampled {
		if v > maxV {
			maxV = v
		}
	}
	if maxV <= 0 {
		return dimStyle.Render(strings.Repeat("·", width))
	}
	var b strings.Builder
	b.Grow(width * 3) // block glyphs are multi-byte UTF-8
	for _, v := range sampled {
		level := int((v / maxV) * float64(len(sparkBlocks)-1))
		if level < 0 {
			level = 0
		}
		if level >= len(sparkBlocks) {
			level = len(sparkBlocks) - 1
		}
		b.WriteRune(sparkBlocks[level])
	}
	return color.Render(b.String())
}
