package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Color palette — dark blue professional theme.
const (
	ColorPrimary       = lipgloss.Color("#4FC3F7")
	ColorAccent        = lipgloss.Color("#29B6F6")
	ColorHighlight     = lipgloss.Color("#FFFFFF")
	ColorSuccess       = lipgloss.Color("#66BB6A")
	ColorWarning       = lipgloss.Color("#FFA726")
	ColorError         = lipgloss.Color("#EF5350")
	ColorCritical      = lipgloss.Color("#FF1744")
	ColorSidebarBg     = lipgloss.Color("#0A1929")
	ColorContentBg     = lipgloss.Color("#0D2137")
	ColorHeaderBg      = lipgloss.Color("#071320")
	ColorStatusBg      = lipgloss.Color("#071320")
	ColorBorder        = lipgloss.Color("#1E3A5F")
	ColorText          = lipgloss.Color("#E3F2FD")
	ColorTextSecondary = lipgloss.Color("#90A4AE")
	ColorTextMuted     = lipgloss.Color("#546E7A")
	ColorSelectedBg    = lipgloss.Color("#1565C0")
)

// SidebarWidth is the fixed character width of the sidebar including its border.
const SidebarWidth = 24

// Box-drawing characters used by helpers across the TUI.
const (
	boxHorizontal = "─" // ─
	boxVertical   = "│" // │
	boxTopLeft    = "┌" // ┌
	boxTopRight   = "┐" // ┐
	boxBottomLeft = "└" // └
	boxBotRight   = "┘" // ┘
	blockLeftHalf = "▌" // ▌  used as the selection indicator
	blockFull     = "█" // █  progress-bar filled cell
	blockShade    = "░" // ░  progress-bar empty cell
)

// Styles.
var (
	SidebarItemStyle = lipgloss.NewStyle().
				Foreground(ColorText).
				Background(ColorSidebarBg)

	SidebarItemSelectedStyle = lipgloss.NewStyle().
					Foreground(ColorHighlight).
					Background(ColorSelectedBg).
					Bold(true)

	StatusBarStyle = lipgloss.NewStyle().
			Background(ColorStatusBg).
			Foreground(ColorText)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorError).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(ColorSuccess).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(ColorWarning)

	TableHeaderStyle = lipgloss.NewStyle().
				Foreground(ColorPrimary).
				Bold(true)

	TableRowStyle = lipgloss.NewStyle().
			Foreground(ColorText)

	TableRowAltStyle = lipgloss.NewStyle().
				Foreground(ColorTextSecondary)

	SpinnerStyle = lipgloss.NewStyle().
			Foreground(ColorPrimary)

	ProgressBarStyle = lipgloss.NewStyle().
				Foreground(ColorPrimary)
)

// RenderHeader builds the four-row header area: empty line, branding line,
// empty line, then a thin horizontal rule that visually anchors the header.
//
// "VANGUARD" is rendered with letter-spacing ("V A N G U A R D") to give it
// a logo-like presence, and is bracketed by short ── runs that lift the row
// off the empty background.
func RenderHeader(width int, version string) string {
	if width < 40 {
		width = 40
	}

	bg := ColorHeaderBg
	emptyLine := lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", width))

	dash := lipgloss.NewStyle().Foreground(ColorBorder).Background(bg).Render(boxHorizontal + boxHorizontal)
	brand := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Background(bg).
		Render("V A N G U A R D")
	dot := lipgloss.NewStyle().Foreground(ColorTextMuted).Background(bg).Render("  ·  ")
	subtitle := lipgloss.NewStyle().Bold(true).Foreground(ColorText).Background(bg).
		Render("DFIR Toolkit")
	leadSpace := lipgloss.NewStyle().Background(bg).Render("  ")
	gapSpace := lipgloss.NewStyle().Background(bg).Render(" ")

	left := leadSpace + dash + gapSpace + brand + gapSpace + dash + dot + subtitle

	right := lipgloss.NewStyle().Foreground(ColorTextSecondary).Background(bg).
		Render(fmt.Sprintf("RidgeLine Cyber  v%s  ", version))

	leftW := lipgloss.Width(left)
	rightW := lipgloss.Width(right)
	gap := width - leftW - rightW
	if gap < 1 {
		gap = 1
	}

	brandLine := left +
		lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", gap)) +
		right

	// Thin rule under the header, anchored at the same width.
	rule := lipgloss.NewStyle().Foreground(ColorBorder).Background(bg).
		Render(strings.Repeat(boxHorizontal, width))

	return emptyLine + "\n" + brandLine + "\n" + emptyLine + "\n" + rule
}

// RenderStatusBar builds the two-row status area: a thin horizontal rule, then
// the single-line status bar pinned to the bottom of the screen.
//
// caseLabel should be either an empty string ("None" rendered) or a
// pre-formatted "<case-name> (<case-id>)" string. Truncation is applied
// here when the label is too long for the bar.
func RenderStatusBar(width int, platform, hostname, elevated, caseLabel, version string) string {
	if width < 40 {
		width = 40
	}

	bg := ColorStatusBg
	rule := lipgloss.NewStyle().Foreground(ColorBorder).Background(bg).
		Render(strings.Repeat(boxHorizontal, width))

	sep := lipgloss.NewStyle().Foreground(ColorBorder).Background(bg).Render("  " + boxVertical + "  ")
	dim := func(s string) string {
		return lipgloss.NewStyle().Foreground(ColorTextSecondary).Background(bg).Render(s)
	}

	plat := dim("Platform: ") +
		lipgloss.NewStyle().Foreground(ColorPrimary).Background(bg).Render(platform)

	host := dim("Host: ") +
		lipgloss.NewStyle().Foreground(ColorPrimary).Background(bg).Render(hostname)

	elevFg := ColorSuccess
	if elevated != "Yes" {
		elevFg = ColorWarning
	}
	elev := dim("Elevated: ") +
		lipgloss.NewStyle().Foreground(elevFg).Background(bg).Render(elevated)

	caseFg := lipgloss.Color(ColorWarning)
	displayLabel := "None"
	if caseLabel != "" {
		displayLabel = caseLabel
		caseFg = ColorPrimary
	}
	// Cap the case label so it doesn't push the version off the right edge.
	if len(displayLabel) > 50 {
		displayLabel = displayLabel[:47] + "..."
	}
	cs := dim("Case: ") +
		lipgloss.NewStyle().Foreground(caseFg).Background(bg).Render(displayLabel)

	ver := lipgloss.NewStyle().Foreground(ColorTextMuted).Background(bg).Render("VanGuard v" + version)

	content := lipgloss.NewStyle().Background(bg).Render("  ") +
		plat + sep + host + sep + elev + sep + cs + sep + ver

	contentW := lipgloss.Width(content)
	if contentW < width {
		content += lipgloss.NewStyle().Background(bg).Render(strings.Repeat(" ", width-contentW))
	}

	return rule + "\n" + content
}

// FormatCaseLabel returns the canonical "<name> (<id>)" string used in the
// status bar and content panes. Empty case → "" (caller renders "None").
func FormatCaseLabel(name, id string) string {
	if id == "" {
		return ""
	}
	if name == "" || name == id {
		return id
	}
	short := name
	if len(short) > 32 {
		short = short[:29] + "..."
	}
	return fmt.Sprintf("%s (%s)", short, id)
}

// ---------------------------------------------------------------------------
// Generic content-pane rendering helpers (boxes, progress bars)
// ---------------------------------------------------------------------------

// SectionRule returns the horizontal rule appended after a section label like
// "COLLECTION ─────────────────". The rule fills out to width but is capped so
// it doesn't dominate the line on narrow terminals.
func SectionRule(label string, width int) string {
	labelStyled := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(label)
	used := lipgloss.Width(labelStyled) + 4 // 2 left margin + " " + dashes
	dashCount := width - used
	if dashCount < 6 {
		dashCount = 6
	}
	if dashCount > 80 {
		dashCount = 80
	}
	dashes := lipgloss.NewStyle().Foreground(ColorBorder).
		Render(strings.Repeat(boxHorizontal, dashCount))
	return "  " + labelStyled + " " + dashes
}

// BoxLines wraps the supplied content lines in a single-line border with
// `title` rendered into the top edge ("┌ Title ──────┐"). Inner content is
// padded so the right border lands at column `innerWidth + 4` (2 pad each side
// + 2 borders).
//
// content lines should NOT be pre-padded; BoxLines applies left/right padding
// itself. Lines longer than innerWidth are truncated.
func BoxLines(title string, innerWidth int, content []string) []string {
	if innerWidth < 20 {
		innerWidth = 20
	}
	titleStyled := lipgloss.NewStyle().Bold(true).Foreground(ColorPrimary).Render(title)
	titleW := lipgloss.Width(titleStyled)

	// Top edge: ┌─ Title ──────────┐
	dashesAfter := innerWidth - titleW - 3 // " Title " + leading "─"
	if dashesAfter < 1 {
		dashesAfter = 1
	}
	border := func(s string) string {
		return lipgloss.NewStyle().Foreground(ColorBorder).Render(s)
	}
	top := "  " + border(boxTopLeft+boxHorizontal) + " " +
		titleStyled + " " +
		border(strings.Repeat(boxHorizontal, dashesAfter)+boxTopRight)

	mid := make([]string, 0, len(content)+2)
	for _, line := range content {
		// Visible width — truncate if necessary.
		w := lipgloss.Width(line)
		if w > innerWidth-2 {
			// Truncate at the rune boundary by trimming whitespace-padded copy.
			trim := truncateVisible(line, innerWidth-2)
			line = trim
			w = lipgloss.Width(line)
		}
		pad := strings.Repeat(" ", innerWidth-2-w)
		mid = append(mid, "  "+border(boxVertical)+" "+line+pad+" "+border(boxVertical))
	}

	bottom := "  " + border(boxBottomLeft+strings.Repeat(boxHorizontal, innerWidth)+boxBotRight)

	return append(append([]string{top}, mid...), bottom)
}

// PlainBoxLines renders an untitled bordered block — used for messages like
// "feature not yet implemented" where the box itself is the framing.
func PlainBoxLines(innerWidth int, content []string) []string {
	if innerWidth < 20 {
		innerWidth = 20
	}
	border := func(s string) string {
		return lipgloss.NewStyle().Foreground(ColorBorder).Render(s)
	}
	top := "  " + border(boxTopLeft+strings.Repeat(boxHorizontal, innerWidth)+boxTopRight)
	bottom := "  " + border(boxBottomLeft+strings.Repeat(boxHorizontal, innerWidth)+boxBotRight)

	mid := make([]string, 0, len(content))
	for _, line := range content {
		w := lipgloss.Width(line)
		if w > innerWidth-2 {
			line = truncateVisible(line, innerWidth-2)
			w = lipgloss.Width(line)
		}
		pad := strings.Repeat(" ", innerWidth-2-w)
		mid = append(mid, "  "+border(boxVertical)+" "+line+pad+" "+border(boxVertical))
	}

	return append(append([]string{top}, mid...), bottom)
}

// TextProgressBar renders a percentage progress bar like
// "[████████░░░░░░░░░░░░] 40%". width is the number of cells in the bar
// (excluding the brackets and percentage label).
func TextProgressBar(percent float64, width int) string {
	if width < 4 {
		width = 4
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := int((percent / 100.0) * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled

	full := lipgloss.NewStyle().Foreground(ColorPrimary).Render(strings.Repeat(blockFull, filled))
	rest := lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat(blockShade, empty))
	bracket := lipgloss.NewStyle().Foreground(ColorTextMuted)
	pct := lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf(" %3.0f%%", percent))
	return bracket.Render("[") + full + rest + bracket.Render("]") + pct
}

// truncateVisible cuts s so its rendered width is at most max, accounting for
// ANSI escape sequences via lipgloss.Width. It walks the string by rune so a
// partial escape sequence is never produced.
func truncateVisible(s string, max int) string {
	if lipgloss.Width(s) <= max {
		return s
	}
	// Best-effort byte-by-byte truncation. Style escapes are short and we
	// don't try to preserve them perfectly — any visible difference here
	// affects truncated tail strings only.
	runes := []rune(s)
	for i := len(runes); i > 0; i-- {
		candidate := string(runes[:i])
		if lipgloss.Width(candidate) <= max-1 {
			return candidate + "…" // …
		}
	}
	return ""
}

// renderOutputPath formats a filesystem path for display alongside an
// "Output:" label. Output paths are important for the analyst (they need to
// know where artifacts landed), so we render them in the bright Primary
// colour and truncate to fit the pane width when needed.
func renderOutputPath(path string, paneWidth int) string {
	maxLen := contentTextWidth(paneWidth) - 14 // reserve room for "Output:" label
	if maxLen < 30 {
		maxLen = 30
	}
	return lipgloss.NewStyle().Foreground(ColorPrimary).Render(TruncatePath(path, maxLen))
}

// contentTextWidth returns the practical inner width for content text given a
// pane width. Subtracts the content pane's left margin and a small right
// safety gutter so right-edge characters don't get clipped by terminals that
// reserve a column for cursor wrap.
func contentTextWidth(paneWidth int) int {
	w := paneWidth - 6
	if w < 30 {
		w = 30
	}
	if w > 120 {
		w = 120
	}
	return w
}

// TruncatePath shortens a long path by replacing the middle with "..." while
// keeping the head (drive/root) and the tail (filename / leaf directory)
// readable. Returns the path unchanged if it already fits.
//
// Example: TruncatePath(`C:\Users\admin82.GR\Desktop\Vanguard\output\<case>\triage\20260501_163217`, 60)
// returns: `C:\Users\admin82.GR\...\output\<case>\triage\20260501_163217` (truncated middle).
func TruncatePath(path string, maxLen int) string {
	if maxLen < 12 {
		maxLen = 12
	}
	if len(path) <= maxLen {
		return path
	}
	const sep = "..."
	headLen := 20
	tailLen := maxLen - headLen - len(sep)
	if tailLen < 8 {
		tailLen = 8
		headLen = maxLen - tailLen - len(sep)
		if headLen < 4 {
			// Path is so long the middle gets crushed. Just keep the tail.
			if tailLen >= len(path) {
				return path
			}
			return sep + path[len(path)-tailLen:]
		}
	}
	return path[:headLen] + sep + path[len(path)-tailLen:]
}

// WrapTextLines wraps a single line to fit within width by breaking on word
// boundaries when possible. Long words that exceed width are split at the
// boundary. Returns the wrapped lines (>=1).
func WrapTextLines(s string, width int) []string {
	if width <= 0 || lipgloss.Width(s) <= width {
		return []string{s}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}
	var (
		lines   []string
		current strings.Builder
	)
	for _, w := range words {
		// Word longer than the available width: hard-break it.
		for lipgloss.Width(w) > width {
			if current.Len() > 0 {
				lines = append(lines, current.String())
				current.Reset()
			}
			lines = append(lines, w[:width])
			w = w[width:]
		}
		needed := lipgloss.Width(w)
		if current.Len() > 0 {
			needed++ // for the joining space
		}
		if lipgloss.Width(current.String())+needed > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(w)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

// FormatStderr indents stderr captured from external commands so it reads as
// quoted output rather than mixing with the TUI chrome. Long lines are
// truncated. Empty input returns an empty slice.
func FormatStderr(stderr string, maxWidth int) []string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return nil
	}
	if maxWidth < 20 {
		maxWidth = 20
	}
	var out []string
	for _, raw := range strings.Split(stderr, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		// Indent and truncate. Stderr from system tools tends to be one line
		// of error per failure — wrapping spans is more confusing than helpful.
		indented := "    " + line
		if lipgloss.Width(indented) > maxWidth {
			indented = truncateVisible(indented, maxWidth)
		}
		out = append(out, indented)
		if len(out) >= 12 {
			out = append(out, "    ... (truncated)")
			break
		}
	}
	return out
}
