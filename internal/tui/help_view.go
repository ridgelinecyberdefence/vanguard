package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/help"
)

// helpContent renders the active Help view.
func (m Model) helpContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Help & Documentation"),
		"",
	}
	switch m.helpState.view {
	case helpViewMenu:
		lines = append(lines, m.helpViewMenu(width)...)
	case helpViewPage:
		lines = append(lines, m.helpViewPage(width)...)
	}
	return lines
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

func (m Model) helpViewMenu(width int) []string {
	out := []string{cSectionLabel("Help & Documentation"), cRule(width), ""}

	items := help.Menu()
	sections := help.Sections()
	for gi, sec := range sections {
		if gi > 0 {
			out = append(out, "")
		}
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).
			Render(sec.Label))
		for i := sec.From; i < sec.To && i < len(items); i++ {
			r := items[i]
			selected := i == m.helpState.menuCursor

			marker := " "
			if selected {
				marker = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(blockLeftHalf)
			}

			num := lipgloss.NewStyle().Foreground(ColorAccent).Render("[" + r.Shortcut + "]")
			label := lipgloss.NewStyle().Foreground(ColorText).Render(r.Title)
			if selected {
				num = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("[" + r.Shortcut + "]")
				label = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(r.Title)
			}
			out = append(out, "  "+marker+" "+num+"  "+label)
		}
	}
	out = append(out, "", cHint("Up/Down: navigate   Enter or shortcut: open   Esc: back"))
	return out
}

// ---------------------------------------------------------------------------
// Page viewer with scrolling
// ---------------------------------------------------------------------------

func (m Model) helpViewPage(width int) []string {
	out := []string{cSectionLabel(m.helpState.currentTitle), cRule(width), ""}

	rows := m.helpViewportRows()
	max := m.helpMaxScroll()
	scroll := m.helpState.scroll
	if scroll > max {
		scroll = max
	}

	end := scroll + rows
	if end > len(m.helpState.pageLines) {
		end = len(m.helpState.pageLines)
	}
	for i := scroll; i < end; i++ {
		line := m.helpState.pageLines[i]
		if line == "" {
			out = append(out, "")
			continue
		}
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
	}

	// Footer / scroll indicator.
	out = append(out, "")
	if max == 0 {
		out = append(out, cHint("Esc: back to help index"))
	} else {
		bar := scrollBar(scroll, max, rows, len(m.helpState.pageLines))
		hint := fmt.Sprintf("↑/↓ scroll   PgUp/PgDn page   Home/End top/bottom   Esc back   %s", bar)
		out = append(out, cHint(hint))
		if scroll < max {
			out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorPrimary).Render("↓ Scroll for more"))
		}
	}
	return out
}

// scrollBar returns a "lines X-Y of N" progress label.
func scrollBar(scroll, max, viewport, total int) string {
	from := scroll + 1
	to := scroll + viewport
	if to > total {
		to = total
	}
	pct := 0
	if max > 0 {
		pct = int(float64(scroll) / float64(max) * 100)
	}
	return fmt.Sprintf("lines %d–%d / %d  (%d%%)",
		from, to, total, pct)
}

// _ keeps strings imported when conditional code paths drop their callers.
var _ = strings.Repeat
