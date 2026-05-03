package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/analysis"
)

// analysisContent renders the active Analysis & Reporting view.
func (m Model) analysisContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Analysis & Reporting"),
		"",
	}

	switch m.analysisState.view {
	case analysisViewNeedCase:
		lines = append(lines, m.analysisViewNeedCase(width)...)
	case analysisViewError:
		lines = append(lines, m.analysisViewError(width)...)
	case analysisViewMessage:
		lines = append(lines, m.analysisViewMessage(width)...)
	case analysisViewSourceSelect:
		lines = append(lines, m.analysisViewSourceSelect(width)...)
	case analysisViewRunning:
		lines = append(lines, m.analysisViewRunning(width)...)
	case analysisViewSummary:
		lines = append(lines, m.analysisViewSummary(width)...)
	case analysisViewReportDone, analysisViewExportDone:
		lines = append(lines, m.analysisViewSummary(width)...)
	case analysisViewNeedTool:
		lines = append(lines, m.analysisViewError(width)...)
	}
	return lines
}

func (m Model) analysisViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Analysis & Reporting"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
	}
}

func (m Model) analysisViewError(width int) []string {
	out := []string{cSectionLabel("Analysis & Reporting — Error"), cRule(width), ""}
	for _, line := range strings.Split(m.analysisState.errorMsg, "\n") {
		out = append(out, "  "+ErrorStyle.Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) analysisViewMessage(width int) []string {
	out := []string{cSectionLabel(m.analysisState.operation), cRule(width), ""}
	for _, line := range m.analysisState.resultLines {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) analysisViewRunning(width int) []string {
	return []string{
		cSectionLabel(m.analysisState.operation), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.analysisState.elapsed)),
		"",
		cHint("Long-running analyses may take several minutes."),
	}
}

func (m Model) analysisViewSummary(width int) []string {
	lines := []string{cSectionLabel(m.analysisState.operation), cRule(width), ""}
	for _, l := range m.analysisState.resultLines {
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(l))
	}
	if m.analysisState.findingsAdded > 0 {
		lines = append(lines, "",
			"  "+SuccessStyle.Render(fmt.Sprintf(
				"%d finding(s) added to the case database.", m.analysisState.findingsAdded)))
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) analysisViewSourceSelect(width int) []string {
	lines := []string{
		cSectionLabel(m.analysisState.operation + " — Select Data Source"), cRule(width),
		"",
	}

	if len(m.analysisState.sources) == 0 {
		lines = append(lines, "  "+WarningStyle.Render("No collections found for this case."))
		lines = append(lines, "", cHint("Run Quick Triage [4] or Disk Collection [2] first."))
		lines = append(lines, "", cHint("Esc to return"))
		return lines
	}

	var lastKind analysis.SourceKind
	for i, s := range m.analysisState.sources {
		if s.Kind != lastKind {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).
				Render(strings.ToUpper(string(s.Kind))+" COLLECTIONS"))
			lastKind = s.Kind
		}
		shortcut := ""
		if i < 9 {
			shortcut = fmt.Sprintf("[%d]", i+1)
		} else {
			shortcut = "   "
		}
		row := fmt.Sprintf("%s %-44s %6d files  %s",
			shortcut, truncDisk(s.Label, 44), s.Files, analysis.FormatBytes(s.Bytes))
		if i == m.analysisState.sourceCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+row))
		} else {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Up/Down: navigate  Enter: select  Esc: cancel"))
	return lines
}

// ---------------------------------------------------------------------------
// IO indirections used by analysis_panel.go
// ---------------------------------------------------------------------------

// osReadDir wraps os.ReadDir; lets analysis_panel.go avoid pulling the os
// import in just for two call sites.
func osReadDir(dir string) ([]os.DirEntry, error) {
	return os.ReadDir(dir)
}
