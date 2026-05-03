package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/updates"
)

// updateContent renders the active Update view.
func (m Model) updateContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Update Tools & Rules"),
		"",
	}
	switch m.updateState.view {
	case updateViewMenu:
		lines = append(lines, m.updateViewMenu(width)...)
	case updateViewError:
		lines = append(lines, m.updateViewError(width)...)
	case updateViewMessage, updateViewVanGuardCheck:
		lines = append(lines, m.updateViewMessage(width)...)
	case updateViewChecking, updateViewUpdating, updateViewBundleCreating:
		lines = append(lines, m.updateViewRunning(width)...)
	case updateViewCheckDone:
		lines = append(lines, m.updateViewCheckDone(width)...)
	case updateViewBundleSelect:
		lines = append(lines, m.updateViewBundleSelect(width)...)
	case updateViewBundleDone:
		lines = append(lines, m.updateViewBundleDone(width)...)
	case updateViewBundleApply:
		lines = append(lines, m.updateViewBundleApply(width)...)
	case updateViewToolPick:
		lines = append(lines, m.updateViewToolPick(width)...)
	case updateViewApplyPath:
		lines = append(lines, m.updateViewApplyPath(width)...)
	}
	return lines
}

// ---------------------------------------------------------------------------
// [3] Tool picker
// ---------------------------------------------------------------------------

func (m Model) updateViewToolPick(width int) []string {
	out := []string{cSectionLabel("Update Specific Tool"), cRule(width), ""}
	if len(m.updateState.toolPickItems) == 0 {
		out = append(out, "  "+WarningStyle.Render(
			"No updateable tools registered. (Manual-install tools aren't shown.)"))
		out = append(out, "", cHint("Press Esc to return."))
		return out
	}
	out = append(out, fmt.Sprintf("  %-3s %-22s %-16s %s", "#", "Tool", "Installed", "Status"))
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorBorder).
		Render(strings.Repeat(boxHorizontal, 60)))

	for i, s := range m.updateState.toolPickItems {
		shortcut := "   "
		if i < 9 {
			shortcut = fmt.Sprintf("[%d]", i+1)
		}
		ver := s.Version
		if ver == "" {
			ver = "(unknown)"
		}
		status := "installed"
		statusFg := ColorSuccess
		if !s.Installed {
			status = "not installed"
			statusFg = ColorTextMuted
		}
		row := fmt.Sprintf("%s %-22s %-16s %s",
			shortcut, truncDisk(s.Name, 22), ver,
			lipgloss.NewStyle().Foreground(statusFg).Render(status))
		if i == m.updateState.toolPickCursor {
			out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+row))
		} else {
			out = append(out, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}
	out = append(out, "")
	out = append(out, cHint("Up/Down: navigate   Enter or shortcut: update   Esc: cancel"))
	return out
}

// ---------------------------------------------------------------------------
// [9] Apply path entry
// ---------------------------------------------------------------------------

func (m Model) updateViewApplyPath(width int) []string {
	return []string{
		cSectionLabel("Apply Offline Update Bundle"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Path to bundle directory or .zip:"),
		"",
		"  " + m.updateState.pathInput.View(),
		"",
		cHint("Enter: apply   Esc: cancel"),
		cHint("Tip: a recent bundle path is pre-filled when one exists."),
	}
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

func (m Model) updateViewMenu(width int) []string {
	rows := updateMenuItems()
	out := []string{cSectionLabel("Update Tools & Rules"), cRule(width), ""}

	last := updates.ReadLastCheck(m.ctx.RootDir)
	lastLabel := "Never"
	if !last.IsZero() {
		lastLabel = last.Local().Format("2006-01-02 15:04") +
			" (" + updates.FormatAge(last) + ")"
	}
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render("Last update check: "+lastLabel), "")

	groups := []struct {
		label string
		from  int
		to    int
	}{
		{"TOOL UPDATES", 0, 3},
		{"RULE UPDATES", 3, 7},
		{"AIR-GAPPED SUPPORT", 7, 9},
		{"VANGUARD", 9, 10},
	}
	for gi, g := range groups {
		if gi > 0 {
			out = append(out, "")
		}
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).Render(g.label))
		for i := g.from; i < g.to; i++ {
			r := rows[i]
			selected := i == m.updateState.menuCursor
			marker := " "
			if selected {
				marker = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(blockLeftHalf)
			}
			num := lipgloss.NewStyle().Foreground(ColorAccent).Render("[" + r.shortcut + "]")
			label := lipgloss.NewStyle().Foreground(ColorText).Render(r.label)
			if selected {
				num = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("[" + r.shortcut + "]")
				label = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(r.label)
			}
			out = append(out, "  "+marker+" "+num+"  "+label)
		}
	}
	out = append(out, "", cHint("Up/Down: navigate   Enter or shortcut: select   Esc: back"))
	return out
}

// ---------------------------------------------------------------------------
// Generic message / error / running
// ---------------------------------------------------------------------------

func (m Model) updateViewError(width int) []string {
	out := []string{cSectionLabel("Update — Error"), cRule(width), ""}
	for _, line := range strings.Split(m.updateState.errorMsg, "\n") {
		out = append(out, "  "+ErrorStyle.Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) updateViewMessage(width int) []string {
	out := []string{cSectionLabel(m.updateState.messageTitle), cRule(width), ""}

	// Outcome-table view (after an update batch finishes).
	if len(m.updateState.outcomes) > 0 {
		out = append(out, m.formatOutcomes()...)
	} else {
		for _, line := range m.updateState.messageLines {
			out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
		}
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) formatOutcomes() []string {
	var out []string
	successes, failures := 0, 0
	for _, o := range m.updateState.outcomes {
		var marker string
		if o.Success {
			marker = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓")
			successes++
		} else {
			marker = lipgloss.NewStyle().Foreground(ColorError).Render("✗")
			failures++
		}
		from := o.From
		if from == "" {
			from = "—"
		}
		to := o.To
		if to == "" {
			to = "—"
		}
		row := fmt.Sprintf("%s  %-30s %-12s → %-12s  %s",
			marker, truncDisk(o.Name, 30), from, to,
			o.Duration.Truncate(time.Second))
		out = append(out, "  "+row)
		if o.Error != "" {
			out = append(out, "    "+ErrorStyle.Render(o.Error))
		}
	}
	out = append(out, "")
	out = append(out, fmt.Sprintf("  Updated: %d   Failed: %d", successes, failures))
	return out
}

func (m Model) updateViewRunning(width int) []string {
	return []string{
		cSectionLabel(m.updateState.operation), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Working..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.updateState.elapsed)),
		"",
		cHint("Long-running downloads may take many minutes."),
	}
}

// ---------------------------------------------------------------------------
// Check result table
// ---------------------------------------------------------------------------

func (m Model) updateViewCheckDone(width int) []string {
	out := []string{
		cSectionLabel("Update Check — " + m.updateState.report.GeneratedAt.Format("2006-01-02 15:04")),
		cRule(width),
		"",
	}
	hdr := fmt.Sprintf("  %-22s %-15s %-15s %s", "Tool", "Installed", "Latest", "Status")
	out = append(out, TableHeaderStyle.Render(hdr))
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorBorder).
		Render(strings.Repeat(boxHorizontal, 70)))

	for _, r := range m.updateState.report.Results {
		status := updateStatusLabel(r.Status)
		row := fmt.Sprintf("  %-22s %-15s %-15s %s",
			truncDisk(r.Name, 22), r.InstalledLabel, r.LatestLabel, status)
		out = append(out, lipgloss.NewStyle().Foreground(ColorText).Render(row))
		if r.Reason != "" {
			out = append(out, "    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Reason))
		}
	}

	uptodate, avail, ni, errs := m.updateState.report.CountByStatus()
	out = append(out, "")
	out = append(out, fmt.Sprintf("  %d up to date   %d updates available   %d not installed   %d errors",
		uptodate, avail, ni, errs))
	if avail > 0 {
		out = append(out, "")
		out = append(out, cHint("[A] Update all   [Esc] Back"))
	} else {
		out = append(out, "", cHint("Press Esc to return"))
	}
	return out
}

func updateStatusLabel(s updates.Status) string {
	switch s {
	case updates.StatusUpToDate:
		return SuccessStyle.Render("Up to date")
	case updates.StatusUpdateAvail:
		return WarningStyle.Render("Update available")
	case updates.StatusNotInstalled:
		return lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Not installed")
	case updates.StatusError:
		return ErrorStyle.Render("Error")
	}
	return string(s)
}

// ---------------------------------------------------------------------------
// Bundle picker / done
// ---------------------------------------------------------------------------

func (m Model) updateViewBundleSelect(width int) []string {
	out := []string{cSectionLabel("Create Offline Update Bundle"), cRule(width), ""}
	out = append(out, "  Select components to include:")
	out = append(out, "")
	for i, opt := range m.updateState.bundleOptions {
		box := "[ ]"
		boxFg := ColorTextMuted
		if opt.Selected {
			box = "[x]"
			boxFg = ColorSuccess
		}
		boxStr := lipgloss.NewStyle().Foreground(boxFg).Render(box)
		row := opt.Label
		if i == m.updateState.bundleCursor {
			out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+box+" "+row))
		} else {
			out = append(out, "    "+boxStr+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}
	out = append(out, "")
	out = append(out, cHint("Space: toggle   A: all   N: none   Enter: create bundle   Esc: cancel"))
	return out
}

func (m Model) updateViewBundleDone(width int) []string {
	r := m.updateState.bundleResult
	if r == nil {
		return []string{"  " + ErrorStyle.Render("(no result)")}
	}
	return []string{
		cSectionLabel("Offline Update Bundle Created"), cRule(width),
		"",
		"  " + SuccessStyle.Render("Bundle ready."),
		"",
		cField("Location", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.BundleDir)),
		cField("Manifest", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.ManifestPath)),
		cField("Components", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d", r.Components))),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(formatDiskBytes(r.Bytes))),
		"",
		cHint("Transfer this directory to air-gapped systems via USB."),
		cHint("Apply with: VanGuard > Update [U] > [9] Apply Offline Bundle"),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) updateViewBundleApply(width int) []string {
	r := m.updateState.bundleApply
	if r == nil {
		return []string{"  " + ErrorStyle.Render("(no result)")}
	}
	out := []string{
		cSectionLabel("Offline Update Bundle Applied"),
		cRule(width),
		"",
		"  Bundle created: " + r.Manifest.Created.Format("2006-01-02 15:04 UTC"),
		"  Components:     " + fmt.Sprintf("%d", len(r.Manifest.Components)),
		"",
	}
	successes, failures := 0, 0
	for _, o := range r.Outcomes {
		var marker string
		if o.Success {
			marker = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓")
			successes++
		} else {
			marker = lipgloss.NewStyle().Foreground(ColorError).Render("✗")
			failures++
		}
		out = append(out, fmt.Sprintf("  %s  %-26s %s",
			marker, truncDisk(o.Name, 26), o.To))
		if o.Error != "" {
			out = append(out, "      "+ErrorStyle.Render(o.Error))
		}
	}
	out = append(out, "")
	out = append(out, fmt.Sprintf("  Applied: %d   Failed: %d", successes, failures))
	out = append(out, "", cHint("Press any key to return"))
	return out
}

// ---------------------------------------------------------------------------
// Tiny IO indirection used by the panel.
// ---------------------------------------------------------------------------

// osExecutable wraps os.Executable so the panel file doesn't need a direct
// os import for that single call.
func osExecutable() (string, error) { return os.Executable() }
