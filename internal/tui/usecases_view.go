package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/usecases"
)

// usecasesContent renders the active Use Cases view.
func (m Model) usecasesContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Use Cases Library"),
		"",
	}
	if m.ctx.ActiveCase != nil {
		lines = append(lines, cField("Active Case",
			lipgloss.NewStyle().Foreground(ColorSuccess).Render(m.ctx.ActiveCase.ID)))
	} else {
		lines = append(lines, "  "+WarningStyle.Render(
			"No active case — running a use case requires one (create in [8])"))
	}
	lines = append(lines, "")

	switch m.usecasesState.view {
	case ucViewError:
		lines = append(lines, m.ucViewError(width)...)
	case ucViewList:
		lines = append(lines, m.ucViewList(width)...)
	case ucViewDetail:
		lines = append(lines, m.ucViewDetail(width)...)
	case ucViewParams:
		lines = append(lines, m.ucViewParams(width)...)
	case ucViewRunning:
		lines = append(lines, m.ucViewRunning(width)...)
	case ucViewSummary:
		lines = append(lines, m.ucViewSummary(width)...)
	case ucViewTemplateDone:
		lines = append(lines, m.ucViewTemplateDone(width)...)
	}
	return lines
}

func (m Model) ucViewError(width int) []string {
	out := []string{cSectionLabel("Use Cases — Error"), cRule(width), ""}
	for _, line := range strings.Split(m.usecasesState.errorMsg, "\n") {
		out = append(out, "  "+ErrorStyle.Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

// ---------------------------------------------------------------------------
// List view
// ---------------------------------------------------------------------------

func (m Model) ucViewList(width int) []string {
	items := m.usecasesState.items
	lines := []string{cSectionLabel("Use Cases Library"), cRule(width), ""}

	if len(items) == 0 {
		lines = append(lines, "  "+WarningStyle.Render("No use cases available for platform "+m.ctx.Platform+"."))
		return lines
	}

	// Group rendering by category prefix.
	var current string
	for i, uc := range items {
		section := categoryFor(uc)
		if section != current {
			if i > 0 {
				lines = append(lines, "")
			}
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorAccent).Bold(true).
				Render(section))
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorBorder).
				Render(strings.Repeat(boxHorizontal, 60)))
			current = section
		}
		row := fmt.Sprintf("%-12s %-44s %-10s %s",
			uc.ID, truncDisk(uc.Name, 44),
			severityLabel(uc.Severity), uc.EstimatedTime)
		if i == m.usecasesState.listCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+row))
		} else {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}

	// Trailing "Create custom template" entry.
	lines = append(lines, "")
	customRow := "Create Custom Use Case Template"
	if m.usecasesState.listCursor == len(items) {
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
			Render("> [+] "+customRow))
	} else {
		lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorAccent).Render("[+] ")+
			lipgloss.NewStyle().Foreground(ColorText).Render(customRow))
	}

	lines = append(lines, "")
	lines = append(lines, cHint("Up/Down: navigate   Enter: select   Esc: back"))
	return lines
}

// categoryFor returns the section header an item belongs in.
func categoryFor(uc *usecases.UseCase) string {
	switch {
	case strings.HasPrefix(uc.ID, "UC-WIN-"):
		return "WINDOWS INVESTIGATIONS"
	case strings.HasPrefix(uc.ID, "UC-LNX-"):
		return "LINUX INVESTIGATIONS"
	case strings.HasPrefix(uc.ID, "UC-XP-"):
		return "CROSS-PLATFORM"
	case strings.HasPrefix(uc.ID, "UC-CUSTOM-"):
		return "CUSTOM INVESTIGATIONS"
	}
	return "OTHER"
}

// severityLabel renders a coloured severity tag.
func severityLabel(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return ErrorStyle.Render("CRITICAL")
	case "high":
		return WarningStyle.Render("HIGH    ")
	case "medium":
		return lipgloss.NewStyle().Foreground(ColorPrimary).Render("MEDIUM  ")
	case "low":
		return lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("LOW     ")
	case "varies":
		return lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("VARIES  ")
	}
	return strings.ToUpper(s)
}

// ---------------------------------------------------------------------------
// Detail view
// ---------------------------------------------------------------------------

func (m Model) ucViewDetail(width int) []string {
	uc := m.usecasesState.selected
	if uc == nil {
		return []string{"  " + ErrorStyle.Render("(no use case selected)")}
	}
	out := []string{
		cSectionLabel(uc.ID + ": " + uc.Name),
		cRule(width),
		"",
		cField("Severity", severityLabel(uc.Severity)+
			lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("    Est. Time: "+uc.EstimatedTime)),
		cField("Platform", lipgloss.NewStyle().Foreground(ColorPrimary).Render(uc.Platform)),
		"",
	}
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render("Description:"))
	for _, line := range wrap(uc.Description, 70) {
		out = append(out, "    "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(line))
	}
	if len(uc.MITREAttack) > 0 {
		out = append(out, "")
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render("MITRE ATT&CK:"))
		out = append(out, "    "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			strings.Join(uc.MITREAttack, ", ")))
	}
	if len(uc.Prerequisites) > 0 {
		out = append(out, "")
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render("Prerequisites:"))
		for _, p := range uc.Prerequisites {
			out = append(out, "    • "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(p))
		}
	}

	out = append(out, "")
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render("Phases:"))
	for i, p := range uc.Phases {
		out = append(out, fmt.Sprintf("    %d. %-32s %d steps",
			i+1, truncDisk(p.Name, 32), len(p.Steps)))
	}

	if len(uc.Parameters) > 0 {
		out = append(out, "")
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render("Parameters:"))
		for _, p := range uc.Parameters {
			tag := "optional"
			if p.Required {
				tag = "required"
			}
			out = append(out, fmt.Sprintf("    • %-22s %s — %s",
				p.Name, tag, p.Description))
		}
	}

	out = append(out, "")
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(
		strings.Repeat(boxHorizontal, 60)))
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorAccent).Render("[R]")+
		lipgloss.NewStyle().Foreground(ColorText).Render(" Run this use case   ")+
		lipgloss.NewStyle().Foreground(ColorAccent).Render("[Esc]")+
		lipgloss.NewStyle().Foreground(ColorText).Render(" Back"))
	return out
}

// ---------------------------------------------------------------------------
// Parameter prompt
// ---------------------------------------------------------------------------

func (m Model) ucViewParams(width int) []string {
	uc := m.usecasesState.selected
	if uc == nil || m.usecasesState.paramIdx >= len(uc.Parameters) {
		return nil
	}
	p := uc.Parameters[m.usecasesState.paramIdx]
	out := []string{
		cSectionLabel("Use Case Parameters"), cRule(width),
		"",
		fmt.Sprintf("  Parameter %d of %d", m.usecasesState.paramIdx+1, len(uc.Parameters)),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(p.Name) +
			lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
				func() string {
					if p.Required {
						return "  (required)"
					}
					return "  (optional)"
				}()),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(p.Description),
		"",
		"  " + m.usecasesState.paramInput.View(),
		"",
		cHint("Enter: next   Esc: cancel"),
	}
	return out
}

// ---------------------------------------------------------------------------
// Running view
// ---------------------------------------------------------------------------

func (m Model) ucViewRunning(width int) []string {
	uc := m.usecasesState.selected
	out := []string{
		cSectionLabel("Running: " + uc.ID + " " + uc.Name), cRule(width),
		"",
		cField("Started", lipgloss.NewStyle().Foreground(ColorText).Render(
			m.usecasesState.startTime.Format("2006-01-02 15:04:05"))),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.usecasesState.elapsed)),
		"",
		cHint("Long-running use cases (Hayabusa, full-disk searches) may take many minutes."),
	}
	return out
}

// ---------------------------------------------------------------------------
// Summary view
// ---------------------------------------------------------------------------

func (m Model) ucViewSummary(width int) []string {
	s := m.usecasesState.summary
	if s == nil {
		return []string{"  " + ErrorStyle.Render("(no summary)")}
	}
	out := []string{
		cSectionLabel("Use Case Complete — " + s.UseCaseID + " " + s.UseCaseName),
		cRule(width),
		"",
		cField("Total Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			s.Duration.Truncate(time.Second).String())),
		cField("Output", renderOutputPath(s.OutputDir, width)),
		cField("Files", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d", s.TotalFiles))),
		"",
		cSectionLabel("Phase Results"),
	}

	for i, p := range s.Phases {
		var marker string
		switch p.Status {
		case usecases.StatusComplete:
			marker = lipgloss.NewStyle().Foreground(ColorSuccess).Render("✓")
		case usecases.StatusPartial:
			marker = lipgloss.NewStyle().Foreground(ColorWarning).Render("~")
		case usecases.StatusFailed:
			marker = lipgloss.NewStyle().Foreground(ColorError).Render("✗")
		default:
			marker = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("·")
		}
		ok, fail, skip := tallyStepStatus(p.Steps)
		out = append(out, fmt.Sprintf("  %s %d. %-30s %-9s %5ds   %d/%d steps%s",
			marker, i+1, truncDisk(p.PhaseName, 30), p.Status,
			int(p.Duration.Seconds()),
			ok, len(p.Steps), tallyTail(skip, fail)))
	}

	uc := m.usecasesState.selected
	if uc != nil {
		if len(uc.AnalysisGuide) > 0 {
			out = append(out, "", cSectionLabel("Analysis Guidance"))
			for _, g := range uc.AnalysisGuide {
				for _, line := range wrap(g, 70) {
					out = append(out, "  • "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(line))
				}
			}
		}
		if len(uc.FollowUp) > 0 {
			out = append(out, "", cSectionLabel("Recommended Follow-Up"))
			for _, f := range uc.FollowUp {
				out = append(out, "  • "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(f))
			}
		}
	}
	out = append(out, "", cHint("Enter or Esc to return to the catalog."))
	return out
}

// tallyStepStatus counts (success, failed, skipped) across steps.
func tallyStepStatus(steps []usecases.StepResult) (ok, fail, skip int) {
	for _, s := range steps {
		switch s.Status {
		case usecases.StatusSuccess:
			ok++
		case usecases.StatusFailed:
			fail++
		case usecases.StatusSkipped:
			skip++
		}
	}
	return
}

func tallyTail(skip, fail int) string {
	bits := make([]string, 0, 2)
	if skip > 0 {
		bits = append(bits, fmt.Sprintf("%d skipped", skip))
	}
	if fail > 0 {
		bits = append(bits, fmt.Sprintf("%d failed", fail))
	}
	if len(bits) == 0 {
		return ""
	}
	return " (" + strings.Join(bits, ", ") + ")"
}

// ---------------------------------------------------------------------------
// Custom template generated
// ---------------------------------------------------------------------------

func (m Model) ucViewTemplateDone(width int) []string {
	return []string{
		cSectionLabel("Custom Use Case Template Created"), cRule(width),
		"",
		"  " + SuccessStyle.Render("Template saved."),
		"",
		cField("Path", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.usecasesState.templatePath)),
		"",
		cHint("Edit the file, change the ID, and re-open Use Cases to see it in the catalog."),
		"",
		cHint("Press any key to return"),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// wrap word-wraps s to a maximum line width. Newlines in the source are
// honoured and start a new wrapped block.
func wrap(s string, width int) []string {
	var out []string
	for _, raw := range strings.Split(s, "\n") {
		words := strings.Fields(raw)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		var cur strings.Builder
		for _, w := range words {
			if cur.Len()+len(w)+1 > width && cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			if cur.Len() > 0 {
				cur.WriteByte(' ')
			}
			cur.WriteString(w)
		}
		if cur.Len() > 0 {
			out = append(out, cur.String())
		}
	}
	return out
}
