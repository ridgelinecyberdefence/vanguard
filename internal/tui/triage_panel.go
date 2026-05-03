package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/triage"
)

// ---------------------------------------------------------------------------
// Triage panel states
// ---------------------------------------------------------------------------

type triageView int

const (
	triageViewNone triageView = iota
	triageViewNeedCase       // prompt to create case
	triageViewCustomSelect   // checkbox selection
	triageViewRunning        // collection in progress
	triageViewDone           // completed summary
)

// TriageState holds all state for the Quick Triage submenu.
type TriageState struct {
	view triageView

	// Step tracking during collection.
	stepNames  []string
	stepStatus []triage.StepStatus
	stepTimes  []time.Duration
	elapsed    time.Duration
	startTime  time.Time
	outputDir  string

	// Custom selection checkboxes.
	customChecked []bool
	customCursor  int
	customIndices []int // resolved step indices for the checked items

	// Final summary.
	summary *triage.CollectionSummary

	// Result lines for simple displays.
	resultLines []string
}

// ---------------------------------------------------------------------------
// Custom tea.Msg types
// ---------------------------------------------------------------------------

// triageStepMsg is sent when a step starts or finishes.
type triageStepMsg struct {
	stepIndex int
	result    *triage.StepResult // nil = started, non-nil = completed
}

// triageDoneMsg is sent when the entire collection completes.
type triageDoneMsg struct {
	summary triage.CollectionSummary
}

// triageTickMsg is sent every second to update elapsed time.
type triageTickMsg time.Time

// ---------------------------------------------------------------------------
// Tick command
// ---------------------------------------------------------------------------

func triageTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return triageTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Triage action handlers — called from activateContentItem
// ---------------------------------------------------------------------------

// handleTriageAction processes triage submenu actions. Returns true if handled.
func (m Model) handleTriageAction(action string) (Model, tea.Cmd, bool) {
	// Match the action prefix BEFORE mutating panel state — the dispatcher
	// chains handlers and a stray clearPanelState would wipe out other panels.
	if !strings.HasPrefix(action, "triage_") {
		return m, nil, false
	}

	m.clearPanelState()

	switch action {
	case "triage_full":
		return m.triageStartCollection(m.triageFullIndices())
	case "triage_procnet":
		return m.triageStartCollection(m.triageProcNetIndices())
	case "triage_logs":
		return m.triageStartCollection(m.triageLogIndices())
	case "triage_persist":
		return m.triageStartCollection(m.triagePersistIndices())
	case "triage_user":
		return m.triageStartCollection(m.triageUserIndices())
	case "triage_sysinfo":
		return m.triageStartCollection(m.triageSysInfoIndices())
	case "triage_browser":
		return m.triageStartBrowserOrCron()
	case "triage_custom":
		return m.triageShowCustomSelect()
	}
	return m, nil, false
}

// ---------------------------------------------------------------------------
// Index helpers (platform-aware)
// ---------------------------------------------------------------------------

func (m Model) triageFullIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsFullTriageIndices()
	}
	return triage.LinuxFullTriageIndices()
}

func (m Model) triageProcNetIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsProcessNetworkIndices()
	}
	return triage.LinuxProcessNetworkIndices()
}

func (m Model) triageLogIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsEventLogIndices()
	}
	return triage.LinuxLogIndices()
}

func (m Model) triagePersistIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsPersistenceIndices()
	}
	return triage.LinuxPersistenceIndices()
}

func (m Model) triageUserIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsUserActivityIndices()
	}
	return triage.LinuxUserActivityIndices()
}

func (m Model) triageSysInfoIndices() []int {
	if m.ctx.Platform == "windows" {
		return triage.WindowsSystemInfoIndices()
	}
	return triage.LinuxSystemInfoIndices()
}

func (m Model) triageStartBrowserOrCron() (Model, tea.Cmd, bool) {
	if m.ctx.Platform == "windows" {
		return m.triageStartCollection(triage.WindowsBrowserIndices())
	}
	return m.triageStartCollection(triage.LinuxCronServicesIndices())
}

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

func (m Model) triageCheckCase() bool {
	return m.ctx.ActiveCase != nil
}

// ---------------------------------------------------------------------------
// Start collection
// ---------------------------------------------------------------------------

func (m Model) triageStartCollection(indices []int) (Model, tea.Cmd, bool) {
	if !m.triageCheckCase() {
		m.triageState.view = triageViewNeedCase
		m.state = stateResult
		return m, nil, true
	}

	// Build collector. Prefer the analyst recorded on the case (set when the
	// case was created) and fall back to the live config so the audit trail
	// reflects who created the evidence rather than whoever happens to be at
	// the console now. Same for organisation.
	analyst := m.ctx.ActiveCase.Analyst
	if analyst == "" {
		analyst = m.ctx.Config.VanGuard.Analyst
	}
	org := m.ctx.ActiveCase.Organization
	if org == "" {
		org = m.ctx.Config.VanGuard.Organization
	}
	c := triage.NewCollector(
		m.ctx.RootDir,
		m.ctx.ActiveCase.ID,
		m.ctx.Hostname,
		analyst,
		m.ctx.Platform,
		m.ctx.Elevated,
		m.ctx.Logger,
	)
	c.CaseName = m.ctx.ActiveCase.Name
	c.Organization = org

	allSteps := c.Steps()

	// Initialise triage state.
	m.triageState = TriageState{
		view:      triageViewRunning,
		startTime: time.Now(),
	}

	m.triageState.stepNames = make([]string, len(allSteps))
	m.triageState.stepStatus = make([]triage.StepStatus, len(allSteps))
	m.triageState.stepTimes = make([]time.Duration, len(allSteps))

	for i, s := range allSteps {
		m.triageState.stepNames[i] = s.Name
		m.triageState.stepStatus[i] = triage.StepSkipped
	}
	for _, idx := range indices {
		if idx >= 0 && idx < len(allSteps) {
			m.triageState.stepStatus[idx] = triage.StepPending
		}
	}

	ts := time.Now().Format("20060102_150405")
	m.triageState.outputDir = c.OutputDir(ts)

	m.state = stateResult

	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	if m.ctx.Audit != nil {
		_ = m.ctx.Audit.Log("quick_triage", m.ctx.Hostname,
			fmt.Sprintf("%d steps", len(indices)), "started", caseID)
	}

	// Launch collection in background.
	// The collection runs in a goroutine. Progress channel messages are consumed
	// inline — bubbletea receives only the final triageDoneMsg. The tick command
	// keeps elapsed time updating.
	idxCopy := make([]int, len(indices))
	copy(idxCopy, indices)

	return m, tea.Batch(
		triageTickCmd(),
		func() tea.Msg {
			summary := c.Run(context.Background(), idxCopy, nil)
			return triageDoneMsg{summary: summary}
		},
	), true
}

// ---------------------------------------------------------------------------
// Custom selection
// ---------------------------------------------------------------------------

func (m Model) triageShowCustomSelect() (Model, tea.Cmd, bool) {
	if !m.triageCheckCase() {
		m.triageState.view = triageViewNeedCase
		m.state = stateResult
		return m, nil, true
	}

	c := triage.NewCollector(m.ctx.RootDir, "", "", "", m.ctx.Platform, false, nil)
	allSteps := c.Steps()

	m.triageState = TriageState{
		view:          triageViewCustomSelect,
		customChecked: make([]bool, len(allSteps)),
		customCursor:  0,
	}

	m.triageState.stepNames = make([]string, len(allSteps))
	for i, s := range allSteps {
		m.triageState.stepNames[i] = s.Name
	}

	// Default checked: first 3 items + persistence.
	defaults := []int{0, 1, 2}
	if m.ctx.Platform == "windows" {
		defaults = append(defaults, 5) // persistence
	} else {
		defaults = append(defaults, 4) // persistence
	}
	for _, idx := range defaults {
		if idx < len(m.triageState.customChecked) {
			m.triageState.customChecked[idx] = true
		}
	}

	m.state = stateResult
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Triage panel Update
// ---------------------------------------------------------------------------

// triageUpdate handles key events when a triage panel view is active.
func (m Model) triageUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.triageState.view == triageViewNone {
		return m, nil, false
	}

	key := msg.String()

	switch m.triageState.view {
	case triageViewNeedCase:
		switch key {
		case "y", "Y":
			// Jump to create case.
			m.triageState.view = triageViewNone
			// Simulate activating config > create case.
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.triageState.view = triageViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case triageViewCustomSelect:
		return m.triageUpdateCustomSelect(key)

	case triageViewRunning:
		// Block all input during collection.
		return m, nil, true

	case triageViewDone:
		// Any key dismisses.
		m.triageState.view = triageViewNone
		m.state = stateSubMenu
		return m, nil, true
	}

	return m, nil, false
}

func (m Model) triageUpdateCustomSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.triageState.view = triageViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.triageState.customCursor > 0 {
			m.triageState.customCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.triageState.customCursor < len(m.triageState.customChecked)-1 {
			m.triageState.customCursor++
		}
		return m, nil, true
	case " ":
		// Toggle checkbox.
		idx := m.triageState.customCursor
		m.triageState.customChecked[idx] = !m.triageState.customChecked[idx]
		return m, nil, true
	case "a", "A":
		// Select all.
		for i := range m.triageState.customChecked {
			m.triageState.customChecked[i] = true
		}
		return m, nil, true
	case "n", "N":
		// Deselect all.
		for i := range m.triageState.customChecked {
			m.triageState.customChecked[i] = false
		}
		return m, nil, true
	case "enter":
		// Collect selected indices.
		var indices []int
		for i, checked := range m.triageState.customChecked {
			if checked {
				indices = append(indices, i)
			}
		}
		if len(indices) == 0 {
			m.statusMessage = "No steps selected."
			return m, nil, true
		}
		return m.triageStartCollection(indices)
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Triage panel View rendering
// ---------------------------------------------------------------------------

func (m Model) triageContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Quick Triage"),
		"",
	}

	switch m.triageState.view {
	case triageViewNeedCase:
		lines = append(lines, m.triageViewNeedCase(width)...)
	case triageViewCustomSelect:
		lines = append(lines, m.triageViewCustomSelect(width)...)
	case triageViewRunning:
		lines = append(lines, m.triageViewRunning(width)...)
	case triageViewDone:
		lines = append(lines, m.triageViewDone(width)...)
	}

	return lines
}

// ---------------------------------------------------------------------------
// Need case view
// ---------------------------------------------------------------------------

func (m Model) triageViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Quick Triage"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
		"",
		cHint("A case is required to organize triage output."),
	}
}

// ---------------------------------------------------------------------------
// Custom select view
// ---------------------------------------------------------------------------

func (m Model) triageViewCustomSelect(width int) []string {
	lines := []string{
		cSectionLabel("Custom Collection"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render("Select collection steps:"),
		"",
	}

	for i, name := range m.triageState.stepNames {
		checked := m.triageState.customChecked[i]
		selected := i == m.triageState.customCursor

		box := "[ ]"
		boxFg := ColorTextMuted
		if checked {
			box = "[x]"
			boxFg = ColorSuccess
		}

		boxStr := lipgloss.NewStyle().Foreground(boxFg).Render(box)
		nameStr := lipgloss.NewStyle().Foreground(ColorText).Render(name)

		if selected {
			cursor := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> ")
			nameStr = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(name)
			lines = append(lines, "  "+cursor+boxStr+" "+nameStr)
		} else {
			lines = append(lines, "    "+boxStr+" "+nameStr)
		}
	}

	lines = append(lines, "")
	lines = append(lines,
		cHint("Space: toggle  A: select all  N: deselect all  Enter: run  Esc: cancel"))

	return lines
}

// ---------------------------------------------------------------------------
// Running view (progress display)
// ---------------------------------------------------------------------------

func (m Model) triageViewRunning(width int) []string {
	lines := []string{
		cSectionLabel(fmt.Sprintf("Full System Triage — %s", m.ctx.Hostname)),
		cRule(width),
		"",
		cField("Started", lipgloss.NewStyle().Foreground(ColorText).Render(
			m.triageState.startTime.Format("2006-01-02 15:04:05"))),
		cField("Output", renderOutputPath(m.triageState.outputDir, width)),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 50)),
	}

	for i, name := range m.triageState.stepNames {
		status := m.triageState.stepStatus[i]
		dur := m.triageState.stepTimes[i]

		var icon, nameStr, durStr string

		switch status {
		case triage.StepSkipped:
			continue // don't show skipped steps
		case triage.StepPending:
			icon = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("[ ]")
			nameStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(name)
		case triage.StepRunning:
			icon = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸]")
			nameStr = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(name)
			durStr = lipgloss.NewStyle().Foreground(ColorPrimary).Render("running...")
		case triage.StepSuccess:
			icon = lipgloss.NewStyle().Foreground(ColorSuccess).Render("[✓]")
			nameStr = lipgloss.NewStyle().Foreground(ColorText).Render(name)
			durStr = lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
				fmt.Sprintf("%d sec", int(dur.Seconds())))
		case triage.StepPartial:
			icon = lipgloss.NewStyle().Foreground(ColorWarning).Render("[~]")
			nameStr = lipgloss.NewStyle().Foreground(ColorText).Render(name)
			durStr = lipgloss.NewStyle().Foreground(ColorWarning).Render(
				fmt.Sprintf("%d sec (partial)", int(dur.Seconds())))
		case triage.StepFailed:
			icon = lipgloss.NewStyle().Foreground(ColorError).Render("[✗]")
			nameStr = lipgloss.NewStyle().Foreground(ColorError).Render(name)
			durStr = lipgloss.NewStyle().Foreground(ColorError).Render("failed")
		}

		// Pad name to fixed width.
		padded := fmt.Sprintf("%-35s", name)
		_ = padded
		line := fmt.Sprintf("  %s %-35s %s", icon, nameStr, durStr)
		lines = append(lines, line)
	}

	// Elapsed time.
	elapsed := m.triageState.elapsed
	lines = append(lines, "")
	lines = append(lines,
		"  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			fmt.Sprintf("Elapsed: %s", formatElapsed(elapsed))))

	if !m.ctx.Elevated {
		lines = append(lines, "")
		lines = append(lines,
			"  "+WarningStyle.Render("WARNING: Running without elevation. Some collections may fail."))
	}

	return lines
}

// ---------------------------------------------------------------------------
// Done view (completion summary)
// ---------------------------------------------------------------------------

func (m Model) triageViewDone(width int) []string {
	lines := []string{
		cSectionLabel("Collection Complete"), cRule(width),
		"",
	}

	if m.triageState.summary != nil {
		s := m.triageState.summary
		lines = append(lines,
			"  "+SuccessStyle.Render("Triage collection completed!"),
			"  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 45)),
			"",
			cField("Case", lipgloss.NewStyle().Foreground(ColorPrimary).Render(s.CaseID)),
			cField("Hostname", lipgloss.NewStyle().Foreground(ColorText).Render(s.Hostname)),
			cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
				s.Duration.Truncate(time.Second).String())),
			cField("Total Files", lipgloss.NewStyle().Foreground(ColorText).Render(
				fmt.Sprintf("%d", s.TotalFiles))),
			cField("Total Size", lipgloss.NewStyle().Foreground(ColorText).Render(
				triage.FormatBytesPublic(s.TotalBytes))),
			cField("Output", renderOutputPath(s.OutputDir, width)),
			"",
		)

		// Per-step results.
		lines = append(lines, cSectionLabel("Steps"))
		for _, r := range s.Steps {
			if r.Status == triage.StepSkipped {
				continue
			}

			var statusStr string
			switch r.Status {
			case triage.StepSuccess:
				statusStr = SuccessStyle.Render("success")
			case triage.StepPartial:
				statusStr = WarningStyle.Render("partial")
			case triage.StepFailed:
				statusStr = ErrorStyle.Render("failed")
			default:
				statusStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Status.String())
			}

			line := fmt.Sprintf("  %-28s %s  %s  %d files  %s",
				lipgloss.NewStyle().Foreground(ColorText).Render(r.Name),
				statusStr,
				lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
					fmt.Sprintf("%ds", int(r.Duration.Seconds()))),
				r.Files,
				lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					triage.FormatBytesPublic(r.Bytes)),
			)
			lines = append(lines, line)

			textW := contentTextWidth(width) - 6 // account for 4-space indent + ⚠ glyph
			for _, w := range r.Warnings {
				wrapped := WrapTextLines(w, textW)
				for i, ln := range wrapped {
					prefix := "    ⚠ "
					if i > 0 {
						prefix = "      "
					}
					lines = append(lines,
						lipgloss.NewStyle().Foreground(ColorWarning).Render(prefix+ln))
				}
			}
		}
	} else {
		// Fallback.
		lines = append(lines, m.triageState.resultLines...)
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func formatElapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
