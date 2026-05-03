package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
)

// ---------------------------------------------------------------------------
// Config panel states
// ---------------------------------------------------------------------------

type configView int

const (
	cfgViewNone configView = iota
	cfgViewCreateCase
	cfgViewListCases
	cfgViewSelectCase
	cfgViewCloseCase
	cfgViewEditAnalyst
	cfgViewEditOrg
	cfgViewDownloading
	cfgViewDownloadDone
	cfgViewIntegrityRunning
	cfgViewIntegrityDone
	cfgViewVolDiagnostic // hidden [V] — Volatility3 detection diagnostic
)

// ConfigState holds all state for the Configuration submenu's interactive panels.
type ConfigState struct {
	view configView

	// Text input form (case creation, config editing).
	input       textinput.Model
	inputStep   int      // multi-step form: 0=name, 1=classification, 2=description
	inputValues []string // collected values from previous steps

	// Classification selection (step 1 of case creation).
	classOptions []string
	classCursor  int

	// Case list.
	cases      []casemanager.Case
	caseCursor int
	caseScroll int // scroll offset for long lists

	// Evidence integrity check.
	integrityResults []casemanager.IntegrityResult
	integritySummary casemanager.IntegritySummary
	integrityErr     string

	// Result / status lines.
	resultLines []string
}

// Classification options for new cases.
var classificationOptions = []string{
	"TLP:RED",
	"TLP:AMBER",
	"TLP:GREEN",
	"TLP:WHITE",
	"CONFIDENTIAL",
	"INTERNAL",
	"PUBLIC",
}

// ---------------------------------------------------------------------------
// Custom tea.Msg types for async operations
// ---------------------------------------------------------------------------

// downloadResultMsg carries the result of an async tool download.
type downloadResultMsg struct {
	lines []string
}

// updateCheckResultMsg carries the result of an async update check.
type updateCheckResultMsg struct {
	lines []string
}

// ---------------------------------------------------------------------------
// Config panel initialisation helpers
// ---------------------------------------------------------------------------

func newTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 120
	ti.Width = 50
	ti.Focus()
	return ti
}

// initConfigState returns a fresh ConfigState.
func initConfigState() ConfigState {
	return ConfigState{
		classOptions: classificationOptions,
	}
}

// ---------------------------------------------------------------------------
// Config panel Update — returns updated model + cmd
// ---------------------------------------------------------------------------

// configUpdate handles key events when a config panel view is active.
// Returns true if the event was consumed.
func (m Model) configUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.cfgState.view == cfgViewNone {
		return m, nil, false
	}

	key := msg.String()

	switch m.cfgState.view {
	case cfgViewCreateCase:
		return m.configUpdateCreateCase(msg, key)
	case cfgViewListCases:
		return m.configUpdateCaseList(key)
	case cfgViewSelectCase:
		return m.configUpdateSelectCase(key)
	case cfgViewCloseCase:
		return m.configUpdateCloseCase(key)
	case cfgViewEditAnalyst, cfgViewEditOrg:
		return m.configUpdateEditField(msg, key)
	case cfgViewDownloading:
		// Block input while downloading.
		return m, nil, true
	case cfgViewDownloadDone:
		// Any key dismisses.
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		return m, nil, true
	case cfgViewIntegrityRunning:
		// Block input while the verifier walks evidence.
		return m, nil, true
	case cfgViewIntegrityDone:
		// Any key dismisses; reset both view and result buffers so the next
		// invocation gets a clean slate.
		m.cfgState.view = cfgViewNone
		m.cfgState.integrityResults = nil
		m.cfgState.integritySummary = casemanager.IntegritySummary{}
		m.cfgState.integrityErr = ""
		m.state = stateSubMenu
		return m, nil, true
	case cfgViewVolDiagnostic:
		// Any key dismisses.
		m.cfgState.view = cfgViewNone
		m.cfgState.resultLines = nil
		m.state = stateSubMenu
		return m, nil, true
	}

	return m, nil, false
}

// ---------------------------------------------------------------------------
// Case creation — multi-step form
// ---------------------------------------------------------------------------

func (m Model) configUpdateCreateCase(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	step := m.cfgState.inputStep

	switch key {
	case "esc":
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		m.statusMessage = "Case creation cancelled."
		return m, nil, true
	}

	// Step 1: classification selection (not a text input).
	if step == 1 {
		switch key {
		case "up", "k":
			if m.cfgState.classCursor > 0 {
				m.cfgState.classCursor--
			}
			return m, nil, true
		case "down", "j":
			if m.cfgState.classCursor < len(m.cfgState.classOptions)-1 {
				m.cfgState.classCursor++
			}
			return m, nil, true
		case "enter":
			classification := m.cfgState.classOptions[m.cfgState.classCursor]
			m.cfgState.inputValues = append(m.cfgState.inputValues, classification)
			// Move to step 2: description.
			m.cfgState.inputStep = 2
			m.cfgState.input = newTextInput("Brief description of the incident...")
			return m, m.cfgState.input.Focus(), true
		}
		return m, nil, true
	}

	// Steps 0 (name) and 2 (description): text input.
	switch key {
	case "enter":
		value := strings.TrimSpace(m.cfgState.input.Value())

		if step == 0 {
			// Name is required.
			if value == "" {
				m.statusMessage = "Case name is required."
				return m, nil, true
			}
			m.cfgState.inputValues = append(m.cfgState.inputValues, value)
			// Move to step 1: classification selection.
			m.cfgState.inputStep = 1
			m.cfgState.classCursor = 0
			m.cfgState.input.Blur()
			return m, nil, true
		}

		if step == 2 {
			// Description is optional.
			m.cfgState.inputValues = append(m.cfgState.inputValues, value)
			return m.finaliseCreateCase()
		}
	default:
		// Forward to textinput.
		var cmd tea.Cmd
		m.cfgState.input, cmd = m.cfgState.input.Update(msg)
		return m, cmd, true
	}

	return m, nil, true
}

func (m Model) finaliseCreateCase() (Model, tea.Cmd, bool) {
	name := m.cfgState.inputValues[0]
	classification := m.cfgState.inputValues[1]
	description := ""
	if len(m.cfgState.inputValues) > 2 {
		description = m.cfgState.inputValues[2]
	}

	analyst := m.ctx.Config.VanGuard.Analyst
	org := m.ctx.Config.VanGuard.Organization

	c, err := m.ctx.CaseManager.CreateCaseFull(name, analyst, org, classification, description)
	if err != nil {
		m.cfgState.view = cfgViewNone
		m.state = stateResult
		m.statusMessage = fmt.Sprintf("Error creating case: %v", err)
		return m, nil, true
	}

	// Create case output directory.
	caseDir := filepath.Join(m.ctx.RootDir, "output", c.ID)
	for _, sub := range []string{"memory", "disk", "triage", "velociraptor", "reports"} {
		_ = os.MkdirAll(filepath.Join(caseDir, sub), 0o700)
	}

	// Set as active case.
	m.ctx.ActiveCase = c

	if m.ctx.Logger != nil {
		m.ctx.Logger.Info("config", "created case %s: %s", c.ID, c.Name)
	}
	if m.ctx.Audit != nil {
		_ = m.ctx.Audit.Log("create_case", "", c.Name, c.ID, c.ID)
	}

	m.cfgState.view = cfgViewNone
	lines := []string{
		"",
		"  " + SuccessStyle.Render("Case created successfully!"),
		"",
		cField("Case ID", lipgloss.NewStyle().Foreground(ColorPrimary).Render(c.ID)),
		cField("Name", lipgloss.NewStyle().Foreground(ColorText).Render(c.Name)),
		cField("Classification", lipgloss.NewStyle().Foreground(ColorWarning).Render(c.Classification)),
		cField("Status", lipgloss.NewStyle().Foreground(ColorSuccess).Render(c.Status)),
		cField("Analyst", lipgloss.NewStyle().Foreground(ColorText).Render(c.Analyst)),
		cField("Organization", lipgloss.NewStyle().Foreground(ColorText).Render(c.Organization)),
		cField("Output Dir", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(caseDir)),
	}

	// One-time security warning: explain that the SQLite database is
	// unencrypted and recommend full-disk encryption on the VanGuard drive.
	// We only render this on the first case creation per VanGuard install,
	// tracked via a marker file so seasoned operators don't see it again.
	if !casemanager.FirstRunWarningSeen(m.ctx.RootDir) {
		lines = append(lines, "")
		lines = append(lines, "  "+ErrorStyle.Bold(true).Render("⚠  SECURITY NOTICE  (shown once)"))
		for _, line := range casemanager.SecurityWarning() {
			lines = append(lines,
				"  "+lipgloss.NewStyle().Foreground(ColorWarning).Render(line))
		}
		_ = casemanager.MarkFirstRunWarningSeen(m.ctx.RootDir)
	}

	lines = append(lines,
		"",
		cHint("Case set as active. Press any key to return."))
	m.cfgState.resultLines = lines
	m.state = stateResult
	m.toolView = ""
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Case list
// ---------------------------------------------------------------------------

func (m Model) configUpdateCaseList(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.cfgState.caseCursor > 0 {
			m.cfgState.caseCursor--
			// Scroll up if cursor went above visible area.
			if m.cfgState.caseCursor < m.cfgState.caseScroll {
				m.cfgState.caseScroll = m.cfgState.caseCursor
			}
		}
		return m, nil, true
	case "down", "j":
		if m.cfgState.caseCursor < len(m.cfgState.cases)-1 {
			m.cfgState.caseCursor++
			// Scroll down if cursor goes below visible area.
			maxVisible := 12
			if m.cfgState.caseCursor >= m.cfgState.caseScroll+maxVisible {
				m.cfgState.caseScroll = m.cfgState.caseCursor - maxVisible + 1
			}
		}
		return m, nil, true
	case "enter":
		// Select case from list.
		if len(m.cfgState.cases) > 0 {
			selected := m.cfgState.cases[m.cfgState.caseCursor]
			m.ctx.ActiveCase = &selected
			m.cfgState.view = cfgViewNone
			m.state = stateSubMenu
			m.statusMessage = fmt.Sprintf("Active case: %s", selected.ID)
			if m.ctx.Logger != nil {
				m.ctx.Logger.Info("config", "selected case %s", selected.ID)
			}
		}
		return m, nil, true
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Select active case (quick select from active cases)
// ---------------------------------------------------------------------------

func (m Model) configUpdateSelectCase(key string) (Model, tea.Cmd, bool) {
	// Reuses the same list navigation as cfgViewListCases.
	return m.configUpdateCaseList(key)
}

// ---------------------------------------------------------------------------
// Close active case
// ---------------------------------------------------------------------------

func (m Model) configUpdateCloseCase(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "y", "Y":
		if m.ctx.ActiveCase != nil {
			closedID := m.ctx.ActiveCase.ID
			err := m.ctx.CaseManager.UpdateCaseStatus(closedID, "closed")
			if err != nil {
				m.statusMessage = fmt.Sprintf("Error closing case: %v", err)
				if m.ctx.Audit != nil {
					_ = m.ctx.Audit.Log("close_case", "", "", "error: "+err.Error(), closedID)
				}
			} else {
				if m.ctx.Logger != nil {
					m.ctx.Logger.Info("config", "closed case %s", closedID)
				}
				if m.ctx.Audit != nil {
					_ = m.ctx.Audit.Log("close_case", "", "", "closed", closedID)
				}
				m.statusMessage = fmt.Sprintf("Case %s closed.", closedID)
				m.ctx.ActiveCase = nil
			}
		}
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		return m, nil, true
	default:
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		m.statusMessage = "Close cancelled."
		return m, nil, true
	}
}

// ---------------------------------------------------------------------------
// Edit analyst / organization
// ---------------------------------------------------------------------------

func (m Model) configUpdateEditField(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		m.statusMessage = "Edit cancelled."
		return m, nil, true
	case "enter":
		value := strings.TrimSpace(m.cfgState.input.Value())
		if m.cfgState.view == cfgViewEditAnalyst {
			m.ctx.Config.VanGuard.Analyst = value
		} else {
			m.ctx.Config.VanGuard.Organization = value
		}
		// Write back to YAML.
		if err := m.ctx.Config.Save(m.ctx.ConfigPath); err != nil {
			m.statusMessage = fmt.Sprintf("Error saving config: %v", err)
		} else {
			field := "Analyst"
			if m.cfgState.view == cfgViewEditOrg {
				field = "Organization"
			}
			m.statusMessage = fmt.Sprintf("%s updated to: %s", field, value)
			if m.ctx.Logger != nil {
				m.ctx.Logger.Info("config", "%s set to %q", field, value)
			}
		}
		m.cfgState.view = cfgViewNone
		m.state = stateSubMenu
		return m, nil, true
	default:
		var cmd tea.Cmd
		m.cfgState.input, cmd = m.cfgState.input.Update(msg)
		return m, cmd, true
	}
}

// ---------------------------------------------------------------------------
// Config action handlers — called from activateContentItem
// ---------------------------------------------------------------------------

// handleConfigAction processes config submenu actions. Returns true if handled.
func (m Model) handleConfigAction(action string) (Model, tea.Cmd, bool) {
	// Ignore non-config actions early — keeps the dispatcher chain clean.
	if !strings.HasPrefix(action, "cfg_") {
		return m, nil, false
	}
	switch action {
	case "cfg_create_case":
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewCreateCase
		m.cfgState.inputStep = 0
		m.cfgState.inputValues = nil
		m.cfgState.input = newTextInput("Case name (e.g., Ransomware Incident 2026-04)")
		m.state = stateResult
		return m, m.cfgState.input.Focus(), true

	case "cfg_list_cases":
		cases, err := m.ctx.CaseManager.ListCases("")
		if err != nil {
			m.statusMessage = fmt.Sprintf("Error loading cases: %v", err)
			m.state = stateResult
			return m, nil, true
		}
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewListCases
		m.cfgState.cases = cases
		m.cfgState.caseCursor = 0
		m.cfgState.caseScroll = 0
		m.state = stateResult
		return m, nil, true

	case "cfg_select_case":
		cases, err := m.ctx.CaseManager.ListCases("active")
		if err != nil {
			m.statusMessage = fmt.Sprintf("Error loading cases: %v", err)
			m.state = stateResult
			return m, nil, true
		}
		if len(cases) == 0 {
			m.statusMessage = "No active cases found."
			m.state = stateResult
			return m, nil, true
		}
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewSelectCase
		m.cfgState.cases = cases
		m.cfgState.caseCursor = 0
		m.cfgState.caseScroll = 0
		m.state = stateResult
		return m, nil, true

	case "cfg_close_case":
		if m.ctx.ActiveCase == nil {
			m.statusMessage = "No active case to close."
			m.state = stateResult
			return m, nil, true
		}
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewCloseCase
		m.state = stateResult
		return m, nil, true

	case "cfg_tool_status":
		m.clearPanelState()
		m.toolView = "status"
		m.toolStatusLines = m.buildToolStatusTable()
		m.state = stateResult
		return m, nil, true

	case "cfg_tool_dl_req":
		m.clearPanelState()
		missing := m.countMissingRequired()
		if missing == 0 {
			m.toolView = "download_done"
			m.toolResultLines = []string{
				SuccessStyle.Render("All required tools are already installed."),
			}
			m.state = stateResult
			return m, nil, true
		}
		m.toolView = "download_confirm"
		m.toolConfirmMsg = fmt.Sprintf("Download %d required tool(s)? (y/n)", missing)
		m.state = stateResult
		return m, nil, true

	case "cfg_tool_dl_all":
		m.clearPanelState()
		missing := m.countMissingDownloadable()
		if missing == 0 {
			m.toolView = "download_done"
			m.toolResultLines = []string{
				SuccessStyle.Render("All downloadable tools are already installed."),
			}
			m.state = stateResult
			return m, nil, true
		}
		m.toolView = "download_all_confirm"
		m.toolConfirmMsg = fmt.Sprintf("Download %d tool(s)? (y/n)", missing)
		m.state = stateResult
		return m, nil, true

	case "cfg_tool_updates":
		m.clearPanelState()
		m.toolView = "checking_updates"
		m.state = stateResult
		return m, m.asyncUpdateCheck(), true

	case "cfg_edit_analyst":
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewEditAnalyst
		m.cfgState.input = newTextInput("Analyst name")
		m.cfgState.input.SetValue(m.ctx.Config.VanGuard.Analyst)
		m.state = stateResult
		return m, m.cfgState.input.Focus(), true

	case "cfg_edit_org":
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewEditOrg
		m.cfgState.input = newTextInput("Organization name")
		m.cfgState.input.SetValue(m.ctx.Config.VanGuard.Organization)
		m.state = stateResult
		return m, m.cfgState.input.Focus(), true

	case "cfg_vol_diag":
		// Hidden diagnostic: dumps the on-disk layout of lib/volatility3/ and
		// the tool registry's view of Volatility3, side by side, so we can
		// pinpoint detection mismatches without grepping logs.
		m.clearPanelState()
		m.cfgState = initConfigState()
		m.cfgState.view = cfgViewVolDiagnostic
		m.cfgState.resultLines = m.buildVolDiagnostic()
		m.state = stateResult
		return m, nil, true

	case "cfg_verify_evidence":
		// Requires an active case to scope the verification — no point
		// integrity-checking nothing.
		m.clearPanelState()
		m.cfgState = initConfigState()
		if m.ctx.ActiveCase == nil {
			m.cfgState.view = cfgViewIntegrityDone
			m.cfgState.integrityErr = "No active case. Select or create a case first."
			m.state = stateResult
			return m, nil, true
		}
		m.cfgState.view = cfgViewIntegrityRunning
		m.state = stateResult
		return m, m.asyncVerifyIntegrity(), true
	}

	return m, nil, false
}

// integrityResultMsg carries the outcome of an async evidence integrity
// verification back to the bubbletea event loop.
type integrityResultMsg struct {
	results []casemanager.IntegrityResult
	summary casemanager.IntegritySummary
	err     error
}

// asyncVerifyIntegrity runs the verification off the UI goroutine — large
// evidence sets (full triage trees) can take several seconds to walk.
func (m Model) asyncVerifyIntegrity() tea.Cmd {
	cm := m.ctx.CaseManager
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	return func() tea.Msg {
		if cm == nil {
			return integrityResultMsg{err: fmt.Errorf("case manager unavailable")}
		}
		results, sum, err := cm.VerifyEvidenceIntegrity(caseID)
		return integrityResultMsg{results: results, summary: sum, err: err}
	}
}

// handleIntegrityResult finalises an integrity verification and routes the
// model into the "done" view that renders the report.
func (m Model) handleIntegrityResult(msg integrityResultMsg) (Model, tea.Cmd) {
	m.cfgState.view = cfgViewIntegrityDone
	if msg.err != nil {
		m.cfgState.integrityErr = msg.err.Error()
		return m, nil
	}
	m.cfgState.integrityResults = msg.results
	m.cfgState.integritySummary = msg.summary
	return m, nil
}

// ---------------------------------------------------------------------------
// Config panel View rendering
// ---------------------------------------------------------------------------

// configContent renders the active config panel view.
func (m Model) configContent(width int) []string {
	switch m.cfgState.view {
	case cfgViewCreateCase:
		return m.configViewCreateCase(width)
	case cfgViewListCases:
		return m.configViewCaseList(width, "All Cases", false)
	case cfgViewSelectCase:
		return m.configViewCaseList(width, "Select Active Case", true)
	case cfgViewCloseCase:
		return m.configViewCloseCase(width)
	case cfgViewEditAnalyst:
		return m.configViewEditField(width, "Edit Analyst Name")
	case cfgViewEditOrg:
		return m.configViewEditField(width, "Edit Organization")
	case cfgViewDownloadDone:
		return m.configViewDownloadDone(width)
	case cfgViewIntegrityRunning:
		return m.configViewIntegrityRunning(width)
	case cfgViewIntegrityDone:
		return m.configViewIntegrityDone(width)
	case cfgViewVolDiagnostic:
		return m.configViewVolDiagnostic(width)
	default:
		// Show result lines if present (e.g., after case creation).
		if len(m.cfgState.resultLines) > 0 {
			lines := []string{
				"",
				cBreadcrumb("Home > Configuration"),
				"",
			}
			lines = append(lines, m.cfgState.resultLines...)
			return lines
		}
		return nil
	}
}

// ---------------------------------------------------------------------------
// Create case view
// ---------------------------------------------------------------------------

func (m Model) configViewCreateCase(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > New Case"),
		"",
		cSectionLabel("Create New Case"), cRule(width),
		"",
	}

	step := m.cfgState.inputStep

	// Show completed steps.
	if step > 0 {
		lines = append(lines,
			cField("Name", lipgloss.NewStyle().Foreground(ColorSuccess).Render(m.cfgState.inputValues[0])))
	}
	if step > 1 {
		lines = append(lines,
			cField("Classification", lipgloss.NewStyle().Foreground(ColorSuccess).Render(m.cfgState.inputValues[1])))
	}

	lines = append(lines, "")

	// Current step.
	switch step {
	case 0:
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Step 1/3: Case Name"),
			"")
		lines = append(lines, "  "+m.cfgState.input.View())
		lines = append(lines, "")
		lines = append(lines, cHint("Enter: next  Esc: cancel"))

	case 1:
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Step 2/3: Classification"),
			"")
		for i, opt := range m.cfgState.classOptions {
			if i == m.cfgState.classCursor {
				lines = append(lines,
					"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
						Render(fmt.Sprintf("  > %s", opt)))
			} else {
				lines = append(lines,
					"    "+lipgloss.NewStyle().Foreground(ColorText).Render(opt))
			}
		}
		lines = append(lines, "")
		lines = append(lines, cHint("Up/Down: select  Enter: confirm  Esc: cancel"))

	case 2:
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Step 3/3: Description (optional)"),
			"")
		lines = append(lines, "  "+m.cfgState.input.View())
		lines = append(lines, "")
		lines = append(lines, cHint("Enter: create case  Esc: cancel"))
	}

	// Progress indicator.
	lines = append(lines, "")
	progress := "  "
	for i := 0; i < 3; i++ {
		if i == step {
			progress += lipgloss.NewStyle().Foreground(ColorPrimary).Render("●")
		} else if i < step {
			progress += lipgloss.NewStyle().Foreground(ColorSuccess).Render("●")
		} else {
			progress += lipgloss.NewStyle().Foreground(ColorTextMuted).Render("○")
		}
		if i < 2 {
			progress += lipgloss.NewStyle().Foreground(ColorBorder).Render("─")
		}
	}
	lines = append(lines, progress)

	return lines
}

// ---------------------------------------------------------------------------
// Case list view (shared between list and select)
// ---------------------------------------------------------------------------

func (m Model) configViewCaseList(width int, title string, activeOnly bool) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > " + title),
		"",
		cSectionLabel(title), cRule(width),
		"",
	}

	if len(m.cfgState.cases) == 0 {
		msg := "No cases found."
		if activeOnly {
			msg = "No active cases found."
		}
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(msg),
			"",
			cHint("Press Esc to return"))
		return lines
	}

	// Table header.
	hdr := fmt.Sprintf("  %-18s %-28s %-12s %-12s %s", "ID", "Name", "Status", "Class.", "Created")
	lines = append(lines,
		TableHeaderStyle.Render(hdr),
		"  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 85)))

	// Visible window.
	maxVisible := 12
	start := m.cfgState.caseScroll
	end := start + maxVisible
	if end > len(m.cfgState.cases) {
		end = len(m.cfgState.cases)
	}

	for i := start; i < end; i++ {
		c := m.cfgState.cases[i]
		selected := i == m.cfgState.caseCursor

		name := c.Name
		if len(name) > 26 {
			name = name[:24] + ".."
		}

		statusFg := ColorTextSecondary
		switch c.Status {
		case "active":
			statusFg = ColorSuccess
		case "closed":
			statusFg = ColorTextMuted
		}

		classFg := ColorWarning
		if c.Classification == "" {
			classFg = ColorTextMuted
		}

		created := c.CreatedAt.Format("2006-01-02")

		if selected {
			prefix := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> ")
			row := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render(fmt.Sprintf("%-18s %-28s", c.ID, name))
			status := lipgloss.NewStyle().Foreground(statusFg).Bold(true).
				Render(fmt.Sprintf("%-12s", c.Status))
			class := lipgloss.NewStyle().Foreground(classFg).Bold(true).
				Render(fmt.Sprintf("%-12s", c.Classification))
			date := lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(created)
			lines = append(lines, prefix+row+status+class+date)
		} else {
			id := lipgloss.NewStyle().Foreground(ColorAccent).Render(fmt.Sprintf("%-18s", c.ID))
			nameStr := lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%-28s", name))
			status := lipgloss.NewStyle().Foreground(statusFg).Render(fmt.Sprintf("%-12s", c.Status))
			class := lipgloss.NewStyle().Foreground(classFg).Render(fmt.Sprintf("%-12s", c.Classification))
			date := lipgloss.NewStyle().Foreground(ColorTextMuted).Render(created)
			lines = append(lines, "  "+id+nameStr+status+class+date)
		}
	}

	// Scroll indicator.
	if len(m.cfgState.cases) > maxVisible {
		lines = append(lines, "")
		lines = append(lines, cHint(fmt.Sprintf("Showing %d-%d of %d cases",
			start+1, end, len(m.cfgState.cases))))
	}

	lines = append(lines, "")
	lines = append(lines, cHint("Up/Down: navigate  Enter: select  Esc: back"))

	return lines
}

// ---------------------------------------------------------------------------
// Close case confirmation
// ---------------------------------------------------------------------------

func (m Model) configViewCloseCase(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > Close Case"),
		"",
		cSectionLabel("Close Active Case"), cRule(width),
		"",
	}

	if m.ctx.ActiveCase == nil {
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render("No active case."))
		return lines
	}

	c := m.ctx.ActiveCase
	lines = append(lines,
		cField("Case ID", lipgloss.NewStyle().Foreground(ColorPrimary).Render(c.ID)),
		cField("Name", lipgloss.NewStyle().Foreground(ColorText).Render(c.Name)),
		cField("Status", lipgloss.NewStyle().Foreground(ColorSuccess).Render(c.Status)),
		cField("Created", lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			c.CreatedAt.Format("2006-01-02 15:04:05 UTC"))),
		"",
		"  "+WarningStyle.Render(fmt.Sprintf("Close case %s? This sets status to 'closed'. (y/N)", c.ID)),
	)

	return lines
}

// ---------------------------------------------------------------------------
// Edit field view
// ---------------------------------------------------------------------------

func (m Model) configViewEditField(width int, title string) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > " + title),
		"",
		cSectionLabel(title), cRule(width),
		"",
	}

	current := ""
	if m.cfgState.view == cfgViewEditAnalyst {
		current = m.ctx.Config.VanGuard.Analyst
	} else {
		current = m.ctx.Config.VanGuard.Organization
	}
	if current == "" {
		current = "(not set)"
	}

	lines = append(lines,
		cField("Current", lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(current)),
		"",
		"  "+m.cfgState.input.View(),
		"",
		cHint("Enter: save  Esc: cancel"))

	return lines
}

// ---------------------------------------------------------------------------
// Download done view
// ---------------------------------------------------------------------------

func (m Model) configViewDownloadDone(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > Download Results"),
		"",
		cSectionLabel("Download Results"), cRule(width),
	}
	lines = append(lines, m.cfgState.resultLines...)
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// Evidence integrity views
// ---------------------------------------------------------------------------

// configViewIntegrityRunning is shown while the integrity check walks evidence
// for the active case — for a full triage tree this can take several seconds.
func (m Model) configViewIntegrityRunning(width int) []string {
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	return []string{
		"",
		cBreadcrumb("Home > Configuration > Verify Evidence Integrity"),
		"",
		cSectionLabel("Evidence Integrity Check"), cRule(width),
		"",
		cField("Case", lipgloss.NewStyle().Foreground(ColorPrimary).Render(caseID)),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(
			"[▸] Walking evidence and recomputing hashes..."),
		"",
		cHint("This re-hashes every evidence file recorded for the case."),
	}
}

// configViewIntegrityDone renders the per-evidence verdict plus a summary
// banner. Modified evidence is treated as a CRITICAL alert.
func (m Model) configViewIntegrityDone(width int) []string {
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > Verify Evidence Integrity"),
		"",
		cSectionLabel("Evidence Integrity Check — Case " + caseID), cRule(width),
		"",
	}

	if m.cfgState.integrityErr != "" {
		lines = append(lines,
			"  "+ErrorStyle.Render("Integrity check failed: "+m.cfgState.integrityErr),
			"", cHint("Press any key to return"))
		return lines
	}

	if len(m.cfgState.integrityResults) == 0 {
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
				"No evidence has been registered for this case yet."),
			"", cHint("Press any key to return"))
		return lines
	}

	for _, r := range m.cfgState.integrityResults {
		lines = append(lines, formatIntegrityRow(r))
		// Detail lines beneath modified / missing rows for the analyst.
		switch r.Status {
		case casemanager.IntegrityModified:
			lines = append(lines,
				"      "+lipgloss.NewStyle().Foreground(ColorTextMuted).
					Render("Stored SHA256:  "+truncateMid(r.StoredSHA256, 32)),
				"      "+lipgloss.NewStyle().Foreground(ColorError).
					Render("Current SHA256: "+truncateMid(r.CurrentSHA256, 32)))
			if r.Details != "" {
				lines = append(lines,
					"      "+lipgloss.NewStyle().Foreground(ColorWarning).Render(r.Details))
			}
		case casemanager.IntegrityMissing:
			lines = append(lines,
				"      "+lipgloss.NewStyle().Foreground(ColorWarning).
					Render("Missing path: "+r.FilePath))
		case casemanager.IntegrityError:
			lines = append(lines,
				"      "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Details))
		case casemanager.IntegrityInfo:
			lines = append(lines,
				"      "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Details))
		}
	}

	s := m.cfgState.integritySummary
	lines = append(lines, "")
	lines = append(lines, cSectionLabel("Summary"), cRule(width))
	lines = append(lines,
		"  "+lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf(
			"%d/%d verified, %d modified, %d missing, %d errors, %d info",
			s.Verified, s.Total, s.Modified, s.Missing, s.Errors, s.Info)))

	if !s.IsClean() {
		lines = append(lines, "")
		lines = append(lines, "  "+ErrorStyle.Bold(true).Render(
			"⚠  EVIDENCE TAMPERING DETECTED — review modified / missing files immediately"))
	} else {
		lines = append(lines, "")
		lines = append(lines, "  "+SuccessStyle.Render("All evidence verified."))
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// formatIntegrityRow renders a single evidence row. Status colour:
// verified → success green, modified → error red (CRITICAL), missing →
// warning yellow, error → muted, info → secondary.
func formatIntegrityRow(r casemanager.IntegrityResult) string {
	var icon, label string
	var style lipgloss.Style
	switch r.Status {
	case casemanager.IntegrityVerified:
		icon, label, style = "[✓]", "verified", SuccessStyle
	case casemanager.IntegrityModified:
		icon, label, style = "[✗]", "MODIFIED", ErrorStyle
	case casemanager.IntegrityMissing:
		icon, label, style = "[!]", "MISSING", WarningStyle
	case casemanager.IntegrityError:
		icon, label, style = "[?]", "error", lipgloss.NewStyle().Foreground(ColorTextMuted)
	case casemanager.IntegrityInfo:
		icon, label, style = "[i]", "info", lipgloss.NewStyle().Foreground(ColorTextSecondary)
	default:
		icon, label, style = "[?]", string(r.Status), lipgloss.NewStyle().Foreground(ColorTextMuted)
	}

	// Path summary: trim the case-output prefix so the row stays readable;
	// the full path is in the details line for modified/missing.
	path := r.FilePath
	if len(path) > 60 {
		path = "..." + path[len(path)-57:]
	}
	count := ""
	if r.FileCount > 0 {
		count = fmt.Sprintf("  %d files", r.FileCount)
	}
	return "  " + style.Render(icon) + " " +
		lipgloss.NewStyle().Foreground(ColorText).Render(path) + count + "    " +
		style.Render(label)
}

// truncateMid returns a string of length keep, cutting from the middle if
// the input is longer. Used to make long hashes readable.
func truncateMid(s string, keep int) string {
	if len(s) <= keep {
		return s
	}
	half := keep / 2
	return s[:half] + "…" + s[len(s)-half:]
}

// ---------------------------------------------------------------------------
// Volatility3 diagnostic — hidden [V] from the Configuration submenu
// ---------------------------------------------------------------------------

// buildVolDiagnostic produces a multi-line report of the on-disk Volatility3
// install state vs. what the tool registry sees. Used to debug "vol.py exists
// but VanGuard says not installed" reports — much faster than re-reading the
// log to figure out which path was checked.
func (m Model) buildVolDiagnostic() []string {
	root := m.ctx.RootDir
	base := filepath.Join(root, "lib", "volatility3")

	hit := func(b bool) string {
		if b {
			return SuccessStyle.Render("found")
		}
		return ErrorStyle.Render("not found")
	}
	exists := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && !info.IsDir()
	}
	dirExists := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.IsDir()
	}

	out := []string{
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"VanGuard root:    "+root),
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Expected path:    "+base),
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Directory exists: ") + hit(dirExists(base)),
		"",
	}

	if dirExists(base) {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
			Render("Contents (one level deep):"))
		entries, err := os.ReadDir(base)
		if err != nil {
			out = append(out, "    "+ErrorStyle.Render("read error: "+err.Error()))
		} else if len(entries) == 0 {
			out = append(out, "    "+lipgloss.NewStyle().Foreground(ColorTextMuted).
				Render("(empty)"))
		} else {
			for _, e := range entries {
				tag := ""
				if e.IsDir() {
					tag = "/"
					sub, _ := os.ReadDir(filepath.Join(base, e.Name()))
					names := []string{}
					for i, s := range sub {
						if i >= 6 {
							names = append(names, "...")
							break
						}
						names = append(names, s.Name())
					}
					out = append(out, fmt.Sprintf("    %-30s  %s",
						lipgloss.NewStyle().Foreground(ColorPrimary).Render(e.Name()+tag),
						lipgloss.NewStyle().Foreground(ColorTextMuted).Render(strings.Join(names, ", "))))
				} else {
					out = append(out, "    "+
						lipgloss.NewStyle().Foreground(ColorText).Render(e.Name()))
				}
			}
		}
		out = append(out, "")
	}

	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render("Searched paths for vol.py:"))
	candidates := []string{
		filepath.Join(base, "vol.py"),
		filepath.Join(base, "volatility3", "cli.py"),
	}
	for _, c := range candidates {
		out = append(out, fmt.Sprintf("    %-60s %s", c, hit(exists(c))))
	}
	// One-level-deep glob.
	matches, _ := filepath.Glob(filepath.Join(base, "*", "vol.py"))
	out = append(out, fmt.Sprintf("    %-60s %s",
		filepath.Join(base, "*", "vol.py"),
		formatGlobHit(matches)))

	out = append(out, "")
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render("Searched paths for volatility3 package:"))
	pkgCandidates := []string{
		filepath.Join(base, "volatility3", "__init__.py"),
	}
	for _, c := range pkgCandidates {
		out = append(out, fmt.Sprintf("    %-60s %s", c, hit(exists(c))))
	}
	pkgMatches, _ := filepath.Glob(filepath.Join(base, "*", "volatility3", "__init__.py"))
	out = append(out, fmt.Sprintf("    %-60s %s",
		filepath.Join(base, "*", "volatility3", "__init__.py"),
		formatGlobHit(pkgMatches)))

	out = append(out, "")
	out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render("Tool registry:"))
	if m.ctx.ToolManager != nil {
		for _, t := range m.ctx.ToolManager.AllTools() {
			if !strings.Contains(t.ID, "volatility3") {
				continue
			}
			installedStyle := ErrorStyle
			installedTxt := "false"
			if t.Installed {
				installedStyle = SuccessStyle
				installedTxt = "true"
			}
			out = append(out,
				"    "+lipgloss.NewStyle().Foreground(ColorText).Render("ID:        ")+t.ID,
				"    "+lipgloss.NewStyle().Foreground(ColorText).Render("LocalPath: ")+t.LocalPath,
				"    "+lipgloss.NewStyle().Foreground(ColorText).Render("Installed: ")+
					installedStyle.Render(installedTxt))
		}
	}

	out = append(out, "", cHint("Press any key to return"))
	return out
}

func formatGlobHit(matches []string) string {
	if len(matches) == 0 {
		return ErrorStyle.Render("no matches")
	}
	if len(matches) == 1 {
		return SuccessStyle.Render("found: " + matches[0])
	}
	return SuccessStyle.Render(fmt.Sprintf("%d matches, first: %s", len(matches), matches[0]))
}

// configViewVolDiagnostic renders the diagnostic report in the content pane.
func (m Model) configViewVolDiagnostic(width int) []string {
	lines := []string{
		cSectionLabel("Volatility3 Diagnostic"),
		cRule(width),
		"",
	}
	lines = append(lines, m.cfgState.resultLines...)
	return lines
}
