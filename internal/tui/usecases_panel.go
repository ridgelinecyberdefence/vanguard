package tui

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/usecases"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type ucView int

const (
	ucViewNone ucView = iota
	ucViewError

	ucViewList     // catalog list
	ucViewDetail   // chosen use case detail card
	ucViewParams   // parameter prompt
	ucViewRunning  // execution
	ucViewSummary  // post-run summary

	ucViewTemplateDone // template generated
)

// UsecasesState holds all panel state for [C] Use Cases.
type UsecasesState struct {
	view ucView

	library *usecases.Library
	items   []*usecases.UseCase // visible (after platform filter + the meta entry)

	listCursor int

	// Selected use case for detail / params / run.
	selected *usecases.UseCase

	// Parameter prompt state.
	paramIdx    int
	paramInput  textinput.Model
	paramValues map[string]string

	// Execution state.
	startTime time.Time
	elapsed   time.Duration
	summary   *usecases.RunSummary

	errorMsg     string
	templatePath string
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type ucTickMsg time.Time

type ucRunDoneMsg struct {
	summary usecases.RunSummary
	err     string
}

func ucTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return ucTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Sidebar entry point — replaces the standard submenu dispatch for "usecases".
// ---------------------------------------------------------------------------

func (m Model) openUsecases() (Model, tea.Cmd) {
	m.clearPanelState()
	m.usecasesState = UsecasesState{}

	// Load library: usecases/ on disk overrides the embedded catalog.
	dir := filepath.Join(m.ctx.RootDir, "usecases")
	lib, err := usecases.Load(dir)
	if err != nil {
		m.usecasesState.view = ucViewError
		m.usecasesState.errorMsg = "loading use case library: " + err.Error()
		m.state = stateResult
		return m, nil
	}
	m.usecasesState.library = lib
	m.usecasesState.items = lib.ForPlatform(m.ctx.Platform)
	m.usecasesState.view = ucViewList
	m.state = stateResult
	return m, nil
}

// ---------------------------------------------------------------------------
// Tick
// ---------------------------------------------------------------------------

func (m Model) handleUcTick() (Model, tea.Cmd) {
	if m.usecasesState.view == ucViewRunning {
		m.usecasesState.elapsed = time.Since(m.usecasesState.startTime)
		return m, ucTickCmd()
	}
	return m, nil
}

func (m Model) handleUcRunDone(msg ucRunDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.usecasesState.view = ucViewError
		m.usecasesState.errorMsg = msg.err
		return m, nil
	}
	m.usecasesState.view = ucViewSummary
	m.usecasesState.summary = &msg.summary
	return m, nil
}

// ---------------------------------------------------------------------------
// Key dispatch
// ---------------------------------------------------------------------------

func (m Model) usecasesUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.usecasesState.view == ucViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.usecasesState.view {
	case ucViewError:
		m.usecasesState.view = ucViewNone
		m.state = stateMainMenu
		m.focus = paneSidebar
		return m, nil, true

	case ucViewList:
		return m.ucUpdateList(key)

	case ucViewDetail:
		return m.ucUpdateDetail(key)

	case ucViewParams:
		return m.ucUpdateParams(msg, key)

	case ucViewRunning:
		return m, nil, true // block input

	case ucViewSummary:
		return m.ucUpdateSummary(key)

	case ucViewTemplateDone:
		m.usecasesState.view = ucViewList
		return m, nil, true
	}
	return m, nil, false
}

func (m Model) ucUpdateList(key string) (Model, tea.Cmd, bool) {
	totalRows := len(m.usecasesState.items) + 1 // +1 for the trailing "Create custom" row
	switch key {
	case "esc":
		m.usecasesState.view = ucViewNone
		m.state = stateMainMenu
		m.focus = paneSidebar
		return m, nil, true
	case "up", "k":
		if m.usecasesState.listCursor > 0 {
			m.usecasesState.listCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.usecasesState.listCursor < totalRows-1 {
			m.usecasesState.listCursor++
		}
		return m, nil, true
	case "enter":
		idx := m.usecasesState.listCursor
		if idx == len(m.usecasesState.items) {
			// Create custom template row.
			path, err := usecases.WriteCustomTemplate(filepath.Join(m.ctx.RootDir, "usecases"))
			if err != nil {
				m.usecasesState.view = ucViewError
				m.usecasesState.errorMsg = err.Error()
				return m, nil, true
			}
			m.usecasesState.templatePath = path
			m.usecasesState.view = ucViewTemplateDone
			return m, nil, true
		}
		if idx >= 0 && idx < len(m.usecasesState.items) {
			m.usecasesState.selected = m.usecasesState.items[idx]
			m.usecasesState.view = ucViewDetail
			return m, nil, true
		}
	}
	return m, nil, true
}

func (m Model) ucUpdateDetail(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc", "backspace":
		m.usecasesState.view = ucViewList
		return m, nil, true
	case "r", "R":
		// Need a case for any execution that produces evidence.
		if m.ctx.ActiveCase == nil {
			m.usecasesState.view = ucViewError
			m.usecasesState.errorMsg = "No active case — create one in [8] Configuration before running a use case."
			return m, nil, true
		}
		uc := m.usecasesState.selected
		if len(uc.Parameters) == 0 {
			mm, cmd := m.ucBeginRun(map[string]string{})
			return mm, cmd, true
		}
		// Start parameter prompt loop.
		m.usecasesState.paramIdx = 0
		m.usecasesState.paramValues = map[string]string{}
		return m.ucPromptParam(0)
	}
	return m, nil, true
}

// ucPromptParam moves to the parameter view at index i. If i is past the end,
// kicks off the run.
func (m Model) ucPromptParam(i int) (Model, tea.Cmd, bool) {
	uc := m.usecasesState.selected
	if i >= len(uc.Parameters) {
		mm, cmd := m.ucBeginRun(m.usecasesState.paramValues)
		return mm, cmd, true
	}
	p := uc.Parameters[i]
	ti := textinput.New()
	placeholder := p.Description
	if p.Default != "" {
		placeholder = p.Description + " (default: " + p.Default + ")"
	}
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	ti.Width = 60
	if p.Default != "" {
		ti.SetValue(p.Default)
	}
	ti.Focus()
	m.usecasesState.paramInput = ti
	m.usecasesState.paramIdx = i
	m.usecasesState.view = ucViewParams
	return m, ti.Focus(), true
}

func (m Model) ucUpdateParams(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	uc := m.usecasesState.selected
	p := uc.Parameters[m.usecasesState.paramIdx]
	switch key {
	case "esc":
		m.usecasesState.view = ucViewList
		return m, nil, true
	case "enter":
		v := strings.TrimSpace(m.usecasesState.paramInput.Value())
		if v == "" && p.Required {
			m.statusMessage = "This parameter is required."
			return m, nil, true
		}
		if v != "" {
			m.usecasesState.paramValues[p.Name] = v
		} else if p.Default != "" {
			m.usecasesState.paramValues[p.Name] = p.Default
		}
		return m.ucPromptParam(m.usecasesState.paramIdx + 1)
	default:
		var cmd tea.Cmd
		m.usecasesState.paramInput, cmd = m.usecasesState.paramInput.Update(msg)
		return m, cmd, true
	}
}

func (m Model) ucBeginRun(params map[string]string) (Model, tea.Cmd) {
	uc := m.usecasesState.selected
	m.usecasesState.view = ucViewRunning
	m.usecasesState.startTime = time.Now()

	// Snapshot context for the goroutine.
	caseID := m.ctx.ActiveCase.ID
	rootDir := m.ctx.RootDir
	platform := m.ctx.Platform
	hostname := m.ctx.Hostname
	analyst := m.ctx.Config.VanGuard.Analyst
	tm := m.ctx.ToolManager
	cm := m.ctx.CaseManager
	logger := m.ctx.Logger

	cmd := func() tea.Msg {
		runner := usecases.New(uc, caseID, rootDir, platform, hostname, analyst, tm, cm, logger)
		summary, err := runner.Run(params)
		msg := ucRunDoneMsg{summary: summary}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(ucTickCmd(), cmd)
}

func (m Model) ucUpdateSummary(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc", "backspace", "enter":
		m.usecasesState.view = ucViewList
		return m, nil, true
	}
	return m, nil, true
}
