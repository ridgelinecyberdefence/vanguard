package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/velociraptor"
)

// ---------------------------------------------------------------------------
// VR panel states
// ---------------------------------------------------------------------------

type vrView int

const (
	vrViewNone vrView = iota
	// Init
	vrViewInitConfirm   // existing config — confirm reinit
	vrViewInitPassword  // password input
	vrViewInitRunning   // async init in progress
	vrViewInitDone      // show result
	vrViewRegenConfirm  // confirm cert regeneration (existing clients will be invalidated)
	// Start / Stop / Status
	vrViewStartRunning
	vrViewStartDone
	vrViewStopping
	vrViewStopDone
	vrViewCheckingStatus
	vrViewStatus
	vrViewOpenUI
	// Client package
	vrViewClientPlatform // platform selection
	vrViewClientRunning
	vrViewClientDone
	// Deploy
	vrViewDeployMethod   // method selection
	vrViewDeployCredHost // host input
	vrViewDeployCredUser // user input
	vrViewDeployCredPass // password/key input
	vrViewDeployCredPort // port input
	vrViewDeployRunning
	vrViewDeployDone
	vrViewDeployManual
	// Offline collector
	vrViewCollectorProfile  // profile selection
	vrViewCollectorPlatform // platform selection
	vrViewCollectorRunning
	vrViewCollectorDone
	// Import
	vrViewImportPath // file path input
	vrViewImportDone
	// Placeholder results
	vrViewPlaceholder
)

// VRState holds all state for the Velociraptor submenu's interactive panels.
type VRState struct {
	view vrView

	// Text input (password, hostname, path).
	input textinput.Model

	// Selection lists.
	selectOptions []string
	selectCursor  int

	// Multi-step deploy form state.
	deployMethod   int
	deployHost     string
	deployUser     string
	deployPassword string
	deployPort     string

	// Collector state.
	collectorProfile  int
	collectorPlatform string

	// Result lines for display.
	resultLines []string
}

// ---------------------------------------------------------------------------
// Custom tea.Msg types for async VR operations
// ---------------------------------------------------------------------------

type vrInitDoneMsg struct {
	result velociraptor.InitResult
}

type vrStartDoneMsg struct {
	result velociraptor.StartResult
}

type vrStopDoneMsg struct {
	result velociraptor.StopResult
}

type vrClientDoneMsg struct {
	result velociraptor.ClientPackageResult
}

type vrCollectorDoneMsg struct {
	result velociraptor.CollectorResult
}

type vrImportDoneMsg struct {
	result velociraptor.ImportResult
}

type vrStatusDoneMsg struct {
	lines []string
}

// ---------------------------------------------------------------------------
// VR panel helpers
// ---------------------------------------------------------------------------

func newPasswordInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.CharLimit = 120
	ti.Width = 50
	ti.Focus()
	return ti
}

func newVRTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	ti.Width = 60
	ti.Focus()
	return ti
}

// ---------------------------------------------------------------------------
// Prerequisite checks
// ---------------------------------------------------------------------------

// vrPrereqBinary checks if velociraptor binary is installed. Returns error lines or nil.
func (m Model) vrPrereqBinary() []string {
	if m.ctx.VRManager == nil {
		return []string{
			"",
			"  " + ErrorStyle.Render("Velociraptor manager not initialized."),
		}
	}
	if !m.ctx.VRManager.BinaryInstalled() {
		return []string{
			"",
			"  " + ErrorStyle.Render("Velociraptor binary not found."),
			"",
			cHint("Press [8] Configuration > [6] Download Required Tools to install."),
		}
	}
	return nil
}

// vrPrereqCase checks if there's an active case.
func (m Model) vrPrereqCase() []string {
	if m.ctx.ActiveCase == nil {
		return []string{
			"",
			"  " + WarningStyle.Render("No active case."),
			"",
			cHint("Press [8] Configuration > [1] Create New Case first."),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// VR panel Update — returns updated model + cmd
// ---------------------------------------------------------------------------

// vrUpdate handles key events when a VR panel view is active.
// Returns true if the event was consumed.
func (m Model) vrUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.vrState.view == vrViewNone {
		return m, nil, false
	}

	key := msg.String()

	switch m.vrState.view {
	// ── Init ──
	case vrViewInitConfirm:
		return m.vrUpdateInitConfirm(key)
	case vrViewRegenConfirm:
		return m.vrUpdateRegenConfirm(key)
	case vrViewInitPassword:
		return m.vrUpdateInitPassword(msg, key)
	case vrViewInitRunning:
		return m, nil, true // block input
	case vrViewInitDone, vrViewStartDone, vrViewStopDone, vrViewStatus,
		vrViewOpenUI, vrViewClientDone, vrViewDeployDone, vrViewDeployManual,
		vrViewCollectorDone, vrViewImportDone, vrViewPlaceholder:
		// Any key dismisses result views.
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		return m, nil, true

	// ── Start / Stop / Status ──
	case vrViewStartRunning, vrViewStopping, vrViewCheckingStatus:
		return m, nil, true // block input during async ops

	// ── Client package ──
	case vrViewClientPlatform:
		return m.vrUpdateSelect(msg, key, m.vrActivateClientPlatform)
	case vrViewClientRunning:
		return m, nil, true

	// ── Deploy ──
	case vrViewDeployMethod:
		return m.vrUpdateSelect(msg, key, m.vrActivateDeployMethod)
	case vrViewDeployCredHost:
		return m.vrUpdateTextInput(msg, key, m.vrAdvanceDeployHost)
	case vrViewDeployCredUser:
		return m.vrUpdateTextInput(msg, key, m.vrAdvanceDeployUser)
	case vrViewDeployCredPass:
		return m.vrUpdateTextInput(msg, key, m.vrAdvanceDeployPass)
	case vrViewDeployCredPort:
		return m.vrUpdateTextInput(msg, key, m.vrAdvanceDeployPort)
	case vrViewDeployRunning:
		return m, nil, true

	// ── Offline collector ──
	case vrViewCollectorProfile:
		return m.vrUpdateSelect(msg, key, m.vrActivateCollectorProfile)
	case vrViewCollectorPlatform:
		return m.vrUpdateSelect(msg, key, m.vrActivateCollectorPlatform)
	case vrViewCollectorRunning:
		return m, nil, true

	// ── Import ──
	case vrViewImportPath:
		return m.vrUpdateTextInput(msg, key, m.vrActivateImportPath)
	}

	return m, nil, false
}

// ---------------------------------------------------------------------------
// Generic helpers for selection lists and text inputs
// ---------------------------------------------------------------------------

type selectCallback func(m Model, idx int) (Model, tea.Cmd, bool)
type textCallback func(m Model, value string) (Model, tea.Cmd, bool)

func (m Model) vrUpdateSelect(msg tea.KeyMsg, key string, activate selectCallback) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.vrState.selectCursor > 0 {
			m.vrState.selectCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.vrState.selectCursor < len(m.vrState.selectOptions)-1 {
			m.vrState.selectCursor++
		}
		return m, nil, true
	case "enter":
		return activate(m, m.vrState.selectCursor)
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx < len(m.vrState.selectOptions) {
			m.vrState.selectCursor = idx
			return activate(m, idx)
		}
	}
	return m, nil, true
}

func (m Model) vrUpdateTextInput(msg tea.KeyMsg, key string, activate textCallback) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		m.statusMessage = "Cancelled."
		return m, nil, true
	case "enter":
		value := strings.TrimSpace(m.vrState.input.Value())
		return activate(m, value)
	default:
		var cmd tea.Cmd
		m.vrState.input, cmd = m.vrState.input.Update(msg)
		return m, cmd, true
	}
}

// ---------------------------------------------------------------------------
// [1] Initialize Server
// ---------------------------------------------------------------------------

func (m Model) vrUpdateInitConfirm(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "y", "Y":
		// Proceed to password input.
		m.vrState.view = vrViewInitPassword
		m.vrState.input = newPasswordInput("Admin password for Velociraptor GUI")
		return m, m.vrState.input.Focus(), true
	default:
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		m.statusMessage = "Initialization cancelled."
		return m, nil, true
	}
}

func (m Model) vrUpdateInitPassword(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		m.statusMessage = "Initialization cancelled."
		return m, nil, true
	case "enter":
		password := m.vrState.input.Value()
		if password == "" {
			m.statusMessage = "Password is required."
			return m, nil, true
		}
		// Launch async init.
		m.vrState.view = vrViewInitRunning
		m.vrState.resultLines = []string{
			"",
			"  " + SpinnerStyle.Render("Initializing Velociraptor server..."),
			"",
			cHint("This may take a moment while certificates are generated."),
		}
		mgr := m.ctx.VRManager
		return m, func() tea.Msg {
			result := mgr.Initialize(password)
			return vrInitDoneMsg{result: result}
		}, true
	default:
		var cmd tea.Cmd
		m.vrState.input, cmd = m.vrState.input.Update(msg)
		return m, cmd, true
	}
}

// ---------------------------------------------------------------------------
// [2] Start Server (async)
// ---------------------------------------------------------------------------

func (m Model) vrStartServer() (Model, tea.Cmd) {
	m.vrState.view = vrViewStartRunning
	m.vrState.resultLines = []string{
		"",
		"  " + SpinnerStyle.Render("Starting Velociraptor server..."),
		"",
		cHint("Waiting for health check (3-5 seconds)..."),
	}
	m.state = stateResult
	mgr := m.ctx.VRManager
	logDir := m.ctx.RootDir + "/logs"
	return m, func() tea.Msg {
		result := mgr.Start(logDir)
		return vrStartDoneMsg{result: result}
	}
}

// ---------------------------------------------------------------------------
// [6] Client package — platform selection callback
// ---------------------------------------------------------------------------

func (m Model) vrActivateClientPlatform(mIn Model, idx int) (Model, tea.Cmd, bool) {
	m = mIn
	platforms := []string{"windows-amd64", "linux-amd64", "linux-arm64"}
	if idx >= len(platforms) {
		return m, nil, true
	}
	platform := platforms[idx]
	caseID := m.ctx.ActiveCase.ID

	m.vrState.view = vrViewClientRunning
	m.vrState.resultLines = []string{
		"",
		"  " + SpinnerStyle.Render(fmt.Sprintf("Generating %s client package...", platform)),
	}
	mgr := m.ctx.VRManager
	return m, func() tea.Msg {
		result := mgr.GenerateClientPackage(platform, caseID)
		return vrClientDoneMsg{result: result}
	}, true
}

// ---------------------------------------------------------------------------
// [7] Deploy — method selection + credential form callbacks
// ---------------------------------------------------------------------------

func (m Model) vrActivateDeployMethod(mIn Model, idx int) (Model, tea.Cmd, bool) {
	m = mIn
	m.vrState.deployMethod = idx

	if idx == 3 {
		// Manual — show instructions immediately.
		m.vrState.view = vrViewDeployManual
		caseID := ""
		if m.ctx.ActiveCase != nil {
			caseID = m.ctx.ActiveCase.ID
		}
		m.vrState.resultLines = m.ctx.VRManager.ManualDeployInstructions(caseID, m.ctx.VRManager.State.GUIPort)
		return m, nil, true
	}

	// Remote deployment — collect credentials.
	m.vrState.view = vrViewDeployCredHost
	m.vrState.input = newVRTextInput("Target hostname or IP address")
	return m, m.vrState.input.Focus(), true
}

func (m Model) vrAdvanceDeployHost(mIn Model, value string) (Model, tea.Cmd, bool) {
	m = mIn
	if value == "" {
		m.statusMessage = "Hostname is required."
		return m, nil, true
	}
	m.vrState.deployHost = value
	m.vrState.view = vrViewDeployCredUser
	m.vrState.input = newVRTextInput("Username")
	return m, m.vrState.input.Focus(), true
}

func (m Model) vrAdvanceDeployUser(mIn Model, value string) (Model, tea.Cmd, bool) {
	m = mIn
	if value == "" {
		m.statusMessage = "Username is required."
		return m, nil, true
	}
	m.vrState.deployUser = value
	m.vrState.view = vrViewDeployCredPass

	switch m.vrState.deployMethod {
	case 1: // SSH — could be key path
		m.vrState.input = newVRTextInput("Password or SSH key path")
	default:
		m.vrState.input = newPasswordInput("Password")
	}
	return m, m.vrState.input.Focus(), true
}

func (m Model) vrAdvanceDeployPass(mIn Model, value string) (Model, tea.Cmd, bool) {
	m = mIn
	m.vrState.deployPassword = value
	m.vrState.view = vrViewDeployCredPort

	defaultPort := "5985"
	switch m.vrState.deployMethod {
	case 0: // WinRM
		defaultPort = "5985"
	case 1: // SSH
		defaultPort = "22"
	case 2: // PSExec
		defaultPort = "445"
	}
	m.vrState.input = newVRTextInput(fmt.Sprintf("Port (default: %s)", defaultPort))
	m.vrState.input.SetValue(defaultPort)
	return m, m.vrState.input.Focus(), true
}

func (m Model) vrAdvanceDeployPort(mIn Model, value string) (Model, tea.Cmd, bool) {
	m = mIn
	m.vrState.deployPort = value

	// Build deployment summary — actual remote deployment requires internal/network/*
	// which is not yet implemented. Show what would happen.
	methods := []string{"WinRM", "SSH", "PSExec"}
	method := methods[m.vrState.deployMethod]

	m.vrState.view = vrViewDeployDone
	m.vrState.resultLines = []string{
		"",
		"  " + WarningStyle.Render("Implementation pending — remote agent push uses an external transport."),
		"",
		cSectionLabel("Deployment Parameters"),
		cField("Method", lipgloss.NewStyle().Foreground(ColorPrimary).Render(method)),
		cField("Target", lipgloss.NewStyle().Foreground(ColorText).Render(m.vrState.deployHost)),
		cField("Username", lipgloss.NewStyle().Foreground(ColorText).Render(m.vrState.deployUser)),
		cField("Port", lipgloss.NewStyle().Foreground(ColorText).Render(m.vrState.deployPort)),
		"",
		cHint("Workaround: copy the generated client package to the target with"),
		cHint("scp / robocopy / Intune and run it elevated. Use [4] Manual deployment"),
		cHint("for the canonical command line for the target platform."),
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// [8] Offline collector — profile + platform callbacks
// ---------------------------------------------------------------------------

func (m Model) vrActivateCollectorProfile(mIn Model, idx int) (Model, tea.Cmd, bool) {
	m = mIn
	if idx == 3 {
		// Custom — placeholder.
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + WarningStyle.Render("Implementation pending — custom artifact picker."),
			"",
			cHint("Workaround: edit the generated YAML in velociraptor/configs/ to add or"),
			cHint("remove artifacts before running [8] Create Offline Collector."),
		}
		return m, nil, true
	}
	m.vrState.collectorProfile = idx

	// Select platform.
	m.vrState.view = vrViewCollectorPlatform
	m.vrState.selectOptions = []string{"Windows", "Linux"}
	m.vrState.selectCursor = 0
	return m, nil, true
}

func (m Model) vrActivateCollectorPlatform(mIn Model, idx int) (Model, tea.Cmd, bool) {
	m = mIn
	platforms := []string{"windows", "linux"}
	if idx >= len(platforms) {
		return m, nil, true
	}
	platform := platforms[idx]
	m.vrState.collectorPlatform = platform

	caseID := m.ctx.ActiveCase.ID
	profileIdx := m.vrState.collectorProfile

	m.vrState.view = vrViewCollectorRunning
	m.vrState.resultLines = []string{
		"",
		"  " + SpinnerStyle.Render("Creating offline collector..."),
	}
	mgr := m.ctx.VRManager
	return m, func() tea.Msg {
		result := mgr.CreateOfflineCollector(profileIdx, platform, caseID)
		return vrCollectorDoneMsg{result: result}
	}, true
}

// ---------------------------------------------------------------------------
// [A] Import — path input callback
// ---------------------------------------------------------------------------

func (m Model) vrActivateImportPath(mIn Model, value string) (Model, tea.Cmd, bool) {
	m = mIn
	if value == "" {
		m.statusMessage = "File path is required."
		return m, nil, true
	}

	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}

	mgr := m.ctx.VRManager
	m.vrState.view = vrViewImportDone
	result := mgr.ImportCollection(value, caseID)

	if !result.Success {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Import failed: "+result.Error),
		}
	} else {
		m.vrState.resultLines = []string{
			"",
			"  " + SuccessStyle.Render("Collection imported successfully."),
			"",
			cField("Import Path", lipgloss.NewStyle().Foreground(ColorText).Render(result.ImportPath)),
			"",
			cHint("View results in the Velociraptor GUI or Analysis & Reporting."),
		}

		// Log as evidence if there's an active case.
		if m.ctx.ActiveCase != nil {
			_, _ = m.ctx.CaseManager.AddEvidence(
				m.ctx.ActiveCase.ID, 0, "velociraptor_collection", value)
		}
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Config action handlers — called from activateContentItem
// ---------------------------------------------------------------------------

// handleVRAction processes velociraptor submenu actions. Returns true if handled.
//
// MUST short-circuit on action prefix BEFORE any state mutation: the dispatcher
// in activateContentItem chains panel handlers, so claiming "handled" for a
// non-VR action (e.g. mem_dumpit) hijacks the dispatch and renders VR content.
func (m Model) handleVRAction(action string) (Model, tea.Cmd, bool) {
	if !strings.HasPrefix(action, "vr_") {
		return m, nil, false
	}

	m.clearPanelState()

	// Binary prerequisite for all VR actions.
	if errLines := m.vrPrereqBinary(); errLines != nil {
		m.vrState.resultLines = errLines
		m.vrState.view = vrViewPlaceholder
		m.state = stateResult
		return m, nil, true
	}

	switch action {
	case "vr_init":
		return m.handleVRInit()
	case "vr_regen_certs":
		return m.handleVRRegenCerts()
	case "vr_start":
		return m.handleVRStart()
	case "vr_stop":
		return m.handleVRStop()
	case "vr_status":
		return m.handleVRStatus()
	case "vr_webui":
		return m.handleVRWebUI()
	case "vr_client":
		return m.handleVRClient()
	case "vr_deploy":
		return m.handleVRDeploy()
	case "vr_offline":
		return m.handleVROffline()
	case "vr_hunt":
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + WarningStyle.Render("Implementation pending — multi-client hunt orchestration."),
			"",
			cHint("Workaround: use the Velociraptor GUI ([5] Open Web UI) to launch hunts"),
			cHint("interactively against connected clients."),
		}
		m.state = stateResult
		return m, nil, true
	case "vr_vql":
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + WarningStyle.Render("Implementation pending — interactive VQL query runner."),
			"",
			cHint("Workaround: run the Velociraptor binary directly:"),
			cHint("  velociraptor.exe --config server.config.yaml query \"<your VQL>\""),
		}
		m.state = stateResult
		return m, nil, true
	case "vr_import":
		return m.handleVRImport()
	case "vr_export":
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + WarningStyle.Render("Implementation pending — bulk results export."),
			"",
			cHint("Workaround: use the Velociraptor GUI's Notebook export, or query the"),
			cHint("datastore directly via 'velociraptor.exe export'."),
		}
		m.state = stateResult
		return m, nil, true
	}

	return m, nil, false
}

// ── [1] Init ──

func (m Model) handleVRInit() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager
	if mgr.ServerInitialized() {
		m.vrState.view = vrViewInitConfirm
		m.state = stateResult
		return m, nil, true
	}
	// Go straight to password input.
	m.vrState.view = vrViewInitPassword
	m.vrState.input = newPasswordInput("Admin password for Velociraptor GUI")
	m.state = stateResult
	return m, m.vrState.input.Focus(), true
}

// handleVRRegenCerts shows a destructive-action confirmation prompt before
// regenerating server certificates. Existing clients trust the OLD cert and
// will fail to connect after rotation — they need new client.config.yaml
// packages, so the operator must explicitly opt in.
func (m Model) handleVRRegenCerts() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager
	if !mgr.ServerInitialized() {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Server not initialized."),
			"",
			cHint("Run [1] Initialize Server first — there are no certificates to regenerate yet."),
		}
		m.state = stateResult
		return m, nil, true
	}
	m.vrState.view = vrViewRegenConfirm
	m.state = stateResult
	return m, nil, true
}

// vrUpdateRegenConfirm handles y/n on the regenerate-certs prompt. On accept
// it routes into the same password-input flow as init — RegenerateCertificates
// is implemented as a re-Init, so the password is required to recreate the
// admin user.
func (m Model) vrUpdateRegenConfirm(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "y", "Y":
		m.vrState.view = vrViewInitPassword
		m.vrState.input = newPasswordInput("Admin password (will be set anew)")
		return m, m.vrState.input.Focus(), true
	default:
		m.vrState.view = vrViewNone
		m.state = stateSubMenu
		m.statusMessage = "Certificate regeneration cancelled."
		return m, nil, true
	}
}

// ── [2] Start ──

func (m Model) handleVRStart() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager
	if !mgr.ServerInitialized() {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Server not initialized."),
			"",
			cHint("Run [1] Initialize Server first."),
		}
		m.state = stateResult
		return m, nil, true
	}
	if mgr.State.Running {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + SuccessStyle.Render(fmt.Sprintf(
				"Server is already running on port %d (PID %d).",
				mgr.State.GUIPort, mgr.State.PID)),
		}
		m.state = stateResult
		return m, nil, true
	}
	mm, cmd := m.vrStartServer()
	return mm, cmd, true
}

// ── [3] Stop ──

func (m Model) handleVRStop() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager
	if !mgr.State.Running {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Server is not running."),
		}
		m.state = stateResult
		return m, nil, true
	}

	m.vrState.view = vrViewStopping
	m.state = stateResult
	m.vrState.resultLines = []string{
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("Stopping server..."),
	}
	cmd := func() tea.Msg {
		return vrStopDoneMsg{result: mgr.Stop()}
	}
	return m, cmd, true
}

// ── [4] Status ──

func (m Model) handleVRStatus() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager

	m.vrState.view = vrViewCheckingStatus
	m.vrState.resultLines = []string{
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("Checking server status..."),
	}
	m.state = stateResult

	cmd := func() tea.Msg {
		info := mgr.Status()

		statusStr := "NOT RUNNING"
		statusFg := ColorError
		if info.Running {
			statusStr = "RUNNING"
			statusFg = ColorSuccess
			if !info.Healthy {
				statusStr = "RUNNING (not responding)"
				statusFg = ColorWarning
			}
		}

		lines := []string{
			"",
			cField("Status", lipgloss.NewStyle().Foreground(statusFg).Bold(true).Render(statusStr)),
		}

		pidStr := "-"
		if info.PID > 0 {
			pidStr = fmt.Sprintf("%d", info.PID)
		}
		lines = append(lines, cField("PID", lipgloss.NewStyle().Foreground(ColorText).Render(pidStr)))
		lines = append(lines, cField("GUI URL", lipgloss.NewStyle().Foreground(ColorAccent).Render(info.GUIURL)))
		lines = append(lines, cField("Frontend", lipgloss.NewStyle().Foreground(ColorText).Render(info.FrontendAddr)))
		lines = append(lines, cField("Config", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(info.ConfigPath)))
		lines = append(lines, cField("Data Store", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(info.DataStorePath)))

		if info.Running {
			uptime := info.Uptime.Truncate(time.Second)
			lines = append(lines, cField("Uptime", lipgloss.NewStyle().Foreground(ColorText).Render(uptime.String())))
		}

		if info.LogPath != "" {
			lines = append(lines, cField("Log", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(info.LogPath)))
		}

		return vrStatusDoneMsg{lines: lines}
	}

	return m, cmd, true
}

// ── [5] Open Web UI ──

func (m Model) handleVRWebUI() (Model, tea.Cmd, bool) {
	mgr := m.ctx.VRManager
	url, err := mgr.OpenWebUI()

	m.vrState.view = vrViewOpenUI
	m.state = stateResult

	if err != nil {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render(err.Error()),
			"",
			cHint("Start the server first with [2]."),
		}
		return m, nil, true
	}

	lines := []string{
		"",
		"  " + SuccessStyle.Render(fmt.Sprintf("Opening %s in default browser...", url)),
	}

	if velociraptor.IsRemoteSession() {
		lines = append(lines,
			"",
			"  "+WarningStyle.Render("Remote session detected."),
			"  "+lipgloss.NewStyle().Foreground(ColorText).Render(
				fmt.Sprintf("Access the GUI at %s from your local browser.", url)),
		)
	}

	m.vrState.resultLines = lines
	return m, nil, true
}

// ── [6] Client Package ──

func (m Model) handleVRClient() (Model, tea.Cmd, bool) {
	if errLines := m.vrPrereqCase(); errLines != nil {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = errLines
		m.state = stateResult
		return m, nil, true
	}
	if !m.ctx.VRManager.ServerInitialized() {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Server not initialized — run [1] Initialize Server first."),
		}
		m.state = stateResult
		return m, nil, true
	}

	m.vrState.view = vrViewClientPlatform
	m.vrState.selectOptions = []string{
		"Windows (amd64)",
		"Linux (amd64)",
		"Linux (arm64)",
	}
	m.vrState.selectCursor = 0
	m.state = stateResult
	return m, nil, true
}

// ── [7] Deploy ──

func (m Model) handleVRDeploy() (Model, tea.Cmd, bool) {
	if errLines := m.vrPrereqCase(); errLines != nil {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = errLines
		m.state = stateResult
		return m, nil, true
	}

	m.vrState.view = vrViewDeployMethod
	m.vrState.selectOptions = []string{
		"WinRM (Windows targets)",
		"SSH (Linux targets)",
		"PSExec (Windows targets)",
		"Manual (copy instructions)",
	}
	m.vrState.selectCursor = 0
	m.state = stateResult
	return m, nil, true
}

// ── [8] Offline Collector ──

func (m Model) handleVROffline() (Model, tea.Cmd, bool) {
	if errLines := m.vrPrereqCase(); errLines != nil {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = errLines
		m.state = stateResult
		return m, nil, true
	}
	if !m.ctx.VRManager.ServerInitialized() {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Server not initialized — run [1] Initialize Server first."),
		}
		m.state = stateResult
		return m, nil, true
	}

	m.vrState.view = vrViewCollectorProfile
	m.vrState.selectOptions = []string{
		"Full Triage (all artifacts)",
		"Quick Triage (essential artifacts only)",
		"Memory + Triage",
		"Custom (select artifacts)",
	}
	m.vrState.selectCursor = 0
	m.state = stateResult
	return m, nil, true
}

// ── [A] Import ──

func (m Model) handleVRImport() (Model, tea.Cmd, bool) {
	if errLines := m.vrPrereqCase(); errLines != nil {
		m.vrState.view = vrViewPlaceholder
		m.vrState.resultLines = errLines
		m.state = stateResult
		return m, nil, true
	}

	m.vrState.view = vrViewImportPath
	m.vrState.input = newVRTextInput("Path to collection ZIP file")
	m.state = stateResult
	return m, m.vrState.input.Focus(), true
}

// ---------------------------------------------------------------------------
// VR panel View rendering
// ---------------------------------------------------------------------------

// vrContent renders the active VR panel view.
func (m Model) vrContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Velociraptor Operations"),
		"",
	}

	switch m.vrState.view {
	case vrViewInitConfirm:
		lines = append(lines, m.vrViewInitConfirm(width)...)
	case vrViewRegenConfirm:
		lines = append(lines, m.vrViewRegenConfirm(width)...)
	case vrViewInitPassword:
		lines = append(lines, m.vrViewInitPassword(width)...)
	case vrViewInitRunning:
		lines = append(lines, m.vrViewProgress(width, "Initializing Server")...)
	case vrViewInitDone:
		lines = append(lines, m.vrViewResult(width, "Server Initialization")...)
	case vrViewStartRunning:
		lines = append(lines, m.vrViewProgress(width, "Starting Server")...)
	case vrViewStartDone:
		lines = append(lines, m.vrViewResult(width, "Server Start")...)
	case vrViewStopping:
		lines = append(lines, m.vrViewProgress(width, "Stopping Server")...)
	case vrViewStopDone:
		lines = append(lines, m.vrViewResult(width, "Server Stop")...)
	case vrViewCheckingStatus:
		lines = append(lines, m.vrViewProgress(width, "Checking Server Status")...)
	case vrViewStatus:
		lines = append(lines, m.vrViewResult(width, "Velociraptor Server Status")...)
	case vrViewOpenUI:
		lines = append(lines, m.vrViewResult(width, "Web UI")...)
	case vrViewClientPlatform:
		lines = append(lines, m.vrViewSelect(width, "Generate Client Package", "Target platform:")...)
	case vrViewClientRunning:
		lines = append(lines, m.vrViewProgress(width, "Generating Client Package")...)
	case vrViewClientDone:
		lines = append(lines, m.vrViewResult(width, "Client Package")...)
	case vrViewDeployMethod:
		lines = append(lines, m.vrViewSelect(width, "Deploy Agent", "Deployment method:")...)
	case vrViewDeployCredHost, vrViewDeployCredUser, vrViewDeployCredPass, vrViewDeployCredPort:
		lines = append(lines, m.vrViewDeployForm(width)...)
	case vrViewDeployRunning:
		lines = append(lines, m.vrViewProgress(width, "Deploying Agent")...)
	case vrViewDeployDone, vrViewDeployManual:
		lines = append(lines, m.vrViewResult(width, "Deploy Agent")...)
	case vrViewCollectorProfile:
		lines = append(lines, m.vrViewSelect(width, "Create Offline Collector", "Collection profile:")...)
	case vrViewCollectorPlatform:
		lines = append(lines, m.vrViewSelect(width, "Create Offline Collector", "Target platform:")...)
	case vrViewCollectorRunning:
		lines = append(lines, m.vrViewProgress(width, "Creating Offline Collector")...)
	case vrViewCollectorDone:
		lines = append(lines, m.vrViewResult(width, "Offline Collector")...)
	case vrViewImportPath:
		lines = append(lines, m.vrViewImportForm(width)...)
	case vrViewImportDone:
		lines = append(lines, m.vrViewResult(width, "Import Collection")...)
	case vrViewPlaceholder:
		lines = append(lines, m.vrState.resultLines...)
		lines = append(lines, "", cHint("Press any key to return"))
	}

	// Append server status footer to all views.
	lines = append(lines, m.vrStatusFooter()...)

	return lines
}

// ---------------------------------------------------------------------------
// View helpers
// ---------------------------------------------------------------------------

func (m Model) vrViewInitConfirm(width int) []string {
	return []string{
		cSectionLabel("Initialize Server"), cRule(width),
		"",
		"  " + WarningStyle.Render("Server configuration already exists."),
		"  " + WarningStyle.Render("Reinitialize? This will overwrite existing certificates. (y/n)"),
	}
}

// vrViewRegenConfirm renders the destructive-action confirmation for
// certificate rotation. Existing client packages embed the OLD cert and
// will fail TLS verification once the server presents the new one — they
// must be re-deployed with fresh client.config.yaml files.
func (m Model) vrViewRegenConfirm(width int) []string {
	return []string{
		cSectionLabel("Regenerate Certificates"), cRule(width),
		"",
		"  " + WarningStyle.Render("Regenerating certificates will disconnect all existing clients."),
		"  " + WarningStyle.Render("They will need new client.config.yaml packages."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"After regeneration: re-deploy via [7] Deploy Agent (Remote) or"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"distribute the new client.config.yaml manually."),
		"",
		"  " + ErrorStyle.Bold(true).Render("Proceed? (y/n)"),
	}
}

func (m Model) vrViewInitPassword(width int) []string {
	return []string{
		cSectionLabel("Initialize Server"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Set Admin Password"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("This password is used to log into the Velociraptor GUI."),
		"",
		"  " + m.vrState.input.View(),
		"",
		cHint("Enter: continue  Esc: cancel"),
	}
}

func (m Model) vrViewProgress(width int, title string) []string {
	lines := []string{
		cSectionLabel(title), cRule(width),
	}
	lines = append(lines, m.vrState.resultLines...)
	return lines
}

func (m Model) vrViewResult(width int, title string) []string {
	lines := []string{
		cSectionLabel(title), cRule(width),
	}
	lines = append(lines, m.vrState.resultLines...)
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) vrViewSelect(width int, title, prompt string) []string {
	lines := []string{
		cSectionLabel(title), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(prompt),
		"",
	}
	for i, opt := range m.vrState.selectOptions {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.vrState.selectCursor {
			lines = append(lines,
				"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
					Render(fmt.Sprintf("  > %s  %s", shortcut, opt)))
		} else {
			sc := lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)
			label := lipgloss.NewStyle().Foreground(ColorText).Render(opt)
			lines = append(lines, "    "+sc+"  "+label)
		}
	}
	lines = append(lines, "", cHint("Up/Down: select  Enter: confirm  Esc: cancel"))
	return lines
}

func (m Model) vrViewDeployForm(width int) []string {
	methods := []string{"WinRM", "SSH", "PSExec"}
	method := methods[m.vrState.deployMethod]

	lines := []string{
		cSectionLabel("Deploy Agent — " + method), cRule(width),
		"",
	}

	// Show completed fields.
	if m.vrState.view >= vrViewDeployCredUser {
		lines = append(lines,
			cField("Host", lipgloss.NewStyle().Foreground(ColorSuccess).Render(m.vrState.deployHost)))
	}
	if m.vrState.view >= vrViewDeployCredPass {
		lines = append(lines,
			cField("Username", lipgloss.NewStyle().Foreground(ColorSuccess).Render(m.vrState.deployUser)))
	}
	if m.vrState.view >= vrViewDeployCredPort {
		lines = append(lines,
			cField("Password", lipgloss.NewStyle().Foreground(ColorSuccess).Render("********")))
	}

	lines = append(lines, "")

	// Current field label.
	switch m.vrState.view {
	case vrViewDeployCredHost:
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Target Hostname / IP"))
	case vrViewDeployCredUser:
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Username"))
	case vrViewDeployCredPass:
		if m.vrState.deployMethod == 1 {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Password or SSH Key Path"))
		} else {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Password"))
		}
	case vrViewDeployCredPort:
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Port"))
	}

	lines = append(lines, "", "  "+m.vrState.input.View(), "")
	lines = append(lines, cHint("Enter: next  Esc: cancel"))
	return lines
}

func (m Model) vrViewImportForm(width int) []string {
	return []string{
		cSectionLabel("Import Offline Collection"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("Collection ZIP Path"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("Enter the full path to the collected ZIP file."),
		"",
		"  " + m.vrState.input.View(),
		"",
		cHint("Enter: import  Esc: cancel"),
	}
}

// vrStatusFooter appends the server status line at the bottom of all VR views.
func (m Model) vrStatusFooter() []string {
	lines := []string{"", ""}

	mgr := m.ctx.VRManager
	if mgr == nil {
		return lines
	}

	// Server status.
	serverLine := "  Server Status: "
	if mgr.State.Running {
		serverLine += SuccessStyle.Render(fmt.Sprintf("RUNNING on port %d", mgr.State.GUIPort))
	} else {
		serverLine += ErrorStyle.Render("NOT RUNNING")
	}

	// Binary status.
	binaryLine := "  Binary: "
	if mgr.BinaryInstalled() {
		binaryLine += SuccessStyle.Render("INSTALLED")
	} else {
		binaryLine += ErrorStyle.Render("NOT FOUND")
	}

	lines = append(lines,
		"  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 40)),
		serverLine,
		binaryLine,
	)

	return lines
}

// ---------------------------------------------------------------------------
// Async result handlers (called from menu.go Update)
// ---------------------------------------------------------------------------

func (m Model) handleVRInitDone(result velociraptor.InitResult) Model {
	m.vrState.view = vrViewInitDone
	m.state = stateResult

	if !result.Success {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Initialization failed:"),
			"  " + ErrorStyle.Render(result.Error),
		}
		// Include steps that did complete.
		if len(result.Steps) > 0 {
			m.vrState.resultLines = append(m.vrState.resultLines, "")
			for _, s := range result.Steps {
				m.vrState.resultLines = append(m.vrState.resultLines,
					"  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(s))
			}
		}
		return m
	}

	m.vrState.resultLines = []string{
		"",
		"  " + SuccessStyle.Render("Server initialized successfully!"),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 40)),
		"",
		cField("Frontend", lipgloss.NewStyle().Foreground(ColorAccent).Render(
			fmt.Sprintf("https://0.0.0.0:%d", result.FrontendPort))),
		cField("GUI", lipgloss.NewStyle().Foreground(ColorAccent).Render(
			fmt.Sprintf("https://localhost:%d", result.GUIPort))),
		cField("Admin User", lipgloss.NewStyle().Foreground(ColorText).Render(result.AdminUser)),
		cField("Server Config", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.ServerConfigPath)),
		cField("Client Config", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.ClientConfigPath)),
		cField("Data Store", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.DataStorePath)),
	}

	if m.ctx.Logger != nil {
		m.ctx.Logger.Info("tui", "velociraptor server initialized")
	}

	return m
}

func (m Model) handleVRStartDone(result velociraptor.StartResult) Model {
	m.vrState.view = vrViewStartDone
	m.state = stateResult

	if result.AlreadyOn {
		m.vrState.resultLines = []string{
			"",
			"  " + SuccessStyle.Render(fmt.Sprintf(
				"Server is already running on port %d (PID %d).",
				m.ctx.VRManager.State.GUIPort, result.PID)),
		}
		return m
	}

	if !result.Success {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Failed to start server:"),
			"  " + ErrorStyle.Render(result.Error),
		}
		return m
	}

	lines := []string{
		"",
		"  " + SuccessStyle.Render("Velociraptor server started!"),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 40)),
		"",
		cField("GUI", lipgloss.NewStyle().Foreground(ColorAccent).Render(result.GUIURL)),
		cField("PID", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", result.PID))),
		cField("Log", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.LogPath)),
	}

	if !result.Healthy {
		lines = append(lines,
			"",
			"  "+WarningStyle.Render(fmt.Sprintf(
				"Server process started (PID %d) but GUI not responding yet.", result.PID)),
			"  "+WarningStyle.Render("Check "+result.LogPath),
		)
	}

	m.vrState.resultLines = lines
	return m
}

func (m Model) handleVRClientDone(result velociraptor.ClientPackageResult) Model {
	m.vrState.view = vrViewClientDone
	m.state = stateResult

	if !result.Success {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Client package generation failed:"),
			"  " + ErrorStyle.Render(result.Error),
		}
		return m
	}

	m.vrState.resultLines = []string{
		"",
		"  " + SuccessStyle.Render("Client package generated!"),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 40)),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorText).Render(result.OutputPath)),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%.1f MB", float64(result.Size)/(1024*1024)))),
		cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.SHA256)),
		"",
		cHint("Deploy this binary to target endpoints. It will auto-connect to the server."),
	}
	return m
}

func (m Model) handleVRCollectorDone(result velociraptor.CollectorResult) Model {
	m.vrState.view = vrViewCollectorDone
	m.state = stateResult

	if !result.Success {
		m.vrState.resultLines = []string{
			"",
			"  " + ErrorStyle.Render("Offline collector creation failed:"),
			"  " + ErrorStyle.Render(result.Error),
		}
		return m
	}

	m.vrState.resultLines = []string{
		"",
		"  " + SuccessStyle.Render("Offline collector created!"),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 40)),
		"",
		cField("Profile", lipgloss.NewStyle().Foreground(ColorPrimary).Render(result.Profile)),
		cField("Platform", lipgloss.NewStyle().Foreground(ColorText).Render(result.Platform)),
		cField("Output", lipgloss.NewStyle().Foreground(ColorText).Render(result.OutputPath)),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%.1f MB", float64(result.Size)/(1024*1024)))),
		cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(result.SHA256)),
		"",
		cSectionLabel("Instructions"),
		"  1. Copy collector to USB drive",
		"  2. Run as Administrator on target",
		"  3. Collector will create a ZIP file with all artifacts",
		"  4. Copy ZIP back and import with [A] Import Offline Collection",
	}
	return m
}
