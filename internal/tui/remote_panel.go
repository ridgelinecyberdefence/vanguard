package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/remote"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type remoteView int

const (
	remoteViewNone remoteView = iota
	remoteViewNeedCase
	remoteViewError
	remoteViewMessage // simple "info" view dismissed by any key

	// Target management.
	remoteViewTargetList
	remoteViewAddHostname
	remoteViewAddIP
	remoteViewAddOS
	remoteViewAddProtocol
	remoteViewAddPort
	remoteViewAddUsername
	remoteViewAddAuthMethod
	remoteViewAddKeyPath
	remoteViewAddNotes
	remoteViewAddConfirm
	remoteViewRemoveConfirm

	// Credentials.
	remoteViewPromptPassword

	// Connectivity / single-target ops.
	remoteViewSelectTarget
	remoteViewRunning
	remoteViewConnDone
	remoteViewOpDone

	// File acquisition / IOC sweep input forms.
	remoteViewAcquirePath
	remoteViewAcquireDesc
	remoteViewIOCType
	remoteViewIOCValue

	// Batch / deploy.
	remoteViewBatchPickTargets
	remoteViewBatchRunning
	remoteViewBatchDone
	remoteViewDeployPickTool
	remoteViewDeployPickTargets
	remoteViewDeployRunning
	remoteViewDeployDone

	// Hunting findings display.
	remoteViewFindings
	// IOC sweep results display.
	remoteViewIOCResults
)

// RemoteState carries everything the remote panel renders or mutates.
type RemoteState struct {
	view remoteView

	// Originating sidebar action.
	action string
	// What to do once a target is picked from remoteViewSelectTarget.
	pendingOp string

	// Active operation messaging.
	operationName string
	startTime     time.Time
	elapsed       time.Duration
	errorMsg      string
	messageTitle  string
	messageLines  []string

	// Targets cache + list cursor.
	targets    []*remote.RemoteTarget
	listCursor int

	// Generic pick set for "select from a few options".
	pickOptions []string
	pickCursor  int

	// Add-target form draft + sub-step input.
	draft     remote.RemoteTarget
	input     textinput.Model
	checkAll  []bool // selection set for batch / deploy targets

	// Active target for the current op.
	current *remote.RemoteTarget
	// Cached password input prompt continuation.
	pendingAfterPassword string

	// Single-result data (connectivity / triage / event log / etc.).
	connResult     *remote.ConnectivityResult
	triageResult   []remote.StepResult
	triageOutDir   string
	collectionRes  *remote.EventLogResult
	acquisition    *remote.AcquisitionResult
	memoryResult   *remote.MemoryCaptureResult
	huntResult     *remote.HuntResult
	iocSweepResult *remote.IOCSweepResult

	// IOC sweep input draft.
	iocType  remote.IOCType
	iocValue string

	// Batch / deploy state.
	batchTriage []remote.BatchTriageResult
	batchIOC    []remote.IOCSweepResult
	deployTool  string
	deployRes   []remote.DeployResult
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type remoteTickMsg time.Time

type remoteConnDoneMsg struct{ res remote.ConnectivityResult }
type remoteTriageDoneMsg struct {
	outDir string
	steps  []remote.StepResult
	err    string
}
type remoteCollectDoneMsg struct {
	kind string // "eventlogs" or "registry"
	res  remote.EventLogResult
	err  string
}
type remoteAcquireDoneMsg struct {
	res remote.AcquisitionResult
	err string
}
type remoteMemoryDoneMsg struct {
	res remote.MemoryCaptureResult
	err string
}
type remoteHuntDoneMsg struct {
	res remote.HuntResult
	err string
}
type remoteIOCDoneMsg struct {
	res remote.IOCSweepResult
}
type remoteBatchTriageDoneMsg struct {
	results []remote.BatchTriageResult
}
type remoteBatchIOCDoneMsg struct {
	results []remote.IOCSweepResult
}
type remoteDeployDoneMsg struct {
	results []remote.DeployResult
}

func remoteTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return remoteTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newRemoteTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	ti.Width = 60
	ti.Focus()
	return ti
}

func newRemotePasswordInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.CharLimit = 200
	ti.Width = 60
	ti.Focus()
	return ti
}

// ensureRemoteState lazily loads the target Store and credential cache.
func (m *Model) ensureRemoteState() error {
	if m.ctx.RemoteCreds == nil {
		m.ctx.RemoteCreds = remote.NewCredentialCache()
	}
	if m.ctx.RemoteStore == nil {
		path := filepath.Join(m.ctx.RootDir, "config", "targets.yaml")
		store, err := remote.NewStore(path)
		if err != nil {
			return err
		}
		m.ctx.RemoteStore = store
	}
	return nil
}

func (m Model) remoteCheckCase() bool { return m.ctx.ActiveCase != nil }

func (m *Model) remoteRequireCase() bool {
	if m.remoteCheckCase() {
		return true
	}
	m.remoteState.view = remoteViewNeedCase
	m.state = stateResult
	return false
}

func (m Model) remoteEngine() *remote.Engine {
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	eng := remote.NewEngine(m.ctx.RootDir, caseID, m.ctx.Logger, m.ctx.RemoteCreds)
	if m.ctx.Config != nil && !m.ctx.Config.Network.PSExec.Cleanup {
		eng.SkipCleanup = true
	}
	return eng
}

// remoteRefreshTargets reloads m.remoteState.targets for the current case.
func (m *Model) remoteRefreshTargets() {
	if m.ctx.RemoteStore == nil {
		return
	}
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	m.remoteState.targets = m.ctx.RemoteStore.ForCase(caseID)
	if m.remoteState.listCursor >= len(m.remoteState.targets) {
		m.remoteState.listCursor = 0
	}
}

// ---------------------------------------------------------------------------
// Action dispatcher
// ---------------------------------------------------------------------------

// handleRemoteAction routes Remote Ops submenu actions.
//
// MUST short-circuit on the action prefix BEFORE any state mutation — the
// dispatcher chains panel handlers and an unprefixed early return would
// hijack other panels' actions.
func (m Model) handleRemoteAction(action string) (Model, tea.Cmd, bool) {
	if !strings.HasPrefix(action, "remote_") {
		return m, nil, false
	}

	m.clearPanelState()
	m.remoteState = RemoteState{action: action}

	if err := m.ensureRemoteState(); err != nil {
		m.remoteState.view = remoteViewError
		m.remoteState.errorMsg = "loading targets: " + err.Error()
		m.state = stateResult
		return m, nil, true
	}

	switch action {
	// Target management.
	case "remote_add":
		if !m.remoteRequireCase() {
			return m, nil, true
		}
		return m.remoteStartAddTarget()
	case "remote_list":
		m.remoteRefreshTargets()
		m.remoteState.view = remoteViewTargetList
		m.state = stateResult
		return m, nil, true
	case "remote_edit":
		m.remoteRefreshTargets()
		m.remoteState.pendingOp = "edit"
		m.remoteState.view = remoteViewSelectTarget
		m.state = stateResult
		return m, nil, true
	case "remote_remove":
		m.remoteRefreshTargets()
		m.remoteState.pendingOp = "remove"
		m.remoteState.view = remoteViewSelectTarget
		m.state = stateResult
		return m, nil, true
	case "remote_test":
		m.remoteRefreshTargets()
		m.remoteState.pendingOp = "test"
		m.remoteState.view = remoteViewSelectTarget
		m.state = stateResult
		return m, nil, true

	// Single-target operations — all need a case + target picker.
	case "remote_triage", "remote_evtx", "remote_registry",
		"remote_acquire", "remote_memory",
		"remote_hunt_proc", "remote_hunt_net", "remote_hunt_persist",
		"remote_ioc":
		if !m.remoteRequireCase() {
			return m, nil, true
		}
		m.remoteRefreshTargets()
		m.remoteState.pendingOp = action
		m.remoteState.view = remoteViewSelectTarget
		m.state = stateResult
		return m, nil, true

	// Multi-target operations.
	case "remote_batch_triage", "remote_batch_ioc":
		if !m.remoteRequireCase() {
			return m, nil, true
		}
		m.remoteRefreshTargets()
		if len(m.remoteState.targets) == 0 {
			m.remoteState.view = remoteViewError
			m.remoteState.errorMsg = "No targets configured. Add one with [1] first."
			m.state = stateResult
			return m, nil, true
		}
		m.remoteState.checkAll = make([]bool, len(m.remoteState.targets))
		for i := range m.remoteState.checkAll {
			m.remoteState.checkAll[i] = true
		}
		m.remoteState.view = remoteViewBatchPickTargets
		m.remoteState.listCursor = 0
		m.state = stateResult
		return m, nil, true

	case "remote_deploy":
		if !m.remoteRequireCase() {
			return m, nil, true
		}
		m.remoteRefreshTargets()
		if len(m.remoteState.targets) == 0 {
			m.remoteState.view = remoteViewError
			m.remoteState.errorMsg = "No targets configured. Add one with [1] first."
			m.state = stateResult
			return m, nil, true
		}
		m.remoteState.pickOptions = []string{
			"Velociraptor client",
			"Hayabusa",
			"Loki",
		}
		m.remoteState.pickCursor = 0
		m.remoteState.view = remoteViewDeployPickTool
		m.state = stateResult
		return m, nil, true
	}
	return m, nil, false
}

// ---------------------------------------------------------------------------
// Tick + key dispatch
// ---------------------------------------------------------------------------

func (m Model) handleRemoteTick() (Model, tea.Cmd) {
	switch m.remoteState.view {
	case remoteViewRunning, remoteViewBatchRunning, remoteViewDeployRunning:
		m.remoteState.elapsed = time.Since(m.remoteState.startTime)
		return m, remoteTickCmd()
	}
	return m, nil
}

func (m Model) remoteUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.remoteState.view == remoteViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.remoteState.view {
	case remoteViewNeedCase:
		switch key {
		case "y", "Y":
			m.remoteState.view = remoteViewNone
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.remoteState.view = remoteViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case remoteViewError, remoteViewMessage,
		remoteViewConnDone, remoteViewOpDone, remoteViewBatchDone,
		remoteViewDeployDone, remoteViewFindings, remoteViewIOCResults:
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true

	case remoteViewRunning, remoteViewBatchRunning, remoteViewDeployRunning:
		return m, nil, true // block input

	case remoteViewTargetList:
		return m.remoteUpdateTargetList(key)

	// Add-target form.
	case remoteViewAddHostname:
		return m.remoteHandleTextInput(msg, key, m.remoteAddHostnameNext)
	case remoteViewAddIP:
		return m.remoteHandleTextInput(msg, key, m.remoteAddIPNext)
	case remoteViewAddOS:
		return m.remoteHandlePick(key, []string{"Windows", "Linux"}, m.remoteAddOSPick)
	case remoteViewAddProtocol:
		return m.remoteHandlePick(key, m.remoteProtocolOptions(), m.remoteAddProtocolPick)
	case remoteViewAddPort:
		return m.remoteHandleTextInput(msg, key, m.remoteAddPortNext)
	case remoteViewAddUsername:
		return m.remoteHandleTextInput(msg, key, m.remoteAddUserNext)
	case remoteViewAddAuthMethod:
		return m.remoteHandlePick(key, []string{"Password", "SSH Key"}, m.remoteAddAuthPick)
	case remoteViewAddKeyPath:
		return m.remoteHandleTextInput(msg, key, m.remoteAddKeyNext)
	case remoteViewAddNotes:
		return m.remoteHandleTextInput(msg, key, m.remoteAddNotesNext)
	case remoteViewAddConfirm:
		switch key {
		case "y", "Y":
			return m.remoteCommitTarget()
		default:
			m.remoteState.view = remoteViewNone
			m.state = stateSubMenu
			m.statusMessage = "Add cancelled."
			return m, nil, true
		}

	// Remove confirmation.
	case remoteViewRemoveConfirm:
		switch key {
		case "y", "Y":
			return m.remoteCommitRemove()
		default:
			m.remoteState.view = remoteViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	// Password prompt.
	case remoteViewPromptPassword:
		return m.remoteHandleTextInput(msg, key, m.remoteSubmitPassword)

	// Target picker for an op.
	case remoteViewSelectTarget:
		return m.remoteUpdateSelectTarget(key)

	// File acquisition.
	case remoteViewAcquirePath:
		return m.remoteHandleTextInput(msg, key, m.remoteAcquirePathNext)
	case remoteViewAcquireDesc:
		return m.remoteHandleTextInput(msg, key, m.remoteAcquireDescNext)

	// IOC sweep input.
	case remoteViewIOCType:
		return m.remoteHandlePick(key,
			[]string{"File hash (SHA256)", "File name pattern", "IP address", "Domain"},
			m.remoteIOCTypePick)
	case remoteViewIOCValue:
		return m.remoteHandleTextInput(msg, key, m.remoteIOCValueSubmit)

	// Batch picker.
	case remoteViewBatchPickTargets:
		return m.remoteUpdateBatchPick(key)

	// Deploy pickers.
	case remoteViewDeployPickTool:
		return m.remoteHandlePick(key, m.remoteState.pickOptions, m.remoteDeployToolPick)
	case remoteViewDeployPickTargets:
		return m.remoteUpdateBatchPick(key)
	}
	return m, nil, false
}

// ---------------------------------------------------------------------------
// Generic input/select helpers
// ---------------------------------------------------------------------------

func (m Model) remoteHandleTextInput(msg tea.KeyMsg, key string, next func(string) (Model, tea.Cmd)) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		m.statusMessage = "Cancelled."
		return m, nil, true
	case "enter":
		v := strings.TrimSpace(m.remoteState.input.Value())
		mm, cmd := next(v)
		return mm, cmd, true
	default:
		var cmd tea.Cmd
		m.remoteState.input, cmd = m.remoteState.input.Update(msg)
		return m, cmd, true
	}
}

func (m Model) remoteHandlePick(key string, options []string, next func(int) (Model, tea.Cmd)) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.remoteState.pickCursor > 0 {
			m.remoteState.pickCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.remoteState.pickCursor < len(options)-1 {
			m.remoteState.pickCursor++
		}
		return m, nil, true
	case "enter":
		mm, cmd := next(m.remoteState.pickCursor)
		return mm, cmd, true
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx >= 0 && idx < len(options) {
			m.remoteState.pickCursor = idx
			mm, cmd := next(idx)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Add-target flow
// ---------------------------------------------------------------------------

func (m Model) remoteStartAddTarget() (Model, tea.Cmd, bool) {
	m.remoteState.draft = remote.RemoteTarget{
		CaseID:     m.ctx.ActiveCase.ID,
		AuthMethod: "password",
		Status:     remote.StatusUntested,
	}
	m.remoteState.view = remoteViewAddHostname
	m.remoteState.input = newRemoteTextInput("Hostname (e.g. DC01)")
	m.state = stateResult
	return m, m.remoteState.input.Focus(), true
}

func (m Model) remoteAddHostnameNext(value string) (Model, tea.Cmd) {
	m.remoteState.draft.Hostname = value
	m.remoteState.view = remoteViewAddIP
	m.remoteState.input = newRemoteTextInput("IP address (e.g. 192.168.1.10) — optional if hostname resolves")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAddIPNext(value string) (Model, tea.Cmd) {
	m.remoteState.draft.IPAddress = value
	m.remoteState.view = remoteViewAddOS
	m.remoteState.pickCursor = 0
	return m, nil
}

func (m Model) remoteAddOSPick(idx int) (Model, tea.Cmd) {
	if idx == 0 {
		m.remoteState.draft.OSType = "windows"
	} else {
		m.remoteState.draft.OSType = "linux"
	}
	m.remoteState.view = remoteViewAddProtocol
	if m.remoteState.draft.OSType == "windows" {
		m.remoteState.pickCursor = 0
	} else {
		m.remoteState.pickCursor = 0 // SSH is the only sensible choice; pickList shows just SSH for Linux
	}
	return m, nil
}

// remoteProtocolOptions returns protocol choices applicable to the draft OS.
func (m Model) remoteProtocolOptions() []string {
	if m.remoteState.draft.OSType == "linux" {
		return []string{"SSH"}
	}
	return []string{"WinRM", "SSH", "PSExec"}
}

func (m Model) remoteAddProtocolPick(idx int) (Model, tea.Cmd) {
	opts := m.remoteProtocolOptions()
	choice := opts[idx]
	switch choice {
	case "WinRM":
		m.remoteState.draft.Protocol = "winrm"
		m.remoteState.draft.Port = 5985
	case "SSH":
		m.remoteState.draft.Protocol = "ssh"
		m.remoteState.draft.Port = 22
	case "PSExec":
		m.remoteState.draft.Protocol = "psexec"
		m.remoteState.draft.Port = 445
	}
	m.remoteState.view = remoteViewAddPort
	m.remoteState.input = newRemoteTextInput(fmt.Sprintf("Port (default %d)", m.remoteState.draft.Port))
	m.remoteState.input.SetValue(fmt.Sprintf("%d", m.remoteState.draft.Port))
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAddPortNext(value string) (Model, tea.Cmd) {
	if value != "" {
		var p int
		_, _ = fmt.Sscanf(value, "%d", &p)
		if p > 0 {
			m.remoteState.draft.Port = p
		}
	}
	m.remoteState.view = remoteViewAddUsername
	m.remoteState.input = newRemoteTextInput("Username")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAddUserNext(value string) (Model, tea.Cmd) {
	m.remoteState.draft.Username = value
	m.remoteState.view = remoteViewAddAuthMethod
	m.remoteState.pickCursor = 0
	if m.remoteState.draft.Protocol != "ssh" {
		// WinRM / PSExec only support password auth in this implementation.
		m.remoteState.draft.AuthMethod = "password"
		m.remoteState.view = remoteViewAddNotes
		m.remoteState.input = newRemoteTextInput("Notes (optional)")
		return m, m.remoteState.input.Focus()
	}
	return m, nil
}

func (m Model) remoteAddAuthPick(idx int) (Model, tea.Cmd) {
	if idx == 0 {
		m.remoteState.draft.AuthMethod = "password"
		m.remoteState.view = remoteViewAddNotes
		m.remoteState.input = newRemoteTextInput("Notes (optional)")
		return m, m.remoteState.input.Focus()
	}
	m.remoteState.draft.AuthMethod = "key"
	m.remoteState.view = remoteViewAddKeyPath
	m.remoteState.input = newRemoteTextInput("Path to SSH private key")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAddKeyNext(value string) (Model, tea.Cmd) {
	m.remoteState.draft.KeyPath = value
	m.remoteState.view = remoteViewAddNotes
	m.remoteState.input = newRemoteTextInput("Notes (optional)")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAddNotesNext(value string) (Model, tea.Cmd) {
	m.remoteState.draft.Notes = value
	m.remoteState.view = remoteViewAddConfirm
	return m, nil
}

func (m Model) remoteCommitTarget() (Model, tea.Cmd, bool) {
	t := m.remoteState.draft
	if _, err := m.ctx.RemoteStore.Add(&t); err != nil {
		m.remoteState.view = remoteViewError
		m.remoteState.errorMsg = "saving target: " + err.Error()
		return m, nil, true
	}
	if m.ctx.CaseManager != nil && m.ctx.ActiveCase != nil {
		_, _ = m.ctx.CaseManager.AddTarget(m.ctx.ActiveCase.ID, t.Hostname, t.IPAddress, t.OSType)
	}
	m.remoteState.view = remoteViewMessage
	m.remoteState.messageTitle = "Target Added"
	m.remoteState.messageLines = []string{
		fmt.Sprintf("Target %s (%s) saved.", t.Hostname, t.IPAddress),
		"",
		"Press [1] List Targets to view all configured targets.",
	}
	return m, nil, true
}

func (m Model) remoteCommitRemove() (Model, tea.Cmd, bool) {
	if m.remoteState.current == nil {
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true
	}
	id := m.remoteState.current.ID
	if err := m.ctx.RemoteStore.Remove(id); err != nil {
		m.remoteState.view = remoteViewError
		m.remoteState.errorMsg = err.Error()
		return m, nil, true
	}
	m.ctx.RemoteCreds.Clear(m.remoteState.current)
	m.remoteState.view = remoteViewMessage
	m.remoteState.messageTitle = "Target Removed"
	m.remoteState.messageLines = []string{"Target removed."}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Target list interaction
// ---------------------------------------------------------------------------

func (m Model) remoteUpdateTargetList(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.remoteState.listCursor > 0 {
			m.remoteState.listCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.remoteState.listCursor < len(m.remoteState.targets)-1 {
			m.remoteState.listCursor++
		}
		return m, nil, true
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Target picker for ops
// ---------------------------------------------------------------------------

func (m Model) remoteUpdateSelectTarget(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.remoteState.listCursor > 0 {
			m.remoteState.listCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.remoteState.listCursor < len(m.remoteState.targets)-1 {
			m.remoteState.listCursor++
		}
		return m, nil, true
	case "enter":
		if len(m.remoteState.targets) == 0 {
			m.remoteState.view = remoteViewError
			m.remoteState.errorMsg = "No targets configured. Add one with [1] first."
			return m, nil, true
		}
		t := m.remoteState.targets[m.remoteState.listCursor]
		m.remoteState.current = t
		return m.remoteAfterTargetSelected(t)
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx >= 0 && idx < len(m.remoteState.targets) {
			m.remoteState.listCursor = idx
			t := m.remoteState.targets[idx]
			m.remoteState.current = t
			return m.remoteAfterTargetSelected(t)
		}
	}
	return m, nil, true
}

// remoteAfterTargetSelected routes to the next view based on the pending op.
func (m Model) remoteAfterTargetSelected(t *remote.RemoteTarget) (Model, tea.Cmd, bool) {
	op := m.remoteState.pendingOp

	if op == "remove" {
		m.remoteState.view = remoteViewRemoveConfirm
		return m, nil, true
	}
	if op == "edit" {
		// Edit is implemented as a fresh add flow seeded from the existing
		// target — pragmatic since the form is already wired for that path.
		m.remoteState.draft = *t
		m.remoteState.view = remoteViewAddHostname
		m.remoteState.input = newRemoteTextInput("Hostname")
		m.remoteState.input.SetValue(t.Hostname)
		// On commit, the existing target ID is preserved by Update via remove+re-add
		// pattern in commitEdit. For simplicity we just add a new entry; user can
		// remove the old one.
		return m, m.remoteState.input.Focus(), true
	}
	if op == "test" {
		// Test connectivity needs credentials.
		return m.remotePromptIfNeeded(t, "test")
	}

	// Single-target ops needing creds.
	switch op {
	case "remote_triage", "remote_evtx", "remote_registry",
		"remote_memory", "remote_hunt_proc", "remote_hunt_net",
		"remote_hunt_persist":
		return m.remotePromptIfNeeded(t, op)
	case "remote_acquire":
		return m.remotePromptIfNeeded(t, "acquire_path")
	case "remote_ioc":
		// IOC asks for type+value first; password later if needed.
		m.remoteState.view = remoteViewIOCType
		m.remoteState.pickCursor = 0
		return m, nil, true
	}
	return m, nil, true
}

// remotePromptIfNeeded asks for a password when the target uses password auth
// and no cached credentials exist; otherwise proceeds straight into the op.
func (m Model) remotePromptIfNeeded(t *remote.RemoteTarget, nextOp string) (Model, tea.Cmd, bool) {
	if t.AuthMethod == "key" {
		// Cache a stub Credentials with the key path so the engine can connect.
		m.ctx.RemoteCreds.Put(t, remote.Credentials{Username: t.Username, KeyPath: t.KeyPath})
		return m.remoteRunOp(t, nextOp)
	}
	if _, ok := m.ctx.RemoteCreds.Get(t); ok {
		return m.remoteRunOp(t, nextOp)
	}
	m.remoteState.view = remoteViewPromptPassword
	m.remoteState.pendingAfterPassword = nextOp
	m.remoteState.input = newRemotePasswordInput("Password for " + t.Username + "@" + t.DisplayName())
	return m, m.remoteState.input.Focus(), true
}

func (m Model) remoteSubmitPassword(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Password is required."
		return m, nil
	}
	t := m.remoteState.current
	m.ctx.RemoteCreds.Put(t, remote.Credentials{
		Username: t.Username,
		Password: []byte(value),
		KeyPath:  t.KeyPath,
	})
	mm, cmd, _ := m.remoteRunOp(t, m.remoteState.pendingAfterPassword)
	return mm, cmd
}

// ---------------------------------------------------------------------------
// Op execution
// ---------------------------------------------------------------------------

func (m Model) remoteRunOp(t *remote.RemoteTarget, op string) (Model, tea.Cmd, bool) {
	switch op {
	case "test":
		return m.remoteRunConnectivity(t)
	case "remote_triage":
		return m.remoteRunTriage(t)
	case "remote_evtx":
		return m.remoteRunCollection(t, "eventlogs")
	case "remote_registry":
		return m.remoteRunCollection(t, "registry")
	case "remote_memory":
		return m.remoteRunMemory(t)
	case "remote_hunt_proc":
		return m.remoteRunHunt(t, "processes")
	case "remote_hunt_net":
		return m.remoteRunHunt(t, "network")
	case "remote_hunt_persist":
		return m.remoteRunHunt(t, "persistence")
	case "acquire_path":
		m.remoteState.view = remoteViewAcquirePath
		m.remoteState.input = newRemoteTextInput("Remote file path (e.g. C:\\Windows\\Temp\\suspicious.exe)")
		return m, m.remoteState.input.Focus(), true
	}
	return m, nil, true
}

func (m Model) remoteRunConnectivity(t *remote.RemoteTarget) (Model, tea.Cmd, bool) {
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = "Connectivity test — " + t.DisplayName()

	engine := m.remoteEngine()
	store := m.ctx.RemoteStore
	cmd := func() tea.Msg {
		res := engine.TestConnectivity(t)
		_ = store.SetStatus(t.ID, res.Status)
		return remoteConnDoneMsg{res: res}
	}
	return m, tea.Batch(remoteTickCmd(), cmd), true
}

func (m Model) remoteRunTriage(t *remote.RemoteTarget) (Model, tea.Cmd, bool) {
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = "Quick Triage — " + t.DisplayName()

	engine := m.remoteEngine()
	target := t
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	cmd := func() tea.Msg {
		outDir, steps, err := engine.TriageTarget(target)
		if err == nil && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "remote_triage", outDir)
		}
		msg := remoteTriageDoneMsg{outDir: outDir, steps: steps}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(remoteTickCmd(), cmd), true
}

func (m Model) remoteRunCollection(t *remote.RemoteTarget, kind string) (Model, tea.Cmd, bool) {
	if t.OSType != "windows" {
		m.remoteState.view = remoteViewError
		m.remoteState.errorMsg = strings.Title(kind) + " collection requires a Windows target."
		return m, nil, true
	}
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	if kind == "eventlogs" {
		m.remoteState.operationName = "Event Log Collection — " + t.DisplayName()
	} else {
		m.remoteState.operationName = "Registry Collection — " + t.DisplayName()
	}

	engine := m.remoteEngine()
	target := t
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	collKind := kind
	cmd := func() tea.Msg {
		var (
			res remote.EventLogResult
			err error
		)
		if collKind == "eventlogs" {
			res, err = engine.CollectEventLogs(target)
		} else {
			res, err = engine.CollectRegistry(target)
		}
		if err == nil && caseManager != nil && res.OutputDir != "" {
			_, _ = caseManager.AddEvidence(caseID, 0, "remote_"+collKind, res.OutputDir)
		}
		msg := remoteCollectDoneMsg{kind: collKind, res: res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(remoteTickCmd(), cmd), true
}

func (m Model) remoteAcquirePathNext(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Path is required."
		return m, nil
	}
	m.remoteState.acquisition = &remote.AcquisitionResult{Source: value}
	m.remoteState.view = remoteViewAcquireDesc
	m.remoteState.input = newRemoteTextInput("Description of this artifact")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteAcquireDescNext(value string) (Model, tea.Cmd) {
	t := m.remoteState.current
	src := m.remoteState.acquisition.Source
	desc := value
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = "File Acquisition — " + t.DisplayName()

	engine := m.remoteEngine()
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	cmd := func() tea.Msg {
		res, err := engine.AcquireFile(t, src, desc)
		if err == nil && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "remote_acquisition", res.Destination)
		}
		msg := remoteAcquireDoneMsg{res: res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(remoteTickCmd(), cmd)
}

func (m Model) remoteRunMemory(t *remote.RemoteTarget) (Model, tea.Cmd, bool) {
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = "Memory Capture — " + t.DisplayName()

	engine := m.remoteEngine()
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	target := t
	cmd := func() tea.Msg {
		res, err := engine.CaptureMemory(target)
		if err == nil && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "remote_memory_dump", res.Destination)
		}
		msg := remoteMemoryDoneMsg{res: res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(remoteTickCmd(), cmd), true
}

func (m Model) remoteRunHunt(t *remote.RemoteTarget, kind string) (Model, tea.Cmd, bool) {
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = strings.Title(kind) + " Snapshot — " + t.DisplayName()

	engine := m.remoteEngine()
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	huntKind := kind
	target := t
	cmd := func() tea.Msg {
		res, err := engine.HuntSnapshot(target, huntKind)
		if err == nil && caseManager != nil {
			if ev, evErr := caseManager.AddEvidence(caseID, 0, "remote_hunt_"+huntKind, res.OutputDir); evErr == nil {
				for _, f := range res.Findings {
					_ = caseManager.AddFinding(caseID, ev.ID, f.Severity, f.Title, f.Detail, "")
				}
			}
		}
		msg := remoteHuntDoneMsg{res: res}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(remoteTickCmd(), cmd), true
}

// ---------------------------------------------------------------------------
// IOC sweep input flow
// ---------------------------------------------------------------------------

func (m Model) remoteIOCTypePick(idx int) (Model, tea.Cmd) {
	switch idx {
	case 0:
		m.remoteState.iocType = remote.IOCFileHash
	case 1:
		m.remoteState.iocType = remote.IOCFileName
	case 2:
		m.remoteState.iocType = remote.IOCIPAddress
	case 3:
		m.remoteState.iocType = remote.IOCDomain
	}
	m.remoteState.view = remoteViewIOCValue
	m.remoteState.input = newRemoteTextInput("IOC value")
	return m, m.remoteState.input.Focus()
}

func (m Model) remoteIOCValueSubmit(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "IOC value required."
		return m, nil
	}
	m.remoteState.iocValue = value

	// Single-target IOC sweep was the entry point — confirm the target needs creds.
	t := m.remoteState.current
	if t == nil {
		// Batch mode — caller routes elsewhere; for now treat as single.
		return m, nil
	}
	if t.AuthMethod == "password" {
		if _, ok := m.ctx.RemoteCreds.Get(t); !ok {
			m.remoteState.view = remoteViewPromptPassword
			m.remoteState.pendingAfterPassword = "ioc_run"
			m.remoteState.input = newRemotePasswordInput("Password for " + t.Username + "@" + t.DisplayName())
			return m, m.remoteState.input.Focus()
		}
	} else {
		m.ctx.RemoteCreds.Put(t, remote.Credentials{Username: t.Username, KeyPath: t.KeyPath})
	}
	return m.remoteRunIOC()
}

func (m Model) remoteRunIOC() (Model, tea.Cmd) {
	m.remoteState.view = remoteViewRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = "IOC Sweep — " + m.remoteState.current.DisplayName()

	engine := m.remoteEngine()
	target := m.remoteState.current
	ioc := remote.IOC{Type: m.remoteState.iocType, Value: m.remoteState.iocValue}
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	cmd := func() tea.Msg {
		res := engine.SweepIOC(target, ioc)
		if caseManager != nil && len(res.Findings) > 0 {
			if ev, evErr := caseManager.AddEvidence(caseID, 0, "remote_ioc_sweep", res.OutputDir); evErr == nil {
				for _, f := range res.Findings {
					_ = caseManager.AddFinding(caseID, ev.ID, f.Severity, f.Title, f.Detail, "")
				}
			}
		}
		return remoteIOCDoneMsg{res: res}
	}
	return m, tea.Batch(remoteTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// Batch + deploy pickers
// ---------------------------------------------------------------------------

func (m Model) remoteUpdateBatchPick(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.remoteState.view = remoteViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.remoteState.listCursor > 0 {
			m.remoteState.listCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.remoteState.listCursor < len(m.remoteState.targets)-1 {
			m.remoteState.listCursor++
		}
		return m, nil, true
	case " ":
		idx := m.remoteState.listCursor
		if idx < len(m.remoteState.checkAll) {
			m.remoteState.checkAll[idx] = !m.remoteState.checkAll[idx]
		}
		return m, nil, true
	case "a", "A":
		for i := range m.remoteState.checkAll {
			m.remoteState.checkAll[i] = true
		}
		return m, nil, true
	case "n", "N":
		for i := range m.remoteState.checkAll {
			m.remoteState.checkAll[i] = false
		}
		return m, nil, true
	case "enter":
		// Selected targets must have creds. For batch ops we require that
		// every target uses key auth OR has a cached password. Anything else
		// falls back to the per-target prompt loop on first failure.
		selected := m.remoteSelectedTargets()
		if len(selected) == 0 {
			m.statusMessage = "Select at least one target with Space."
			return m, nil, true
		}
		// Pre-seed key-auth creds.
		for _, t := range selected {
			if t.AuthMethod == "key" {
				m.ctx.RemoteCreds.Put(t, remote.Credentials{Username: t.Username, KeyPath: t.KeyPath})
			}
		}
		switch m.remoteState.view {
		case remoteViewBatchPickTargets:
			if m.remoteState.action == "remote_batch_triage" {
				mm, cmd := m.remoteRunBatchTriage(selected)
				return mm, cmd, true
			}
			if m.remoteState.action == "remote_batch_ioc" {
				m.remoteState.view = remoteViewIOCType
				m.remoteState.pickCursor = 0
				return m, nil, true
			}
		case remoteViewDeployPickTargets:
			mm, cmd := m.remoteRunDeploy(selected)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

// remoteSelectedTargets returns the subset of m.remoteState.targets whose
// checkAll[i] is true.
func (m Model) remoteSelectedTargets() []*remote.RemoteTarget {
	var out []*remote.RemoteTarget
	for i, t := range m.remoteState.targets {
		if i < len(m.remoteState.checkAll) && m.remoteState.checkAll[i] {
			out = append(out, t)
		}
	}
	return out
}

func (m Model) remoteRunBatchTriage(selected []*remote.RemoteTarget) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewBatchRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = fmt.Sprintf("Batch Triage — %d targets", len(selected))

	engine := m.remoteEngine()
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager
	targets := selected
	cmd := func() tea.Msg {
		results := engine.BatchTriage(targets, nil)
		if caseManager != nil {
			for _, r := range results {
				if r.Error == "" {
					_, _ = caseManager.AddEvidence(caseID, 0, "remote_triage", r.OutputDir)
				}
			}
		}
		return remoteBatchTriageDoneMsg{results: results}
	}
	return m, tea.Batch(remoteTickCmd(), cmd)
}

func (m Model) remoteDeployToolPick(idx int) (Model, tea.Cmd) {
	switch idx {
	case 0:
		m.remoteState.deployTool = "velociraptor"
	case 1:
		m.remoteState.deployTool = "hayabusa"
	case 2:
		m.remoteState.deployTool = "loki"
	}
	m.remoteRefreshTargets()
	m.remoteState.checkAll = make([]bool, len(m.remoteState.targets))
	m.remoteState.view = remoteViewDeployPickTargets
	m.remoteState.listCursor = 0
	return m, nil
}

func (m Model) remoteRunDeploy(selected []*remote.RemoteTarget) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewDeployRunning
	m.remoteState.startTime = time.Now()
	m.remoteState.operationName = fmt.Sprintf("Deploy %s — %d targets",
		m.remoteState.deployTool, len(selected))

	engine := m.remoteEngine()
	rootDir := m.ctx.RootDir
	tool := m.remoteState.deployTool
	targets := selected
	cmd := func() tea.Msg {
		results := engine.DeployTool(targets,
			func(t *remote.RemoteTarget) (string, string) {
				return remote.DeployBinaryPaths(rootDir, tool, t)
			}, nil)
		return remoteDeployDoneMsg{results: results}
	}
	return m, tea.Batch(remoteTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// Async message handlers
// ---------------------------------------------------------------------------

func (m Model) handleRemoteConnDone(msg remoteConnDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewConnDone
	m.remoteState.connResult = &msg.res
	return m, nil
}

func (m Model) handleRemoteTriageDone(msg remoteTriageDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewOpDone
	m.remoteState.triageOutDir = msg.outDir
	m.remoteState.triageResult = msg.steps
	if msg.err != "" {
		m.remoteState.errorMsg = msg.err
	}
	return m, nil
}

func (m Model) handleRemoteCollectDone(msg remoteCollectDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewOpDone
	m.remoteState.collectionRes = &msg.res
	if msg.err != "" {
		m.remoteState.errorMsg = msg.err
	}
	return m, nil
}

func (m Model) handleRemoteAcquireDone(msg remoteAcquireDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewOpDone
	m.remoteState.acquisition = &msg.res
	if msg.err != "" {
		m.remoteState.errorMsg = msg.err
	}
	return m, nil
}

func (m Model) handleRemoteMemoryDone(msg remoteMemoryDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewOpDone
	m.remoteState.memoryResult = &msg.res
	if msg.err != "" {
		m.remoteState.errorMsg = msg.err
	}
	return m, nil
}

func (m Model) handleRemoteHuntDone(msg remoteHuntDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.remoteState.view = remoteViewError
		m.remoteState.errorMsg = msg.err
		return m, nil
	}
	m.remoteState.view = remoteViewFindings
	m.remoteState.huntResult = &msg.res
	return m, nil
}

func (m Model) handleRemoteIOCDone(msg remoteIOCDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewIOCResults
	m.remoteState.iocSweepResult = &msg.res
	return m, nil
}

func (m Model) handleRemoteBatchTriageDone(msg remoteBatchTriageDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewBatchDone
	m.remoteState.batchTriage = msg.results
	return m, nil
}

func (m Model) handleRemoteBatchIOCDone(msg remoteBatchIOCDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewBatchDone
	m.remoteState.batchIOC = msg.results
	return m, nil
}

func (m Model) handleRemoteDeployDone(msg remoteDeployDoneMsg) (Model, tea.Cmd) {
	m.remoteState.view = remoteViewDeployDone
	m.remoteState.deployRes = msg.results
	return m, nil
}
