package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/app"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
	"github.com/ridgelinecyberdefence/vanguard/internal/triage"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type menuState int

const (
	stateMainMenu menuState = iota
	stateSubMenu
	stateResult
)

type focusPane int

const (
	paneSidebar focusPane = iota
	paneContent
)

// MenuItem represents a single selectable entry.
type MenuItem struct {
	Label    string
	Shortcut string
	Action   string
	Section  string // optional section header rendered above this item
}

// AppContext carries shared application state into the TUI.
// AppContext is the shared application state. It's a type alias on app.Context
// so the web frontend and the TUI both build on the same struct without a
// circular import.
type AppContext = app.Context

// Model implements tea.Model for the VanGuard application shell.
type Model struct {
	ctx           *AppContext
	state         menuState
	sidebarCursor int
	contentItems  []MenuItem
	contentCursor int
	activeAction  string
	activeTitle   string
	focus         focusPane
	statusMessage string
	confirmQuit   bool
	width         int
	height        int

	// Content pane scrolling. Reset to 0 whenever the content pane changes
	// (new submenu, new result, returning from a panel). Updated by
	// up/down/PgUp/PgDn/Home/End when the content pane has focus and the
	// rendered content exceeds the visible height.
	contentScrollOffset int
	contentTotalLines   int
	contentVisibleLines int

	// Tool management state.
	toolView        string   // "status", "download_confirm", "downloading", "download_done", "updates"
	toolStatusLines []string // pre-rendered tool status table lines
	toolConfirmMsg  string   // confirmation prompt text
	toolResultLines []string // download/update result lines

	// Config panel state.
	cfgState ConfigState

	// Velociraptor panel state.
	vrState VRState

	// Triage panel state.
	triageState TriageState

	// Hunting panel state.
	huntingState HuntingState

	// Memory forensics panel state.
	memState MemoryState

	// Disk collection panel state.
	diskState DiskState

	// Remote operations panel state.
	remoteState RemoteState

	// Analysis & reporting panel state.
	analysisState AnalysisState

	// Use cases panel state.
	usecasesState UsecasesState

	// Updates panel state.
	updateState UpdateState

	// Help panel state.
	helpState HelpState
}

// clearPanelState resets all result-screen panel state. Call this when
// entering a new result view to ensure no stale state from a prior panel
// can intercept key events.
func (m *Model) clearPanelState() {
	// Scrolling state belongs to the panel content; reset whenever the panel
	// changes so a fresh view always opens at the top.
	m.contentScrollOffset = 0
	m.cfgState.view = cfgViewNone
	m.cfgState.resultLines = nil
	m.toolView = ""
	m.toolStatusLines = nil
	m.toolResultLines = nil
	m.vrState.view = vrViewNone
	m.triageState.view = triageViewNone
	m.huntingState.view = huntingViewNone
	m.memState.view = memViewNone
	m.memState.resultLines = nil
	m.diskState.view = diskViewNone
	m.diskState.resultLines = nil
	m.remoteState.view = remoteViewNone
	m.remoteState.errorMsg = ""
	m.remoteState.messageLines = nil
	m.analysisState.view = analysisViewNone
	m.analysisState.resultLines = nil
	m.analysisState.errorMsg = ""
	m.usecasesState.view = ucViewNone
	m.usecasesState.errorMsg = ""
	m.updateState.view = updateViewNone
	m.updateState.errorMsg = ""
	m.updateState.messageLines = nil
	m.updateState.outcomes = nil
	m.helpState.view = helpViewNone
	m.helpState.pageLines = nil
}

// panelInteractive reports whether any panel is currently in a view that
// consumes alphanumeric keystrokes — text inputs, list selectors, multi-step
// forms. When true, the global "press a sidebar number to navigate" shortcut
// yields so the keystroke goes to the panel instead of stealing focus.
//
// Blocker / info / progress / done views are intentionally NOT listed —
// sidebar shortcuts SHOULD short-circuit through those (any-key-dismiss).
func (m *Model) panelInteractive() bool {
	if m.panelTextInputActive() {
		return true
	}
	switch m.memState.view {
	case memViewDumpSelect, memViewYaraSelect, memViewSymbols,
		memViewRemoteMethod, memViewGUIChoose:
		return true
	}
	switch m.cfgState.view {
	case cfgViewListCases, cfgViewSelectCase:
		return true
	}
	switch m.diskState.view {
	case diskViewSourceSelect, diskViewKapeCustomTargets,
		diskViewUACProfileSelect, diskViewBrowse:
		return true
	}
	return false
}

// routeTextInputKey forwards a non-Enter/non-Esc keystroke directly to
// whichever text-input field is currently focused. This is the body of the
// "text input intercept" gate at the top of handleKey — it returns the model
// + cmd so the caller can return immediately without falling through to the
// rest of handleKey's logic.
//
// Important: panel update functions (configUpdate, memoryUpdate, etc.) ALSO
// forward keys to their input components for Enter/Esc/etc. We bypass those
// here for plain typing keys to keep the path short and to guarantee no
// other handler can steal the keystroke.
func (m Model) routeTextInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.cfgState.view {
	case cfgViewCreateCase:
		// Step 1 is a list selection (classification), not a text input.
		if m.cfgState.inputStep == 1 {
			return m, nil
		}
		var cmd tea.Cmd
		m.cfgState.input, cmd = m.cfgState.input.Update(msg)
		return m, cmd
	case cfgViewEditAnalyst, cfgViewEditOrg:
		var cmd tea.Cmd
		m.cfgState.input, cmd = m.cfgState.input.Update(msg)
		return m, cmd
	}
	switch m.memState.view {
	case memViewDumpPathInput, memViewYaraCustomPath,
		memViewCustomPlugin, memViewCustomPluginArgs,
		memViewRemoteHost, memViewRemoteUser, memViewRemotePass, memViewRemotePort,
		memViewGUIDumpPath, memViewGUICliPath:
		var cmd tea.Cmd
		m.memState.input, cmd = m.memState.input.Update(msg)
		return m, cmd
	}
	switch m.remoteState.view {
	case remoteViewAddHostname, remoteViewAddIP, remoteViewAddPort,
		remoteViewAddUsername, remoteViewAddKeyPath, remoteViewAddNotes,
		remoteViewPromptPassword, remoteViewAcquirePath,
		remoteViewAcquireDesc, remoteViewIOCValue:
		var cmd tea.Cmd
		m.remoteState.input, cmd = m.remoteState.input.Update(msg)
		return m, cmd
	}
	switch m.diskState.view {
	case diskViewSourceCustomPath, diskViewLnxAppPath,
		diskViewManualSrc, diskViewManualDesc:
		var cmd tea.Cmd
		m.diskState.input, cmd = m.diskState.input.Update(msg)
		return m, cmd
	}
	if m.usecasesState.view == ucViewParams {
		var cmd tea.Cmd
		m.usecasesState.paramInput, cmd = m.usecasesState.paramInput.Update(msg)
		return m, cmd
	}
	if m.updateState.view == updateViewApplyPath {
		var cmd tea.Cmd
		m.updateState.pathInput, cmd = m.updateState.pathInput.Update(msg)
		return m, cmd
	}
	// Should be unreachable: panelTextInputActive returned true but no
	// matching state was found here. Drop the key rather than fall through.
	return m, nil
}

// panelTextInputActive reports whether the active panel is in a text-input
// view (single-line, multi-step form, or password prompt). When true, the
// global key handler routes ALL keystrokes to the panel — number keys,
// letters, everything except Enter/Esc which the panel itself handles —
// so the user can type freely without sidebar shortcuts hijacking input.
//
// Adding a new text input? Add the state constant here too. The cost of
// missing one is "user types '5' and gets sent to Memory Forensics" — high
// surprise, low recovery.
func (m *Model) panelTextInputActive() bool {
	switch m.cfgState.view {
	case cfgViewCreateCase, cfgViewEditAnalyst, cfgViewEditOrg:
		return true
	}
	switch m.memState.view {
	case memViewDumpPathInput, memViewYaraCustomPath,
		memViewCustomPlugin, memViewCustomPluginArgs,
		memViewRemoteHost, memViewRemoteUser, memViewRemotePass, memViewRemotePort,
		memViewGUIDumpPath, memViewGUICliPath:
		return true
	}
	switch m.remoteState.view {
	case remoteViewAddHostname, remoteViewAddIP, remoteViewAddPort,
		remoteViewAddUsername, remoteViewAddKeyPath, remoteViewAddNotes,
		remoteViewPromptPassword, remoteViewAcquirePath,
		remoteViewAcquireDesc, remoteViewIOCValue:
		return true
	}
	switch m.diskState.view {
	case diskViewSourceCustomPath, diskViewLnxAppPath,
		diskViewManualSrc, diskViewManualDesc:
		return true
	}
	if m.usecasesState.view == ucViewParams {
		return true
	}
	if m.updateState.view == updateViewApplyPath {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Sidebar data
// ---------------------------------------------------------------------------

var allSidebarItems = []MenuItem{
	// OPERATIONS  (indices 0-7)
	{Label: "Velociraptor", Shortcut: "1", Action: "velociraptor"},
	{Label: "Disk Collection", Shortcut: "2", Action: "disk"},
	{Label: "Threat Hunting", Shortcut: "3", Action: "hunting"},
	{Label: "Quick Triage", Shortcut: "4", Action: "triage"},
	{Label: "Memory Forensics", Shortcut: "5", Action: "memory"},
	{Label: "Remote Ops", Shortcut: "6", Action: "remote"},
	{Label: "Analysis", Shortcut: "7", Action: "analysis"},
	{Label: "Configuration", Shortcut: "8", Action: "config"},
	// TOOLS  (indices 8-9)
	{Label: "Update", Shortcut: "U", Action: "update"},
	{Label: "Use Cases", Shortcut: "C", Action: "usecases"},
	// (no label)  (indices 10-11)
	{Label: "Help", Shortcut: "H", Action: "help"},
	{Label: "Quit", Shortcut: "Q", Action: "quit"},
}

type sidebarSection struct {
	Label string
	Start int
	End   int
}

var sidebarSections = []sidebarSection{
	{"OPERATIONS", 0, 8},
	{"TOOLS", 8, 10},
	{"", 10, 12},
}

// ---------------------------------------------------------------------------
// Submenu definitions
// ---------------------------------------------------------------------------

type subMenuDef struct {
	Title string
	Items []MenuItem
}

// subMenuDefs contains the platform-independent submenu definitions.
var subMenuDefs = map[string]subMenuDef{
	"velociraptor": {
		Title: "Velociraptor Operations",
		Items: []MenuItem{
			// SERVER MANAGEMENT
			{Label: "Initialize Server", Shortcut: "1", Action: "vr_init", Section: "SERVER MANAGEMENT"},
			{Label: "Start Server", Shortcut: "2", Action: "vr_start"},
			{Label: "Stop Server", Shortcut: "3", Action: "vr_stop"},
			{Label: "Server Status", Shortcut: "4", Action: "vr_status"},
			{Label: "Open Web UI", Shortcut: "5", Action: "vr_webui"},
			{Label: "Regenerate Certificates", Shortcut: "R", Action: "vr_regen_certs"},
			// CLIENT MANAGEMENT
			{Label: "Generate Client Package", Shortcut: "6", Action: "vr_client", Section: "CLIENT MANAGEMENT"},
			{Label: "Deploy Agent (Remote)", Shortcut: "7", Action: "vr_deploy"},
			{Label: "Create Offline Collector", Shortcut: "8", Action: "vr_offline"},
			// OPERATIONS
			{Label: "Launch Hunt", Shortcut: "9", Action: "vr_hunt", Section: "OPERATIONS"},
			{Label: "Run VQL Query", Shortcut: "0", Action: "vr_vql"},
			{Label: "Import Offline Collection", Shortcut: "A", Action: "vr_import"},
			{Label: "Export Results", Shortcut: "B", Action: "vr_export"},
		},
	},
	"triage": {Title: "Quick Triage"}, // placeholder — resolved by platform overrides below
	"remote": {
		Title: "Remote Operations",
		Items: []MenuItem{
			// TARGET MANAGEMENT
			{Label: "Add Remote Target", Shortcut: "1", Action: "remote_add", Section: "TARGET MANAGEMENT"},
			{Label: "List Targets", Shortcut: "2", Action: "remote_list"},
			{Label: "Edit Target", Shortcut: "3", Action: "remote_edit"},
			{Label: "Remove Target", Shortcut: "4", Action: "remote_remove"},
			{Label: "Test Connectivity", Shortcut: "5", Action: "remote_test"},
			// REMOTE COLLECTION
			{Label: "Remote Quick Triage", Shortcut: "6", Action: "remote_triage", Section: "REMOTE COLLECTION"},
			{Label: "Remote Event Log Collection", Shortcut: "7", Action: "remote_evtx"},
			{Label: "Remote Registry Collection", Shortcut: "8", Action: "remote_registry"},
			{Label: "Remote File Acquisition", Shortcut: "9", Action: "remote_acquire"},
			{Label: "Remote Memory Capture", Shortcut: "0", Action: "remote_memory"},
			// REMOTE HUNTING
			{Label: "Remote Process Snapshot", Shortcut: "A", Action: "remote_hunt_proc", Section: "REMOTE HUNTING"},
			{Label: "Remote Network Snapshot", Shortcut: "B", Action: "remote_hunt_net"},
			{Label: "Remote Persistence Check", Shortcut: "C", Action: "remote_hunt_persist"},
			{Label: "Remote IOC Sweep", Shortcut: "D", Action: "remote_ioc"},
			// MULTI-TARGET OPERATIONS
			{Label: "Batch Triage (All Targets)", Shortcut: "E", Action: "remote_batch_triage", Section: "MULTI-TARGET OPERATIONS"},
			{Label: "Batch IOC Sweep (All Targets)", Shortcut: "F", Action: "remote_batch_ioc"},
			{Label: "Deploy Tool to Targets", Shortcut: "G", Action: "remote_deploy"},
		},
	},
	"config": {
		Title: "Configuration",
		Items: []MenuItem{
			// CASE MANAGEMENT
			{Label: "Create New Case", Shortcut: "1", Action: "cfg_create_case", Section: "CASE MANAGEMENT"},
			{Label: "List All Cases", Shortcut: "2", Action: "cfg_list_cases"},
			{Label: "Select Active Case", Shortcut: "3", Action: "cfg_select_case"},
			{Label: "Close Active Case", Shortcut: "4", Action: "cfg_close_case"},
			{Label: "Verify Evidence Integrity", Shortcut: "V", Action: "cfg_verify_evidence"},
			{Label: "Diagnose Volatility3", Shortcut: "D", Action: "cfg_vol_diag"},
			// TOOL MANAGEMENT
			{Label: "Tool Status", Shortcut: "5", Action: "cfg_tool_status", Section: "TOOL MANAGEMENT"},
			{Label: "Download Required Tools", Shortcut: "6", Action: "cfg_tool_dl_req"},
			{Label: "Download All Tools", Shortcut: "7", Action: "cfg_tool_dl_all"},
			{Label: "Check for Updates", Shortcut: "8", Action: "cfg_tool_updates"},
			// SETTINGS
			{Label: "Edit Analyst Name", Shortcut: "9", Action: "cfg_edit_analyst", Section: "SETTINGS"},
			{Label: "Edit Organization", Shortcut: "0", Action: "cfg_edit_org"},
		},
	},
}

// platformSubMenuDefs contains platform-specific submenu overrides.
// Key format: "action:platform" (e.g., "disk:windows").
var platformSubMenuDefs = map[string]subMenuDef{
	// ── Disk Collection ──────────────────────────────────────────────────
	"disk:windows": {
		Title: "Disk Artifact Collection",
		Items: []MenuItem{
			// KAPE COLLECTION
			{Label: "KAPE — SANS Triage", Shortcut: "1", Action: "disk_kape_sans", Section: "KAPE COLLECTION"},
			{Label: "KAPE — Full Collection", Shortcut: "2", Action: "disk_kape_full"},
			{Label: "KAPE — Custom Targets", Shortcut: "3", Action: "disk_kape_custom"},
			{Label: "KAPE — Event Logs Only", Shortcut: "4", Action: "disk_kape_evtx"},
			{Label: "KAPE — Registry Only", Shortcut: "5", Action: "disk_kape_registry"},
			{Label: "KAPE — Browser Artifacts Only", Shortcut: "6", Action: "disk_kape_browser"},
			// EZ TOOLS PARSING
			{Label: "Parse with EZ Tools (All Parsers)", Shortcut: "7", Action: "disk_ez_all", Section: "EZ TOOLS PARSING"},
			{Label: "Parse Event Logs (EvtxECmd)", Shortcut: "8", Action: "disk_ez_evtx"},
			{Label: "Parse MFT (MFTECmd)", Shortcut: "9", Action: "disk_ez_mft"},
			{Label: "Parse Registry (RECmd)", Shortcut: "0", Action: "disk_ez_reg"},
			{Label: "Parse Prefetch (PECmd)", Shortcut: "A", Action: "disk_ez_prefetch"},
			{Label: "Parse Amcache (AmcacheParser)", Shortcut: "B", Action: "disk_ez_amcache"},
			{Label: "Parse Shimcache (AppCompatCacheParser)", Shortcut: "C", Action: "disk_ez_shimcache"},
			{Label: "Parse Jump Lists (JLECmd)", Shortcut: "D", Action: "disk_ez_jumplist"},
			{Label: "Parse LNK Files (LECmd)", Shortcut: "E", Action: "disk_ez_lnk"},
			{Label: "Parse SRUM (SrumECmd)", Shortcut: "F", Action: "disk_ez_srum"},
			{Label: "Parse Recycle Bin (RBCmd)", Shortcut: "G", Action: "disk_ez_recyclebin"},
			// MANUAL COLLECTION
			{Label: "Targeted File Copy", Shortcut: "H", Action: "disk_manual_copy", Section: "MANUAL COLLECTION"},
			{Label: "Browse Evidence Directory", Shortcut: "I", Action: "disk_browse"},
		},
	},
	"disk:linux": {
		Title: "Disk Artifact Collection",
		Items: []MenuItem{
			// UAC COLLECTION
			{Label: "UAC — Full Profile", Shortcut: "1", Action: "disk_uac_full", Section: "UAC COLLECTION"},
			{Label: "UAC — IR Triage Profile", Shortcut: "2", Action: "disk_uac_triage"},
			{Label: "UAC — Custom Profile", Shortcut: "3", Action: "disk_uac_custom"},
			// LOG COLLECTION
			{Label: "System Logs (/var/log/)", Shortcut: "4", Action: "disk_lnx_syslog", Section: "LOG COLLECTION"},
			{Label: "Auth Logs", Shortcut: "5", Action: "disk_lnx_auth"},
			{Label: "Web Server Logs (Apache/Nginx)", Shortcut: "6", Action: "disk_lnx_weblogs"},
			{Label: "Application Logs", Shortcut: "7", Action: "disk_lnx_applogs"},
			{Label: "Journal Logs (systemd)", Shortcut: "8", Action: "disk_lnx_journal"},
			// USER ARTIFACTS
			{Label: "All User Home Directories", Shortcut: "9", Action: "disk_lnx_userhomes", Section: "USER ARTIFACTS"},
			{Label: "Bash/Zsh History (All Users)", Shortcut: "0", Action: "disk_lnx_history"},
			{Label: "SSH Artifacts (keys, known_hosts, config)", Shortcut: "A", Action: "disk_lnx_ssh"},
			{Label: "Cron Jobs (All Users)", Shortcut: "B", Action: "disk_lnx_cron"},
			// SYSTEM ARTIFACTS
			{Label: "Package Manager Logs & Lists", Shortcut: "C", Action: "disk_lnx_packages", Section: "SYSTEM ARTIFACTS"},
			{Label: "Systemd Unit Files", Shortcut: "D", Action: "disk_lnx_systemd"},
			{Label: "Network Configuration", Shortcut: "E", Action: "disk_lnx_network"},
			{Label: "Docker/Container Artifacts", Shortcut: "F", Action: "disk_lnx_docker"},
			// MANUAL COLLECTION
			{Label: "Targeted File Copy", Shortcut: "G", Action: "disk_manual_copy", Section: "MANUAL COLLECTION"},
			{Label: "Browse Evidence Directory", Shortcut: "H", Action: "disk_browse"},
		},
	},

	// ── Threat Hunting & Scanning ────────────────────────────────────────
	"hunting:windows": {
		Title: "Threat Hunting & Scanning",
		Items: []MenuItem{
			{Label: "Hayabusa \u2014 Full Scan", Shortcut: "1", Action: "hunt_haya_full"},
			{Label: "Hayabusa \u2014 Critical Only", Shortcut: "2", Action: "hunt_haya_crit"},
			{Label: "Hayabusa \u2014 Lateral Movement", Shortcut: "3", Action: "hunt_haya_lateral"},
			{Label: "Hayabusa \u2014 Persistence", Shortcut: "4", Action: "hunt_haya_persist"},
			{Label: "Chainsaw \u2014 Hunt", Shortcut: "5", Action: "hunt_chainsaw"},
			{Label: "Loki \u2014 IOC Scan", Shortcut: "6", Action: "hunt_loki"},
			{Label: "YARA Scan (Files)", Shortcut: "7", Action: "hunt_yara"},
			{Label: "Sigma Detection", Shortcut: "8", Action: "hunt_sigma"},
			// LIVE HUNTING
			{Label: "Suspicious Processes", Shortcut: "A", Action: "hunt_live_proc", Section: "LIVE HUNTING"},
			{Label: "Network Connections", Shortcut: "B", Action: "hunt_live_net"},
			{Label: "Scheduled Tasks", Shortcut: "C", Action: "hunt_live_schtask"},
			{Label: "Autoruns / Startup Items", Shortcut: "D", Action: "hunt_live_autoruns"},
			{Label: "Service Anomalies", Shortcut: "E", Action: "hunt_live_services"},
		},
	},
	"hunting:linux": {
		Title: "Threat Hunting & Scanning",
		Items: []MenuItem{
			{Label: "Hayabusa \u2014 Full Scan (imported Windows logs)", Shortcut: "1", Action: "hunt_haya_full"},
			{Label: "Chainsaw \u2014 Hunt", Shortcut: "2", Action: "hunt_chainsaw"},
			{Label: "Loki \u2014 IOC Scan", Shortcut: "3", Action: "hunt_loki"},
			{Label: "YARA Scan (Files)", Shortcut: "4", Action: "hunt_yara"},
			{Label: "Sigma Detection", Shortcut: "5", Action: "hunt_sigma"},
			// LIVE HUNTING
			{Label: "Suspicious Processes", Shortcut: "A", Action: "hunt_live_proc", Section: "LIVE HUNTING"},
			{Label: "Network Connections", Shortcut: "B", Action: "hunt_live_net"},
			{Label: "Cron Jobs", Shortcut: "C", Action: "hunt_live_cron"},
			{Label: "Systemd Services", Shortcut: "D", Action: "hunt_live_systemd"},
			{Label: "SUID/SGID Files", Shortcut: "E", Action: "hunt_live_suid"},
			{Label: "Open Ports & Listeners", Shortcut: "F", Action: "hunt_live_ports"},
			{Label: "Kernel Modules", Shortcut: "G", Action: "hunt_live_kmod"},
			{Label: "User Login History", Shortcut: "H", Action: "hunt_live_logins"},
		},
	},

	// ── Memory Forensics ─────────────────────────────────────────────────
	"memory:windows": {
		Title: "Memory Forensics",
		Items: []MenuItem{
			// WINDOWS MEMORY CAPTURE
			{Label: "Capture with DumpIt", Shortcut: "1", Action: "mem_dumpit", Section: "WINDOWS MEMORY CAPTURE"},
			{Label: "Capture with WinPmem", Shortcut: "2", Action: "mem_winpmem"},
			{Label: "Capture with Belkasoft RAM Capturer", Shortcut: "3", Action: "mem_belkasoft"},
			{Label: "Capture with Magnet RAM Capture", Shortcut: "4", Action: "mem_magnet"},
			{Label: "Capture via Velociraptor Agent", Shortcut: "5", Action: "mem_vr"},
			{Label: "Remote Memory Capture", Shortcut: "6", Action: "mem_remote"},
			// MEMORY ANALYSIS — shortcuts shifted past the capture section.
			{Label: "Auto-Profile & Full Analysis", Shortcut: "7", Action: "mem_vol_profile", Section: "MEMORY ANALYSIS"},
			{Label: "Process Analysis", Shortcut: "8", Action: "mem_vol_proc"},
			{Label: "Network Analysis", Shortcut: "9", Action: "mem_vol_net"},
			{Label: "Malware Detection (malfind)", Shortcut: "0", Action: "mem_vol_malfind"},
			{Label: "Registry Analysis", Shortcut: "A", Action: "mem_vol_registry"},
			{Label: "Timeline Generation", Shortcut: "B", Action: "mem_vol_timeline"},
			{Label: "YARA Scan Memory Dump", Shortcut: "C", Action: "mem_vol_yara"},
			{Label: "Custom Volatility Plugin", Shortcut: "D", Action: "mem_vol_custom"},
			{Label: "Symbol Management", Shortcut: "E", Action: "mem_vol_symbols"},
		},
	},
	"memory:linux": {
		Title: "Memory Forensics",
		Items: []MenuItem{
			// LINUX MEMORY CAPTURE
			{Label: "Capture with AVML", Shortcut: "1", Action: "mem_avml", Section: "LINUX MEMORY CAPTURE"},
			{Label: "Capture with LiME", Shortcut: "2", Action: "mem_lime"},
			{Label: "Capture via Velociraptor Agent", Shortcut: "3", Action: "mem_vr"},
			{Label: "Remote Memory Capture", Shortcut: "4", Action: "mem_remote"},
			// MEMORY ANALYSIS
			{Label: "Auto-Profile & Full Analysis", Shortcut: "5", Action: "mem_vol_profile", Section: "MEMORY ANALYSIS"},
			{Label: "Process Analysis", Shortcut: "6", Action: "mem_vol_proc"},
			{Label: "Network Analysis", Shortcut: "7", Action: "mem_vol_net"},
			{Label: "Malware Detection (malfind)", Shortcut: "8", Action: "mem_vol_malfind"},
			{Label: "Kernel Module Analysis", Shortcut: "9", Action: "mem_vol_kmod"},
			{Label: "Timeline Generation", Shortcut: "0", Action: "mem_vol_timeline"},
			{Label: "YARA Scan Memory Dump", Shortcut: "A", Action: "mem_vol_yara"},
			{Label: "Custom Volatility Plugin", Shortcut: "B", Action: "mem_vol_custom"},
			{Label: "Symbol Management", Shortcut: "C", Action: "mem_vol_symbols"},
		},
	},

	// ── Analysis & Reporting ─────────────────────────────────────────────
	"analysis:windows": {
		Title: "Analysis & Reporting",
		Items: []MenuItem{
			// EVENT LOG ANALYSIS
			{Label: "Parse Event Logs (EvtxECmd)", Shortcut: "1", Action: "an_evtx_parse", Section: "EVENT LOG ANALYSIS"},
			{Label: "Event Log Summary & Statistics", Shortcut: "2", Action: "an_evtx_summary"},
			{Label: "Logon Analysis (4624/4625/4648)", Shortcut: "3", Action: "an_evtx_logon"},
			{Label: "Process Execution Analysis (4688)", Shortcut: "4", Action: "an_evtx_proc"},
			{Label: "Service Installation Analysis (7045)", Shortcut: "5", Action: "an_evtx_service"},
			// FILESYSTEM ANALYSIS
			{Label: "Parse MFT (MFTECmd)", Shortcut: "6", Action: "an_mft", Section: "FILESYSTEM ANALYSIS"},
			{Label: "Parse Prefetch (PECmd)", Shortcut: "7", Action: "an_prefetch"},
			{Label: "Parse Amcache (AmcacheParser)", Shortcut: "8", Action: "an_amcache"},
			{Label: "Parse Shimcache (AppCompatCacheParser)", Shortcut: "9", Action: "an_shimcache"},
			{Label: "Parse Jump Lists (JLECmd)", Shortcut: "0", Action: "an_jumplist"},
			{Label: "Parse LNK Files (LECmd)", Shortcut: "A", Action: "an_lnk"},
			{Label: "Parse SRUM (SrumECmd)", Shortcut: "B", Action: "an_srum"},
			{Label: "Parse Recycle Bin (RBCmd)", Shortcut: "C", Action: "an_recyclebin"},
			// REGISTRY ANALYSIS
			{Label: "Parse Registry Hives (RECmd)", Shortcut: "D", Action: "an_registry", Section: "REGISTRY ANALYSIS"},
			{Label: "Registry Key Timeline", Shortcut: "E", Action: "an_registry_timeline"},
			// MEMORY ANALYSIS
			{Label: "Volatility3 Analysis", Shortcut: "F", Action: "an_memory", Section: "MEMORY ANALYSIS"},
			// TIMELINE & CORRELATION
			{Label: "Build Super Timeline", Shortcut: "G", Action: "an_super_timeline", Section: "TIMELINE & CORRELATION"},
			{Label: "Correlate Findings", Shortcut: "H", Action: "an_correlate"},
			{Label: "MITRE ATT&CK Mapping", Shortcut: "I", Action: "an_mitre"},
			// REPORTING
			{Label: "Generate HTML Report", Shortcut: "J", Action: "an_report_html", Section: "REPORTING"},
			{Label: "Generate Executive Summary", Shortcut: "K", Action: "an_report_exec"},
			{Label: "Export Findings (CSV)", Shortcut: "L", Action: "an_export_findings"},
			{Label: "Export Timeline (CSV)", Shortcut: "M", Action: "an_export_timeline"},
			{Label: "Export IOC List", Shortcut: "N", Action: "an_export_iocs"},
		},
	},
	"analysis:linux": {
		Title: "Analysis & Reporting",
		Items: []MenuItem{
			// LOG ANALYSIS
			{Label: "Auth Log Analysis", Shortcut: "1", Action: "an_lnx_auth", Section: "LOG ANALYSIS"},
			{Label: "Syslog Analysis", Shortcut: "2", Action: "an_lnx_syslog"},
			{Label: "Web Server Log Analysis", Shortcut: "3", Action: "an_lnx_web"},
			{Label: "Journal Log Analysis", Shortcut: "4", Action: "an_lnx_journal"},
			{Label: "Log Timeline", Shortcut: "5", Action: "an_lnx_log_timeline"},
			// FILESYSTEM ANALYSIS
			{Label: "File Timeline (find + stat)", Shortcut: "6", Action: "an_lnx_file_timeline", Section: "FILESYSTEM ANALYSIS"},
			{Label: "Recently Modified Files", Shortcut: "7", Action: "an_lnx_recent"},
			{Label: "Suspicious File Locations", Shortcut: "8", Action: "an_lnx_suspicious"},
			// USER ANALYSIS
			{Label: "Shell History Analysis", Shortcut: "9", Action: "an_lnx_shell", Section: "USER ANALYSIS"},
			{Label: "SSH Key & Access Analysis", Shortcut: "0", Action: "an_lnx_ssh"},
			{Label: "User Account Audit", Shortcut: "A", Action: "an_lnx_users"},
			// MEMORY ANALYSIS
			{Label: "Volatility3 Analysis", Shortcut: "B", Action: "an_memory", Section: "MEMORY ANALYSIS"},
			// TIMELINE & CORRELATION
			{Label: "Build Super Timeline", Shortcut: "C", Action: "an_super_timeline", Section: "TIMELINE & CORRELATION"},
			{Label: "Correlate Findings", Shortcut: "D", Action: "an_correlate"},
			{Label: "MITRE ATT&CK Mapping", Shortcut: "E", Action: "an_mitre"},
			// REPORTING
			{Label: "Generate HTML Report", Shortcut: "F", Action: "an_report_html", Section: "REPORTING"},
			{Label: "Generate Executive Summary", Shortcut: "G", Action: "an_report_exec"},
			{Label: "Export Findings (CSV)", Shortcut: "H", Action: "an_export_findings"},
			{Label: "Export Timeline (CSV)", Shortcut: "I", Action: "an_export_timeline"},
			{Label: "Export IOC List", Shortcut: "J", Action: "an_export_iocs"},
		},
	},

	// ── Quick Triage ─────────────────────────────────────────────────────
	"triage:windows": {
		Title: "Quick Triage",
		Items: []MenuItem{
			{Label: "Full Triage (Recommended)", Shortcut: "1", Action: "triage_full", Section: "WINDOWS QUICK TRIAGE"},
			{Label: "Process & Network Snapshot", Shortcut: "2", Action: "triage_procnet"},
			{Label: "Event Log Collection", Shortcut: "3", Action: "triage_logs"},
			{Label: "Persistence Check", Shortcut: "4", Action: "triage_persist"},
			{Label: "User Activity", Shortcut: "5", Action: "triage_user"},
			{Label: "System Information", Shortcut: "6", Action: "triage_sysinfo"},
			{Label: "Browser Artifacts", Shortcut: "7", Action: "triage_browser"},
			{Label: "Custom Collection", Shortcut: "8", Action: "triage_custom"},
		},
	},
	"triage:linux": {
		Title: "Quick Triage",
		Items: []MenuItem{
			{Label: "Full Triage (Recommended)", Shortcut: "1", Action: "triage_full", Section: "LINUX QUICK TRIAGE"},
			{Label: "Process & Network Snapshot", Shortcut: "2", Action: "triage_procnet"},
			{Label: "Log Collection", Shortcut: "3", Action: "triage_logs"},
			{Label: "Persistence Check", Shortcut: "4", Action: "triage_persist"},
			{Label: "User Activity", Shortcut: "5", Action: "triage_user"},
			{Label: "System Information", Shortcut: "6", Action: "triage_sysinfo"},
			{Label: "Cron & Services", Shortcut: "7", Action: "triage_browser"},
			{Label: "Custom Collection", Shortcut: "8", Action: "triage_custom"},
		},
	},
}

// ---------------------------------------------------------------------------
// Model lifecycle
// ---------------------------------------------------------------------------

func newModel(ctx *AppContext) Model {
	return Model{
		ctx:   ctx,
		state: stateMainMenu,
		focus: paneSidebar,
	}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	// Async tool download result.
	case downloadResultMsg:
		m.toolView = "download_done"
		m.toolResultLines = msg.lines
		m.state = stateResult
		return m, nil

	// Async evidence integrity verification result.
	case integrityResultMsg:
		mm, cmd := m.handleIntegrityResult(msg)
		return mm, cmd

	// Async update check result.
	case updateCheckResultMsg:
		m.toolView = "updates"
		m.toolResultLines = msg.lines
		m.state = stateResult
		return m, nil

	// Async VR operation results.
	case vrInitDoneMsg:
		return m.handleVRInitDone(msg.result), nil
	case vrStartDoneMsg:
		return m.handleVRStartDone(msg.result), nil
	case vrStopDoneMsg:
		m.vrState.view = vrViewStopDone
		m.state = stateResult
		if msg.result.Success {
			m.vrState.resultLines = []string{"", "  " + SuccessStyle.Render("Server stopped.")}
		} else {
			m.vrState.resultLines = []string{"", "  " + ErrorStyle.Render("Error: "+msg.result.Error)}
		}
		return m, nil
	case vrClientDoneMsg:
		return m.handleVRClientDone(msg.result), nil
	case vrCollectorDoneMsg:
		return m.handleVRCollectorDone(msg.result), nil
	case vrStatusDoneMsg:
		m.vrState.view = vrViewStatus
		m.vrState.resultLines = msg.lines
		m.state = stateResult
		return m, nil

	case vrImportDoneMsg:
		m.vrState.view = vrViewImportDone
		m.state = stateResult
		if msg.result.Success {
			m.vrState.resultLines = []string{
				"", "  " + SuccessStyle.Render("Collection imported successfully."),
				"", cField("Import Path", lipgloss.NewStyle().Foreground(ColorText).Render(msg.result.ImportPath)),
			}
		} else {
			m.vrState.resultLines = []string{"", "  " + ErrorStyle.Render("Import failed: "+msg.result.Error)}
		}
		return m, nil

	// Triage progress messages.
	case triageTickMsg:
		if m.triageState.view == triageViewRunning {
			m.triageState.elapsed = time.Since(m.triageState.startTime)
			return m, triageTickCmd()
		}
		return m, nil

	case triageStepMsg:
		if msg.result == nil {
			// Step started.
			if msg.stepIndex >= 0 && msg.stepIndex < len(m.triageState.stepStatus) {
				m.triageState.stepStatus[msg.stepIndex] = triage.StepRunning
			}
		} else {
			// Step completed.
			if msg.stepIndex >= 0 && msg.stepIndex < len(m.triageState.stepStatus) {
				m.triageState.stepStatus[msg.stepIndex] = msg.result.Status
				m.triageState.stepTimes[msg.stepIndex] = msg.result.Duration
			}
		}
		return m, nil

	case triageDoneMsg:
		m.triageState.view = triageViewDone
		m.triageState.summary = &msg.summary
		m.state = stateResult
		caseID := ""
		if m.ctx.ActiveCase != nil {
			caseID = m.ctx.ActiveCase.ID
		}
		// Register evidence (which itself emits an audit "add_evidence" entry).
		if m.ctx.ActiveCase != nil && m.ctx.CaseManager != nil {
			_, _ = m.ctx.CaseManager.AddEvidence(
				m.ctx.ActiveCase.ID, 0, "triage_collection", m.triageState.outputDir)
		}
		// High-level audit entry covering the whole collection — easier to
		// scan in audit.jsonl than per-file evidence rows.
		if m.ctx.Audit != nil {
			result := fmt.Sprintf("complete: %d steps, %d files",
				len(msg.summary.Steps), msg.summary.TotalFiles)
			_ = m.ctx.Audit.Log("quick_triage", m.ctx.Hostname,
				m.triageState.outputDir, result, caseID)
		}
		return m, nil

	// Hunting progress messages.
	case huntingTickMsg:
		if m.huntingState.view == huntingViewRunning {
			m.huntingState.elapsed = time.Since(m.huntingState.startTime)
			return m, huntingTickCmd()
		}
		return m, nil

	case huntingScanDoneMsg:
		m.huntingState.view = huntingViewDone
		m.huntingState.result = &msg.result
		m.state = stateResult
		// Register evidence for findings.
		if m.ctx.ActiveCase != nil && m.ctx.CaseManager != nil && msg.result.Output != "" {
			_, _ = m.ctx.CaseManager.AddEvidence(
				m.ctx.ActiveCase.ID, 0, "threat_hunting", msg.result.Output)
		}
		return m, nil

	// Memory forensics async messages.
	case memTickMsg:
		return m.handleMemTick()
	case memCaptureProgressMsg:
		m.memState.captureProgress = msg.progress
		return m, nil
	case memCaptureDoneMsg:
		if m.ctx.Audit != nil {
			caseID := ""
			if m.ctx.ActiveCase != nil {
				caseID = m.ctx.ActiveCase.ID
			}
			result := "complete: " + msg.result.OutputPath
			if !msg.result.Success {
				result = "failed: " + msg.result.Error
			}
			_ = m.ctx.Audit.Log("memory_capture", m.ctx.Hostname,
				string(msg.result.Tool), result, caseID)
		}
		return m.handleMemCaptureDone(msg.result), nil
	case memAnalysisStepMsg:
		return m.handleMemAnalysisStep(msg.update)
	case memAnalysisDoneMsg:
		return m.handleMemAnalysisDone(msg.summary)
	case memSinglePluginDoneMsg:
		return m.handleMemSinglePluginDone(msg.result)
	case memSymbolDownloadDoneMsg:
		return m.handleMemSymbolDownloadDone(msg.result)
	case memDepsInstalledMsg:
		return m.handleMemDepsInstalled(msg)

	// Disk collection async messages.
	case diskTickMsg:
		return m.handleDiskTick()
	case diskKapeDoneMsg:
		return m.handleDiskKapeDone(msg.result)
	case diskSinglePluginDoneMsg:
		return m.handleDiskSinglePluginDone(msg.result)
	case diskAllParsersDoneMsg:
		return m.handleDiskAllParsersDone(msg.results)
	case diskUACDoneMsg:
		return m.handleDiskUACDone(msg.result)
	case diskLnxDoneMsg:
		return m.handleDiskLnxDone(msg.result)
	case diskManualDoneMsg:
		return m.handleDiskManualDone(msg.result)

	// Remote operations async messages.
	case remoteTickMsg:
		return m.handleRemoteTick()
	case remoteConnDoneMsg:
		return m.handleRemoteConnDone(msg)
	case remoteTriageDoneMsg:
		return m.handleRemoteTriageDone(msg)
	case remoteCollectDoneMsg:
		return m.handleRemoteCollectDone(msg)
	case remoteAcquireDoneMsg:
		return m.handleRemoteAcquireDone(msg)
	case remoteMemoryDoneMsg:
		return m.handleRemoteMemoryDone(msg)
	case remoteHuntDoneMsg:
		return m.handleRemoteHuntDone(msg)
	case remoteIOCDoneMsg:
		return m.handleRemoteIOCDone(msg)
	case remoteBatchTriageDoneMsg:
		return m.handleRemoteBatchTriageDone(msg)
	case remoteBatchIOCDoneMsg:
		return m.handleRemoteBatchIOCDone(msg)
	case remoteDeployDoneMsg:
		return m.handleRemoteDeployDone(msg)

	// Analysis async messages.
	case analysisTickMsg:
		return m.handleAnalysisTick()
	case analysisRunDoneMsg:
		return m.handleAnalysisRunDone(msg)

	// Use cases async messages.
	case ucTickMsg:
		return m.handleUcTick()
	case ucRunDoneMsg:
		return m.handleUcRunDone(msg)

	// Update async messages.
	case updateTickMsg:
		return m.handleUpdateTick()
	case updateCheckDoneMsg:
		return m.handleUpdateCheckDone(msg)
	case updateApplyDoneMsg:
		return m.handleUpdateApplyDone(msg)
	case updateBundleCreateDoneMsg:
		return m.handleUpdateBundleCreateDone(msg)
	case updateBundleApplyDoneMsg:
		return m.handleUpdateBundleApplyDone(msg)
	case updateVanGuardDoneMsg:
		return m.handleUpdateVanGuardDone(msg)

	case tea.KeyMsg:
		return m.handleKey(msg)

	default:
		// Forward cursor blink and other messages to textinput when active.
		if m.cfgState.view == cfgViewCreateCase ||
			m.cfgState.view == cfgViewEditAnalyst ||
			m.cfgState.view == cfgViewEditOrg {
			var cmd tea.Cmd
			m.cfgState.input, cmd = m.cfgState.input.Update(msg)
			return m, cmd
		}
		// VR text inputs.
		if m.vrState.view == vrViewInitPassword ||
			m.vrState.view == vrViewDeployCredHost ||
			m.vrState.view == vrViewDeployCredUser ||
			m.vrState.view == vrViewDeployCredPass ||
			m.vrState.view == vrViewDeployCredPort ||
			m.vrState.view == vrViewImportPath {
			var cmd tea.Cmd
			m.vrState.input, cmd = m.vrState.input.Update(msg)
			return m, cmd
		}
		// Memory text inputs.
		if m.memState.view == memViewDumpPathInput ||
			m.memState.view == memViewCustomPlugin ||
			m.memState.view == memViewCustomPluginArgs ||
			m.memState.view == memViewYaraCustomPath ||
			m.memState.view == memViewRemoteHost ||
			m.memState.view == memViewRemoteUser ||
			m.memState.view == memViewRemotePass ||
			m.memState.view == memViewRemotePort ||
			m.memState.view == memViewGUIDumpPath ||
			m.memState.view == memViewGUICliPath {
			var cmd tea.Cmd
			m.memState.input, cmd = m.memState.input.Update(msg)
			return m, cmd
		}
		// Disk collection text inputs.
		if m.diskState.view == diskViewKapeCustomTargets ||
			m.diskState.view == diskViewSourceCustomPath ||
			m.diskState.view == diskViewLnxAppPath ||
			m.diskState.view == diskViewManualSrc ||
			m.diskState.view == diskViewManualDesc {
			var cmd tea.Cmd
			m.diskState.input, cmd = m.diskState.input.Update(msg)
			return m, cmd
		}
		// Use cases parameter prompt input.
		if m.usecasesState.view == ucViewParams {
			var cmd tea.Cmd
			m.usecasesState.paramInput, cmd = m.usecasesState.paramInput.Update(msg)
			return m, cmd
		}
		// Update bundle apply path input.
		if m.updateState.view == updateViewApplyPath {
			var cmd tea.Cmd
			m.updateState.pathInput, cmd = m.updateState.pathInput.Update(msg)
			return m, cmd
		}
		// Remote ops text inputs (everything that uses m.remoteState.input).
		if m.remoteState.view == remoteViewAddHostname ||
			m.remoteState.view == remoteViewAddIP ||
			m.remoteState.view == remoteViewAddPort ||
			m.remoteState.view == remoteViewAddUsername ||
			m.remoteState.view == remoteViewAddKeyPath ||
			m.remoteState.view == remoteViewAddNotes ||
			m.remoteState.view == remoteViewPromptPassword ||
			m.remoteState.view == remoteViewAcquirePath ||
			m.remoteState.view == remoteViewAcquireDesc ||
			m.remoteState.view == remoteViewIOCValue {
			var cmd tea.Cmd
			m.remoteState.input, cmd = m.remoteState.input.Update(msg)
			return m, cmd
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// ============================================================
	// TEXT INPUT INTERCEPT — must be the first thing checked.
	// ============================================================
	//
	// When any panel is in a text-input view, every keystroke (numbers,
	// letters, symbols, backspace) MUST go to the input component. Only
	// Enter (submit) and Esc (cancel) get routed to the panel's own
	// update logic, where they're handled as form-control actions.
	//
	// Without this gate, the global sidebar number shortcut below would
	// hijack "1"-"8" and the analyst's case name "Incident 2026-001"
	// would teleport them to the Memory Forensics submenu after typing
	// the first digit. The previous attempt to fix this via guards on
	// each individual handler was fragile (every new handler had to
	// remember to check). This gate is unmissable — nothing reads keys
	// before it.
	if m.panelTextInputActive() {
		switch key {
		case "enter", "esc":
			// Fall through to panel-specific dispatchers below — they
			// treat these as form-control actions (submit/cancel).
		case "ctrl+c":
			// Always allow quitting from any text input.
			return m, tea.Quit
		default:
			return m.routeTextInputKey(msg)
		}
	}

	// Quit confirmation takes priority.
	if m.confirmQuit {
		switch key {
		case "y", "Y":
			return m, tea.Quit
		default:
			m.confirmQuit = false
			m.statusMessage = ""
			return m, nil
		}
	}

	// Result screen.
	if m.state == stateResult {
		// Sidebar number shortcuts (1-8) ALWAYS jump to the requested
		// sidebar item, regardless of the current panel state — UNLESS the
		// panel is in an interactive view that uses number keys (e.g. memory
		// dump selection, YARA rule selection, remote method picker). Without
		// this short-circuit, pressing "5" while a "Volatility3 Required"
		// blocker is shown gets eaten by the panel as a dismiss key, and the
		// user has to press "5" twice to navigate.
		if len(key) == 1 && key >= "1" && key <= "8" && !m.panelInteractive() {
			idx := int(key[0]-'0') - 1
			if idx >= 0 && idx < len(allSidebarItems) {
				m.clearPanelState()
				m.toolView = ""
				m.toolStatusLines = nil
				m.toolResultLines = nil
				m.statusMessage = ""
				m.sidebarCursor = idx
				return m.activateSidebarItem(idx)
			}
		}

		// Tool download confirmation prompts take highest priority — they
		// use toolView (not cfgState.view), so they must be checked before
		// the panel dispatches that could swallow the y/n key.
		if m.toolView == "download_confirm" {
			if key == "y" || key == "Y" {
				m.toolView = "downloading"
				return m, m.asyncDownloadRequired()
			}
			m.toolView = ""
			m.state = stateSubMenu
			m.statusMessage = "Download cancelled."
			return m, nil
		}
		if m.toolView == "download_all_confirm" {
			if key == "y" || key == "Y" {
				m.toolView = "downloading"
				return m, m.asyncDownloadAll()
			}
			m.toolView = ""
			m.state = stateSubMenu
			m.statusMessage = "Download cancelled."
			return m, nil
		}

		// Block input during async tool operations.
		if m.toolView == "downloading" || m.toolView == "checking_updates" {
			return m, nil
		}

		// Scroll keys take priority over panel dispatch so they work in every
		// panel's result/info/error view without each panel re-implementing
		// them. We pick keys that no panel uses for its own logic: PgUp /
		// PgDn / Home / End / mouse-wheel-equivalent ctrl+up / ctrl+down.
		switch key {
		case "pgup":
			m = m.scrollContent(-m.scrollPageStep())
			return m, nil
		case "pgdown":
			m = m.scrollContent(m.scrollPageStep())
			return m, nil
		case "home":
			m.contentScrollOffset = 0
			return m, nil
		case "end":
			m.contentScrollOffset = m.scrollMaxOffset()
			return m, nil
		case "ctrl+up":
			m = m.scrollContent(-1)
			return m, nil
		case "ctrl+down":
			m = m.scrollContent(1)
			return m, nil
		}

		// Config panel views.
		if m.cfgState.view != cfgViewNone {
			updated, cmd, consumed := m.configUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// VR panel views.
		if m.vrState.view != vrViewNone {
			updated, cmd, consumed := m.vrUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Triage panel views.
		if m.triageState.view != triageViewNone {
			updated, cmd, consumed := m.triageUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Hunting panel views.
		if m.huntingState.view != huntingViewNone {
			updated, cmd, consumed := m.huntingUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Memory forensics panel views.
		if m.memState.view != memViewNone {
			updated, cmd, consumed := m.memoryUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Disk collection panel views.
		if m.diskState.view != diskViewNone {
			updated, cmd, consumed := m.diskUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Remote operations panel views.
		if m.remoteState.view != remoteViewNone {
			updated, cmd, consumed := m.remoteUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Analysis panel views.
		if m.analysisState.view != analysisViewNone {
			updated, cmd, consumed := m.analysisUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Use cases panel views.
		if m.usecasesState.view != ucViewNone {
			updated, cmd, consumed := m.usecasesUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Update panel views.
		if m.updateState.view != updateViewNone {
			updated, cmd, consumed := m.updateUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Help panel views.
		if m.helpState.view != helpViewNone {
			updated, cmd, consumed := m.helpUpdate(msg)
			if consumed {
				return updated, cmd
			}
		}

		// Config result lines (e.g., after case creation) — any key dismisses.
		if len(m.cfgState.resultLines) > 0 {
			m.cfgState.resultLines = nil
			m.cfgState.view = cfgViewNone
			if len(m.contentItems) > 0 {
				m.state = stateSubMenu
			} else {
				m.state = stateMainMenu
			}
			return m, nil
		}

		// Any other key dismisses the result.
		m.toolView = ""
		m.toolStatusLines = nil
		m.toolResultLines = nil
		if len(m.contentItems) > 0 {
			m.state = stateSubMenu
		} else {
			m.state = stateMainMenu
		}
		m.statusMessage = ""
		return m, nil
	}

	switch key {
	case "ctrl+c":
		return m, tea.Quit

	case "tab":
		if m.state == stateSubMenu && len(m.contentItems) > 0 {
			if m.focus == paneSidebar {
				m.focus = paneContent
			} else {
				m.focus = paneSidebar
			}
		}
		return m, nil

	case "up", "k", "K":
		// K (uppercase) triggers content shortcut if it matches; k/up always navigate.
		if key == "K" && m.focus == paneContent && m.state == stateSubMenu {
			if idx := m.findContentByShortcut("K"); idx >= 0 {
				m.contentCursor = idx
				return m.activateContentItem(idx)
			}
		}
		if m.focus == paneSidebar {
			if m.sidebarCursor > 0 {
				m.sidebarCursor--
			}
		} else if m.state == stateSubMenu {
			if m.contentCursor > 0 {
				m.contentCursor--
			}
		}
		return m, nil

	case "down", "j", "J":
		// J (uppercase) triggers content shortcut if it matches; j/down always navigate.
		if key == "J" && m.focus == paneContent && m.state == stateSubMenu {
			if idx := m.findContentByShortcut("J"); idx >= 0 {
				m.contentCursor = idx
				return m.activateContentItem(idx)
			}
		}
		if m.focus == paneSidebar {
			if m.sidebarCursor < len(allSidebarItems)-1 {
				m.sidebarCursor++
			}
		} else if m.state == stateSubMenu {
			if m.contentCursor < len(m.contentItems)-1 {
				m.contentCursor++
			}
		}
		return m, nil

	case "left":
		m.focus = paneSidebar
		return m, nil

	case "right":
		if m.state == stateSubMenu && len(m.contentItems) > 0 {
			m.focus = paneContent
		}
		return m, nil

	case "enter":
		if m.focus == paneSidebar {
			return m.activateSidebarItem(m.sidebarCursor)
		}
		if m.focus == paneContent && m.state == stateSubMenu {
			return m.activateContentItem(m.contentCursor)
		}

	case "esc", "backspace":
		if m.state == stateSubMenu {
			m.state = stateMainMenu
			m.focus = paneSidebar
			m.contentItems = nil
			m.activeAction = ""
			m.activeTitle = ""
			m.statusMessage = ""
		}
		return m, nil

	// Number keys 0-9.
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9":
		if m.focus == paneContent && m.state == stateSubMenu {
			if idx := m.findContentByShortcut(key); idx >= 0 {
				m.contentCursor = idx
				return m.activateContentItem(idx)
			}
		} else if key != "9" && key != "0" {
			idx := int(key[0]-'0') - 1
			m.sidebarCursor = idx
			return m.activateSidebarItem(idx)
		}

	// Letter shortcuts — content pane gets priority if it has a matching item.
	// Note: j/k are reserved for vim-style up/down navigation above.
	case "a", "A", "b", "B", "c", "C", "d", "D", "e", "E", "f", "F",
		"g", "G", "h", "H", "i", "I", "l", "L", "m", "M", "n", "N", "o", "O":
		if m.focus == paneContent && m.state == stateSubMenu {
			upper := strings.ToUpper(key)
			if idx := m.findContentByShortcut(upper); idx >= 0 {
				m.contentCursor = idx
				return m.activateContentItem(idx)
			}
		}
		// Fall through to sidebar shortcuts when content didn't match.
		switch key {
		case "c", "C":
			m.sidebarCursor = 9
			return m.activateSidebarItem(9)
		case "h", "H":
			m.sidebarCursor = 10
			return m.activateSidebarItem(10)
		}

	case "u", "U":
		m.sidebarCursor = 8
		return m.activateSidebarItem(8)
	case "q", "Q":
		m.sidebarCursor = 11
		return m.activateSidebarItem(11)
	}

	return m, nil
}

func (m Model) activateSidebarItem(idx int) (Model, tea.Cmd) {
	if idx < 0 || idx >= len(allSidebarItems) {
		return m, nil
	}
	item := allSidebarItems[idx]

	if m.ctx.Logger != nil {
		m.ctx.Logger.Debug("tui", "sidebar: selected item %d (%s) -> action=%s",
			idx, item.Label, item.Action)
	}

	// Quit triggers confirmation dialog.
	if item.Action == "quit" {
		m.confirmQuit = true
		return m, nil
	}

	// Use Cases is a dynamic catalog rather than a static submenu — route
	// directly to its panel. The panel renders a list, detail card, and
	// execution view all in the content pane.
	if item.Action == "usecases" {
		mm, cmd := m.openUsecases()
		return mm, cmd
	}

	// Update follows the same direct-panel pattern: the body is a curated
	// menu plus dynamic check / apply views rather than a static submenu.
	if item.Action == "update" {
		mm, cmd := m.openUpdates()
		return mm, cmd
	}

	// Help — static catalog rendered with a scrolling page viewer.
	if item.Action == "help" {
		mm, cmd := m.openHelp()
		return mm, cmd
	}

	// Items with submenus open the content pane.
	// Check platform-specific override first, then fall back to shared.
	if sub, ok := m.resolveSubMenu(item.Action); ok {
		m.state = stateSubMenu
		m.activeAction = item.Action
		m.activeTitle = sub.Title
		m.contentItems = sub.Items
		m.contentCursor = 0
		m.focus = paneContent
		m.statusMessage = ""
		return m, nil
	}

	// Items without submenus show a result message.
	m.statusMessage = fmt.Sprintf("Selected: %s", item.Label)
	m.state = stateResult
	return m, nil
}

func (m Model) activateContentItem(idx int) (Model, tea.Cmd) {
	if idx < 0 || idx >= len(m.contentItems) {
		return m, nil
	}
	item := m.contentItems[idx]

	if m.ctx.Logger != nil {
		m.ctx.Logger.Debug("tui", "content: activate item %d (%s) action=%s activeAction=%s",
			idx, item.Label, item.Action, m.activeAction)
	}

	// Dispatch chain. Each handler MUST short-circuit on action prefix before
	// touching state — otherwise it can hijack a sibling panel's action.
	if updated, cmd, handled := m.handleConfigAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleVRAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleTriageAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleHuntingAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleMemoryAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleDiskAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleRemoteAction(item.Action); handled {
		return updated, cmd
	}
	if updated, cmd, handled := m.handleAnalysisAction(item.Action); handled {
		return updated, cmd
	}

	if m.ctx.Logger != nil {
		m.ctx.Logger.Warn("tui", "content: no handler claimed action %s", item.Action)
	}
	m.statusMessage = fmt.Sprintf("%s — Implementation pending", item.Label)
	m.state = stateResult
	return m, nil
}

// resolveSubMenu returns the submenu definition for the given action,
// checking platform-specific overrides first then shared definitions.
func (m Model) resolveSubMenu(action string) (subMenuDef, bool) {
	key := action + ":" + m.ctx.Platform
	if sub, ok := platformSubMenuDefs[key]; ok {
		return sub, true
	}
	if sub, ok := subMenuDefs[action]; ok {
		return sub, true
	}
	return subMenuDef{}, false
}

// ---------------------------------------------------------------------------
// View — full application layout
// ---------------------------------------------------------------------------

func (m Model) View() string {
	w := m.width
	h := m.height
	if w < 80 {
		w = 80
	}
	if h < 24 {
		h = 24
	}

	// Header is now 4 rows (empty, brand, empty, rule) and status is 2 rows
	// (rule, content). Total chrome = 6 rows.
	mainH := h - 6
	if mainH < 10 {
		mainH = 10
	}
	contentW := w - SidebarWidth

	header := RenderHeader(w, m.ctx.Version)

	sidebarLines := m.buildSidebarLines(mainH)
	contentLines := m.buildContentLines(contentW, mainH)

	mainRows := make([]string, mainH)
	for i := 0; i < mainH; i++ {
		mainRows[i] = sidebarLines[i] + contentLines[i]
	}
	main := strings.Join(mainRows, "\n")

	elevated := "No"
	if m.ctx.Elevated {
		elevated = "Yes"
	}
	caseLabel := ""
	if m.ctx.ActiveCase != nil {
		caseLabel = FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID)
	}
	status := RenderStatusBar(w, m.ctx.Platform, m.ctx.Hostname, elevated, caseLabel, m.ctx.Version)

	// Header brings its own bottom rule; status brings its own top rule, so we
	// don't add extra blank separator rows here.
	return header + "\n" + main + "\n" + status
}

// ---------------------------------------------------------------------------
// Sidebar rendering
// ---------------------------------------------------------------------------

func (m Model) buildSidebarLines(height int) []string {
	sideW := SidebarWidth - 1 // 23 content chars + 1 border char
	lines := make([]string, 0, height)

	for _, sec := range sidebarSections {
		// Blank line margin before every section except the first.
		if len(lines) > 0 {
			lines = append(lines, sidebarEmptyLine(sideW))
		}
		// Section label.
		if sec.Label != "" {
			label := lipgloss.NewStyle().
				Foreground(ColorTextMuted).Background(ColorSidebarBg).
				Render("  " + sec.Label)
			lines = append(lines,
				lipgloss.NewStyle().Width(sideW).Background(ColorSidebarBg).Render(label)+
					borderChar(ColorSidebarBg))
		}
		// Items.
		for i := sec.Start; i < sec.End; i++ {
			lines = append(lines, m.sidebarItemLine(i, sideW))
		}
	}

	// Pad remaining height.
	for len(lines) < height {
		lines = append(lines, sidebarEmptyLine(sideW))
	}
	return lines[:height]
}

func sidebarEmptyLine(width int) string {
	return lipgloss.NewStyle().Width(width).Background(ColorSidebarBg).Render("") +
		borderChar(ColorSidebarBg)
}

func borderChar(bg lipgloss.Color) string {
	return lipgloss.NewStyle().Foreground(ColorBorder).Background(bg).Render("\u2502")
}

func (m Model) sidebarItemLine(idx, width int) string {
	item := allSidebarItems[idx]
	selected := idx == m.sidebarCursor

	// Selected items get a left half-block indicator in Primary color and the
	// label rendered bold-on-selected-bg. Unselected items reserve a single
	// space at column 0 so the [shortcut] columns line up regardless of state.
	if selected {
		indicator := lipgloss.NewStyle().Foreground(ColorPrimary).Background(ColorSelectedBg).
			Render(blockLeftHalf)
		num := lipgloss.NewStyle().Foreground(ColorHighlight).Background(ColorSelectedBg).Bold(true).
			Render(fmt.Sprintf("[%s]", item.Shortcut))
		label := lipgloss.NewStyle().Foreground(ColorHighlight).Background(ColorSelectedBg).Bold(true).
			Render(item.Label)
		sp := lipgloss.NewStyle().Background(ColorSelectedBg).Render(" ")
		text := indicator + sp + num + sp + label
		return lipgloss.NewStyle().Width(width).Background(ColorSelectedBg).Render(text) +
			borderChar(ColorSelectedBg)
	}

	leadGap := lipgloss.NewStyle().Background(ColorSidebarBg).Render(" ") // matches indicator width
	num := lipgloss.NewStyle().Foreground(ColorAccent).Background(ColorSidebarBg).
		Render(fmt.Sprintf("[%s]", item.Shortcut))
	label := lipgloss.NewStyle().Foreground(ColorText).Background(ColorSidebarBg).
		Render(item.Label)
	sp := lipgloss.NewStyle().Background(ColorSidebarBg).Render(" ")
	text := leadGap + sp + num + sp + label

	return lipgloss.NewStyle().Width(width).Background(ColorSidebarBg).Render(text) +
		borderChar(ColorSidebarBg)
}

// ---------------------------------------------------------------------------
// Content rendering
// ---------------------------------------------------------------------------

// panelRawContent returns the un-paginated content lines for whichever panel
// is currently active (or the submenu/dashboard fallback). Used both by the
// view renderer (which then applies scrolling and padding) and by the key
// handler (which needs to know total line count for scroll bounds).
func (m Model) panelRawContent(width int) []string {
	var raw []string

	// Config panel views take priority when active.
	if m.state == stateResult && m.cfgState.view != cfgViewNone {
		raw = m.configContent(width)
	} else if m.state == stateResult && len(m.cfgState.resultLines) > 0 {
		raw = m.configContent(width)
	} else if m.state == stateResult && m.vrState.view != vrViewNone {
		raw = m.vrContent(width)
	} else if m.state == stateResult && m.triageState.view != triageViewNone {
		raw = m.triageContent(width)
	} else if m.state == stateResult && m.huntingState.view != huntingViewNone {
		raw = m.huntingContent(width)
	} else if m.state == stateResult && m.memState.view != memViewNone {
		raw = m.memoryContent(width)
	} else if m.state == stateResult && m.diskState.view != diskViewNone {
		raw = m.diskContent(width)
	} else if m.state == stateResult && m.remoteState.view != remoteViewNone {
		raw = m.remoteContent(width)
	} else if m.state == stateResult && m.analysisState.view != analysisViewNone {
		raw = m.analysisContent(width)
	} else if m.state == stateResult && m.usecasesState.view != ucViewNone {
		raw = m.usecasesContent(width)
	} else if m.state == stateResult && m.updateState.view != updateViewNone {
		raw = m.updateContent(width)
	} else if m.state == stateResult && m.helpState.view != helpViewNone {
		raw = m.helpContent(width)
	} else if m.state == stateResult && m.toolView != "" {
		raw = m.toolContent(width)
	} else if len(m.contentItems) > 0 && m.state != stateMainMenu {
		raw = m.subMenuContent(width)
	} else {
		raw = m.dashboardContent(width)
	}

	// Overlay messages.
	if m.confirmQuit {
		raw = append(raw, "", "  "+WarningStyle.Render("Quit VanGuard? (y/N)"))
	} else if m.statusMessage != "" {
		// "X — Implementation pending" lands here; render as a bordered box so
		// it reads as a panel rather than a stray line of green text.
		if strings.Contains(m.statusMessage, "Implementation pending") {
			feature := strings.TrimSuffix(m.statusMessage, " — Implementation pending")
			inner := dashboardCardWidth(width)
			body := []string{
				lipgloss.NewStyle().Foreground(ColorText).Render("Implementation pending."),
				lipgloss.NewStyle().Foreground(ColorTextSecondary).Render("Module: " + feature),
				"",
				lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					"Use the individual tool commands directly in the meantime, or"),
				lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					"check Help [H] for a list of working features."),
			}
			raw = append(raw, "")
			raw = append(raw, PlainBoxLines(inner, body)...)
			raw = append(raw, "", cHint("Press any key to return"))
		} else {
			raw = append(raw, "", "  "+SuccessStyle.Render(m.statusMessage))
		}
	}
	return raw
}

func (m Model) buildContentLines(width, height int) []string {
	raw := m.panelRawContent(width)

	// Apply scroll window. We reserve one row at the bottom for the
	// scroll/hint indicator and one at the top for the "↑ more" marker
	// when scrolled. This means the visible content area is height-2 rows.
	visible := height
	hintRow := ""
	hintWidth := width

	total := len(raw)
	offset := m.contentScrollOffset
	maxOffset := total - visible
	if maxOffset < 0 {
		maxOffset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	if offset < 0 {
		offset = 0
	}

	var windowed []string
	if total <= visible {
		windowed = raw
		// Pad to height.
		for len(windowed) < height {
			windowed = append(windowed, "")
		}
		// Render bottom hint inline replacing last row.
		hintRow = renderScrollHint(hintWidth, false, false, total, total)
		windowed[height-1] = hintRow
	} else {
		// Reserve top for "↑ more" if scrolled, bottom for "↓ more" / hint.
		topMarker := offset > 0
		bottomMarker := offset+visible < total

		// We must always render exactly `height` rows. The first row is the
		// top marker (or empty), the last row is the bottom hint, and the
		// middle holds raw[offset : offset+(visible-2)].
		bodyHeight := visible - 2
		if bodyHeight < 1 {
			bodyHeight = 1
		}
		end := offset + bodyHeight
		if end > total {
			end = total
		}
		body := raw[offset:end]

		if topMarker {
			windowed = append(windowed,
				"  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					fmt.Sprintf("↑ more (%d above)", offset)))
		} else {
			windowed = append(windowed, "")
		}
		windowed = append(windowed, body...)
		// Pad body if short.
		for len(windowed) < height-1 {
			windowed = append(windowed, "")
		}
		hintRow = renderScrollHint(hintWidth, topMarker, bottomMarker, end, total)
		windowed = append(windowed, hintRow)
	}

	// Pad or trim to exact height as a safety.
	for len(windowed) < height {
		windowed = append(windowed, "")
	}
	if len(windowed) > height {
		windowed = windowed[:height]
	}

	out := make([]string, height)
	for i := 0; i < height; i++ {
		out[i] = lipgloss.NewStyle().Width(width).Background(ColorContentBg).Render(windowed[i])
	}
	return out
}

// scrollContent shifts contentScrollOffset by delta lines, clamped to the
// valid range. Returns the updated model so it composes nicely with the key
// handler.
func (m Model) scrollContent(delta int) Model {
	max := m.scrollMaxOffset()
	off := m.contentScrollOffset + delta
	if off < 0 {
		off = 0
	}
	if off > max {
		off = max
	}
	m.contentScrollOffset = off
	return m
}

// scrollMaxOffset returns the largest valid scroll offset given the current
// content's total line count and the visible content height. Returns 0 when
// the content fits the visible area.
func (m Model) scrollMaxOffset() int {
	width := m.width - SidebarWidth
	if width < 30 {
		width = 30
	}
	mainH := m.height - 6
	if mainH < 10 {
		mainH = 10
	}
	total := len(m.panelRawContent(width))
	max := total - mainH
	if max < 0 {
		return 0
	}
	return max
}

// scrollPageStep returns the scroll-by-page distance: roughly half the visible
// content height, with a sane floor.
func (m Model) scrollPageStep() int {
	mainH := m.height - 6
	if mainH < 10 {
		mainH = 10
	}
	step := mainH / 2
	if step < 5 {
		step = 5
	}
	return step
}

// renderScrollHint formats the bottom-row "↓ more / Esc back / line position"
// hint. Always shown (even on non-scrolled views) so the keybinding is always
// discoverable.
func renderScrollHint(width int, hasTop, hasBottom bool, current, total int) string {
	var parts []string
	if hasBottom {
		parts = append(parts, "↓ more")
	}
	parts = append(parts, "Esc: back", "↑↓: scroll")
	left := "  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(strings.Join(parts, "  "))

	pos := fmt.Sprintf("%d/%d", current, total)
	right := lipgloss.NewStyle().Foreground(ColorTextMuted).Render(pos) + "  "

	leftW := lipgloss.Width(left)
	rightW := lipgloss.Width(right)
	gap := width - leftW - rightW
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// dashboardContent builds the Home content pane lines.
// dashboardContent renders Home as a series of bordered cards. Each card is
// produced by BoxLines so the dashboard reads as a structured panel rather
// than a flat list.
func (m Model) dashboardContent(width int) []string {
	innerW := dashboardCardWidth(width)
	lines := []string{
		"",
		cBreadcrumb("Home"),
		"",
	}

	// ── Case Status ──
	// Show case name and ID on separate rows so the human-readable name has
	// pride of place but the ID is available for cross-referencing.
	caseNameVal := lipgloss.NewStyle().Foreground(ColorWarning).Render("None")
	caseIDVal := lipgloss.NewStyle().Foreground(ColorTextMuted).Render("—")
	if m.ctx.ActiveCase != nil {
		name := m.ctx.ActiveCase.Name
		if name == "" {
			name = "(unnamed)"
		}
		caseNameVal = lipgloss.NewStyle().Foreground(ColorPrimary).Render(name)
		caseIDVal = lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(m.ctx.ActiveCase.ID)
	}

	investigator := lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Not set")
	if v := m.ctx.Config.VanGuard.Analyst; v != "" {
		investigator = lipgloss.NewStyle().Foreground(ColorText).Render(v)
	}
	org := lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Not set")
	if v := m.ctx.Config.VanGuard.Organization; v != "" {
		org = lipgloss.NewStyle().Foreground(ColorText).Render(v)
	}

	caseCard := BoxLines("Case Status", innerW, []string{
		cardField("Active Case", caseNameVal),
		cardField("Case ID", caseIDVal),
		cardField("Hostname", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.ctx.Hostname)),
		cardField("Investigator", investigator),
		cardField("Organization", org),
	})
	lines = append(lines, caseCard...)
	lines = append(lines, "")

	// ── Quick Actions ──
	hint := func(s string) string {
		return lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(s)
	}
	actionsCard := BoxLines("Quick Actions", innerW, []string{
		hint("Press [1]–[8] or select from the sidebar"),
		hint("Press [C] to open the Use Cases library"),
		hint("Press [8] to create a new case"),
	})
	lines = append(lines, actionsCard...)
	lines = append(lines, "")

	// ── System ──
	elevStr := "No"
	elevFg := ColorWarning
	if m.ctx.Elevated {
		elevStr = "Yes"
		elevFg = ColorSuccess
	}
	systemCard := BoxLines("System", innerW, []string{
		cardField("Platform", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.ctx.Platform)),
		cardField("Elevated", lipgloss.NewStyle().Foreground(elevFg).Render(elevStr)),
		cardField("Tools", m.toolCategoryBreakdown()),
	})
	lines = append(lines, systemCard...)
	lines = append(lines, "")

	// ── Resources ──
	resourcesCard := BoxLines("Resources", innerW, []string{
		cardField("Training", lipgloss.NewStyle().Foreground(ColorAccent).Render("training.ridgelinecyber.com")),
		cardField("Website", lipgloss.NewStyle().Foreground(ColorAccent).Render("ridgelinecyber.com")),
	})
	lines = append(lines, resourcesCard...)

	return lines
}

// dashboardCardWidth returns the inner width (between borders) for the
// Home cards. Capped so cards don't stretch absurdly on wide terminals.
func dashboardCardWidth(paneWidth int) int {
	w := paneWidth - 6 // 2-char left margin + 2 borders + 2 right pad
	if w < 30 {
		w = 30
	}
	if w > 80 {
		w = 80
	}
	return w
}

// cardField formats a "label  value" row for use inside a BoxLines card.
// Unlike cField it doesn't add an outer 2-space margin (the box renders the
// border + padding itself).
func cardField(label, value string) string {
	l := lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render(fmt.Sprintf("%-14s", label+":"))
	return l + " " + value
}

// subMenuContent builds the submenu list content pane lines.
func (m Model) subMenuContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > " + m.activeTitle),
		"",
	}

	// Hunting prerequisites.
	if m.activeAction == "hunting" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render("No active case — create one in [8] before running ops that produce evidence"))
		}
		if !m.ctx.Elevated {
			lines = append(lines,
				"  "+WarningStyle.Render("WARNING: Running without elevation. Some scans may fail."))
		}
		// Tool availability summary.
		huntTools := m.huntingToolStatus()
		if huntTools != "" {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(huntTools))
		}
		lines = append(lines, "")
	}

	// Triage prerequisites.
	if m.activeAction == "triage" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render("No active case — create one in [8] before running ops that produce evidence"))
		}
		if !m.ctx.Elevated {
			lines = append(lines,
				"  "+WarningStyle.Render("WARNING: Running without elevation. Some collections will fail."))
		}
		lines = append(lines, "")
	}

	// Analysis & Reporting prerequisites.
	if m.activeAction == "analysis" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render(
				"No active case — create one in [8] before running ops that produce evidence"))
		}
		lines = append(lines, "")
	}

	// Remote Operations prerequisites.
	if m.activeAction == "remote" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render("No active case — create one in [8] before running ops that produce evidence"))
		}
		if !m.ctx.Elevated {
			lines = append(lines, "  "+WarningStyle.Render(
				"Some remote operations require Administrator/root on the analyst machine."))
		}
		lines = append(lines, "")
	}

	// Disk Collection prerequisites.
	if m.activeAction == "disk" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render("No active case — create one in [8] before running ops that produce evidence"))
		}
		if !m.ctx.Elevated {
			lines = append(lines,
				"  "+WarningStyle.Render("Some collections require Administrator/root."))
		} else {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
				"Elevation: required for KAPE / system-wide collections."))
		}
		lines = append(lines, "")
	}

	// Memory Forensics prerequisites.
	if m.activeAction == "memory" {
		if m.ctx.ActiveCase != nil {
			lines = append(lines, cField("Active Case",
				lipgloss.NewStyle().Foreground(ColorSuccess).Render(
					FormatCaseLabel(m.ctx.ActiveCase.Name, m.ctx.ActiveCase.ID))))
		} else {
			lines = append(lines, "  "+WarningStyle.Render("No active case — create one in [8] before running ops that produce evidence"))
		}
		elevHint := "Required for memory capture."
		if !m.ctx.Elevated {
			lines = append(lines,
				"  "+WarningStyle.Render("WARNING: Memory capture requires Administrator/root."))
		} else {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
				"Elevation: "+elevHint))
		}
		lines = append(lines, "")
	}

	for i, item := range m.contentItems {
		// Section header — render above this item with an extra blank line
		// before it so groups breathe.
		if item.Section != "" {
			if i > 0 {
				lines = append(lines, "", "") // two-line gap between sections
			}
			lines = append(lines, cSectionLabel(item.Section), cRule(width))
		}

		// All items align at column 6: 2-char left margin, 2-char indicator
		// slot, single space, then `[shortcut]`. Selected items fill the
		// indicator slot with ▌ in Primary; unselected leave it blank so
		// nothing shifts horizontally between states.
		selected := i == m.contentCursor && m.focus == paneContent
		var indicator string
		if selected {
			indicator = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(blockLeftHalf)
		} else {
			indicator = " "
		}

		var num, label string
		if selected {
			num = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render(fmt.Sprintf("[%s]", item.Shortcut))
			label = lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(item.Label)
		} else {
			num = lipgloss.NewStyle().Foreground(ColorAccent).
				Render(fmt.Sprintf("[%s]", item.Shortcut))
			label = lipgloss.NewStyle().Foreground(ColorText).Render(item.Label)
		}
		lines = append(lines, "  "+indicator+" "+num+"  "+label)
	}

	if m.state == stateSubMenu {
		lines = append(lines, "")
		hint := lipgloss.NewStyle().Foreground(ColorTextMuted).
			Render("  Tab: switch pane   Esc: back   Enter: select")
		lines = append(lines, hint)
	}

	return lines
}

// findContentByShortcut returns the index of the content item whose shortcut
// matches key (case-insensitive), or -1 if none match.
func (m Model) findContentByShortcut(key string) int {
	upper := strings.ToUpper(key)
	for i, item := range m.contentItems {
		if strings.ToUpper(item.Shortcut) == upper {
			return i
		}
	}
	return -1
}

// Content helper functions.

func cBreadcrumb(path string) string {
	return "  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(path)
}

func cSectionLabel(title string) string {
	return "  " + lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(title)
}

// cRule returns a horizontal divider intended to follow a section label. The
// rule width is capped to a comfortable maximum so it doesn't dominate very
// wide terminals, but it now extends past the old 30-char limit so section
// headers feel anchored.
func cRule(width int) string {
	n := width - 4
	if n > 60 {
		n = 60
	}
	if n < 10 {
		n = 10
	}
	return "  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat(boxHorizontal, n))
}

func cField(label, value string) string {
	l := lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render(fmt.Sprintf("  %-14s", label+":"))
	return l + " " + value
}

func cHint(text string) string {
	return "  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(text)
}

// ---------------------------------------------------------------------------
// Tool management views
// ---------------------------------------------------------------------------

// toolContent renders the active tool management view.
func (m Model) toolContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Configuration > Tool Management"),
		"",
	}

	switch m.toolView {
	case "status":
		lines = append(lines, cSectionLabel("Tool Status"), cRule(width))
		lines = append(lines, m.toolStatusLines...)
		lines = append(lines, "")
		platform := m.ctx.Platform
		if m.ctx.ToolManager != nil {
			platform = m.ctx.ToolManager.Platform()
		}
		lines = append(lines,
			cHint(fmt.Sprintf("Showing tools for: %s", platform)),
			cHint("Tools marked (manual install) require manual download or package manager installation."),
			cHint("Tools marked (compile required) must be built for the target system."))
		lines = append(lines, "")
		lines = append(lines, cHint("Press any key to return"))

	case "download_confirm", "download_all_confirm":
		lines = append(lines, cSectionLabel("Download Tools"), cRule(width))
		lines = append(lines, "")
		lines = append(lines, "  "+WarningStyle.Render(m.toolConfirmMsg))

	case "downloading":
		lines = append(lines, cSectionLabel("Downloading Tools"), cRule(width))
		lines = append(lines, "")
		lines = append(lines, "  "+SpinnerStyle.Render("[▸] Downloading tools, please wait..."))
		lines = append(lines, "  "+TextProgressBar(50, 30))
		lines = append(lines, "")
		lines = append(lines, cHint("Each tool is fetched from GitHub and verified before install."))

	case "checking_updates":
		lines = append(lines, cSectionLabel("Update Check"), cRule(width))
		lines = append(lines, "")
		lines = append(lines, "  "+SpinnerStyle.Render("[▸] Checking for updates..."))
		lines = append(lines, "  "+TextProgressBar(50, 30))

	case "download_done":
		lines = append(lines, cSectionLabel("Download Results"), cRule(width))
		lines = append(lines, m.toolResultLines...)
		lines = append(lines, "")
		lines = append(lines, cHint("Press any key to return"))

	case "updates":
		lines = append(lines, cSectionLabel("Update Check"), cRule(width))
		lines = append(lines, m.toolResultLines...)
		lines = append(lines, "")
		lines = append(lines, cHint("Press any key to return"))
	}

	return lines
}

// buildToolStatusTable produces the formatted tool status lines grouped by category.
func (m Model) buildToolStatusTable() []string {
	return buildToolStatusTableStatic(m.ctx.ToolManager)
}

// buildToolStatusTableStatic produces the formatted tool status lines.
// Safe to call from a goroutine — only touches the ToolManager.
func buildToolStatusTableStatic(tm *tools.ToolManager) []string {
	if tm == nil {
		return []string{"  " + ErrorStyle.Render("Tool manager not initialized")}
	}

	groups := tm.GetStatusByCategory()
	if len(groups) == 0 {
		return []string{"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render("No tools registered for this platform")}
	}

	var lines []string

	// Column widths chosen so the table reads as a proper grid even for
	// long-pathed tools. Status is the only column whose visible width is
	// shorter than its formatted width (because of ANSI escapes), so we
	// pad it manually with formatStatusCell below.
	const (
		nameW   = 22
		reqW    = 6
		statusW = 11
		ruleW   = 76
	)
	rule := "  " + lipgloss.NewStyle().Foreground(ColorBorder).
		Render(strings.Repeat(boxHorizontal, ruleW))

	hdr := fmt.Sprintf("%-*s%-*s%-*s%s",
		nameW, "Name", reqW, "Req", statusW, "Status", "Path")
	hdrLine := "  " + TableHeaderStyle.Render(hdr)

	for gi, g := range groups {
		if gi > 0 {
			lines = append(lines, "")
		}

		// Category header + thin top rule.
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(g.Label))
		lines = append(lines, rule, hdrLine, rule)

		for _, s := range g.Tools {
			lines = append(lines, formatToolRow(s, nameW, reqW, statusW))
		}

		// Bottom rule closes the category block.
		lines = append(lines, rule)
	}

	return lines
}

// formatToolRow renders a single tool row aligned to the given column widths.
// The status column is padded by hand because lipgloss-styled strings carry
// ANSI escapes that fmt's width specifier can't account for.
func formatToolRow(s tools.ToolStatus, nameW, reqW, statusW int) string {
	// Python3 is a detection-only pseudo-tool — render with FOUND / NOT FOUND
	// and a "-" in the req column so it's clearly distinct from downloadables.
	isDetectOnly := strings.HasPrefix(s.ID, "python3-")

	reqStr := "No"
	switch {
	case isDetectOnly:
		reqStr = "-"
	case s.Required:
		reqStr = "Yes"
	}

	statusCell := formatStatusCell(s, statusW, isDetectOnly)

	nameField := lipgloss.NewStyle().Foreground(ColorText).
		Render(fmt.Sprintf("%-*s", nameW, truncateVisible(s.Name, nameW-1)))
	reqField := lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render(fmt.Sprintf("%-*s", reqW, reqStr))

	pathStr := s.Path
	if isDetectOnly && !s.Installed {
		pathStr = "Install Python 3 or place portable Python in lib/python-embedded/"
	} else if s.Manual && !isDetectOnly {
		if strings.Contains(s.Description, "Must be compiled") {
			pathStr += " (compile required)"
		} else {
			pathStr += " (manual install)"
		}
	}
	pathField := lipgloss.NewStyle().Foreground(ColorTextMuted).Render(pathStr)

	return "  " + nameField + reqField + statusCell + pathField
}

// formatStatusCell renders the colored INSTALLED / MISSING / MODIFIED (or
// FOUND / NOT FOUND for detection-only tools) badge then pads to width on
// the visible-character axis (lipgloss escapes would otherwise throw off
// fmt %-*s).
//
// MODIFIED takes priority over INSTALLED — the binary is on disk but its
// SHA256 has drifted from what we recorded at download time. That's a
// tampering signal worth surfacing prominently.
func formatStatusCell(s tools.ToolStatus, width int, detectOnly bool) string {
	var label string
	var style lipgloss.Style
	switch {
	case detectOnly && s.Installed:
		label = "FOUND"
		style = SuccessStyle
	case detectOnly:
		label = "NOT FOUND"
		style = WarningStyle
	case s.Installed && s.Modified:
		label = "MODIFIED"
		style = ErrorStyle
	case s.Installed:
		label = "INSTALLED"
		style = SuccessStyle
	case s.Required:
		label = "MISSING"
		style = ErrorStyle
	default:
		label = "MISSING"
		style = WarningStyle
	}
	pad := width - len(label)
	if pad < 1 {
		pad = 1
	}
	return style.Render(label) + strings.Repeat(" ", pad)
}

// toolCategoryBreakdown builds the "3/6 collection │ 1/3 analysis │ ..." string.
func (m Model) toolCategoryBreakdown() string {
	if m.ctx.ToolManager == nil {
		return lipgloss.NewStyle().Foreground(ColorTextMuted).Render("unknown")
	}

	counts := m.ctx.ToolManager.CountByCategory()
	sep := lipgloss.NewStyle().Foreground(ColorBorder).Render("  \u2502  ")

	var parts []string
	for _, cat := range tools.CategoryOrder {
		c, ok := counts[cat]
		if !ok {
			continue
		}
		fg := ColorWarning
		if c[0] == c[1] {
			fg = ColorSuccess
		}
		num := lipgloss.NewStyle().Foreground(fg).Render(fmt.Sprintf("%d/%d", c[0], c[1]))
		label := lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(" " + cat)
		parts = append(parts, num+label)
	}

	return strings.Join(parts, sep)
}

// huntingToolStatus returns a summary of detection tool availability.
func (m Model) huntingToolStatus() string {
	if m.ctx.ToolManager == nil {
		return ""
	}

	type toolCheck struct {
		label string
		id    string
	}

	checks := []toolCheck{
		{"Hayabusa", m.huntingHayabusaToolID()},
		{"Chainsaw", m.huntingChainsawToolID()},
		{"Loki", m.huntingLokiToolID()},
	}

	var parts []string
	for _, c := range checks {
		t := m.ctx.ToolManager.GetTool(c.id)
		if t != nil && t.Installed {
			parts = append(parts, c.label+": OK")
		} else {
			parts = append(parts, c.label+": MISSING")
		}
	}

	return "Tools: " + strings.Join(parts, " | ")
}

// countMissingRequired returns how many required, downloadable tools are not installed.
func (m Model) countMissingRequired() int {
	if m.ctx.ToolManager == nil {
		return 0
	}
	count := 0
	statuses := m.ctx.ToolManager.GetStatus()
	for _, s := range statuses {
		if s.Required && !s.Installed {
			t := m.ctx.ToolManager.GetTool(s.ID)
			if t != nil && t.GitHubRepo != "" {
				count++
			}
		}
	}
	return count
}

// countMissingDownloadable returns how many downloadable tools are not installed.
func (m Model) countMissingDownloadable() int {
	if m.ctx.ToolManager == nil {
		return 0
	}
	count := 0
	statuses := m.ctx.ToolManager.GetStatus()
	for _, s := range statuses {
		if !s.Installed {
			t := m.ctx.ToolManager.GetTool(s.ID)
			if t != nil && t.GitHubRepo != "" {
				count++
			}
		}
	}
	return count
}

// asyncDownloadRequired wraps runDownloadRequired in a tea.Cmd so it runs
// in a goroutine and doesn't block the TUI event loop.
func (m Model) asyncDownloadRequired() tea.Cmd {
	tm := m.ctx.ToolManager
	return func() tea.Msg {
		lines := runDownloadRequiredSync(tm)
		return downloadResultMsg{lines: lines}
	}
}

// asyncDownloadAll wraps runDownloadAll in a tea.Cmd goroutine.
func (m Model) asyncDownloadAll() tea.Cmd {
	tm := m.ctx.ToolManager
	return func() tea.Msg {
		lines := runDownloadAllSync(tm)
		return downloadResultMsg{lines: lines}
	}
}

// asyncUpdateCheck wraps buildUpdateCheckResults in a tea.Cmd goroutine.
func (m Model) asyncUpdateCheck() tea.Cmd {
	tm := m.ctx.ToolManager
	return func() tea.Msg {
		lines := buildUpdateCheckResultsSync(tm)
		return updateCheckResultMsg{lines: lines}
	}
}

// runDownloadRequiredSync executes the download of all missing required tools.
// Safe to call from a goroutine — only touches the ToolManager.
func runDownloadRequiredSync(tm *tools.ToolManager) []string {
	if tm == nil {
		return []string{"  " + ErrorStyle.Render("Tool manager not initialized")}
	}

	var lines []string

	statuses := tm.GetStatus()
	for _, s := range statuses {
		if !s.Required || s.Installed {
			continue
		}
		t := tm.GetTool(s.ID)
		if t == nil {
			continue
		}
		if t.GitHubRepo == "" {
			lines = append(lines,
				"  "+lipgloss.NewStyle().Foreground(ColorText).Render(s.Name)+
					"  "+WarningStyle.Render("Manual install required"))
			continue
		}

		lines = append(lines, downloadProgressLine(s.Name))

		if err := tm.DownloadTool(s.ID); err != nil {
			lines = append(lines,
				"  "+ErrorStyle.Render(fmt.Sprintf("  FAILED: %v", err)))
		} else {
			lines = append(lines,
				"  "+SuccessStyle.Render("  done"))
		}
		lines = append(lines, downloadPostHints(s.ID)...)
	}

	// Re-scan after downloads.
	tm.ScanInstalled()

	if len(lines) == 0 {
		lines = append(lines, "  "+SuccessStyle.Render("All required tools are installed."))
	}

	// Append updated status table.
	lines = append(lines, "")
	lines = append(lines, cSectionLabel("Updated Status"))
	lines = append(lines, buildToolStatusTableStatic(tm)...)

	return lines
}

// downloadProgressLine returns the "Downloading <name>..." line shown before
// each tool's install attempt. Volatility3 gets a friendlier framework-level
// label since it's a Python package, not a single binary.
func downloadProgressLine(name string) string {
	if strings.HasPrefix(name, "Volatility3") {
		return "  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Downloading Volatility3 framework...")
	}
	return "  " + lipgloss.NewStyle().Foreground(ColorText).Render(
		fmt.Sprintf("Downloading %s...", name))
}

// downloadPostHints returns optional hint lines appended after a successful
// download. Volatility3 reminds the user that Python 3 is needed at run time.
func downloadPostHints(toolID string) []string {
	if strings.HasPrefix(toolID, "volatility3-") {
		return []string{
			"    " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
				"Note: Python 3 is also required. VanGuard will check for it"),
			"    " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
				"when you run a memory analysis."),
		}
	}
	return nil
}

// runDownloadAllSync executes the download of all missing downloadable tools.
// Safe to call from a goroutine — only touches the ToolManager.
func runDownloadAllSync(tm *tools.ToolManager) []string {
	if tm == nil {
		return []string{"  " + ErrorStyle.Render("Tool manager not initialized")}
	}

	var lines []string

	statuses := tm.GetStatus()
	for _, s := range statuses {
		if s.Installed {
			continue
		}
		t := tm.GetTool(s.ID)
		if t == nil {
			continue
		}
		if t.GitHubRepo == "" {
			lines = append(lines,
				"  "+lipgloss.NewStyle().Foreground(ColorText).Render(s.Name)+
					"  "+WarningStyle.Render("Manual install required"))
			continue
		}

		lines = append(lines, downloadProgressLine(s.Name))

		if err := tm.DownloadTool(s.ID); err != nil {
			lines = append(lines,
				"  "+ErrorStyle.Render(fmt.Sprintf("  FAILED: %v", err)))
		} else {
			lines = append(lines,
				"  "+SuccessStyle.Render("  done"))
		}
		lines = append(lines, downloadPostHints(s.ID)...)
	}

	// Re-scan after downloads.
	tm.ScanInstalled()

	if len(lines) == 0 {
		lines = append(lines, "  "+SuccessStyle.Render("All downloadable tools are installed."))
	}

	lines = append(lines, "")
	lines = append(lines, cSectionLabel("Updated Status"))
	lines = append(lines, buildToolStatusTableStatic(tm)...)

	return lines
}

// buildUpdateCheckResultsSync queries GitHub for the latest versions and formats results.
// Safe to call from a goroutine — only touches the ToolManager.
func buildUpdateCheckResultsSync(tm *tools.ToolManager) []string {
	if tm == nil {
		return []string{"  " + ErrorStyle.Render("Tool manager not initialized")}
	}

	updates, err := tm.CheckForUpdates()
	if err != nil {
		return []string{"  " + ErrorStyle.Render(fmt.Sprintf("Error checking updates: %v", err))}
	}

	if len(updates) == 0 {
		return []string{
			"",
			"  " + SuccessStyle.Render("All tools are up to date."),
		}
	}

	hdr := fmt.Sprintf("  %-20s %-18s %-18s %s", "Tool", "Current", "Available", "Asset")
	sep := "  " + strings.Repeat("\u2500", 70)
	lines := []string{
		"",
		TableHeaderStyle.Render(hdr),
		lipgloss.NewStyle().Foreground(ColorBorder).Render(sep),
	}

	for _, u := range updates {
		current := u.CurrentVersion
		if current == "" {
			current = "not installed"
		}
		nameField := lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%-20s", u.Name))
		curField := lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(fmt.Sprintf("%-18s", current))
		newField := lipgloss.NewStyle().Foreground(ColorSuccess).Render(fmt.Sprintf("%-18s", u.LatestVersion))
		sizeField := lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			fmt.Sprintf("%s (%.1f MB)", u.AssetName, float64(u.AssetSize)/(1024*1024)))
		lines = append(lines, "  "+nameField+curField+newField+sizeField)
	}

	return lines
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

// Run initialises the bubbletea program and runs the TUI.
func Run(ctx *AppContext) error {
	// Suppress stderr logging while bubbletea owns the terminal.
	if ctx.Logger != nil {
		ctx.Logger.SetFileOnly(true)
		defer ctx.Logger.SetFileOnly(false)
	}

	m := newModel(ctx)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("running TUI: %w", err)
	}
	return nil
}
