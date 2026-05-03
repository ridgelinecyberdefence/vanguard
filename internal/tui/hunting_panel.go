package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/hunting"
)

// ---------------------------------------------------------------------------
// Hunting panel states
// ---------------------------------------------------------------------------

type huntingView int

const (
	huntingViewNone huntingView = iota
	huntingViewNeedCase
	huntingViewNeedTool     // tool not installed
	huntingViewSourceSelect // select scan target (live / collected / path)
	huntingViewRunning
	huntingViewDone
)

// HuntingState holds all state for the Threat Hunting & Scanning submenu.
type HuntingState struct {
	view huntingView

	// Current operation.
	operationName string
	operationAction string

	// Source selection for tool-based scans.
	sourceOptions []string
	sourceCursor  int

	// Progress tracking.
	scanName  string
	startTime time.Time
	elapsed   time.Duration

	// Result.
	result    *hunting.ScanResult
	errorMsg  string

	// Result lines for display.
	resultLines []string
}

// ---------------------------------------------------------------------------
// Custom tea.Msg types
// ---------------------------------------------------------------------------

type huntingTickMsg time.Time

type huntingScanDoneMsg struct {
	result hunting.ScanResult
}

// ---------------------------------------------------------------------------
// Tick command
// ---------------------------------------------------------------------------

func huntingTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return huntingTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Hunting action handlers — called from activateContentItem
// ---------------------------------------------------------------------------

func (m Model) handleHuntingAction(action string) (Model, tea.Cmd, bool) {
	// Match the action prefix BEFORE mutating panel state — the dispatcher
	// chains handlers and a stray clearPanelState would wipe out other panels.
	if !strings.HasPrefix(action, "hunt_") {
		return m, nil, false
	}

	m.clearPanelState()

	// Tool-based scans need source selection.
	switch action {
	case "hunt_haya_full", "hunt_haya_crit", "hunt_haya_lateral", "hunt_haya_persist":
		return m.huntingToolScan(action, "Hayabusa", m.huntingHayabusaToolID())

	case "hunt_chainsaw":
		return m.huntingToolScan(action, "Chainsaw", m.huntingChainsawToolID())

	case "hunt_loki":
		return m.huntingToolScan(action, "Loki", m.huntingLokiToolID())

	case "hunt_yara":
		return m.huntingToolScan(action, "YARA", "yara-rules")

	case "hunt_sigma":
		return m.huntingToolScan(action, "Sigma", m.huntingChainsawToolID())

	// Live hunting operations.
	case "hunt_live_proc":
		return m.huntingLiveStart(action, "Suspicious Processes")
	case "hunt_live_net":
		return m.huntingLiveStart(action, "Network Anomalies")
	case "hunt_live_schtask":
		return m.huntingLiveStart(action, "Scheduled Task Audit")
	case "hunt_live_autoruns":
		return m.huntingLiveStart(action, "Autoruns & Startup Audit")
	case "hunt_live_services":
		return m.huntingLiveStart(action, "Service Anomaly Detection")
	case "hunt_live_cron":
		return m.huntingLiveStart(action, "Cron Job Audit")
	case "hunt_live_systemd":
		return m.huntingLiveStart(action, "Systemd Service Audit")
	case "hunt_live_suid":
		return m.huntingLiveStart(action, "SUID/SGID File Audit")
	case "hunt_live_ports":
		return m.huntingLiveStart(action, "Open Port Audit")
	case "hunt_live_kmod":
		return m.huntingLiveStart(action, "Kernel Module Audit")
	case "hunt_live_logins":
		return m.huntingLiveStart(action, "User Login Anomalies")
	case "hunt_live_hidden":
		return m.huntingLiveStart(action, "Hidden Files & Directories")
	case "hunt_live_immutable":
		return m.huntingLiveStart(action, "Immutable File Detection")
	}

	return m, nil, false
}

// ---------------------------------------------------------------------------
// Tool ID helpers
// ---------------------------------------------------------------------------

func (m Model) huntingHayabusaToolID() string {
	if m.ctx.Platform == "windows" {
		return "hayabusa-win"
	}
	return "hayabusa-lnx"
}

func (m Model) huntingChainsawToolID() string {
	if m.ctx.Platform == "windows" {
		return "chainsaw-win"
	}
	return "chainsaw-lnx"
}

func (m Model) huntingLokiToolID() string {
	if m.ctx.Platform == "windows" {
		return "loki-win"
	}
	return "loki-lnx"
}

// ---------------------------------------------------------------------------
// Tool-based scan setup (source selection)
// ---------------------------------------------------------------------------

func (m Model) huntingToolScan(action, toolName, toolID string) (Model, tea.Cmd, bool) {
	if !m.huntingCheckCase() {
		m.huntingState.view = huntingViewNeedCase
		m.state = stateResult
		return m, nil, true
	}

	// Check tool availability.
	scanner := hunting.NewScanner(m.ctx.RootDir, m.ctx.ActiveCase.ID, m.ctx.Platform,
		m.ctx.Elevated, m.ctx.Logger, m.ctx.ToolManager)
	if !scanner.ToolAvailable(toolID) {
		m.huntingState = HuntingState{
			view:     huntingViewNeedTool,
			errorMsg: fmt.Sprintf("%s is not installed. Install it via Configuration > Tool Management.", toolName),
		}
		m.state = stateResult
		return m, nil, true
	}

	// Show source selection.
	m.huntingState = HuntingState{
		view:            huntingViewSourceSelect,
		operationName:   toolName,
		operationAction: action,
		sourceCursor:    0,
	}

	// Build source options.
	m.huntingState.sourceOptions = []string{
		"Live System (current host)",
	}

	// Check if collected triage data exists.
	triageDir := filepath.Join(m.ctx.RootDir, "output", m.ctx.ActiveCase.ID, "triage")
	if _, err := os.Stat(triageDir); err == nil {
		m.huntingState.sourceOptions = append(m.huntingState.sourceOptions,
			"Collected Artifacts (triage output)")
	}

	m.state = stateResult
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Live hunting start
// ---------------------------------------------------------------------------

func (m Model) huntingLiveStart(action, name string) (Model, tea.Cmd, bool) {
	if !m.huntingCheckCase() {
		m.huntingState.view = huntingViewNeedCase
		m.state = stateResult
		return m, nil, true
	}

	m.huntingState = HuntingState{
		view:            huntingViewRunning,
		operationAction: action,
		scanName:        name,
		startTime:       time.Now(),
	}
	m.state = stateResult

	actionCopy := action
	return m, tea.Batch(
		huntingTickCmd(),
		func() tea.Msg {
			result := m.runLiveHunt(actionCopy)
			return huntingScanDoneMsg{result: result}
		},
	), true
}

// ---------------------------------------------------------------------------
// Execute tool-based scan
// ---------------------------------------------------------------------------

func (m Model) huntingStartToolScan(action, targetDir string) (Model, tea.Cmd) {
	scanner := hunting.NewScanner(m.ctx.RootDir, m.ctx.ActiveCase.ID, m.ctx.Platform,
		m.ctx.Elevated, m.ctx.Logger, m.ctx.ToolManager)

	ts := time.Now().Format("20060102_150405")
	outDir := scanner.OutputDir(ts)

	m.huntingState.view = huntingViewRunning
	m.huntingState.startTime = time.Now()

	// Determine scan name from action.
	switch action {
	case "hunt_haya_full":
		m.huntingState.scanName = "Hayabusa — Full Scan"
	case "hunt_haya_crit":
		m.huntingState.scanName = "Hayabusa — Critical Only"
	case "hunt_haya_lateral":
		m.huntingState.scanName = "Hayabusa — Lateral Movement"
	case "hunt_haya_persist":
		m.huntingState.scanName = "Hayabusa — Persistence"
	case "hunt_chainsaw":
		m.huntingState.scanName = "Chainsaw Hunt"
	case "hunt_loki":
		m.huntingState.scanName = "Loki IOC Scan"
	case "hunt_yara":
		m.huntingState.scanName = "YARA Scan"
	case "hunt_sigma":
		m.huntingState.scanName = "Sigma Detection"
	}

	actionCopy := action
	targetDirCopy := targetDir
	rootDir := m.ctx.RootDir
	caseID := m.ctx.ActiveCase.ID
	platform := m.ctx.Platform
	elevated := m.ctx.Elevated

	return m, tea.Batch(
		huntingTickCmd(),
		func() tea.Msg {
			s := hunting.NewScanner(rootDir, caseID, platform, elevated, nil, nil)
			// Re-create scanner with tool manager in the goroutine scope.
			_ = s
			var result hunting.ScanResult

			// TUI doesn't (yet) wire into the web task manager, so each
			// scan runs against context.Background(). Internally the
			// scanner derives its per-scan WithTimeout from this parent.
			scanCtx := context.Background()
			switch actionCopy {
			case "hunt_haya_full":
				result = scanner.RunHayabusa(scanCtx, "full", targetDirCopy, outDir)
			case "hunt_haya_crit":
				result = scanner.RunHayabusa(scanCtx, "critical", targetDirCopy, outDir)
			case "hunt_haya_lateral":
				result = scanner.RunHayabusa(scanCtx, "lateral", targetDirCopy, outDir)
			case "hunt_haya_persist":
				result = scanner.RunHayabusa(scanCtx, "persist", targetDirCopy, outDir)
			case "hunt_chainsaw":
				result = scanner.RunChainsaw(scanCtx, targetDirCopy, outDir)
			case "hunt_loki":
				result = scanner.RunLoki(scanCtx, targetDirCopy, outDir)
			case "hunt_yara":
				result = scanner.RunYARA(scanCtx, "all", targetDirCopy, outDir)
			case "hunt_sigma":
				result = scanner.RunSigma(scanCtx, targetDirCopy, outDir)
			default:
				result = hunting.ScanResult{
					Name:   actionCopy,
					Status: hunting.ScanFailed,
					Warnings: []string{"Unknown scan action"},
				}
			}

			return huntingScanDoneMsg{result: result}
		},
	)
}

// ---------------------------------------------------------------------------
// Execute live hunting
// ---------------------------------------------------------------------------

func (m Model) runLiveHunt(action string) hunting.ScanResult {
	ts := time.Now().Format("20060102_150405")
	outDir := filepath.Join(m.ctx.RootDir, "output", m.ctx.ActiveCase.ID, "threat_hunting", ts, "live")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch action {
	// Windows live hunting.
	case "hunt_live_proc":
		if m.ctx.Platform == "windows" {
			return hunting.WinSuspiciousProcesses(ctx, filepath.Join(outDir, "suspicious_processes"), m.ctx.Logger)
		}
		return hunting.LnxSuspiciousProcesses(ctx, filepath.Join(outDir, "suspicious_processes"), m.ctx.Logger)

	case "hunt_live_net":
		if m.ctx.Platform == "windows" {
			return hunting.WinNetworkAnomalies(ctx, filepath.Join(outDir, "network_anomalies"), m.ctx.Logger)
		}
		return hunting.LnxNetworkAnomalies(ctx, filepath.Join(outDir, "network_anomalies"), m.ctx.Logger)

	case "hunt_live_schtask":
		return hunting.WinScheduledTasks(ctx, filepath.Join(outDir, "scheduled_tasks"), m.ctx.Logger)

	case "hunt_live_autoruns":
		return hunting.WinAutorunsAudit(ctx, filepath.Join(outDir, "autoruns"), m.ctx.Logger)

	case "hunt_live_services":
		return hunting.WinServiceAnomalies(ctx, filepath.Join(outDir, "service_anomalies"), m.ctx.Logger)

	// Linux live hunting.
	case "hunt_live_cron":
		return hunting.LnxCronAudit(ctx, filepath.Join(outDir, "cron_audit"), m.ctx.Logger)

	case "hunt_live_systemd":
		return hunting.LnxSystemdAudit(ctx, filepath.Join(outDir, "systemd_audit"), m.ctx.Logger)

	case "hunt_live_suid":
		return hunting.LnxSUIDSGIDAudit(ctx, filepath.Join(outDir, "suid_sgid"), m.ctx.Logger)

	case "hunt_live_ports":
		return hunting.LnxOpenPortAudit(ctx, filepath.Join(outDir, "open_ports"), m.ctx.Logger)

	case "hunt_live_kmod":
		return hunting.LnxKernelModuleAudit(ctx, filepath.Join(outDir, "kernel_modules"), m.ctx.Logger)

	case "hunt_live_logins":
		return hunting.LnxLoginAnomalies(ctx, filepath.Join(outDir, "login_anomalies"), m.ctx.Logger)

	case "hunt_live_hidden":
		return hunting.LnxHiddenFiles(ctx, filepath.Join(outDir, "hidden_files"), m.ctx.Logger)

	case "hunt_live_immutable":
		return hunting.LnxImmutableFiles(ctx, filepath.Join(outDir, "immutable_files"), m.ctx.Logger)
	}

	return hunting.ScanResult{
		Name:     action,
		Status:   hunting.ScanFailed,
		Warnings: []string{"Unknown hunt action"},
	}
}

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

func (m Model) huntingCheckCase() bool {
	return m.ctx.ActiveCase != nil
}

// ---------------------------------------------------------------------------
// Hunting panel Update
// ---------------------------------------------------------------------------

func (m Model) huntingUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.huntingState.view == huntingViewNone {
		return m, nil, false
	}

	key := msg.String()

	switch m.huntingState.view {
	case huntingViewNeedCase:
		switch key {
		case "y", "Y":
			m.huntingState.view = huntingViewNone
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.huntingState.view = huntingViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case huntingViewNeedTool:
		// Any key dismisses.
		m.huntingState.view = huntingViewNone
		m.state = stateSubMenu
		return m, nil, true

	case huntingViewSourceSelect:
		return m.huntingUpdateSourceSelect(key)

	case huntingViewRunning:
		// Block all input during scan.
		return m, nil, true

	case huntingViewDone:
		// Any key dismisses.
		m.huntingState.view = huntingViewNone
		m.state = stateSubMenu
		return m, nil, true
	}

	return m, nil, false
}

func (m Model) huntingUpdateSourceSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.huntingState.view = huntingViewNone
		m.state = stateSubMenu
		return m, nil, true

	case "up", "k":
		if m.huntingState.sourceCursor > 0 {
			m.huntingState.sourceCursor--
		}
		return m, nil, true

	case "down", "j":
		if m.huntingState.sourceCursor < len(m.huntingState.sourceOptions)-1 {
			m.huntingState.sourceCursor++
		}
		return m, nil, true

	case "enter":
		var targetDir string
		switch m.huntingState.sourceCursor {
		case 0:
			// Live system — use default log paths.
			if m.ctx.Platform == "windows" {
				targetDir = `C:\Windows\System32\winevt\Logs`
			} else {
				targetDir = "/var/log"
			}
		case 1:
			// Collected artifacts.
			targetDir = filepath.Join(m.ctx.RootDir, "output", m.ctx.ActiveCase.ID, "triage")
		}

		m2, cmd := m.huntingStartToolScan(m.huntingState.operationAction, targetDir)
		return m2, cmd, true
	}

	return m, nil, true
}

// ---------------------------------------------------------------------------
// Hunting panel View rendering
// ---------------------------------------------------------------------------

func (m Model) huntingContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Threat Hunting & Scanning"),
		"",
	}

	switch m.huntingState.view {
	case huntingViewNeedCase:
		lines = append(lines, m.huntingViewNeedCase(width)...)
	case huntingViewNeedTool:
		lines = append(lines, m.huntingViewNeedTool(width)...)
	case huntingViewSourceSelect:
		lines = append(lines, m.huntingViewSourceSelect(width)...)
	case huntingViewRunning:
		lines = append(lines, m.huntingViewRunning(width)...)
	case huntingViewDone:
		lines = append(lines, m.huntingViewDone(width)...)
	}

	return lines
}

func (m Model) huntingViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Threat Hunting"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
		"",
		cHint("A case is required to organize hunting output."),
	}
}

func (m Model) huntingViewNeedTool(width int) []string {
	return []string{
		cSectionLabel("Threat Hunting"), cRule(width),
		"",
		"  " + ErrorStyle.Render("Tool not available"),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(m.huntingState.errorMsg),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) huntingViewSourceSelect(width int) []string {
	lines := []string{
		cSectionLabel(m.huntingState.operationName + " — Select Scan Target"), cRule(width),
		"",
	}

	for i, opt := range m.huntingState.sourceOptions {
		selected := i == m.huntingState.sourceCursor

		if selected {
			cursor := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> ")
			optStr := lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render(opt)
			lines = append(lines, "  "+cursor+optStr)
		} else {
			optStr := lipgloss.NewStyle().Foreground(ColorText).Render(opt)
			lines = append(lines, "    "+optStr)
		}
	}

	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  Esc: cancel"))

	return lines
}

func (m Model) huntingViewRunning(width int) []string {
	lines := []string{
		cSectionLabel(m.huntingState.scanName), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running scan..."),
		"",
		cField("Started", lipgloss.NewStyle().Foreground(ColorText).Render(
			m.huntingState.startTime.Format("2006-01-02 15:04:05"))),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			fmt.Sprintf("Elapsed: %s", formatElapsed(m.huntingState.elapsed))),
		"",
	}

	if !m.ctx.Elevated {
		lines = append(lines,
			"  "+WarningStyle.Render("WARNING: Running without elevation. Some scans may fail."))
	}

	return lines
}

func (m Model) huntingViewDone(width int) []string {
	lines := []string{
		cSectionLabel("Scan Complete"), cRule(width),
		"",
	}

	if m.huntingState.result != nil {
		r := m.huntingState.result

		// Status line.
		var statusStr string
		switch r.Status {
		case hunting.ScanSuccess:
			statusStr = SuccessStyle.Render("Completed — no issues found")
		case hunting.ScanPartial:
			statusStr = WarningStyle.Render("Completed — findings detected")
		case hunting.ScanFailed:
			statusStr = ErrorStyle.Render("Failed")
		default:
			statusStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Status.String())
		}

		lines = append(lines,
			cField("Scan", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.Name)),
			cField("Status", statusStr),
			cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
				fmt.Sprintf("%d sec", int(r.Duration.Seconds())))),
		)

		if r.Output != "" {
			lines = append(lines, cField("Output", renderOutputPath(r.Output, width)))
		}

		if r.Lines > 0 {
			lines = append(lines, cField("Detections", lipgloss.NewStyle().Foreground(ColorWarning).Render(
				fmt.Sprintf("%d", r.Lines))))
		}

		// Findings.
		if len(r.Findings) > 0 {
			lines = append(lines, "")
			lines = append(lines, cSectionLabel("Findings"))
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 50)))

			for _, f := range r.Findings {
				var sevStyle lipgloss.Style
				switch f.Severity {
				case "critical":
					sevStyle = lipgloss.NewStyle().Foreground(ColorCritical).Bold(true)
				case "high":
					sevStyle = lipgloss.NewStyle().Foreground(ColorError)
				case "medium":
					sevStyle = lipgloss.NewStyle().Foreground(ColorWarning)
				case "low":
					sevStyle = lipgloss.NewStyle().Foreground(ColorTextSecondary)
				default:
					sevStyle = lipgloss.NewStyle().Foreground(ColorTextMuted)
				}

				sevLabel := sevStyle.Render(fmt.Sprintf("[%s]", strings.ToUpper(f.Severity)))
				titleStr := lipgloss.NewStyle().Foreground(ColorText).Render(f.Title)
				lines = append(lines, fmt.Sprintf("  %s %s", sevLabel, titleStr))

				if f.MITRE != "" {
					lines = append(lines,
						"    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render("MITRE: "+f.MITRE))
				}
			}
		}

		// Warnings.
		if len(r.Warnings) > 0 {
			lines = append(lines, "")
			for _, w := range r.Warnings {
				lines = append(lines, "  "+WarningStyle.Render("⚠ "+w))
			}
		}
	} else if m.huntingState.errorMsg != "" {
		lines = append(lines, "  "+ErrorStyle.Render(m.huntingState.errorMsg))
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}
