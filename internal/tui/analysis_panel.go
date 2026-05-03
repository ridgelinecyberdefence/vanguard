package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/analysis"
	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/disk"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type analysisView int

const (
	analysisViewNone analysisView = iota
	analysisViewNeedCase
	analysisViewNeedTool
	analysisViewError
	analysisViewMessage

	analysisViewSourceSelect
	analysisViewRunning

	analysisViewSummary       // generic "summary lines" result view
	analysisViewReportDone    // report-generated message
	analysisViewExportDone    // CSV / TXT export message
)

// AnalysisState carries everything the analysis panel renders or mutates.
type AnalysisState struct {
	view analysisView

	// Active dispatch context.
	action       string // current sidebar action
	operation    string // human label for the running op
	startTime    time.Time
	elapsed      time.Duration
	errorMsg     string
	resultLines  []string
	outputPath   string
	findingsAdded int

	// Source picker state.
	sources       []analysis.DataSource
	sourceCursor  int
	pendingAction string // action to run once a source is picked
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type analysisTickMsg time.Time

type analysisRunDoneMsg struct {
	lines        []string
	outputPath   string
	findingsAdded int
	err          string
}

func analysisTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return analysisTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (m Model) analysisCheckCase() bool { return m.ctx.ActiveCase != nil }

func (m *Model) analysisRequireCase() bool {
	if m.analysisCheckCase() {
		return true
	}
	m.analysisState.view = analysisViewNeedCase
	m.state = stateResult
	return false
}

func (m Model) analysisCaseID() string {
	if m.ctx.ActiveCase == nil {
		return ""
	}
	return m.ctx.ActiveCase.ID
}

// ---------------------------------------------------------------------------
// Action dispatcher
// ---------------------------------------------------------------------------

func (m Model) handleAnalysisAction(action string) (Model, tea.Cmd, bool) {
	if !strings.HasPrefix(action, "an_") {
		return m, nil, false
	}

	m.clearPanelState()
	m.analysisState = AnalysisState{action: action}

	if !m.analysisRequireCase() {
		return m, nil, true
	}

	switch action {

	// ── Memory analysis: route to the existing memory panel so we don't
	// duplicate the Volatility plumbing.
	case "an_memory":
		m.analysisState = AnalysisState{}
		mm, cmd, _ := m.handleMemoryAction("mem_vol_profile")
		return mm, cmd, true

	// ── Event log analysis (no source selector — operates on the most
	// recent ParsedEventLogs.csv it can find).
	case "an_evtx_summary":
		return m.analysisStartEventLog(action, "Event Log Summary",
			analysis.FormatEventLogSummary, runEventLogSummary)
	case "an_evtx_logon":
		return m.analysisStartEventLogWithFindings(action, "Logon Analysis (4624/4625/4648)",
			runLogonAnalysis)
	case "an_evtx_proc":
		return m.analysisStartEventLogWithFindings(action, "Process Execution Analysis (4688)",
			runProcessAnalysis)
	case "an_evtx_service":
		return m.analysisStartEventLogWithFindings(action, "Service Installation Analysis (7045)",
			runServiceAnalysis)

	// ── Linux log analysis (also no source selector — uses the latest
	// disk-collection logs subdirectory).
	case "an_lnx_auth":
		return m.analysisStartLinuxAuth()
	case "an_lnx_syslog":
		return m.analysisStartLinuxSyslog()
	case "an_lnx_web":
		return m.analysisStartLinuxWeb()
	case "an_lnx_journal":
		return m.analysisStartLinuxJournal()

	// ── EZ Tools parser delegation — share the disk package's runners.
	case "an_evtx_parse":
		return m.analysisStartEZ(action, "EvtxECmd")
	case "an_mft":
		return m.analysisStartEZ(action, "MFTECmd")
	case "an_prefetch":
		return m.analysisStartEZ(action, "PECmd")
	case "an_amcache":
		return m.analysisStartEZ(action, "AmcacheParser")
	case "an_shimcache":
		return m.analysisStartEZ(action, "AppCompatCacheParser")
	case "an_jumplist":
		return m.analysisStartEZ(action, "JLECmd")
	case "an_lnk":
		return m.analysisStartEZ(action, "LECmd")
	case "an_srum":
		return m.analysisStartEZ(action, "SrumECmd")
	case "an_recyclebin":
		return m.analysisStartEZ(action, "RBCmd")
	case "an_registry":
		return m.analysisStartEZ(action, "RECmd")

	// ── Timeline + correlation + MITRE.
	case "an_super_timeline":
		return m.analysisStartSuperTimeline()
	case "an_correlate":
		return m.analysisStartCorrelate()
	case "an_mitre":
		return m.analysisStartMITRE()

	// ── Reporting & exports.
	case "an_report_html":
		return m.analysisStartReportHTML()
	case "an_report_exec":
		return m.analysisStartExecSummary()
	case "an_export_findings":
		return m.analysisStartExportFindings()
	case "an_export_timeline":
		return m.analysisStartExportTimeline()
	case "an_export_iocs":
		return m.analysisStartExportIOCs()

	// ── Linux items not implemented yet — show clean "coming soon" panel.
	case "an_lnx_log_timeline", "an_lnx_file_timeline", "an_lnx_recent",
		"an_lnx_suspicious", "an_lnx_shell", "an_lnx_ssh", "an_lnx_users",
		"an_registry_timeline":
		return m.analysisShowMessage("Coming Soon", []string{
			"This Analysis & Reporting item is not yet implemented.",
			"",
			"Available now:",
			"  • Event log analysis (Windows: [1]–[5])",
			"  • Log analysis (Linux: [1]–[4])",
			"  • EZ Tools parsing ([6]–[D] / [6]–[8])",
			"  • Super timeline, correlation, MITRE mapping",
			"  • HTML report, executive summary, CSV/TXT/STIX exports",
		})
	}

	return m, nil, false
}

// ---------------------------------------------------------------------------
// Tick + key dispatch
// ---------------------------------------------------------------------------

func (m Model) handleAnalysisTick() (Model, tea.Cmd) {
	if m.analysisState.view == analysisViewRunning {
		m.analysisState.elapsed = time.Since(m.analysisState.startTime)
		return m, analysisTickCmd()
	}
	return m, nil
}

func (m Model) handleAnalysisRunDone(msg analysisRunDoneMsg) (Model, tea.Cmd) {
	if msg.err != "" {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = msg.err
		return m, nil
	}
	m.analysisState.view = analysisViewSummary
	m.analysisState.resultLines = msg.lines
	m.analysisState.outputPath = msg.outputPath
	m.analysisState.findingsAdded = msg.findingsAdded
	return m, nil
}

func (m Model) analysisUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.analysisState.view == analysisViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.analysisState.view {
	case analysisViewNeedCase:
		switch key {
		case "y", "Y":
			m.analysisState.view = analysisViewNone
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.analysisState.view = analysisViewNone
			m.state = stateSubMenu
			return m, nil, true
		}
	case analysisViewError, analysisViewMessage, analysisViewNeedTool,
		analysisViewSummary, analysisViewReportDone, analysisViewExportDone:
		m.analysisState.view = analysisViewNone
		m.state = stateSubMenu
		return m, nil, true

	case analysisViewRunning:
		return m, nil, true // block

	case analysisViewSourceSelect:
		return m.analysisHandleSourceSelect(key)
	}
	return m, nil, false
}

func (m Model) analysisHandleSourceSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.analysisState.view = analysisViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.analysisState.sourceCursor > 0 {
			m.analysisState.sourceCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.analysisState.sourceCursor < len(m.analysisState.sources)-1 {
			m.analysisState.sourceCursor++
		}
		return m, nil, true
	case "enter":
		if len(m.analysisState.sources) == 0 {
			m.analysisState.view = analysisViewError
			m.analysisState.errorMsg = "No data sources available — run a collection first."
			return m, nil, true
		}
		src := m.analysisState.sources[m.analysisState.sourceCursor]
		mm, cmd := m.analysisRunEZ(m.analysisState.pendingAction, src.Path)
		return mm, cmd, true
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx >= 0 && idx < len(m.analysisState.sources) {
			m.analysisState.sourceCursor = idx
			src := m.analysisState.sources[idx]
			mm, cmd := m.analysisRunEZ(m.analysisState.pendingAction, src.Path)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Convenience: simple "show a message and dismiss" helper.
// ---------------------------------------------------------------------------

func (m Model) analysisShowMessage(title string, lines []string) (Model, tea.Cmd, bool) {
	m.analysisState.view = analysisViewMessage
	m.analysisState.operation = title
	m.analysisState.resultLines = lines
	m.state = stateResult
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Event-log analyses (use most-recent ParsedEventLogs.csv)
// ---------------------------------------------------------------------------

// runFn is a generic runner that consumes a CSV path and returns lines + error.
type runFn func(csvPath string) ([]string, error)

func runEventLogSummary(csvPath string) ([]string, error) {
	s, err := analysis.EventLogStats(csvPath)
	if err != nil {
		return nil, err
	}
	return analysis.FormatEventLogSummary(s), nil
}

// runWithFindingsFn additionally returns analysis.Finding entries for the case DB.
type runWithFindingsFn func(csvPath string) ([]string, []analysis.Finding, error)

func runLogonAnalysis(csvPath string) ([]string, []analysis.Finding, error) {
	r, err := analysis.AnalyzeLogons(csvPath)
	if err != nil {
		return nil, nil, err
	}
	return analysis.FormatLogonAnalysis(r), r.Findings, nil
}

func runProcessAnalysis(csvPath string) ([]string, []analysis.Finding, error) {
	r, err := analysis.AnalyzeProcessExecutions(csvPath)
	if err != nil {
		return nil, nil, err
	}
	return analysis.FormatProcessAnalysis(r), r.Findings, nil
}

func runServiceAnalysis(csvPath string) ([]string, []analysis.Finding, error) {
	r, err := analysis.AnalyzeServices(csvPath)
	if err != nil {
		return nil, nil, err
	}
	return analysis.FormatServiceAnalysis(r), r.Findings, nil
}

// analysisStartEventLog runs a no-findings analyser on the latest event-log CSV.
func (m Model) analysisStartEventLog(action, label string,
	formatter func(*analysis.EventLogSummary) []string,
	runner runFn) (Model, tea.Cmd, bool) {

	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	csvPath := analysis.FindEventLogCSV(filepath.Join(rootDir, "output", caseID, "analysis"))
	if csvPath == "" {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = "No parsed event log CSV found.\nRun [1] Parse Event Logs (EvtxECmd) first."
		m.state = stateResult
		return m, nil, true
	}
	_ = formatter // formatter is used inside runner via the closure above

	m.analysisState.operation = label
	m.analysisState.startTime = time.Now()
	m.analysisState.view = analysisViewRunning
	m.state = stateResult

	cmd := func() tea.Msg {
		lines, err := runner(csvPath)
		msg := analysisRunDoneMsg{lines: lines, outputPath: csvPath}
		if err != nil {
			msg.err = err.Error()
		}
		return msg
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

// analysisStartEventLogWithFindings runs an analyser whose Findings should be
// persisted to the case DB.
func (m Model) analysisStartEventLogWithFindings(action, label string, runner runWithFindingsFn) (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager
	csvPath := analysis.FindEventLogCSV(filepath.Join(rootDir, "output", caseID, "analysis"))
	if csvPath == "" {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = "No parsed event log CSV found.\nRun [1] Parse Event Logs (EvtxECmd) first."
		m.state = stateResult
		return m, nil, true
	}

	m.analysisState.operation = label
	m.analysisState.startTime = time.Now()
	m.analysisState.view = analysisViewRunning
	m.state = stateResult

	cmd := func() tea.Msg {
		lines, findings, err := runner(csvPath)
		msg := analysisRunDoneMsg{lines: lines, outputPath: csvPath}
		if err != nil {
			msg.err = err.Error()
			return msg
		}
		if cm != nil {
			for _, f := range findings {
				_ = cm.AddFindingFull(caseID, 0, f.Severity, f.Title, f.Description, f.MITRETechnique, f.IOCType, f.IOCValue)
			}
			msg.findingsAdded = len(findings)
		}
		return msg
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

// ---------------------------------------------------------------------------
// Linux log analyses
// ---------------------------------------------------------------------------

func (m Model) analysisStartLinuxAuth() (Model, tea.Cmd, bool) {
	return m.analysisStartLinuxLog("Auth Log Analysis", "auth_log",
		func(root string) ([]string, []analysis.Finding, error) {
			r, err := analysis.AnalyzeAuthLog(root)
			if err != nil {
				return nil, nil, err
			}
			return analysis.FormatAuthLog(r), r.Findings, nil
		})
}

func (m Model) analysisStartLinuxSyslog() (Model, tea.Cmd, bool) {
	return m.analysisStartLinuxLog("Syslog Analysis", "syslog",
		func(root string) ([]string, []analysis.Finding, error) {
			r, err := analysis.AnalyzeSyslog(root)
			if err != nil {
				return nil, nil, err
			}
			return analysis.FormatSyslog(r), r.Findings, nil
		})
}

func (m Model) analysisStartLinuxWeb() (Model, tea.Cmd, bool) {
	return m.analysisStartLinuxLog("Web Server Log Analysis", "weblog",
		func(root string) ([]string, []analysis.Finding, error) {
			r, err := analysis.AnalyzeWebLogs(root)
			if err != nil {
				return nil, nil, err
			}
			return analysis.FormatWebLogs(r), r.Findings, nil
		})
}

func (m Model) analysisStartLinuxJournal() (Model, tea.Cmd, bool) {
	return m.analysisStartLinuxLog("Journal Log Analysis", "journal",
		func(root string) ([]string, []analysis.Finding, error) {
			r, err := analysis.AnalyzeJournal(root)
			if err != nil {
				return nil, nil, err
			}
			return analysis.FormatJournal(r), r.Findings, nil
		})
}

// analysisStartLinuxLog runs a Linux log analyser against
// output/{case}/disk/*/logs/{kind}/. Falls back to the most recent disk
// collection's whole tree when no /logs/{kind}/ subtree exists.
func (m Model) analysisStartLinuxLog(label, kind string,
	runner func(root string) ([]string, []analysis.Finding, error)) (Model, tea.Cmd, bool) {

	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager

	// Find the latest disk collection that contains a logs/{kind} subdir.
	root := findLatestLinuxLogRoot(rootDir, caseID, kind)
	if root == "" {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = fmt.Sprintf(
			"No %s logs found.\nRun Disk Collection [2] > Linux %s collection first.",
			kind, strings.Title(kind))
		m.state = stateResult
		return m, nil, true
	}

	m.analysisState.operation = label
	m.analysisState.startTime = time.Now()
	m.analysisState.view = analysisViewRunning
	m.state = stateResult

	cmd := func() tea.Msg {
		lines, findings, err := runner(root)
		msg := analysisRunDoneMsg{lines: lines, outputPath: root}
		if err != nil {
			msg.err = err.Error()
			return msg
		}
		if cm != nil {
			for _, f := range findings {
				_ = cm.AddFindingFull(caseID, 0, f.Severity, f.Title, f.Description, f.MITRETechnique, f.IOCType, f.IOCValue)
			}
			msg.findingsAdded = len(findings)
		}
		return msg
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

// findLatestLinuxLogRoot returns the most recent disk collection subdir
// containing logs/{kind}/, or "" if none exists.
func findLatestLinuxLogRoot(rootDir, caseID, kind string) string {
	base := filepath.Join(rootDir, "output", caseID, "disk")
	entries, err := readDirSortedByMTime(base)
	if err != nil {
		return ""
	}
	for _, ts := range entries {
		candidate := filepath.Join(base, ts, "logs", kind)
		if dirHasContents(candidate) {
			return candidate
		}
	}
	// Fall back to most recent disk collection root.
	if len(entries) > 0 {
		return filepath.Join(base, entries[0])
	}
	return ""
}

// ---------------------------------------------------------------------------
// EZ Tools delegation
// ---------------------------------------------------------------------------

// analysisStartEZ asks the analyst to pick a data source, then runs the matching
// disk-package parser against it.
func (m Model) analysisStartEZ(action, label string) (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	sources, err := analysis.DiscoverDataSources(rootDir, caseID, analysis.SourceFilter{})
	if err != nil {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = err.Error()
		m.state = stateResult
		return m, nil, true
	}
	if len(sources) == 0 {
		m.analysisState.view = analysisViewError
		m.analysisState.errorMsg = "No collected data sources found.\nRun Quick Triage [4] or Disk Collection [2] first."
		m.state = stateResult
		return m, nil, true
	}
	m.analysisState.operation = label
	m.analysisState.sources = sources
	m.analysisState.sourceCursor = 0
	m.analysisState.pendingAction = action
	m.analysisState.view = analysisViewSourceSelect
	m.state = stateResult
	return m, nil, true
}

func (m Model) analysisRunEZ(action, sourcePath string) (Model, tea.Cmd) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	logger := m.ctx.Logger
	cm := m.ctx.CaseManager

	ts := analysis.CollectionTimestamp()
	m.analysisState.startTime = time.Now()
	m.analysisState.view = analysisViewRunning

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		ez := disk.NewEZToolsManager(rootDir, logger)
		var (
			result disk.CollectionResult
			subdir string
		)
		switch action {
		case "an_evtx_parse":
			subdir = "evtxecmd"
			result = ez.EvtxECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_mft":
			subdir = "mftecmd"
			result = ez.MFTECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_prefetch":
			subdir = "pecmd"
			result = ez.PECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_amcache":
			subdir = "amcache"
			result = ez.AmcacheParser(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_shimcache":
			subdir = "shimcache"
			result = ez.AppCompatCacheParser(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_jumplist":
			subdir = "jumplists"
			result = ez.JLECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_lnk":
			subdir = "lnkfiles"
			result = ez.LECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_srum":
			subdir = "srum"
			result = ez.SrumECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_recyclebin":
			subdir = "recyclebin"
			result = ez.RBCmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		case "an_registry":
			subdir = "recmd"
			result = ez.RECmd(ctx, sourcePath, analysis.AnalysisDir(rootDir, caseID, ts, subdir))
		}

		// Post-run verification: tools that exit cleanly but produce zero
		// output bytes are not actually successful. Common causes: corrupt
		// artifacts, parser doesn't recognise the input format, the source
		// directory contains files but not the expected artifact layout.
		if result.Status == disk.StatusSuccess && result.Bytes == 0 {
			result.Status = disk.StatusFailed
			result.Error = fmt.Sprintf(
				"%s exited cleanly but produced no output. The input artifacts may be corrupt, missing, or from an unsupported version. Source: %s",
				result.Name, sourcePath)
		}

		lines := []string{
			fmt.Sprintf("Tool:     %s", result.Name),
			fmt.Sprintf("Status:   %s", result.Status),
			fmt.Sprintf("Duration: %s", result.Duration.Truncate(time.Second)),
			fmt.Sprintf("Files:    %d", result.Files),
			fmt.Sprintf("Bytes:    %s", analysis.FormatBytes(result.Bytes)),
		}
		if result.OutputFile != "" {
			lines = append(lines, "Output:   "+result.OutputFile)
		} else if result.OutputDir != "" {
			lines = append(lines, "Output:   "+result.OutputDir)
		}
		if result.Error != "" {
			lines = append(lines, "Error:    "+result.Error)
		}
		if result.Status == disk.StatusSuccess && cm != nil {
			outPath := result.OutputDir
			if result.OutputFile != "" {
				outPath = result.OutputFile
			}
			_, _ = cm.AddEvidence(caseID, 0, "analysis_"+subdir, outPath)
		}
		msg := analysisRunDoneMsg{lines: lines, outputPath: result.OutputDir}
		if result.Status == disk.StatusFailed {
			msg.err = result.Error
		}
		return msg
	}
	return m, tea.Batch(analysisTickCmd(), cmd)
}

// ---------------------------------------------------------------------------
// Super timeline / correlation / MITRE
// ---------------------------------------------------------------------------

func (m Model) analysisStartSuperTimeline() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager
	ts := analysis.CollectionTimestamp()
	outDir := analysis.AnalysisDir(rootDir, caseID, ts, "timeline")

	m.analysisState.operation = "Build Super Timeline"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		res, err := analysis.BuildSuperTimeline(rootDir, caseID, outDir)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		if cm != nil && res.OutputFile != "" {
			_, _ = cm.AddEvidence(caseID, 0, "super_timeline", res.OutputFile)
		}
		return analysisRunDoneMsg{
			lines:      analysis.FormatTimelineResult(res),
			outputPath: res.OutputFile,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartCorrelate() (Model, tea.Cmd, bool) {
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager

	m.analysisState.operation = "Correlate Findings"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		findings, err := cm.ListFindings(caseID)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		res := analysis.CorrelateFindings(findings)
		return analysisRunDoneMsg{lines: analysis.FormatCorrelation(res)}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartMITRE() (Model, tea.Cmd, bool) {
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager

	m.analysisState.operation = "MITRE ATT&CK Mapping"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		findings, err := cm.ListFindings(caseID)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		res := analysis.BuildMITREMapping(findings)
		return analysisRunDoneMsg{lines: analysis.FormatMITREMapping(res)}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

// ---------------------------------------------------------------------------
// Reports + exports
// ---------------------------------------------------------------------------

func (m Model) analysisStartReportHTML() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	c := m.ctx.ActiveCase
	cm := m.ctx.CaseManager
	version := m.ctx.Version
	al := m.ctx.Audit

	m.analysisState.operation = "Generate HTML Report"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		path, err := analysis.GenerateHTMLReport(rootDir, version, cm, c)
		if err != nil {
			if al != nil {
				_ = al.Log("generate_report", "", "html", "error: "+err.Error(), c.ID)
			}
			return analysisRunDoneMsg{err: err.Error()}
		}
		if cm != nil {
			_, _ = cm.AddEvidence(c.ID, 0, "report_html", path)
		}
		if al != nil {
			_ = al.Log("generate_report", path, "html", "complete", c.ID)
		}
		return analysisRunDoneMsg{
			lines: []string{
				"HTML investigation report generated.",
				"",
				"Output: " + path,
			},
			outputPath: path,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartExecSummary() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	c := m.ctx.ActiveCase
	cm := m.ctx.CaseManager

	m.analysisState.operation = "Generate Executive Summary"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		path, err := analysis.GenerateExecutiveSummary(rootDir, cm, c)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		if cm != nil {
			_, _ = cm.AddEvidence(c.ID, 0, "report_exec", path)
		}
		txtPath := strings.TrimSuffix(path, ".html") + ".txt"
		return analysisRunDoneMsg{
			lines: []string{
				"Executive summary generated (HTML + plain text).",
				"",
				"HTML: " + path,
				"Text: " + txtPath,
			},
			outputPath: path,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartExportFindings() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager

	m.analysisState.operation = "Export Findings (CSV)"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		path, err := analysis.ExportFindingsCSV(rootDir, cm, caseID)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		return analysisRunDoneMsg{
			lines: []string{
				"Findings exported to CSV.",
				"",
				"Output: " + path,
			},
			outputPath: path,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartExportTimeline() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()

	m.analysisState.operation = "Export Timeline (CSV)"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		path, err := analysis.ExportTimelineCSV(rootDir, caseID)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		return analysisRunDoneMsg{
			lines: []string{
				"Super timeline exported.",
				"",
				"Output: " + path,
			},
			outputPath: path,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

func (m Model) analysisStartExportIOCs() (Model, tea.Cmd, bool) {
	rootDir := m.ctx.RootDir
	caseID := m.analysisCaseID()
	cm := m.ctx.CaseManager

	m.analysisState.operation = "Export IOC List"
	m.analysisState.view = analysisViewRunning
	m.analysisState.startTime = time.Now()
	m.state = stateResult

	cmd := func() tea.Msg {
		res, err := analysis.ExportIOCs(rootDir, cm, caseID)
		if err != nil {
			return analysisRunDoneMsg{err: err.Error()}
		}
		return analysisRunDoneMsg{
			lines:      analysis.FormatIOCExport(res),
			outputPath: res.CSVPath,
		}
	}
	return m, tea.Batch(analysisTickCmd(), cmd), true
}

// ---------------------------------------------------------------------------
// Tiny dir helpers used by the Linux log resolvers.
// ---------------------------------------------------------------------------

// readDirSortedByMTime returns subdirectory names of dir, newest mod-time first.
func readDirSortedByMTime(dir string) ([]string, error) {
	entries, err := osReadDir(dir)
	if err != nil {
		return nil, err
	}
	type pair struct {
		name string
		mod  time.Time
	}
	var pairs []pair
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, _ := e.Info()
		if info != nil {
			pairs = append(pairs, pair{name: e.Name(), mod: info.ModTime()})
		}
	}
	// Newest first.
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].mod.After(pairs[j].mod)
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.name
	}
	return out, nil
}

func dirHasContents(dir string) bool {
	if dir == "" {
		return false
	}
	entries, err := osReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}
	return true
}

// Wrapper indirections so we don't pull os.* into the dispatcher's import set
// just for tiny calls — the helpers live in analysis_view.go alongside the
// other small IO bits used for rendering.

var _ = (*casemanager.Case)(nil) // keep casemanager import used even when builds drop the field
