package tui

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ridgelinecyberdefence/vanguard/internal/disk"
)

// ---------------------------------------------------------------------------
// View IDs
// ---------------------------------------------------------------------------

type diskView int

const (
	diskViewNone diskView = iota
	diskViewNeedCase
	diskViewNeedKape
	diskViewNeedEZ
	diskViewNeedUAC
	diskViewError

	diskViewKapeConfirm
	diskViewKapeRunning
	diskViewKapeDone
	diskViewKapeCustomTargets

	diskViewSourceSelect
	diskViewSourceCustomPath
	diskViewSinglePluginRunning
	diskViewSinglePluginDone

	diskViewAllParsersRunning
	diskViewAllParsersDone

	diskViewUACConfirm
	diskViewUACRunning
	diskViewUACDone
	diskViewUACProfileSelect

	diskViewLnxConfirm
	diskViewLnxRunning
	diskViewLnxDone
	diskViewLnxAppPath

	diskViewManualSrc
	diskViewManualDesc
	diskViewManualRunning
	diskViewManualDone

	diskViewBrowse
)

// DiskState holds the disk-collection panel state.
type DiskState struct {
	view diskView

	// The originating sidebar action.
	action string

	// Generic preset/operation labels.
	operationName string
	preset        string // KAPE preset id
	uacProfile    string

	// Source selection.
	sourceOptions []string
	sourceCursor  int
	sourcePath    string

	// Custom-target / app-path / browse text input.
	input textinput.Model

	// Running state.
	startTime time.Time
	elapsed   time.Duration

	// Single-step result.
	singleResult *disk.CollectionResult

	// All-parsers run.
	allSteps     []disk.AllParsersStep
	allStatuses  []disk.Status
	allDurations []time.Duration
	allResults   []disk.CollectionResult

	// UAC profile listing.
	uacProfiles []string
	uacCursor   int

	// Manual copy form.
	manualSrc    string
	manualDesc   string
	manualResult *disk.ManualCopyResult

	// Browse tree.
	browseRoot   *disk.EvidenceNode
	browseFlat   []*disk.EvidenceNode
	browseCursor int

	// Free-form error / placeholder lines.
	errorMsg    string
	resultLines []string
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type diskTickMsg time.Time

type diskKapeDoneMsg struct {
	result disk.CollectionResult
}

type diskSinglePluginDoneMsg struct {
	result disk.CollectionResult
}

type diskAllParsersStepMsg struct {
	stepIndex int
	result    *disk.CollectionResult // nil = step started
}

type diskAllParsersDoneMsg struct {
	results []disk.CollectionResult
}

type diskUACDoneMsg struct {
	result disk.CollectionResult
}

type diskLnxDoneMsg struct {
	result disk.CollectionResult
}

type diskManualDoneMsg struct {
	result disk.ManualCopyResult
}

func diskTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return diskTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (m Model) diskCheckCase() bool {
	return m.ctx.ActiveCase != nil
}

// diskRequireCase shows the case-needed view and reports whether to proceed.
func (m *Model) diskRequireCase() bool {
	if m.diskCheckCase() {
		return true
	}
	m.diskState.view = diskViewNeedCase
	m.state = stateResult
	return false
}

func (m Model) diskKape() *disk.KapeManager {
	return disk.NewKapeManager(m.ctx.RootDir, m.ctx.Logger)
}

func (m Model) diskEZ() *disk.EZToolsManager {
	return disk.NewEZToolsManager(m.ctx.RootDir, m.ctx.Logger)
}

func (m Model) diskUAC() *disk.UACManager {
	return disk.NewUACManager(m.ctx.RootDir, m.ctx.Logger)
}

func (m Model) diskLinux() *disk.LinuxCollector {
	return disk.NewLinuxCollector(m.ctx.RootDir, m.ctx.Logger)
}

func (m Model) diskCaseID() string {
	if m.ctx.ActiveCase == nil {
		return ""
	}
	return m.ctx.ActiveCase.ID
}

func newDiskTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 512
	ti.Width = 60
	ti.Focus()
	return ti
}

// ---------------------------------------------------------------------------
// Action dispatcher
// ---------------------------------------------------------------------------

// handleDiskAction routes Disk Collection submenu actions.
//
// MUST short-circuit on the action prefix BEFORE any state mutation — the
// dispatcher chains panel handlers and an unprefixed early return would
// hijack other panels' actions.
func (m Model) handleDiskAction(action string) (Model, tea.Cmd, bool) {
	if !strings.HasPrefix(action, "disk_") {
		return m, nil, false
	}

	m.clearPanelState()
	m.diskState = DiskState{action: action}

	// Route by prefix groups — KAPE / EZ / UAC / Linux / Manual / Browse.
	switch {
	case strings.HasPrefix(action, "disk_kape_"):
		return m.diskStartKape(action)
	case action == "disk_ez_all":
		return m.diskStartAllParsers()
	case strings.HasPrefix(action, "disk_ez_"):
		return m.diskStartEZParser(action)
	case strings.HasPrefix(action, "disk_uac_"):
		return m.diskStartUAC(action)
	case strings.HasPrefix(action, "disk_lnx_"):
		return m.diskStartLinuxStep(action)
	case action == "disk_manual_copy":
		return m.diskStartManual()
	case action == "disk_browse":
		return m.diskStartBrowse()
	}

	return m, nil, false
}

// ---------------------------------------------------------------------------
// KAPE flow
// ---------------------------------------------------------------------------

func (m Model) diskStartKape(action string) (Model, tea.Cmd, bool) {
	if m.ctx.Platform != "windows" {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "KAPE is Windows-only."
		m.state = stateResult
		return m, nil, true
	}
	k := m.diskKape()
	if !k.Installed() {
		m.diskState.view = diskViewNeedKape
		m.state = stateResult
		return m, nil, true
	}
	if !m.diskRequireCase() {
		return m, nil, true
	}

	switch action {
	case "disk_kape_sans":
		m.diskState.preset = "sans"
		m.diskState.operationName = "SANS Triage (!SANS_Triage)"
	case "disk_kape_full":
		m.diskState.preset = "full"
		m.diskState.operationName = "Full Collection (!BasicCollection)"
	case "disk_kape_evtx":
		m.diskState.preset = "evtx"
		m.diskState.operationName = "Event Logs Only"
	case "disk_kape_registry":
		m.diskState.preset = "registry"
		m.diskState.operationName = "Registry Hives Only"
	case "disk_kape_browser":
		m.diskState.preset = "browser"
		m.diskState.operationName = "Web Browser Artifacts"
	case "disk_kape_custom":
		m.diskState.view = diskViewKapeCustomTargets
		m.diskState.input = newDiskTextInput("Comma-separated KAPE target names")
		m.state = stateResult
		return m, m.diskState.input.Focus(), true
	}

	m.diskState.view = diskViewKapeConfirm
	m.state = stateResult
	return m, nil, true
}

func (m Model) diskKapeBeginPreset() (Model, tea.Cmd) {
	m.diskState.view = diskViewKapeRunning
	m.diskState.startTime = time.Now()
	preset := m.diskState.preset
	caseID := m.diskCaseID()
	rootDir := m.ctx.RootDir
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager

	subdir := "kape"
	if preset == "evtx" {
		subdir = "eventlogs"
	} else if preset == "registry" {
		subdir = "registry"
	} else if preset == "browser" {
		subdir = "browser"
	}
	ts := disk.CollectionTimestamp()
	outDir := disk.CollectionDir(rootDir, caseID, ts, subdir)

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()
		k := disk.NewKapeManager(rootDir, logger)
		result := k.CollectPreset(ctx, preset, outDir)
		if result.Status == disk.StatusSuccess && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "kape_collection", outDir)
		}
		return diskKapeDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) diskKapeBeginCustom(targets string) (Model, tea.Cmd) {
	parts := splitAndTrim(targets, ",")
	if len(parts) == 0 {
		m.statusMessage = "At least one target is required."
		return m, nil
	}
	m.diskState.view = diskViewKapeRunning
	m.diskState.startTime = time.Now()
	m.diskState.operationName = "Custom: " + strings.Join(parts, ",")
	caseID := m.diskCaseID()
	rootDir := m.ctx.RootDir
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	outDir := disk.CollectionDir(rootDir, caseID, ts, "kape")

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()
		k := disk.NewKapeManager(rootDir, logger)
		result := k.Collect(ctx, disk.CollectRequest{
			Targets:   parts,
			Source:    disk.SystemDrive(),
			OutputDir: outDir,
		})
		if result.Status == disk.StatusSuccess && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "kape_collection", outDir)
		}
		return diskKapeDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskKapeDone(result disk.CollectionResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewKapeDone
	m.diskState.singleResult = &result
	return m, nil
}

// ---------------------------------------------------------------------------
// EZ Tools flow — single parser
// ---------------------------------------------------------------------------

func (m Model) diskStartEZParser(action string) (Model, tea.Cmd, bool) {
	if m.ctx.Platform != "windows" {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "EZ Tools are Windows-only."
		m.state = stateResult
		return m, nil, true
	}
	ez := m.diskEZ()
	if !ez.Installed() {
		m.diskState.view = diskViewNeedEZ
		m.state = stateResult
		return m, nil, true
	}
	if !m.diskRequireCase() {
		return m, nil, true
	}

	m.diskState.operationName = ezToolLabel(action)
	m.diskState.view = diskViewSourceSelect
	m.diskState.sourceOptions = m.diskBuildSourceOptions()
	m.diskState.sourceCursor = 0
	m.state = stateResult
	return m, nil, true
}

func (m Model) diskStartAllParsers() (Model, tea.Cmd, bool) {
	if m.ctx.Platform != "windows" {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "EZ Tools are Windows-only."
		m.state = stateResult
		return m, nil, true
	}
	ez := m.diskEZ()
	if !ez.Installed() {
		m.diskState.view = diskViewNeedEZ
		m.state = stateResult
		return m, nil, true
	}
	if !m.diskRequireCase() {
		return m, nil, true
	}

	m.diskState.action = "disk_ez_all"
	m.diskState.operationName = "EZ Tools — Full Parse"
	m.diskState.view = diskViewSourceSelect
	m.diskState.sourceOptions = m.diskBuildSourceOptions()
	m.diskState.sourceCursor = 0
	m.state = stateResult
	return m, nil, true
}

// diskBuildSourceOptions assembles available parse-source choices.
func (m Model) diskBuildSourceOptions() []string {
	var opts []string
	if disk.LatestKapeCollection(m.ctx.RootDir, m.diskCaseID()) != "" {
		opts = append(opts, "Latest KAPE collection")
	}
	if disk.LatestTriageCollection(m.ctx.RootDir, m.diskCaseID()) != "" {
		opts = append(opts, "Latest triage collection")
	}
	opts = append(opts, "Custom path…")
	opts = append(opts, "Live system (C:\\)")
	return opts
}

// diskResolveSource maps a selection index to a concrete source path.
// Returns "" when the user must enter a custom path next.
func (m *Model) diskResolveSource(idx int) string {
	if idx < 0 || idx >= len(m.diskState.sourceOptions) {
		return ""
	}
	opt := m.diskState.sourceOptions[idx]
	switch opt {
	case "Latest KAPE collection":
		return disk.LatestKapeCollection(m.ctx.RootDir, m.diskCaseID())
	case "Latest triage collection":
		return disk.LatestTriageCollection(m.ctx.RootDir, m.diskCaseID())
	case "Live system (C:\\)":
		return disk.SystemDrive()
	}
	return "" // Custom path
}

func (m Model) diskSelectSource(idx int) (Model, tea.Cmd) {
	source := m.diskResolveSource(idx)
	if source == "" {
		m.diskState.view = diskViewSourceCustomPath
		m.diskState.input = newDiskTextInput("Path to artifact directory")
		return m, m.diskState.input.Focus()
	}
	return m.diskRunWithSource(source)
}

func (m Model) diskRunWithSource(source string) (Model, tea.Cmd) {
	m.diskState.sourcePath = source
	if m.diskState.action == "disk_ez_all" {
		return m.diskBeginAllParsers()
	}
	return m.diskBeginSingleParser()
}

func (m Model) diskBeginSingleParser() (Model, tea.Cmd) {
	m.diskState.view = diskViewSinglePluginRunning
	m.diskState.startTime = time.Now()
	action := m.diskState.action
	source := m.diskState.sourcePath
	rootDir := m.ctx.RootDir
	caseID := m.diskCaseID()
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	subdir := ezSubdir(action)
	outDir := disk.CollectionDir(rootDir, caseID, ts, filepath.Join("parsed", subdir))

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		ez := disk.NewEZToolsManager(rootDir, logger)
		result := runEZForAction(ctx, ez, action, source, outDir)
		if result.Status == disk.StatusSuccess && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "ez_tools_parse", outDir)
		}
		return diskSinglePluginDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskSinglePluginDone(result disk.CollectionResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewSinglePluginDone
	m.diskState.singleResult = &result
	return m, nil
}

// ---------------------------------------------------------------------------
// All-parsers flow
// ---------------------------------------------------------------------------

func (m Model) diskBeginAllParsers() (Model, tea.Cmd) {
	m.diskState.view = diskViewAllParsersRunning
	m.diskState.startTime = time.Now()

	ez := m.diskEZ()
	steps := ez.AllParsers()
	m.diskState.allSteps = steps
	m.diskState.allStatuses = make([]disk.Status, len(steps))
	m.diskState.allDurations = make([]time.Duration, len(steps))
	for i := range steps {
		m.diskState.allStatuses[i] = disk.StatusPending
	}

	source := m.diskState.sourcePath
	rootDir := m.ctx.RootDir
	caseID := m.diskCaseID()
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	parsedRoot := disk.CollectionDir(rootDir, caseID, ts, "parsed")

	stepCount := len(steps)
	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()
		ez := disk.NewEZToolsManager(rootDir, logger)
		results := make([]disk.CollectionResult, stepCount)
		for i, step := range steps {
			results[i] = step.Run(ctx, source, filepath.Join(parsedRoot, step.SubDir))
		}
		if caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "ez_tools_parse", parsedRoot)
		}
		_ = ez
		return diskAllParsersDoneMsg{results: results}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskAllParsersDone(results []disk.CollectionResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewAllParsersDone
	m.diskState.allResults = results
	for i, r := range results {
		if i < len(m.diskState.allStatuses) {
			m.diskState.allStatuses[i] = r.Status
			m.diskState.allDurations[i] = r.Duration
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// UAC flow
// ---------------------------------------------------------------------------

func (m Model) diskStartUAC(action string) (Model, tea.Cmd, bool) {
	if m.ctx.Platform != "linux" {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "UAC is Linux-only."
		m.state = stateResult
		return m, nil, true
	}
	u := m.diskUAC()
	if !u.Installed() {
		m.diskState.view = diskViewNeedUAC
		m.state = stateResult
		return m, nil, true
	}
	if !m.diskRequireCase() {
		return m, nil, true
	}

	switch action {
	case "disk_uac_full":
		m.diskState.uacProfile = "full"
		m.diskState.operationName = "UAC — Full Profile"
	case "disk_uac_triage":
		m.diskState.uacProfile = "ir_triage"
		m.diskState.operationName = "UAC — IR Triage"
	case "disk_uac_custom":
		profiles, err := u.ListProfiles()
		if err != nil || len(profiles) == 0 {
			m.diskState.view = diskViewError
			m.diskState.errorMsg = "no UAC profiles found in bin/linux/uac/profiles/"
			m.state = stateResult
			return m, nil, true
		}
		m.diskState.uacProfiles = profiles
		m.diskState.uacCursor = 0
		m.diskState.view = diskViewUACProfileSelect
		m.state = stateResult
		return m, nil, true
	}

	m.diskState.view = diskViewUACConfirm
	m.state = stateResult
	return m, nil, true
}

func (m Model) diskUACBegin() (Model, tea.Cmd) {
	m.diskState.view = diskViewUACRunning
	m.diskState.startTime = time.Now()
	profile := m.diskState.uacProfile
	caseID := m.diskCaseID()
	rootDir := m.ctx.RootDir
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	outDir := disk.CollectionDir(rootDir, caseID, ts, "uac")

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Minute)
		defer cancel()
		u := disk.NewUACManager(rootDir, logger)
		result := u.Run(ctx, profile, outDir)
		if result.Status == disk.StatusSuccess && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "uac_collection", outDir)
		}
		return diskUACDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskUACDone(result disk.CollectionResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewUACDone
	m.diskState.singleResult = &result
	return m, nil
}

// ---------------------------------------------------------------------------
// Linux native step flow
// ---------------------------------------------------------------------------

func (m Model) diskStartLinuxStep(action string) (Model, tea.Cmd, bool) {
	if m.ctx.Platform != "linux" {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "Linux-only collection."
		m.state = stateResult
		return m, nil, true
	}
	if !m.diskRequireCase() {
		return m, nil, true
	}

	m.diskState.operationName = lnxLabel(action)

	if action == "disk_lnx_applogs" {
		m.diskState.view = diskViewLnxAppPath
		m.diskState.input = newDiskTextInput("Application log path (blank for common defaults)")
		m.state = stateResult
		return m, m.diskState.input.Focus(), true
	}

	m.diskState.view = diskViewLnxConfirm
	m.state = stateResult
	return m, nil, true
}

func (m Model) diskLnxBegin(customPath string) (Model, tea.Cmd) {
	m.diskState.view = diskViewLnxRunning
	m.diskState.startTime = time.Now()
	action := m.diskState.action
	rootDir := m.ctx.RootDir
	caseID := m.diskCaseID()
	logger := m.ctx.Logger
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	outDir := lnxOutputDir(rootDir, caseID, ts, action)

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		lc := disk.NewLinuxCollector(rootDir, logger)
		result := runLinuxStep(ctx, lc, action, outDir, customPath)
		if (result.Status == disk.StatusSuccess || result.Status == disk.StatusPartial) && caseManager != nil {
			_, _ = caseManager.AddEvidence(caseID, 0, "linux_collection", outDir)
		}
		return diskLnxDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskLnxDone(result disk.CollectionResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewLnxDone
	m.diskState.singleResult = &result
	return m, nil
}

// ---------------------------------------------------------------------------
// Manual copy + browser
// ---------------------------------------------------------------------------

func (m Model) diskStartManual() (Model, tea.Cmd, bool) {
	if !m.diskRequireCase() {
		return m, nil, true
	}
	m.diskState.view = diskViewManualSrc
	m.diskState.input = newDiskTextInput("Source path (file or directory)")
	m.state = stateResult
	return m, m.diskState.input.Focus(), true
}

func (m Model) diskManualAdvanceSrc(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Source path is required."
		return m, nil
	}
	m.diskState.manualSrc = value
	m.diskState.view = diskViewManualDesc
	m.diskState.input = newDiskTextInput("Description (what is this artifact)")
	return m, m.diskState.input.Focus()
}

func (m Model) diskManualBegin(description string) (Model, tea.Cmd) {
	m.diskState.manualDesc = description
	m.diskState.view = diskViewManualRunning
	m.diskState.startTime = time.Now()

	src := m.diskState.manualSrc
	desc := description
	rootDir := m.ctx.RootDir
	caseID := m.diskCaseID()
	caseManager := m.ctx.CaseManager
	ts := disk.CollectionTimestamp()
	outDir := disk.CollectionDir(rootDir, caseID, ts, "manual")

	cmd := func() tea.Msg {
		result := disk.ManualCopy(src, outDir, desc)
		if result.Success && !result.IsDir && caseManager != nil {
			// Single-file copy: register the destination file with hash.
			if ev, err := caseManager.AddEvidence(caseID, 0, "manual_copy", result.Destination); err == nil && desc != "" {
				_ = caseManager.AddFinding(caseID, ev.ID, "info", desc, "", "")
			}
		} else if result.Success && caseManager != nil {
			// Directory copy: register the destination directory.
			_, _ = caseManager.AddEvidence(caseID, 0, "manual_copy", outDir)
		}
		return diskManualDoneMsg{result: result}
	}
	return m, tea.Batch(diskTickCmd(), cmd)
}

func (m Model) handleDiskManualDone(result disk.ManualCopyResult) (Model, tea.Cmd) {
	m.diskState.view = diskViewManualDone
	m.diskState.manualResult = &result
	return m, nil
}

func (m Model) diskStartBrowse() (Model, tea.Cmd, bool) {
	if !m.diskRequireCase() {
		return m, nil, true
	}
	root, err := disk.LoadEvidenceTree(m.ctx.RootDir, m.diskCaseID())
	if err != nil {
		m.diskState.view = diskViewError
		m.diskState.errorMsg = "loading evidence tree: " + err.Error()
		m.state = stateResult
		return m, nil, true
	}
	m.diskState.browseRoot = root
	m.diskState.browseFlat = disk.FlattenVisible(root)
	m.diskState.browseCursor = 0
	m.diskState.view = diskViewBrowse
	m.state = stateResult
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Tick + key dispatch
// ---------------------------------------------------------------------------

func (m Model) handleDiskTick() (Model, tea.Cmd) {
	switch m.diskState.view {
	case diskViewKapeRunning, diskViewSinglePluginRunning,
		diskViewAllParsersRunning, diskViewUACRunning,
		diskViewLnxRunning, diskViewManualRunning:
		m.diskState.elapsed = time.Since(m.diskState.startTime)
		return m, diskTickCmd()
	}
	return m, nil
}

func (m Model) diskUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.diskState.view == diskViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.diskState.view {
	case diskViewNeedCase:
		switch key {
		case "y", "Y":
			m.diskState.view = diskViewNone
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.diskState.view = diskViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case diskViewNeedKape, diskViewNeedEZ, diskViewNeedUAC, diskViewError:
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		return m, nil, true

	case diskViewKapeConfirm:
		switch key {
		case "y", "Y":
			mm, cmd := m.diskKapeBeginPreset()
			return mm, cmd, true
		default:
			m.diskState.view = diskViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case diskViewKapeCustomTargets:
		return m.diskHandleTextInput(msg, key, m.diskKapeBeginCustom)

	case diskViewSourceSelect:
		return m.diskHandleSourceSelect(key)

	case diskViewSourceCustomPath:
		return m.diskHandleTextInput(msg, key, func(value string) (Model, tea.Cmd) {
			if value == "" {
				m.statusMessage = "Path is required."
				return m, nil
			}
			return m.diskRunWithSource(value)
		})

	case diskViewUACConfirm:
		switch key {
		case "y", "Y":
			mm, cmd := m.diskUACBegin()
			return mm, cmd, true
		default:
			m.diskState.view = diskViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case diskViewUACProfileSelect:
		return m.diskHandleUACProfileSelect(key)

	case diskViewLnxConfirm:
		switch key {
		case "y", "Y":
			mm, cmd := m.diskLnxBegin("")
			return mm, cmd, true
		default:
			m.diskState.view = diskViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case diskViewLnxAppPath:
		return m.diskHandleTextInput(msg, key, func(value string) (Model, tea.Cmd) {
			return m.diskLnxBegin(value)
		})

	case diskViewManualSrc:
		return m.diskHandleTextInput(msg, key, m.diskManualAdvanceSrc)

	case diskViewManualDesc:
		return m.diskHandleTextInput(msg, key, m.diskManualBegin)

	case diskViewKapeRunning, diskViewSinglePluginRunning,
		diskViewAllParsersRunning, diskViewUACRunning,
		diskViewLnxRunning, diskViewManualRunning:
		return m, nil, true

	case diskViewKapeDone, diskViewSinglePluginDone, diskViewAllParsersDone,
		diskViewUACDone, diskViewLnxDone, diskViewManualDone:
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		return m, nil, true

	case diskViewBrowse:
		return m.diskHandleBrowse(key)
	}

	return m, nil, false
}

func (m Model) diskHandleTextInput(msg tea.KeyMsg, key string, activate func(string) (Model, tea.Cmd)) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		m.statusMessage = "Cancelled."
		return m, nil, true
	case "enter":
		value := strings.TrimSpace(m.diskState.input.Value())
		mm, cmd := activate(value)
		return mm, cmd, true
	default:
		var cmd tea.Cmd
		m.diskState.input, cmd = m.diskState.input.Update(msg)
		return m, cmd, true
	}
}

func (m Model) diskHandleSourceSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.diskState.sourceCursor > 0 {
			m.diskState.sourceCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.diskState.sourceCursor < len(m.diskState.sourceOptions)-1 {
			m.diskState.sourceCursor++
		}
		return m, nil, true
	case "enter":
		mm, cmd := m.diskSelectSource(m.diskState.sourceCursor)
		return mm, cmd, true
	case "1", "2", "3", "4":
		idx := int(key[0]-'0') - 1
		if idx < len(m.diskState.sourceOptions) {
			m.diskState.sourceCursor = idx
			mm, cmd := m.diskSelectSource(idx)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

func (m Model) diskHandleUACProfileSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.diskState.uacCursor > 0 {
			m.diskState.uacCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.diskState.uacCursor < len(m.diskState.uacProfiles)-1 {
			m.diskState.uacCursor++
		}
		return m, nil, true
	case "enter":
		m.diskState.uacProfile = m.diskState.uacProfiles[m.diskState.uacCursor]
		m.diskState.operationName = "UAC — " + m.diskState.uacProfile
		m.diskState.view = diskViewUACConfirm
		return m, nil, true
	}
	return m, nil, true
}

func (m Model) diskHandleBrowse(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc", "q", "Q":
		m.diskState.view = diskViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.diskState.browseCursor > 0 {
			m.diskState.browseCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.diskState.browseCursor < len(m.diskState.browseFlat)-1 {
			m.diskState.browseCursor++
		}
		return m, nil, true
	case "enter", " ":
		if m.diskState.browseCursor < len(m.diskState.browseFlat) {
			node := m.diskState.browseFlat[m.diskState.browseCursor]
			if node.IsDir {
				if node.Expanded {
					node.Expanded = false
				} else {
					_ = node.Expand()
				}
				m.diskState.browseFlat = disk.FlattenVisible(m.diskState.browseRoot)
			}
		}
		return m, nil, true
	}
	return m, nil, true
}

// ---------------------------------------------------------------------------
// Action → label / subdir / runner mappings
// ---------------------------------------------------------------------------

func ezToolLabel(action string) string {
	switch action {
	case "disk_ez_evtx":
		return "EvtxECmd (Event Logs)"
	case "disk_ez_mft":
		return "MFTECmd ($MFT)"
	case "disk_ez_reg":
		return "RECmd (Registry)"
	case "disk_ez_prefetch":
		return "PECmd (Prefetch)"
	case "disk_ez_amcache":
		return "AmcacheParser"
	case "disk_ez_shimcache":
		return "AppCompatCacheParser (Shimcache)"
	case "disk_ez_jumplist":
		return "JLECmd (Jump Lists)"
	case "disk_ez_lnk":
		return "LECmd (LNK Files)"
	case "disk_ez_srum":
		return "SrumECmd (SRUM)"
	case "disk_ez_recyclebin":
		return "RBCmd (Recycle Bin)"
	}
	return action
}

func ezSubdir(action string) string {
	switch action {
	case "disk_ez_evtx":
		return "evtxecmd"
	case "disk_ez_mft":
		return "mftecmd"
	case "disk_ez_reg":
		return "recmd"
	case "disk_ez_prefetch":
		return "pecmd"
	case "disk_ez_amcache":
		return "amcache"
	case "disk_ez_shimcache":
		return "shimcache"
	case "disk_ez_jumplist":
		return "jumplists"
	case "disk_ez_lnk":
		return "lnkfiles"
	case "disk_ez_srum":
		return "srum"
	case "disk_ez_recyclebin":
		return "recyclebin"
	}
	return strings.TrimPrefix(action, "disk_ez_")
}

func runEZForAction(ctx context.Context, ez *disk.EZToolsManager, action, source, outDir string) disk.CollectionResult {
	switch action {
	case "disk_ez_evtx":
		return ez.EvtxECmd(ctx, source, outDir)
	case "disk_ez_mft":
		return ez.MFTECmd(ctx, source, outDir)
	case "disk_ez_reg":
		return ez.RECmd(ctx, source, outDir)
	case "disk_ez_prefetch":
		return ez.PECmd(ctx, source, outDir)
	case "disk_ez_amcache":
		return ez.AmcacheParser(ctx, source, outDir)
	case "disk_ez_shimcache":
		return ez.AppCompatCacheParser(ctx, source, outDir)
	case "disk_ez_jumplist":
		return ez.JLECmd(ctx, source, outDir)
	case "disk_ez_lnk":
		return ez.LECmd(ctx, source, outDir)
	case "disk_ez_srum":
		return ez.SrumECmd(ctx, source, outDir)
	case "disk_ez_recyclebin":
		return ez.RBCmd(ctx, source, outDir)
	}
	return disk.CollectionResult{Name: action, Status: disk.StatusFailed,
		Error: "unknown EZ Tools action: " + action}
}

func lnxLabel(action string) string {
	switch action {
	case "disk_lnx_syslog":
		return "System Logs"
	case "disk_lnx_auth":
		return "Auth Logs"
	case "disk_lnx_weblogs":
		return "Web Server Logs"
	case "disk_lnx_applogs":
		return "Application Logs"
	case "disk_lnx_journal":
		return "Journal Logs"
	case "disk_lnx_userhomes":
		return "User Home Directories"
	case "disk_lnx_history":
		return "Shell History"
	case "disk_lnx_ssh":
		return "SSH Artifacts"
	case "disk_lnx_cron":
		return "Cron Jobs"
	case "disk_lnx_packages":
		return "Package Manager Logs & Lists"
	case "disk_lnx_systemd":
		return "Systemd Unit Files"
	case "disk_lnx_network":
		return "Network Configuration"
	case "disk_lnx_docker":
		return "Docker / Container Artifacts"
	}
	return action
}

func lnxOutputDir(rootDir, caseID, ts, action string) string {
	switch action {
	case "disk_lnx_syslog":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("logs", "system"))
	case "disk_lnx_auth":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("logs", "auth"))
	case "disk_lnx_weblogs":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("logs", "webserver"))
	case "disk_lnx_applogs":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("logs", "applications"))
	case "disk_lnx_journal":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("logs", "journal"))
	case "disk_lnx_userhomes":
		return disk.CollectionDir(rootDir, caseID, ts, "users")
	case "disk_lnx_history":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("users", "history"))
	case "disk_lnx_ssh":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("users", "ssh"))
	case "disk_lnx_cron":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("persistence", "cron"))
	case "disk_lnx_packages":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("system", "packages"))
	case "disk_lnx_systemd":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("persistence", "systemd"))
	case "disk_lnx_network":
		return disk.CollectionDir(rootDir, caseID, ts, filepath.Join("system", "network"))
	case "disk_lnx_docker":
		return disk.CollectionDir(rootDir, caseID, ts, "containers")
	}
	return disk.CollectionDir(rootDir, caseID, ts, action)
}

func runLinuxStep(ctx context.Context, lc *disk.LinuxCollector, action, outDir, customPath string) disk.CollectionResult {
	switch action {
	case "disk_lnx_syslog":
		return lc.CollectSystemLogs(ctx, outDir)
	case "disk_lnx_auth":
		return lc.CollectAuthLogs(ctx, outDir)
	case "disk_lnx_weblogs":
		return lc.CollectWebServerLogs(ctx, outDir)
	case "disk_lnx_applogs":
		return lc.CollectAppLogs(ctx, outDir, customPath)
	case "disk_lnx_journal":
		return lc.CollectJournal(ctx, outDir)
	case "disk_lnx_userhomes":
		return lc.CollectUserHomes(ctx, outDir)
	case "disk_lnx_history":
		return lc.CollectShellHistory(ctx, outDir)
	case "disk_lnx_ssh":
		return lc.CollectSSHArtifacts(ctx, outDir)
	case "disk_lnx_cron":
		return lc.CollectCron(ctx, outDir)
	case "disk_lnx_packages":
		return lc.CollectPackages(ctx, outDir)
	case "disk_lnx_systemd":
		return lc.CollectSystemd(ctx, outDir)
	case "disk_lnx_network":
		return lc.CollectNetwork(ctx, outDir)
	case "disk_lnx_docker":
		return lc.CollectDocker(ctx, outDir)
	}
	return disk.CollectionResult{Name: action, Status: disk.StatusFailed,
		Error: "unknown linux action: " + action}
}

func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

