package tui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/memory"
)

// ---------------------------------------------------------------------------
// Memory panel states
// ---------------------------------------------------------------------------

type memView int

const (
	memViewNone memView = iota
	memViewNeedCase
	memViewNeedTool
	memViewNeedVolatility
	memViewNeedPython
	memViewInstallingDeps
	memViewDepsFailed
	memViewCaptureConfirm
	memViewCapturing
	memViewCaptureDone
	memViewDumpSelect
	memViewDumpPathInput
	memViewAnalysisRunning
	memViewAnalysisDone
	memViewSinglePluginRunning
	memViewSinglePluginDone
	memViewMalfindResults
	memViewYaraSelect
	memViewYaraCustomPath
	memViewYaraResults
	memViewTimelineDone
	memViewCustomPlugin
	memViewCustomPluginArgs
	memViewCustomPluginRunning
	memViewCustomPluginDone
	memViewSymbols
	memViewSymbolsDownloading
	memViewSymbolsDone
	memViewVRClientSelect
	memViewVRRunning
	memViewVRDone
	memViewRemoteMethod
	memViewRemoteHost
	memViewRemoteUser
	memViewRemotePass
	memViewRemotePort
	memViewRemoteRunning
	memViewRemoteDone
	memViewLimeInstructions
	memViewError

	// GUI-launch capture flow (Belkasoft / Magnet RAM Capture).
	memViewGUIChoose       // "Launch GUI" vs "CLI mode"
	memViewGUILaunched     // GUI started, awaiting analyst confirmation
	memViewGUIDumpPath     // analyst types the path to the produced dump
	memViewGUICliPath      // analyst types desired output path for the CLI attempt
	memViewGUIRunning      // hashing/registering in progress
)

// MemoryState carries all panel state for the Memory Forensics submenu.
type MemoryState struct {
	view memView

	// Active operation context.
	action      string // current sidebar action
	captureTool memory.CaptureTool
	captureBin  string
	outputPath  string
	startTime   time.Time
	elapsed     time.Duration

	// Capture progress.
	captureProgress memory.CaptureProgress
	captureResult   *memory.CaptureResult

	// Dump selection.
	dumps        []memory.DumpInfo
	dumpCursor   int
	selectedDump string

	// Analysis tracking.
	analysisAction  string // resolved analysis action (mem_vol_proc, etc.)
	pluginNames     []string
	pluginStatus    []memory.AnalysisStepStatus
	pluginTimes     []time.Duration
	currentStep     int
	analysisSummary *memory.AnalysisSummary

	// Single-plugin / custom result.
	singleResult *memory.PluginResult
	customPlugin string
	customArgs   string

	// YARA selection.
	yaraOptions []string
	yaraCursor  int
	yaraRules   string // resolved rules path
	yaraPlugin  string // "windows.yarascan" or "yarascan.YaraScan"

	// Symbol management.
	symbolView    int // 0=overview, 1=download windows, 2=download linux
	symbolMessage string

	// Generic select state (remote method, VR client).
	selectOptions []string
	selectCursor  int

	// Multi-step input state.
	input       textinput.Model
	remoteMethod int // 0=WinRM, 1=SSH, 2=PSExec
	remoteHost   string
	remoteUser   string
	remotePass   string
	remotePort   string

	// Error message.
	errorMsg string

	// Dismissable result lines (for placeholder views).
	resultLines []string

	// GUI-launch flow (Belkasoft / Magnet RAM Capture).
	guiToolName    string // human-friendly tool label
	guiToolURL     string // download URL for missing-tool message
	guiPickCursor  int    // 0=launch GUI, 1=CLI mode
}

// ---------------------------------------------------------------------------
// Async messages
// ---------------------------------------------------------------------------

type memTickMsg time.Time

type memCaptureProgressMsg struct {
	progress memory.CaptureProgress
}

type memCaptureDoneMsg struct {
	result memory.CaptureResult
}

type memAnalysisStepMsg struct {
	update memory.AnalysisStepUpdate
}

type memAnalysisDoneMsg struct {
	summary memory.AnalysisSummary
}

type memSinglePluginDoneMsg struct {
	result memory.PluginResult
}

type memSymbolDownloadDoneMsg struct {
	result symbolDownloadResult
}

type symbolDownloadResult struct {
	OS      string // "windows" or "linux"
	Files   int
	Bytes   int64
	Error   string
	Success bool
}

func memTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return memTickMsg(t)
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newMemTextInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 256
	ti.Width = 60
	ti.Focus()
	return ti
}

func newMemPasswordInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.CharLimit = 120
	ti.Width = 50
	ti.Focus()
	return ti
}

func (m Model) memCheckCase() bool {
	return m.ctx.ActiveCase != nil
}

// memToolID maps a logical capture tool to its registered tool ID.
func (m Model) memToolID(tool memory.CaptureTool) string {
	switch tool {
	case memory.ToolDumpIt:
		return "dumpit-win"
	case memory.ToolWinPmem:
		return "winpmem"
	case memory.ToolBelkasoft:
		return "belkasoft_ram"
	case memory.ToolMagnetRAM:
		return "magnet_ram"
	case memory.ToolAVML:
		return "avml-lnx"
	case memory.ToolLiME:
		return "lime-lnx"
	}
	return ""
}

// memCaptureManager builds a CaptureManager bound to the active case.
func (m Model) memCaptureManager() *memory.CaptureManager {
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	return memory.NewCaptureManager(
		m.ctx.RootDir, caseID, m.ctx.Hostname, m.ctx.Platform,
		m.ctx.Logger, m.ctx.ToolManager,
	)
}

// memVolatilityRunner builds a Volatility runner.
func (m Model) memVolatilityRunner() *memory.VolatilityRunner {
	return memory.NewVolatilityRunner(m.ctx.RootDir, m.ctx.Logger)
}

// ---------------------------------------------------------------------------
// Action dispatcher
// ---------------------------------------------------------------------------

// handleMemoryAction routes Memory Forensics submenu actions.
//
// Prerequisite policy: each operation validates ONLY what it actually needs.
// The submenu is never blocked from rendering. An active case is required for
// operations that produce evidence (capture, analysis), but Symbol Management
// runs without one.
func (m Model) handleMemoryAction(action string) (Model, tea.Cmd, bool) {
	if !strings.HasPrefix(action, "mem_") {
		return m, nil, false
	}

	m.clearPanelState()
	m.memState = MemoryState{action: action}

	switch action {
	case "mem_dumpit":
		return m.memStartCapture(memory.ToolDumpIt, "DumpIt", "dmp")
	case "mem_winpmem":
		return m.memStartCapture(memory.ToolWinPmem, "WinPmem", "raw")
	case "mem_belkasoft":
		return m.memStartGUICapture(memory.ToolBelkasoft, "Belkasoft RAM Capturer",
			"https://belkasoft.com/ram-capturer")
	case "mem_magnet":
		return m.memStartGUICapture(memory.ToolMagnetRAM, "Magnet RAM Capture",
			"https://www.magnetforensics.com/resources/magnet-ram-capture/")
	case "mem_avml":
		return m.memStartCapture(memory.ToolAVML, "AVML", "lime")
	case "mem_lime":
		return m.memStartLiMECapture()
	case "mem_vr":
		return m.memVelociraptorCapture()
	case "mem_remote":
		return m.memRemoteCaptureStart()

	case "mem_vol_profile":
		return m.memStartAnalysis(action)
	case "mem_vol_proc", "mem_vol_net", "mem_vol_malfind",
		"mem_vol_registry", "mem_vol_kmod", "mem_vol_timeline":
		return m.memStartSinglePluginAnalysis(action)
	case "mem_vol_yara":
		return m.memStartYara()
	case "mem_vol_custom":
		return m.memStartCustomPlugin()
	case "mem_vol_symbols":
		// Symbol Management has no prerequisites — works without a case.
		return m.memShowSymbols()
	}

	return m, nil, false
}

// memRequireCase shows the "no active case" prompt and returns false when the
// caller should abort. Use only in operations that genuinely need a case.
func (m *Model) memRequireCase() bool {
	if m.memCheckCase() {
		return true
	}
	m.memState.view = memViewNeedCase
	m.state = stateResult
	return false
}

// ---------------------------------------------------------------------------
// Capture flow
// ---------------------------------------------------------------------------

func (m Model) memStartCapture(tool memory.CaptureTool, label, ext string) (Model, tea.Cmd, bool) {
	// Check the specific capture tool before bothering the user about a case.
	cm := m.memCaptureManager()
	bin := cm.ToolPath(m.memToolID(tool))
	if bin == "" {
		m.memState.view = memViewNeedTool
		m.memState.errorMsg = label + " is not installed. Install via Configuration > Tool Management."
		m.state = stateResult
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}

	m.memState.captureTool = tool
	m.memState.captureBin = bin
	m.memState.outputPath = cm.SuggestedOutputPath(ext)
	m.memState.view = memViewCaptureConfirm
	m.state = stateResult
	return m, nil, true
}

func (m Model) memStartLiMECapture() (Model, tea.Cmd, bool) {
	cm := m.memCaptureManager()
	koPath := cm.LimeKoPath()
	if _, err := os.Stat(koPath); err != nil {
		m.memState.view = memViewLimeInstructions
		m.state = stateResult
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.captureTool = memory.ToolLiME
	m.memState.captureBin = koPath
	m.memState.outputPath = cm.SuggestedOutputPath("lime")
	m.memState.view = memViewCaptureConfirm
	m.state = stateResult
	return m, nil, true
}

// memStartGUICapture handles capture tools that are primarily GUI-driven
// (Belkasoft RAM Capturer, Magnet RAM Capture). The CLI flag surface for these
// products is undocumented or version-dependent, so we offer two paths:
//   1. Launch the GUI (`cmd /c start <bin>`) and let the analyst drive it,
//      then prompt for the dump file path so we can hash + register evidence.
//   2. CLI mode — try invoking the binary with an output path argument.
func (m Model) memStartGUICapture(tool memory.CaptureTool, label, downloadURL string) (Model, tea.Cmd, bool) {
	cm := m.memCaptureManager()
	bin := cm.ToolPath(m.memToolID(tool))
	if bin == "" {
		m.memState.view = memViewNeedTool
		m.memState.errorMsg = fmt.Sprintf(
			"%s is not installed.\n\nDownload from: %s\nPlace at: %s",
			label, downloadURL, expectedGUIPath(m.ctx.RootDir, tool))
		m.state = stateResult
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.captureTool = tool
	m.memState.captureBin = bin
	m.memState.guiToolName = label
	m.memState.guiToolURL = downloadURL
	m.memState.guiPickCursor = 0
	m.memState.view = memViewGUIChoose
	m.state = stateResult
	return m, nil, true
}

// expectedGUIPath returns the spec'd LocalPath for a GUI capture tool, used in
// the missing-tool message so the user knows where to drop the binary.
func expectedGUIPath(rootDir string, tool memory.CaptureTool) string {
	switch tool {
	case memory.ToolBelkasoft:
		return filepath.Join(rootDir, "bin", "windows", "belkasoft", "RamCapture64.exe")
	case memory.ToolMagnetRAM:
		return filepath.Join(rootDir, "bin", "windows", "magnet", "MagnetRAMCapture.exe")
	}
	return ""
}

// memLaunchGUI starts the chosen GUI capture tool in a detached window
// (`cmd /c start "" <bin>`) and moves to the "awaiting dump path" view.
func (m Model) memLaunchGUI() (Model, tea.Cmd) {
	bin := m.memState.captureBin
	if m.ctx.Logger != nil {
		m.ctx.Logger.Info("memory", "launching GUI capture tool: %s", bin)
	}
	// We don't wait on the process — the GUI runs interactively until the
	// analyst exits it. Using `cmd /c start` decouples it from our stdio.
	go func() {
		_ = exec.Command("cmd", "/c", "start", "", bin).Run()
	}()
	m.memState.view = memViewGUILaunched
	return m, nil
}

// memBeginGUICli runs the GUI tool in CLI mode with a user-supplied output
// path. Many of these tools ignore the argument and dump next to the EXE
// instead, so we still prompt for the actual dump path on completion.
func (m Model) memBeginGUICli(outputPath string) (Model, tea.Cmd) {
	bin := m.memState.captureBin
	m.memState.outputPath = outputPath
	m.memState.view = memViewGUIRunning
	m.memState.startTime = time.Now()
	go func() {
		// Best-effort CLI invocation — we let it complete or fail without
		// blocking. The analyst then provides the actual dump path.
		_ = exec.Command(bin, outputPath).Run()
	}()
	// After kicking it off, wait for the analyst to confirm + provide the
	// real dump location. The CLI may have ignored our outputPath entirely.
	m.memState.view = memViewGUIDumpPath
	m.memState.input = newMemTextInput("Path to produced dump file (e.g. " + outputPath + ")")
	m.memState.input.SetValue(outputPath)
	return m, m.memState.input.Focus()
}

// memCompleteGUICapture takes the analyst-supplied dump path, verifies it,
// hashes it, and registers it as evidence. The result lands on the standard
// memViewCaptureDone screen.
func (m Model) memCompleteGUICapture(dumpPath string) (Model, tea.Cmd) {
	if dumpPath == "" {
		m.statusMessage = "Dump path is required."
		return m, nil
	}
	info, err := os.Stat(dumpPath)
	if err != nil {
		m.memState.view = memViewError
		m.memState.errorMsg = "Dump file not found: " + err.Error()
		return m, nil
	}
	if info.IsDir() {
		m.memState.view = memViewError
		m.memState.errorMsg = "Path is a directory, not a file: " + dumpPath
		return m, nil
	}

	hash, hashErr := sha256OfFile(dumpPath)
	result := memory.CaptureResult{
		Tool:       m.memState.captureTool,
		Hostname:   m.ctx.Hostname,
		OutputPath: dumpPath,
		Size:       info.Size(),
		SHA256:     hash,
		Duration:   time.Since(m.memState.startTime),
		Success:    true,
	}
	if hashErr != nil {
		result.Error = "hash failed: " + hashErr.Error()
	}

	// Register as evidence in the case database.
	if m.ctx.ActiveCase != nil && m.ctx.CaseManager != nil {
		_, _ = m.ctx.CaseManager.AddEvidence(
			m.ctx.ActiveCase.ID, 0, "memory_dump", dumpPath)
	}

	m.memState.captureResult = &result
	m.memState.view = memViewCaptureDone
	return m, nil
}

// sha256OfFile streams a file through SHA256 and returns the hex digest.
func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (m Model) memBeginCapture() (Model, tea.Cmd) {
	m.memState.view = memViewCapturing
	m.memState.startTime = time.Now()

	cm := m.memCaptureManager()
	tool := m.memState.captureTool
	bin := m.memState.captureBin
	outPath := m.memState.outputPath

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()

		progressCh := make(chan memory.CaptureProgress, 16)
		var result memory.CaptureResult

		// Drain progress in a goroutine that sends bubbletea-compatible
		// messages via a tea.Program ticker substitute. We can't push to the
		// program loop directly from here, so we just collect the last value
		// and publish it via the periodic memTickMsg snapshot.
		go func() {
			for range progressCh {
				// Drained by the periodic ticker via getLastProgress.
			}
		}()

		if tool == memory.ToolLiME {
			result = cm.RunLiME(ctx, bin, outPath, nil)
		} else {
			req := memory.CaptureRequest{
				Tool:       tool,
				BinPath:    bin,
				OutputPath: outPath,
			}
			result = cm.Run(ctx, req, nil)
		}

		// Register evidence on success.
		if result.Success && m.ctx.ActiveCase != nil && m.ctx.CaseManager != nil {
			_, _ = m.ctx.CaseManager.AddEvidence(
				m.ctx.ActiveCase.ID, 0, "memory_dump", outPath)
		}

		return memCaptureDoneMsg{result: result}
	}

	return m, tea.Batch(memTickCmd(), cmd)
}

func (m Model) handleMemTick() (Model, tea.Cmd) {
	if m.memState.view == memViewCapturing ||
		m.memState.view == memViewAnalysisRunning ||
		m.memState.view == memViewSinglePluginRunning ||
		m.memState.view == memViewCustomPluginRunning ||
		m.memState.view == memViewSymbolsDownloading ||
		m.memState.view == memViewVRRunning ||
		m.memState.view == memViewRemoteRunning ||
		m.memState.view == memViewInstallingDeps {
		m.memState.elapsed = time.Since(m.memState.startTime)
		// Sample the dump file size for capture progress.
		if m.memState.view == memViewCapturing && m.memState.outputPath != "" {
			if info, err := os.Stat(m.memState.outputPath); err == nil {
				m.memState.captureProgress.BytesWritten = info.Size()
				if m.memState.captureProgress.TotalBytes == 0 {
					m.memState.captureProgress.TotalBytes = memory.TotalRAM()
				}
			}
		}
		return m, memTickCmd()
	}
	return m, nil
}

func (m Model) handleMemCaptureDone(result memory.CaptureResult) Model {
	m.memState.view = memViewCaptureDone
	m.memState.captureResult = &result
	m.state = stateResult
	return m
}

// handleMemDepsInstalled finalises the one-shot pip install: on success the
// user is dropped back to the analysis flow they originally requested; on
// failure the error is surfaced for inspection.
func (m Model) handleMemDepsInstalled(msg memDepsInstalledMsg) (Model, tea.Cmd) {
	if msg.err != nil {
		m.memState.view = memViewDepsFailed
		m.memState.errorMsg = msg.err.Error()
		return m, nil
	}
	// Re-enter the original analysis flow now that deps are ready.
	if m.memState.action != "" {
		mm, cmd, _ := m.handleMemoryAction(m.memState.action)
		return mm, cmd
	}
	m.memState.view = memViewNone
	m.state = stateSubMenu
	return m, nil
}

// ---------------------------------------------------------------------------
// Velociraptor & remote capture
// ---------------------------------------------------------------------------

func (m Model) memVelociraptorCapture() (Model, tea.Cmd, bool) {
	// Velociraptor capture: check Velociraptor first, then case.
	if m.ctx.VRManager == nil || !m.ctx.VRManager.BinaryInstalled() {
		m.memState.view = memViewError
		m.memState.errorMsg = "Velociraptor binary not installed. Configure it via [8] Configuration > [6] Download Required Tools."
		m.state = stateResult
		return m, nil, true
	}
	if !m.ctx.VRManager.State.Running {
		m.memState.view = memViewError
		m.memState.errorMsg = "Velociraptor server is not running. Start it via [1] Velociraptor > [2] Start Server."
		m.state = stateResult
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}

	// We cannot enumerate clients without a richer Velociraptor client API
	// surface (only offered in Phase 5). Show the operator-friendly message
	// and let them launch the artifact from the GUI.
	m.memState.view = memViewError
	m.memState.errorMsg = "Memory acquisition via Velociraptor agent must currently be launched from the Velociraptor GUI.\n\n" +
		"Use artifact: Windows.Memory.Acquisition (Windows) or Linux.Sys.AVML (Linux).\n" +
		"Once collected, import the result via [1] Velociraptor > [A] Import Offline Collection."
	m.state = stateResult
	return m, nil, true
}

func (m Model) memRemoteCaptureStart() (Model, tea.Cmd, bool) {
	// Remote capture writes evidence to the case after streaming back.
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.view = memViewRemoteMethod
	m.memState.selectCursor = 0
	if m.ctx.Platform == "linux" {
		m.memState.selectOptions = []string{"SSH (Linux target)"}
	} else {
		m.memState.selectOptions = []string{
			"WinRM (Windows target)",
			"SSH (Linux target)",
			"PSExec (Windows target)",
		}
	}
	m.state = stateResult
	return m, nil, true
}

func (m Model) memRemoteSelectMethod(idx int) (Model, tea.Cmd) {
	m.memState.remoteMethod = idx
	m.memState.view = memViewRemoteHost
	m.memState.input = newMemTextInput("Target hostname or IP")
	return m, m.memState.input.Focus()
}

func (m Model) memRemoteAdvanceHost(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Hostname is required."
		return m, nil
	}
	m.memState.remoteHost = value
	m.memState.view = memViewRemoteUser
	m.memState.input = newMemTextInput("Username")
	return m, m.memState.input.Focus()
}

func (m Model) memRemoteAdvanceUser(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Username is required."
		return m, nil
	}
	m.memState.remoteUser = value
	m.memState.view = memViewRemotePass
	if m.memState.remoteMethod == 1 {
		m.memState.input = newMemTextInput("Password or SSH key path")
	} else {
		m.memState.input = newMemPasswordInput("Password")
	}
	return m, m.memState.input.Focus()
}

func (m Model) memRemoteAdvancePass(value string) (Model, tea.Cmd) {
	m.memState.remotePass = value
	m.memState.view = memViewRemotePort
	defaultPort := "5985"
	switch m.memState.remoteMethod {
	case 1:
		defaultPort = "22"
	case 2:
		defaultPort = "445"
	}
	m.memState.input = newMemTextInput("Port (default " + defaultPort + ")")
	m.memState.input.SetValue(defaultPort)
	return m, m.memState.input.Focus()
}

func (m Model) memRemoteAdvancePort(value string) (Model, tea.Cmd) {
	m.memState.remotePort = value
	// internal/network/* is not implemented yet — show what would happen.
	m.memState.view = memViewRemoteDone
	methods := []string{"WinRM", "SSH", "PSExec"}
	method := methods[m.memState.remoteMethod]
	m.memState.resultLines = []string{
		"",
		"  " + WarningStyle.Render("Remote memory capture engine pending (Phase 6: Remote Operations)."),
		"",
		cSectionLabel("Capture Plan"),
		cField("Method", lipgloss.NewStyle().Foreground(ColorPrimary).Render(method)),
		cField("Target", lipgloss.NewStyle().Foreground(ColorText).Render(m.memState.remoteHost)),
		cField("User", lipgloss.NewStyle().Foreground(ColorText).Render(m.memState.remoteUser)),
		cField("Port", lipgloss.NewStyle().Foreground(ColorText).Render(m.memState.remotePort)),
		"",
		cHint("Workflow: copy capture tool → run remotely → stream dump back → cleanup → register evidence."),
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Analysis flow — dump selection
// ---------------------------------------------------------------------------

func (m Model) memStartAnalysis(action string) (Model, tea.Cmd, bool) {
	// Analysis prereqs: Volatility3 + Python first (it's hard to do anything
	// useful without them), then a case to write output into.
	if !m.memCheckVolatility() {
		m.state = stateResult
		// When the check decided to install pip deps, return its command.
		if m.memState.view == memViewInstallingDeps {
			return m, m.memInstallDeps(), true
		}
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.analysisAction = action
	m.memState.view = memViewDumpSelect
	m.memState.dumps = m.memListDumps()
	m.memState.dumpCursor = 0
	m.state = stateResult
	return m, nil, true
}

func (m Model) memStartSinglePluginAnalysis(action string) (Model, tea.Cmd, bool) {
	return m.memStartAnalysis(action)
}

func (m Model) memStartYara() (Model, tea.Cmd, bool) {
	if !m.memCheckVolatility() {
		m.state = stateResult
		if m.memState.view == memViewInstallingDeps {
			return m, m.memInstallDeps(), true
		}
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.analysisAction = "mem_vol_yara"
	m.memState.view = memViewDumpSelect
	m.memState.dumps = m.memListDumps()
	m.memState.dumpCursor = 0
	m.state = stateResult
	return m, nil, true
}

func (m Model) memStartCustomPlugin() (Model, tea.Cmd, bool) {
	if !m.memCheckVolatility() {
		m.state = stateResult
		if m.memState.view == memViewInstallingDeps {
			return m, m.memInstallDeps(), true
		}
		return m, nil, true
	}
	if !m.memRequireCase() {
		return m, nil, true
	}
	m.memState.analysisAction = "mem_vol_custom"
	m.memState.view = memViewDumpSelect
	m.memState.dumps = m.memListDumps()
	m.memState.dumpCursor = 0
	m.state = stateResult
	return m, nil, true
}

// memCheckVolatility verifies the analysis stack is ready: Volatility3 source
// is on disk, a Python 3 interpreter is detectable, and the one-shot pip
// install has run. On failure it sets the appropriate view (NeedVolatility /
// NeedPython / InstallingDeps) and returns false.
//
// When dependencies haven't been installed yet, this kicks off the install
// asynchronously and returns false — the caller's tea.Cmd is dropped. The
// user re-triggers the analysis after install completes.
func (m *Model) memCheckVolatility() bool {
	r := m.memVolatilityRunner()
	if !r.HasVolatilityScript() {
		m.memState.view = memViewNeedVolatility
		return false
	}
	if !r.HasPython() {
		m.memState.view = memViewNeedPython
		return false
	}
	// Both present — install pip deps once, lazily.
	if !r.DepsInstalled() {
		// View change is enough; the dispatcher's caller will return the
		// install command via memInstallDeps when it sees this view.
		m.memState.view = memViewInstallingDeps
		m.memState.startTime = time.Now()
		return false
	}
	return true
}

// memInstallDeps returns the tea.Cmd that runs `pip install -r requirements`
// and emits memDepsInstalledMsg when complete.
func (m Model) memInstallDeps() tea.Cmd {
	r := m.memVolatilityRunner()
	return tea.Batch(memTickCmd(), func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := r.InstallDeps(ctx)
		return memDepsInstalledMsg{err: err}
	})
}

type memDepsInstalledMsg struct {
	err error
}

// memListDumps returns dumps under the active case's memory directory.
func (m Model) memListDumps() []memory.DumpInfo {
	if m.ctx.ActiveCase == nil {
		return nil
	}
	dir := filepath.Join(m.ctx.RootDir, "output", m.ctx.ActiveCase.ID, "memory")
	dumps, _ := memory.ListDumps(dir)
	return dumps
}

// memSelectDump finalizes dump selection and routes to the next step.
func (m Model) memSelectDump(path string) (Model, tea.Cmd) {
	m.memState.selectedDump = path

	switch m.memState.analysisAction {
	case "mem_vol_profile":
		return m.memBeginFullAnalysis()
	case "mem_vol_proc":
		return m.memBeginSinglePlugin(m.memProcPlugin(), nil)
	case "mem_vol_net":
		return m.memBeginSinglePlugin(m.memNetPlugin(), nil)
	case "mem_vol_malfind":
		return m.memBeginSinglePlugin(m.memMalfindPlugin(), nil)
	case "mem_vol_registry":
		return m.memBeginSinglePlugin("windows.registry.hivelist", nil)
	case "mem_vol_kmod":
		return m.memBeginSinglePlugin("linux.lsmod", nil)
	case "mem_vol_timeline":
		return m.memBeginSinglePlugin("timeliner.Timeliner", nil)
	case "mem_vol_yara":
		// Move to YARA rule selection.
		m.memState.view = memViewYaraSelect
		m.memState.yaraOptions = []string{
			"Bundled malware rules (rules/yara/malware/)",
			"All bundled rules (rules/yara/)",
			"Custom rules file",
		}
		m.memState.yaraCursor = 0
		if m.ctx.Platform == "windows" {
			m.memState.yaraPlugin = "windows.yarascan"
		} else {
			m.memState.yaraPlugin = "yarascan.YaraScan"
		}
		return m, nil
	case "mem_vol_custom":
		m.memState.view = memViewCustomPlugin
		m.memState.input = newMemTextInput("Plugin name (e.g., windows.pslist, linux.bash)")
		return m, m.memState.input.Focus()
	}
	return m, nil
}

func (m Model) memProcPlugin() string {
	if m.ctx.Platform == "windows" {
		return "windows.pslist"
	}
	return "linux.pslist"
}

func (m Model) memNetPlugin() string {
	if m.ctx.Platform == "windows" {
		return "windows.netscan"
	}
	return "linux.sockstat"
}

func (m Model) memMalfindPlugin() string {
	if m.ctx.Platform == "windows" {
		return "windows.malfind"
	}
	return "linux.malfind"
}

// ---------------------------------------------------------------------------
// Full analysis
// ---------------------------------------------------------------------------

func (m Model) memBeginFullAnalysis() (Model, tea.Cmd) {
	m.memState.view = memViewAnalysisRunning
	m.memState.startTime = time.Now()

	dump := m.memState.selectedDump
	outDir := memory.AnalysisOutputDir(m.ctx.RootDir, m.ctx.ActiveCase.ID)
	r := m.memVolatilityRunner()

	// Pick plugin set based on host platform — without a separate detection call
	// for every action, we default to the analyst's platform. The runner also
	// performs OS detection internally before plugins run.
	var plugins []string
	if m.ctx.Platform == "windows" {
		plugins = memory.WindowsFullAnalysisPlugins()
	} else {
		plugins = memory.LinuxFullAnalysisPlugins()
	}

	m.memState.pluginNames = plugins
	m.memState.pluginStatus = make([]memory.AnalysisStepStatus, len(plugins))
	m.memState.pluginTimes = make([]time.Duration, len(plugins))
	for i := range plugins {
		m.memState.pluginStatus[i] = memory.StepPending
	}
	m.memState.currentStep = -1

	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		// We can't push step-by-step messages back to bubbletea from this
		// goroutine without a channel pump; for clarity we run all plugins
		// synchronously and emit a final analysis-done message. The TUI shows
		// elapsed time via memTickCmd while the run is in progress.
		req := memory.AnalysisRequest{
			DumpFile:  dump,
			OutputDir: outDir,
			Plugins:   plugins,
		}
		summary := r.RunFullAnalysis(ctx, req, nil)

		// Register evidence and findings.
		if summary.Success && caseManager != nil {
			if ev, err := caseManager.AddEvidence(caseID, 0, "memory_analysis", outDir); err == nil {
				for _, f := range summary.Findings {
					_ = caseManager.AddFinding(caseID, ev.ID, f.Severity, f.Title, f.Detail, "")
				}
			}
		}
		return memAnalysisDoneMsg{summary: summary}
	}
	return m, tea.Batch(memTickCmd(), cmd)
}

func (m Model) handleMemAnalysisStep(update memory.AnalysisStepUpdate) (Model, tea.Cmd) {
	if update.StepIndex < 0 || update.StepIndex >= len(m.memState.pluginStatus) {
		return m, nil
	}
	if update.Result == nil {
		m.memState.pluginStatus[update.StepIndex] = memory.StepRunning
		m.memState.currentStep = update.StepIndex
	} else {
		m.memState.pluginStatus[update.StepIndex] = update.Result.Status
		m.memState.pluginTimes[update.StepIndex] = update.Result.Duration
	}
	return m, nil
}

func (m Model) handleMemAnalysisDone(summary memory.AnalysisSummary) (Model, tea.Cmd) {
	m.memState.view = memViewAnalysisDone
	m.memState.analysisSummary = &summary
	// Mirror plugin statuses for display.
	for i, p := range summary.Plugins {
		if i < len(m.memState.pluginStatus) {
			m.memState.pluginStatus[i] = p.Status
			m.memState.pluginTimes[i] = p.Duration
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Single-plugin analysis (Process / Network / Malfind / Registry / Kmod / Timeline)
// ---------------------------------------------------------------------------

func (m Model) memBeginSinglePlugin(plugin string, extraArgs []string) (Model, tea.Cmd) {
	m.memState.view = memViewSinglePluginRunning
	m.memState.startTime = time.Now()
	m.memState.customPlugin = plugin

	dump := m.memState.selectedDump
	outDir := memory.AnalysisOutputDir(m.ctx.RootDir, m.ctx.ActiveCase.ID)
	r := m.memVolatilityRunner()
	caseID := m.ctx.ActiveCase.ID
	caseManager := m.ctx.CaseManager

	cmd := func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		result := r.RunPlugin(ctx, dump, plugin, outDir, extraArgs...)

		// Parse findings for malfind / yarascan and register them.
		if result.Status == memory.StepSuccess && caseManager != nil {
			var findings []memory.Finding
			switch plugin {
			case "windows.malfind", "linux.malfind":
				findings = memory.ParseMalfindFindings(result.OutFile, plugin)
			case "windows.yarascan", "yarascan.YaraScan":
				findings = memory.ParseYaraFindings(result.OutFile)
			}
			if len(findings) > 0 {
				if ev, err := caseManager.AddEvidence(caseID, 0, "memory_analysis", result.OutFile); err == nil {
					for _, f := range findings {
						_ = caseManager.AddFinding(caseID, ev.ID, f.Severity, f.Title, f.Detail, "")
					}
				}
			}
		}
		return memSinglePluginDoneMsg{result: result}
	}
	return m, tea.Batch(memTickCmd(), cmd)
}

func (m Model) handleMemSinglePluginDone(result memory.PluginResult) (Model, tea.Cmd) {
	m.memState.singleResult = &result
	switch m.memState.customPlugin {
	case "windows.malfind", "linux.malfind":
		m.memState.view = memViewMalfindResults
	case "windows.yarascan", "yarascan.YaraScan":
		m.memState.view = memViewYaraResults
	case "timeliner.Timeliner":
		m.memState.view = memViewTimelineDone
	default:
		if m.memState.action == "mem_vol_custom" {
			m.memState.view = memViewCustomPluginDone
		} else {
			m.memState.view = memViewSinglePluginDone
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// YARA flow
// ---------------------------------------------------------------------------

func (m Model) memYaraSelectRules(idx int) (Model, tea.Cmd) {
	switch idx {
	case 0:
		m.memState.yaraRules = filepath.Join(m.ctx.RootDir, "rules", "yara", "malware")
		return m.memBeginSinglePlugin(m.memState.yaraPlugin, []string{"--yara-file", m.memState.yaraRules})
	case 1:
		m.memState.yaraRules = filepath.Join(m.ctx.RootDir, "rules", "yara")
		return m.memBeginSinglePlugin(m.memState.yaraPlugin, []string{"--yara-file", m.memState.yaraRules})
	case 2:
		m.memState.view = memViewYaraCustomPath
		m.memState.input = newMemTextInput("Path to YARA rules file")
		return m, m.memState.input.Focus()
	}
	return m, nil
}

func (m Model) memYaraCustomPath(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Path is required."
		return m, nil
	}
	m.memState.yaraRules = value
	return m.memBeginSinglePlugin(m.memState.yaraPlugin, []string{"--yara-file", value})
}

// ---------------------------------------------------------------------------
// Custom plugin flow
// ---------------------------------------------------------------------------

func (m Model) memCustomPluginAdvance(value string) (Model, tea.Cmd) {
	if value == "" {
		m.statusMessage = "Plugin name is required."
		return m, nil
	}
	m.memState.customPlugin = value
	m.memState.view = memViewCustomPluginArgs
	m.memState.input = newMemTextInput("Additional arguments (optional, leave blank for none)")
	return m, m.memState.input.Focus()
}

func (m Model) memCustomPluginRun(value string) (Model, tea.Cmd) {
	m.memState.customArgs = value
	var extra []string
	if value != "" {
		extra = strings.Fields(value)
	}
	return m.memBeginSinglePlugin(m.memState.customPlugin, extra)
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

func (m Model) memShowSymbols() (Model, tea.Cmd, bool) {
	m.memState.view = memViewSymbols
	m.state = stateResult
	return m, nil, true
}

func (m Model) memDownloadSymbols(osFamily string) (Model, tea.Cmd) {
	m.memState.view = memViewSymbolsDownloading
	m.memState.startTime = time.Now()
	m.memState.symbolMessage = "Downloading " + osFamily + " symbols..."
	rootDir := m.ctx.RootDir

	cmd := func() tea.Msg {
		result := downloadVolatilitySymbols(rootDir, osFamily)
		return memSymbolDownloadDoneMsg{result: result}
	}
	return m, tea.Batch(memTickCmd(), cmd)
}

func (m Model) handleMemSymbolDownloadDone(result symbolDownloadResult) (Model, tea.Cmd) {
	m.memState.view = memViewSymbolsDone
	if result.Success {
		m.memState.symbolMessage = fmt.Sprintf(
			"Installed %d %s symbol files (%s).",
			result.Files, result.OS, memory.FormatBytes(result.Bytes))
	} else {
		m.memState.symbolMessage = "Symbol download failed: " + result.Error
	}
	return m, nil
}

// downloadVolatilitySymbols fetches and unpacks the official symbol bundles.
// The archive is a zip with the symbol files at the root.
func downloadVolatilitySymbols(rootDir, osFamily string) symbolDownloadResult {
	result := symbolDownloadResult{OS: osFamily}

	url := ""
	switch osFamily {
	case "windows":
		url = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
	case "linux":
		url = "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"
	default:
		result.Error = "unknown OS family"
		return result
	}

	destDir := filepath.Join(rootDir, "lib", "volatility3", "symbols", osFamily)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		result.Error = "creating symbol dir: " + err.Error()
		return result
	}

	// Stream download to a temp file.
	tmp, err := os.CreateTemp(destDir, "vg-symbols-*.zip")
	if err != nil {
		result.Error = "creating temp file: " + err.Error()
		return result
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		tmp.Close()
		result.Error = "download: " + err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		result.Error = fmt.Sprintf("download returned HTTP %d", resp.StatusCode)
		return result
	}

	written, err := io.Copy(tmp, resp.Body)
	tmp.Close()
	if err != nil {
		result.Error = "writing archive: " + err.Error()
		return result
	}
	result.Bytes = written

	files, err := unzipTo(tmpPath, destDir)
	if err != nil {
		result.Error = "extracting: " + err.Error()
		return result
	}
	result.Files = files
	result.Success = true
	return result
}

// ---------------------------------------------------------------------------
// Update — key dispatch
// ---------------------------------------------------------------------------

func (m Model) memoryUpdate(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	if m.memState.view == memViewNone {
		return m, nil, false
	}
	key := msg.String()

	switch m.memState.view {
	case memViewNeedCase:
		switch key {
		case "y", "Y":
			m.memState.view = memViewNone
			m2, cmd, _ := m.handleConfigAction("cfg_create_case")
			return m2, cmd, true
		default:
			m.memState.view = memViewNone
			m.state = stateSubMenu
			return m, nil, true
		}

	case memViewNeedTool, memViewNeedVolatility, memViewNeedPython,
		memViewDepsFailed, memViewError, memViewLimeInstructions:
		m.memState.view = memViewNone
		m.state = stateSubMenu
		return m, nil, true

	case memViewInstallingDeps:
		// Block input while the pip install runs. Completion is handled by
		// memDepsInstalledMsg.
		return m, nil, true

	case memViewCaptureConfirm:
		switch key {
		case "y", "Y":
			mm, cmd := m.memBeginCapture()
			return mm, cmd, true
		default:
			m.memState.view = memViewNone
			m.state = stateSubMenu
			m.statusMessage = "Capture cancelled."
			return m, nil, true
		}

	// GUI capture (Belkasoft / Magnet) — pick launch mode.
	case memViewGUIChoose:
		switch key {
		case "esc":
			m.memState.view = memViewNone
			m.state = stateSubMenu
			m.statusMessage = "Capture cancelled."
			return m, nil, true
		case "up", "k":
			if m.memState.guiPickCursor > 0 {
				m.memState.guiPickCursor--
			}
			return m, nil, true
		case "down", "j":
			if m.memState.guiPickCursor < 1 {
				m.memState.guiPickCursor++
			}
			return m, nil, true
		case "enter", "1", "2":
			pick := m.memState.guiPickCursor
			if key == "1" {
				pick = 0
			} else if key == "2" {
				pick = 1
			}
			if pick == 0 {
				mm, cmd := m.memLaunchGUI()
				return mm, cmd, true
			}
			cm := m.memCaptureManager()
			suggested := cm.SuggestedOutputPath("dmp")
			m.memState.view = memViewGUICliPath
			m.memState.input = newMemTextInput("Output path for capture")
			m.memState.input.SetValue(suggested)
			return m, m.memState.input.Focus(), true
		}
		return m, nil, true

	// After the GUI is launched, prompt the analyst to enter the dump path.
	case memViewGUILaunched:
		switch key {
		case "esc":
			m.memState.view = memViewNone
			m.state = stateSubMenu
			m.statusMessage = "Capture cancelled."
			return m, nil, true
		case "enter", " ":
			m.memState.view = memViewGUIDumpPath
			m.memState.input = newMemTextInput("Path to produced dump file")
			m.memState.startTime = time.Now()
			return m, m.memState.input.Focus(), true
		}
		return m, nil, true

	case memViewGUIDumpPath:
		return m.memUpdateTextInput(msg, key, m.memCompleteGUICapture)

	case memViewGUICliPath:
		return m.memUpdateTextInput(msg, key, func(value string) (Model, tea.Cmd) {
			if value == "" {
				m.statusMessage = "Output path is required."
				return m, nil
			}
			return m.memBeginGUICli(value)
		})

	case memViewGUIRunning:
		return m, nil, true

	case memViewCapturing,
		memViewAnalysisRunning,
		memViewSinglePluginRunning,
		memViewCustomPluginRunning,
		memViewSymbolsDownloading,
		memViewVRRunning,
		memViewRemoteRunning:
		// Block input while async work runs.
		return m, nil, true

	case memViewCaptureDone, memViewAnalysisDone, memViewSinglePluginDone,
		memViewMalfindResults, memViewYaraResults, memViewTimelineDone,
		memViewCustomPluginDone, memViewSymbolsDone, memViewVRDone, memViewRemoteDone:
		m.memState.view = memViewNone
		m.state = stateSubMenu
		return m, nil, true

	case memViewDumpSelect:
		return m.memUpdateDumpSelect(key)

	case memViewDumpPathInput:
		return m.memUpdateDumpPathInput(msg, key)

	case memViewYaraSelect:
		switch key {
		case "esc":
			m.memState.view = memViewNone
			m.state = stateSubMenu
			return m, nil, true
		case "up", "k":
			if m.memState.yaraCursor > 0 {
				m.memState.yaraCursor--
			}
			return m, nil, true
		case "down", "j":
			if m.memState.yaraCursor < len(m.memState.yaraOptions)-1 {
				m.memState.yaraCursor++
			}
			return m, nil, true
		case "enter":
			mm, cmd := m.memYaraSelectRules(m.memState.yaraCursor)
			return mm, cmd, true
		case "1", "2", "3":
			idx := int(key[0]-'0') - 1
			if idx < len(m.memState.yaraOptions) {
				m.memState.yaraCursor = idx
				mm, cmd := m.memYaraSelectRules(idx)
				return mm, cmd, true
			}
		}
		return m, nil, true

	case memViewYaraCustomPath:
		return m.memUpdateTextInput(msg, key, m.memYaraCustomPath)

	case memViewCustomPlugin:
		return m.memUpdateTextInput(msg, key, m.memCustomPluginAdvance)

	case memViewCustomPluginArgs:
		return m.memUpdateTextInput(msg, key, m.memCustomPluginRun)

	case memViewSymbols:
		switch key {
		case "esc":
			m.memState.view = memViewNone
			m.state = stateSubMenu
			return m, nil, true
		case "1":
			// Refresh status — re-render handles this.
			return m, nil, true
		case "2":
			mm, cmd := m.memDownloadSymbols("windows")
			return mm, cmd, true
		case "3":
			mm, cmd := m.memDownloadSymbols("linux")
			return mm, cmd, true
		}
		return m, nil, true

	case memViewRemoteMethod:
		switch key {
		case "esc":
			m.memState.view = memViewNone
			m.state = stateSubMenu
			return m, nil, true
		case "up", "k":
			if m.memState.selectCursor > 0 {
				m.memState.selectCursor--
			}
			return m, nil, true
		case "down", "j":
			if m.memState.selectCursor < len(m.memState.selectOptions)-1 {
				m.memState.selectCursor++
			}
			return m, nil, true
		case "enter":
			mm, cmd := m.memRemoteSelectMethod(m.memState.selectCursor)
			return mm, cmd, true
		case "1", "2", "3":
			idx := int(key[0]-'0') - 1
			if idx < len(m.memState.selectOptions) {
				m.memState.selectCursor = idx
				mm, cmd := m.memRemoteSelectMethod(idx)
				return mm, cmd, true
			}
		}
		return m, nil, true

	case memViewRemoteHost:
		return m.memUpdateTextInput(msg, key, m.memRemoteAdvanceHost)
	case memViewRemoteUser:
		return m.memUpdateTextInput(msg, key, m.memRemoteAdvanceUser)
	case memViewRemotePass:
		return m.memUpdateTextInput(msg, key, m.memRemoteAdvancePass)
	case memViewRemotePort:
		return m.memUpdateTextInput(msg, key, m.memRemoteAdvancePort)
	}

	return m, nil, false
}

// memUpdateTextInput is a tiny helper for memory-panel text input handling.
func (m Model) memUpdateTextInput(msg tea.KeyMsg, key string, activate func(string) (Model, tea.Cmd)) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.memState.view = memViewNone
		m.state = stateSubMenu
		m.statusMessage = "Cancelled."
		return m, nil, true
	case "enter":
		value := strings.TrimSpace(m.memState.input.Value())
		mm, cmd := activate(value)
		return mm, cmd, true
	default:
		var cmd tea.Cmd
		m.memState.input, cmd = m.memState.input.Update(msg)
		return m, cmd, true
	}
}

func (m Model) memUpdateDumpSelect(key string) (Model, tea.Cmd, bool) {
	switch key {
	case "esc":
		m.memState.view = memViewNone
		m.state = stateSubMenu
		return m, nil, true
	case "up", "k":
		if m.memState.dumpCursor > 0 {
			m.memState.dumpCursor--
		}
		return m, nil, true
	case "down", "j":
		if m.memState.dumpCursor < len(m.memState.dumps)-1 {
			m.memState.dumpCursor++
		}
		return m, nil, true
	case "p", "P":
		m.memState.view = memViewDumpPathInput
		m.memState.input = newMemTextInput("Absolute path to dump file")
		return m, m.memState.input.Focus(), true
	case "enter":
		if len(m.memState.dumps) == 0 {
			m.memState.view = memViewDumpPathInput
			m.memState.input = newMemTextInput("Absolute path to dump file")
			return m, m.memState.input.Focus(), true
		}
		dump := m.memState.dumps[m.memState.dumpCursor]
		mm, cmd := m.memSelectDump(dump.Path)
		return mm, cmd, true
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(key[0]-'0') - 1
		if idx >= 0 && idx < len(m.memState.dumps) {
			m.memState.dumpCursor = idx
			dump := m.memState.dumps[idx]
			mm, cmd := m.memSelectDump(dump.Path)
			return mm, cmd, true
		}
	}
	return m, nil, true
}

func (m Model) memUpdateDumpPathInput(msg tea.KeyMsg, key string) (Model, tea.Cmd, bool) {
	return m.memUpdateTextInput(msg, key, func(value string) (Model, tea.Cmd) {
		if value == "" {
			m.statusMessage = "Path is required."
			return m, nil
		}
		if _, err := os.Stat(value); err != nil {
			m.memState.errorMsg = "Dump file not found: " + value
			m.memState.view = memViewError
			return m, nil
		}
		return m.memSelectDump(value)
	})
}
