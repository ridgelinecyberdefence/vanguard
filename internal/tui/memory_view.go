package tui

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/memory"
)

// memoryContent renders the active Memory Forensics panel view.
func (m Model) memoryContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Memory Forensics"),
		"",
	}

	switch m.memState.view {
	case memViewNeedCase:
		lines = append(lines, m.memViewNeedCase(width)...)
	case memViewNeedTool:
		lines = append(lines, m.memViewNeedTool(width)...)
	case memViewNeedVolatility:
		lines = append(lines, m.memViewNeedVolatility(width)...)
	case memViewNeedPython:
		lines = append(lines, m.memViewNeedPython(width)...)
	case memViewInstallingDeps:
		lines = append(lines, m.memViewInstallingDeps(width)...)
	case memViewDepsFailed:
		lines = append(lines, m.memViewDepsFailed(width)...)
	case memViewError:
		lines = append(lines, m.memViewError(width)...)
	case memViewLimeInstructions:
		lines = append(lines, m.memViewLimeInstructions(width)...)

	case memViewCaptureConfirm:
		lines = append(lines, m.memViewCaptureConfirm(width)...)
	case memViewCapturing:
		lines = append(lines, m.memViewCapturing(width)...)
	case memViewCaptureDone:
		lines = append(lines, m.memViewCaptureDone(width)...)

	// GUI capture flow.
	case memViewGUIChoose:
		lines = append(lines, m.memViewGUIChoose(width)...)
	case memViewGUILaunched:
		lines = append(lines, m.memViewGUILaunched(width)...)
	case memViewGUIDumpPath:
		lines = append(lines, m.memViewSimpleInput(
			m.memState.guiToolName+" — Capture Complete",
			"Path to produced dump file:")...)
	case memViewGUICliPath:
		lines = append(lines, m.memViewSimpleInput(
			m.memState.guiToolName+" — CLI Mode",
			"Output path:")...)
	case memViewGUIRunning:
		lines = append(lines, m.memViewGUIRunning(width)...)

	case memViewDumpSelect:
		lines = append(lines, m.memViewDumpSelect(width)...)
	case memViewDumpPathInput:
		lines = append(lines, m.memViewSimpleInput("Custom Dump Path", "Absolute path to memory dump file:")...)

	case memViewAnalysisRunning:
		lines = append(lines, m.memViewAnalysisRunning(width)...)
	case memViewAnalysisDone:
		lines = append(lines, m.memViewAnalysisDone(width)...)

	case memViewSinglePluginRunning:
		lines = append(lines, m.memViewSinglePluginRunning(width)...)
	case memViewSinglePluginDone:
		lines = append(lines, m.memViewSinglePluginDone(width)...)

	case memViewMalfindResults:
		lines = append(lines, m.memViewMalfindResults(width)...)
	case memViewYaraSelect:
		lines = append(lines, m.memViewYaraSelect(width)...)
	case memViewYaraCustomPath:
		lines = append(lines, m.memViewSimpleInput("Custom YARA Rules", "Path to YARA rules file:")...)
	case memViewYaraResults:
		lines = append(lines, m.memViewYaraResults(width)...)
	case memViewTimelineDone:
		lines = append(lines, m.memViewTimelineDone(width)...)

	case memViewCustomPlugin:
		lines = append(lines, m.memViewSimpleInput("Custom Volatility Plugin", "Plugin name (e.g., windows.pslist):")...)
	case memViewCustomPluginArgs:
		lines = append(lines, m.memViewSimpleInput("Custom Volatility Plugin", "Additional arguments (optional):")...)
	case memViewCustomPluginRunning:
		lines = append(lines, m.memViewSinglePluginRunning(width)...)
	case memViewCustomPluginDone:
		lines = append(lines, m.memViewSinglePluginDone(width)...)

	case memViewSymbols:
		lines = append(lines, m.memViewSymbols(width)...)
	case memViewSymbolsDownloading:
		lines = append(lines, m.memViewSymbolsDownloading(width)...)
	case memViewSymbolsDone:
		lines = append(lines, m.memViewSymbolsDone(width)...)

	case memViewRemoteMethod:
		lines = append(lines, m.memViewRemoteMethod(width)...)
	case memViewRemoteHost:
		lines = append(lines, m.memViewSimpleInput("Remote Capture", "Target hostname or IP:")...)
	case memViewRemoteUser:
		lines = append(lines, m.memViewSimpleInput("Remote Capture", "Username:")...)
	case memViewRemotePass:
		lines = append(lines, m.memViewSimpleInput("Remote Capture", "Password / SSH key:")...)
	case memViewRemotePort:
		lines = append(lines, m.memViewSimpleInput("Remote Capture", "Port:")...)
	case memViewRemoteRunning:
		lines = append(lines, m.memViewRemoteRunning(width)...)
	case memViewRemoteDone:
		lines = append(lines, m.memState.resultLines...)
		lines = append(lines, "", cHint("Press any key to return"))
	}

	return lines
}

// ---------------------------------------------------------------------------
// Common views
// ---------------------------------------------------------------------------

func (m Model) memViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Memory Forensics"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
		"",
		cHint("A case is required to organise memory captures and analysis output."),
	}
}

func (m Model) memViewNeedTool(width int) []string {
	return []string{
		cSectionLabel("Memory Capture"), cRule(width),
		"",
		"  " + ErrorStyle.Render("Tool not available"),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(m.memState.errorMsg),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) memViewNeedVolatility(width int) []string {
	return []string{
		cSectionLabel("Volatility3 Required"), cRule(width),
		"",
		"  " + ErrorStyle.Render("Volatility3 framework is not installed."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Install via [8] Configuration > [6] Download Required Tools."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"VanGuard will fetch the latest stable Volatility3 source from"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"github.com/volatilityfoundation/volatility3 into lib/volatility3/."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"Python 3 is also required to run Volatility3 — VanGuard will check"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"for it the first time you launch a memory analysis."),
		"",
		cHint("Press any key to return"),
	}
}

// memViewNeedPython is shown when Volatility3 is installed but no Python 3
// interpreter could be located. Two install paths are documented: system-wide
// vs. portable / embedded.
func (m Model) memViewNeedPython(width int) []string {
	return []string{
		cSectionLabel("Python 3 Required for Volatility3"), cRule(width),
		"",
		"  " + WarningStyle.Render("Volatility3 is installed but Python 3 was not found."),
		"",
		cSectionLabel("Options"),
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("1. ") +
			lipgloss.NewStyle().Foreground(ColorText).Render("Install Python 3 system-wide:"),
		"     " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"https://www.python.org/downloads/"),
		"     " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"After install, restart VanGuard."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("2. ") +
			lipgloss.NewStyle().Foreground(ColorText).Render("Place portable Python 3 in lib/python-embedded/"),
		"     " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Download embeddable Python from python.org:"),
		"     " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip"),
		"     " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"Extract to: lib/python-embedded/"),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"VanGuard will detect Python 3 automatically on next launch."),
		"",
		cHint("Press any key to return"),
	}
}

// memViewInstallingDeps is shown while `pip install -r requirements.txt`
// runs against the freshly-downloaded Volatility3 source. This is a one-shot
// install — the .vanguard_deps_installed marker prevents re-runs.
func (m Model) memViewInstallingDeps(width int) []string {
	return []string{
		cSectionLabel("Installing Volatility3 Dependencies"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(
			"[▸] Installing Volatility3 dependencies... this may take a minute."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Running: python -m pip install -r lib/volatility3/requirements.txt"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"This runs once — subsequent analyses skip the install."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: " + formatElapsed(m.memState.elapsed)),
	}
}

// memViewDepsFailed surfaces a pip install failure (e.g. no network, missing
// build tools, locked-down PyPI mirror).
func (m Model) memViewDepsFailed(width int) []string {
	out := []string{
		cSectionLabel("Dependency Installation Failed"), cRule(width),
		"",
		"  " + ErrorStyle.Render("pip install -r requirements.txt failed."),
		"",
	}
	for _, line := range strings.Split(m.memState.errorMsg, "\n") {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(line))
	}
	out = append(out,
		"",
		"  "+lipgloss.NewStyle().Foreground(ColorText).Render(
			"Try installing manually: cd lib/volatility3 && pip install -r requirements.txt"),
		"",
		cHint("Press any key to return"))
	return out
}

func (m Model) memViewError(width int) []string {
	out := []string{
		cSectionLabel("Memory Forensics"), cRule(width),
		"",
	}
	for _, line := range strings.Split(m.memState.errorMsg, "\n") {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) memViewLimeInstructions(width int) []string {
	kernel := "unknown (run 'uname -r' to check)"
	return []string{
		cSectionLabel("LiME Kernel Module Required"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"LiME requires compilation for the target kernel."),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 50)),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"On the target system (or one with matching kernel headers):"),
		"",
		cHint("  1. git clone https://github.com/504ensicsLabs/LiME"),
		cHint("  2. cd LiME/src"),
		cHint("  3. make"),
		cHint("  4. Copy lime-<kernel>.ko to VanGuard/bin/linux/lime.ko"),
		"",
		cField("Current kernel", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(kernel)),
		"",
		cHint("Press any key to return"),
	}
}

// ---------------------------------------------------------------------------
// GUI capture views (Belkasoft / Magnet RAM Capture)
// ---------------------------------------------------------------------------

// memViewGUIChoose offers the analyst a choice between launching the GUI or
// attempting CLI mode. CLI flag support varies between tool versions, so we
// surface both options and document the caveat.
func (m Model) memViewGUIChoose(width int) []string {
	options := []string{
		"Launch GUI (recommended)",
		"CLI mode — pass output path (may not be supported by all versions)",
	}
	lines := []string{
		cSectionLabel(m.memState.guiToolName), cRule(width),
		"",
		cField("Binary", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.memState.captureBin)),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			m.memState.guiToolName+" may require GUI interaction."),
		"",
	}
	for i, opt := range options {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.memState.guiPickCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+shortcut+" "+opt))
		} else {
			lines = append(lines, "    "+
				lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(opt))
		}
	}
	if !m.ctx.Elevated {
		lines = append(lines, "",
			"  "+WarningStyle.Render("WARNING: Memory capture requires Administrator privileges."))
	}
	lines = append(lines, "", cHint("Enter: select  Esc: cancel"))
	return lines
}

// memViewGUILaunched is shown after we kick off the GUI, while waiting for
// the analyst to perform the capture and confirm completion.
func (m Model) memViewGUILaunched(width int) []string {
	return []string{
		cSectionLabel(m.memState.guiToolName + " — GUI Launched"), cRule(width),
		"",
		"  " + SuccessStyle.Render("GUI started. Complete the capture in the tool's window."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"When the capture is complete, press Enter and provide the path to"),
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"the produced dump file. VanGuard will hash it and register evidence."),
		"",
		cHint("Enter: continue  Esc: cancel"),
	}
}

// memViewGUIRunning is shown briefly while the CLI invocation is in flight.
func (m Model) memViewGUIRunning(width int) []string {
	return []string{
		cSectionLabel(m.memState.guiToolName + " — Running"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(
			"[▸] Capture running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)),
	}
}

// ---------------------------------------------------------------------------
// Capture views
// ---------------------------------------------------------------------------

func (m Model) memViewCaptureConfirm(width int) []string {
	totalRAM := memory.TotalRAM()
	ramStr := "unknown"
	if totalRAM > 0 {
		ramStr = memory.FormatBytes(totalRAM)
	}

	toolName := captureToolLabel(m.memState.captureTool)
	lines := []string{
		cSectionLabel("Memory Capture — " + toolName), cRule(width),
		"",
		cField("Host", lipgloss.NewStyle().Foreground(ColorText).Render(m.ctx.Hostname)),
		cField("RAM", lipgloss.NewStyle().Foreground(ColorText).Render(ramStr)),
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.memState.outputPath)),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"This will capture a full memory dump."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Estimated time depends on RAM size."),
		"  " + WarningStyle.Render("Ensure sufficient disk space (RAM size + 10%)."),
		"",
	}

	if !m.ctx.Elevated {
		lines = append(lines,
			"  "+ErrorStyle.Render("WARNING: Memory capture requires Administrator/root privileges."),
			"")
	}

	lines = append(lines, "  "+WarningStyle.Render("Proceed? (y/n)"))
	return lines
}

func (m Model) memViewCapturing(width int) []string {
	toolName := captureToolLabel(m.memState.captureTool)
	lines := []string{
		cSectionLabel("Memory Capture — " + toolName), cRule(width),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.memState.outputPath)),
		"",
	}

	bytes := m.memState.captureProgress.BytesWritten
	total := m.memState.captureProgress.TotalBytes
	if total == 0 {
		total = memory.TotalRAM()
	}

	statusLine := lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).
		Render("[▸] Capturing memory...")
	lines = append(lines, "  "+statusLine)

	if bytes > 0 {
		var progressLine string
		if total > 0 {
			pct := float64(bytes) / float64(total) * 100
			if pct > 100 {
				pct = 100
			}
			progressLine = fmt.Sprintf("Capturing... %s / %s (%.0f%%)",
				memory.FormatBytes(bytes), memory.FormatBytes(total), pct)
		} else {
			progressLine = fmt.Sprintf("Captured: %s", memory.FormatBytes(bytes))
		}
		lines = append(lines,
			"  "+lipgloss.NewStyle().Foreground(ColorText).Render(progressLine))

		if total > 0 {
			lines = append(lines, "  "+memProgressBar(width, bytes, total))
		}
	}

	lines = append(lines, "")
	lines = append(lines,
		"  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)))

	if !m.ctx.Elevated {
		lines = append(lines, "")
		lines = append(lines, "  "+WarningStyle.Render(
			"WARNING: Capturing without elevation may fail or produce a partial image."))
	}
	return lines
}

func (m Model) memViewCaptureDone(width int) []string {
	lines := []string{
		cSectionLabel("Memory Capture Complete"), cRule(width),
		"",
	}

	if m.memState.captureResult == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	r := m.memState.captureResult
	if !r.Success {
		lines = append(lines,
			"  "+ErrorStyle.Render("Capture failed."),
			"",
			cField("Error", lipgloss.NewStyle().Foreground(ColorError).Render(r.Error)),
		)
		if r.Stderr != "" {
			lines = append(lines, "")
			lines = append(lines, cSectionLabel("Stderr"))
			for _, line := range splitForView(r.Stderr, 12) {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(line))
			}
		}
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	lines = append(lines,
		"  "+SuccessStyle.Render("Memory capture completed."),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutputPath)),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(memory.FormatBytes(r.Size))),
		cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.SHA256)),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
		"",
		cHint("Run [5] Auto-Profile & Full Analysis to analyze this dump."),
		"",
		cHint("Press any key to return"),
	)
	return lines
}

// ---------------------------------------------------------------------------
// Dump selection
// ---------------------------------------------------------------------------

func (m Model) memViewDumpSelect(width int) []string {
	lines := []string{
		cSectionLabel("Select Memory Dump"), cRule(width),
		"",
	}

	if len(m.memState.dumps) == 0 {
		lines = append(lines,
			"  "+WarningStyle.Render("No memory dumps found."),
			"",
			cHint("Capture memory first with options [1]-[4]."),
			"",
			cHint("Press [P] to enter a custom path or Esc to cancel."),
		)
		return lines
	}

	for i, dump := range m.memState.dumps {
		selected := i == m.memState.dumpCursor
		shortcut := ""
		if i < 9 {
			shortcut = fmt.Sprintf("[%d]", i+1)
		} else {
			shortcut = "   "
		}

		row := fmt.Sprintf("%s %-40s %10s   %s",
			shortcut,
			truncate(dump.Name, 40),
			memory.FormatBytes(dump.Size),
			dump.Modified.Format("2006-01-02 15:04"))

		if selected {
			lines = append(lines,
				"  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> "+row))
		} else {
			lines = append(lines,
				"    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}

	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  P: enter custom path  Esc: cancel"))
	return lines
}

// ---------------------------------------------------------------------------
// Analysis views
// ---------------------------------------------------------------------------

func (m Model) memViewAnalysisRunning(width int) []string {
	dumpName := filepath.Base(m.memState.selectedDump)
	lines := []string{
		cSectionLabel("Auto-Analysis — " + dumpName), cRule(width),
		"",
		cField("Dump", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.memState.selectedDump)),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 50)),
	}

	for i, plugin := range m.memState.pluginNames {
		status := m.memState.pluginStatus[i]
		dur := m.memState.pluginTimes[i]
		label := memory.PluginPretty(plugin)

		var icon, nameStr, durStr string
		switch status {
		case memory.StepPending:
			icon = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("[ ]")
			nameStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(label)
		case memory.StepRunning:
			icon = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸]")
			nameStr = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(label)
			durStr = lipgloss.NewStyle().Foreground(ColorPrimary).Render("running...")
		case memory.StepSuccess:
			icon = lipgloss.NewStyle().Foreground(ColorSuccess).Render("[✓]")
			nameStr = lipgloss.NewStyle().Foreground(ColorText).Render(label)
			durStr = lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
				fmt.Sprintf("%d sec", int(dur.Seconds())))
		case memory.StepFailed:
			icon = lipgloss.NewStyle().Foreground(ColorError).Render("[✗]")
			nameStr = lipgloss.NewStyle().Foreground(ColorError).Render(label)
			durStr = lipgloss.NewStyle().Foreground(ColorError).Render("failed")
		case memory.StepSkipped:
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s %-35s %s", icon, nameStr, durStr))
	}

	lines = append(lines, "")
	lines = append(lines,
		"  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)))
	return lines
}

func (m Model) memViewAnalysisDone(width int) []string {
	lines := []string{
		cSectionLabel("Analysis Complete"), cRule(width),
		"",
	}

	s := m.memState.analysisSummary
	if s == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No summary data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	if s.Error != "" {
		lines = append(lines,
			"  "+ErrorStyle.Render("Analysis failed: "+s.Error),
			"", cHint("Press any key to return"))
		return lines
	}

	lines = append(lines,
		"  "+SuccessStyle.Render("Memory analysis completed."),
		"",
		cField("Dump", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(filepath.Base(s.DumpFile))),
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(s.OutputDir)),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			s.Duration.Truncate(time.Second).String())),
	)
	if s.DetectedOS != "" {
		lines = append(lines,
			cField("Detected OS", lipgloss.NewStyle().Foreground(ColorPrimary).Render(s.DetectedOS)))
	}

	lines = append(lines, "", cSectionLabel("Counts"))
	lines = append(lines,
		cField("Processes", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", s.Processes))),
		cField("Connections", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", s.Connections))),
		cField("Suspicious", lipgloss.NewStyle().Foreground(ColorWarning).Render(fmt.Sprintf("%d", s.Suspicious))),
		cField("Services", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", s.Services))),
		cField("Registry Hives", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", s.RegistryHives))),
		cField("Kernel Modules", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", s.KernelModules))),
	)

	if len(s.Findings) > 0 {
		lines = append(lines, "", cSectionLabel("Findings"))
		max := 8
		for i, f := range s.Findings {
			if i >= max {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					fmt.Sprintf("... %d more findings — see %s", len(s.Findings)-max, s.OutputDir)))
				break
			}
			lines = append(lines, "  "+formatMemFinding(f))
		}
		lines = append(lines, "",
			"  "+WarningStyle.Render("Critical findings flagged — review malfind output."))
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// Single plugin views
// ---------------------------------------------------------------------------

func (m Model) memViewSinglePluginRunning(width int) []string {
	plugin := m.memState.customPlugin
	if plugin == "" {
		plugin = "(plugin)"
	}
	lines := []string{
		cSectionLabel("Running plugin: " + plugin), cRule(width),
		"",
		cField("Dump", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(filepath.Base(m.memState.selectedDump))),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)),
	}
	return lines
}

func (m Model) memViewSinglePluginDone(width int) []string {
	plugin := m.memState.customPlugin
	lines := []string{
		cSectionLabel("Plugin Complete: " + plugin), cRule(width),
		"",
	}

	r := m.memState.singleResult
	if r == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	if r.Status == memory.StepFailed {
		lines = append(lines,
			"  "+ErrorStyle.Render("Plugin failed."),
			"",
			cField("Error", lipgloss.NewStyle().Foreground(ColorError).Render(r.Error)))

		if strings.Contains(r.Error, "symbol tables") {
			lines = append(lines, "",
				"  "+WarningStyle.Render("Open Memory Forensics > [C] Symbol Management to install."))
		}
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	lines = append(lines,
		"  "+SuccessStyle.Render("Plugin completed."),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutFile)),
		cField("Lines", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", r.Lines))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
		"",
	)

	// Show first ~20 lines of output as preview.
	if data, err := os.ReadFile(r.OutFile); err == nil {
		preview := splitForView(string(data), 20)
		if len(preview) > 0 {
			lines = append(lines, cSectionLabel("Output (first lines)"))
			for _, line := range preview {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(line))
			}
		}
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) memViewMalfindResults(width int) []string {
	lines := []string{
		cSectionLabel("Malfind Results"), cRule(width),
		"",
	}

	r := m.memState.singleResult
	if r == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	if r.Status == memory.StepFailed {
		lines = append(lines, "  "+ErrorStyle.Render("Plugin failed: "+r.Error))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	findings := memory.ParseMalfindFindings(r.OutFile, m.memState.customPlugin)
	if len(findings) == 0 {
		lines = append(lines, "  "+SuccessStyle.Render("No suspicious memory regions detected."))
	} else {
		for _, f := range findings {
			lines = append(lines, "  "+formatMemFinding(f))
			if f.Address != "" {
				lines = append(lines,
					"    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Address: "+f.Address))
			}
		}
	}

	lines = append(lines, "",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutFile)),
		"", cHint("Press any key to return"))
	return lines
}

func (m Model) memViewYaraResults(width int) []string {
	lines := []string{
		cSectionLabel("YARA Scan Results"), cRule(width),
		"",
	}
	r := m.memState.singleResult
	if r == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}
	if r.Status == memory.StepFailed {
		lines = append(lines, "  "+ErrorStyle.Render("YARA scan failed: "+r.Error))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	findings := memory.ParseYaraFindings(r.OutFile)
	if len(findings) == 0 {
		lines = append(lines, "  "+SuccessStyle.Render("No YARA matches found."))
	} else {
		max := 12
		for i, f := range findings {
			if i >= max {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					fmt.Sprintf("... %d more matches — see %s", len(findings)-max, r.OutFile)))
				break
			}
			lines = append(lines, "  "+formatMemFinding(f))
			if f.Address != "" {
				lines = append(lines,
					"    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render("Offset: "+f.Address))
			}
		}
	}

	lines = append(lines, "",
		cField("Rules", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.memState.yaraRules)),
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutFile)),
		"", cHint("Press any key to return"))
	return lines
}

func (m Model) memViewTimelineDone(width int) []string {
	lines := []string{
		cSectionLabel("Timeline Generation Complete"), cRule(width),
		"",
	}
	r := m.memState.singleResult
	if r == nil || r.Status == memory.StepFailed {
		msg := "Timeline generation failed."
		if r != nil {
			msg += " " + r.Error
		}
		lines = append(lines, "  "+ErrorStyle.Render(msg))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	lines = append(lines,
		"  "+SuccessStyle.Render(fmt.Sprintf("Timeline generated with %d events.", r.Lines)),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutFile)),
		"",
		cHint("Export to Timeline Explorer or other analysis tool."),
		"",
		cHint("Press any key to return"),
	)
	return lines
}

// ---------------------------------------------------------------------------
// YARA, custom plugin, symbols, remote views
// ---------------------------------------------------------------------------

func (m Model) memViewYaraSelect(width int) []string {
	lines := []string{
		cSectionLabel("YARA Scan — Rule Selection"), cRule(width),
		"",
	}
	for i, opt := range m.memState.yaraOptions {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.memState.yaraCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+shortcut+" "+opt))
		} else {
			lines = append(lines, "    "+
				lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(opt))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  Esc: cancel"))
	return lines
}

func (m Model) memViewSimpleInput(title, prompt string) []string {
	lines := []string{
		cSectionLabel(title), cRule(80),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(prompt),
		"",
		"  " + m.memState.input.View(),
		"",
		cHint("Enter: submit  Esc: cancel"),
	}
	return lines
}

func (m Model) memViewSymbols(width int) []string {
	r := m.memVolatilityRunner()
	winCount := r.CountSymbolFiles("windows")
	lnxCount := r.CountSymbolFiles("linux")

	lines := []string{
		cSectionLabel("Volatility3 Symbol Tables"), cRule(width),
		"",
		cField("Windows Symbols", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d files", winCount))),
		cField("Linux Symbols", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d files", lnxCount))),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Symbol ISF files are required for memory analysis."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"Reference: https://volatility3.readthedocs.io/en/latest/symbol-tables.html"),
		"",
		cHint("Manual install: extract archives to lib/volatility3/symbols/{windows,linux}/"),
		"",
		cSectionLabel("Actions"),
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("[1]") + " " +
			lipgloss.NewStyle().Foreground(ColorText).Render("Refresh status"),
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("[2]") + " " +
			lipgloss.NewStyle().Foreground(ColorText).Render("Download Windows symbols (requires internet)"),
		"  " + lipgloss.NewStyle().Foreground(ColorAccent).Render("[3]") + " " +
			lipgloss.NewStyle().Foreground(ColorText).Render("Download Linux symbols (requires internet)"),
		"",
		cHint("Esc to return"),
	}
	return lines
}

func (m Model) memViewSymbolsDownloading(width int) []string {
	return []string{
		cSectionLabel("Downloading Symbols"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(
			"[▸] " + m.memState.symbolMessage),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)),
	}
}

func (m Model) memViewSymbolsDone(width int) []string {
	return []string{
		cSectionLabel("Symbol Download Complete"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(m.memState.symbolMessage),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) memViewRemoteMethod(width int) []string {
	lines := []string{
		cSectionLabel("Remote Memory Capture — Method"), cRule(width),
		"",
	}
	for i, opt := range m.memState.selectOptions {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.memState.selectCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+shortcut+" "+opt))
		} else {
			lines = append(lines, "    "+
				lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(opt))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  Esc: cancel"))
	return lines
}

func (m Model) memViewRemoteRunning(width int) []string {
	return []string{
		cSectionLabel("Remote Memory Capture"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).
			Render("[▸] Capturing memory from " + m.memState.remoteHost + "..."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.memState.elapsed)),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func captureToolLabel(tool memory.CaptureTool) string {
	switch tool {
	case memory.ToolDumpIt:
		return "DumpIt"
	case memory.ToolWinPmem:
		return "WinPmem"
	case memory.ToolAVML:
		return "AVML"
	case memory.ToolLiME:
		return "LiME"
	case memory.ToolVelociraptor:
		return "Velociraptor"
	case memory.ToolRemote:
		return "Remote"
	}
	return string(tool)
}

func formatMemFinding(f memory.Finding) string {
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
	sev := sevStyle.Render(fmt.Sprintf("[%s]", strings.ToUpper(f.Severity)))
	title := lipgloss.NewStyle().Foreground(ColorText).Render(f.Title)
	return sev + " " + title
}

func memProgressBar(width int, current, total int64) string {
	barWidth := width - 12
	if barWidth < 10 {
		barWidth = 10
	}
	if barWidth > 50 {
		barWidth = 50
	}
	if total == 0 {
		return ""
	}
	pct := float64(current) / float64(total)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(barWidth))
	empty := barWidth - filled
	bar := lipgloss.NewStyle().Foreground(ColorPrimary).Render(strings.Repeat("█", filled)) +
		lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("░", empty))
	return bar + " " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
		fmt.Sprintf("%5.1f%%", pct*100))
}

func splitForView(s string, max int) []string {
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) > max {
		all = all[:max]
	}
	out := make([]string, 0, len(all))
	for _, line := range all {
		if len(line) > 100 {
			line = line[:100] + "..."
		}
		out = append(out, line)
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// ---------------------------------------------------------------------------
// Symbol archive extraction
// ---------------------------------------------------------------------------

// unzipTo extracts a zip archive to dest, returning the count of regular files
// extracted.
func unzipTo(archive, dest string) (int, error) {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	count := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		// Sanitise destination path against zip-slip.
		target := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return count, err
		}

		src, err := f.Open()
		if err != nil {
			return count, err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			src.Close()
			return count, err
		}
		if _, err := io.Copy(out, src); err != nil {
			src.Close()
			out.Close()
			return count, err
		}
		src.Close()
		out.Close()
		count++
	}
	return count, nil
}
