package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/remote"
)

// remoteContent renders the active Remote Operations view.
func (m Model) remoteContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Remote Operations"),
		"",
	}

	switch m.remoteState.view {
	case remoteViewNeedCase:
		lines = append(lines, m.remoteViewNeedCase(width)...)
	case remoteViewError:
		lines = append(lines, m.remoteViewError(width)...)
	case remoteViewMessage:
		lines = append(lines, m.remoteViewMessage(width)...)

	// Target management.
	case remoteViewTargetList:
		lines = append(lines, m.remoteViewTargetList(width, false)...)
	case remoteViewSelectTarget:
		lines = append(lines, m.remoteViewSelectTarget(width)...)
	case remoteViewBatchPickTargets, remoteViewDeployPickTargets:
		lines = append(lines, m.remoteViewBatchPick(width)...)
	case remoteViewRemoveConfirm:
		lines = append(lines, m.remoteViewRemoveConfirm(width)...)

	// Add-target form.
	case remoteViewAddHostname:
		lines = append(lines, m.remoteViewInput("Add Target — Hostname", "Hostname:")...)
	case remoteViewAddIP:
		lines = append(lines, m.remoteViewInput("Add Target — IP", "IP address (optional):")...)
	case remoteViewAddOS:
		lines = append(lines, m.remoteViewPick("Add Target — OS", []string{"Windows", "Linux"})...)
	case remoteViewAddProtocol:
		lines = append(lines, m.remoteViewPick("Add Target — Protocol", m.remoteProtocolOptions())...)
	case remoteViewAddPort:
		lines = append(lines, m.remoteViewInput("Add Target — Port", "Port:")...)
	case remoteViewAddUsername:
		lines = append(lines, m.remoteViewInput("Add Target — Username", "Username:")...)
	case remoteViewAddAuthMethod:
		lines = append(lines, m.remoteViewPick("Add Target — Auth Method", []string{"Password", "SSH Key"})...)
	case remoteViewAddKeyPath:
		lines = append(lines, m.remoteViewInput("Add Target — SSH Key", "Path to SSH private key:")...)
	case remoteViewAddNotes:
		lines = append(lines, m.remoteViewInput("Add Target — Notes", "Notes (optional):")...)
	case remoteViewAddConfirm:
		lines = append(lines, m.remoteViewAddConfirm(width)...)

	// Credential prompt.
	case remoteViewPromptPassword:
		t := m.remoteState.current
		title := "Credentials"
		prompt := "Password:"
		if t != nil {
			title += " — " + t.DisplayName()
			prompt = fmt.Sprintf("Password for %s:", t.Username)
		}
		lines = append(lines, m.remoteViewInput(title, prompt)...)

	// File acquisition.
	case remoteViewAcquirePath:
		lines = append(lines, m.remoteViewInput("Remote File Acquisition", "Remote file path:")...)
	case remoteViewAcquireDesc:
		lines = append(lines, m.remoteViewInput("Remote File Acquisition", "Description:")...)

	// IOC sweep input.
	case remoteViewIOCType:
		lines = append(lines, m.remoteViewPick("IOC Sweep — Type",
			[]string{
				"File hash (SHA256)",
				"File name pattern",
				"IP address",
				"Domain",
			})...)
	case remoteViewIOCValue:
		lines = append(lines, m.remoteViewInput("IOC Sweep — Value", "IOC value:")...)

	// Deploy tool picker.
	case remoteViewDeployPickTool:
		lines = append(lines, m.remoteViewPick("Deploy Tool — Select", m.remoteState.pickOptions)...)

	// Active operation.
	case remoteViewRunning:
		lines = append(lines, m.remoteViewRunning()...)
	case remoteViewBatchRunning, remoteViewDeployRunning:
		lines = append(lines, m.remoteViewRunning()...)

	// Single results.
	case remoteViewConnDone:
		lines = append(lines, m.remoteViewConnResult(width)...)
	case remoteViewOpDone:
		lines = append(lines, m.remoteViewOpResult(width)...)

	// Hunt findings.
	case remoteViewFindings:
		lines = append(lines, m.remoteViewHuntResult(width)...)

	// IOC sweep results.
	case remoteViewIOCResults:
		lines = append(lines, m.remoteViewIOCResult(width)...)

	// Batch / deploy results.
	case remoteViewBatchDone:
		lines = append(lines, m.remoteViewBatchResult(width)...)
	case remoteViewDeployDone:
		lines = append(lines, m.remoteViewDeployResult(width)...)
	}
	return lines
}

// ---------------------------------------------------------------------------
// Common views
// ---------------------------------------------------------------------------

func (m Model) remoteViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Remote Operations"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
	}
}

func (m Model) remoteViewError(width int) []string {
	out := []string{
		cSectionLabel("Remote Operations — Error"), cRule(width),
		"",
	}
	for _, line := range strings.Split(m.remoteState.errorMsg, "\n") {
		out = append(out, "  "+ErrorStyle.Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) remoteViewMessage(width int) []string {
	out := []string{
		cSectionLabel(m.remoteState.messageTitle), cRule(width),
		"",
	}
	for _, line := range m.remoteState.messageLines {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) remoteViewInput(title, prompt string) []string {
	return []string{
		cSectionLabel(title), cRule(80),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(prompt),
		"",
		"  " + m.remoteState.input.View(),
		"",
		cHint("Enter: submit  Esc: cancel"),
	}
}

func (m Model) remoteViewPick(title string, options []string) []string {
	lines := []string{cSectionLabel(title), cRule(80), ""}
	for i, opt := range options {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.remoteState.pickCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+shortcut+" "+opt))
		} else {
			lines = append(lines, "    "+
				lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(opt))
		}
	}
	lines = append(lines, "", cHint("Enter: select  Esc: cancel"))
	return lines
}

// ---------------------------------------------------------------------------
// Target list / picker
// ---------------------------------------------------------------------------

func (m Model) remoteViewTargetList(width int, picker bool) []string {
	caseID := ""
	if m.ctx.ActiveCase != nil {
		caseID = m.ctx.ActiveCase.ID
	}
	title := "Remote Targets — Case " + caseID
	if picker {
		title = "Select Target"
	}
	lines := []string{cSectionLabel(title), cRule(width), ""}

	if len(m.remoteState.targets) == 0 {
		lines = append(lines, "  "+WarningStyle.Render("No targets configured."), "",
			cHint("Press [1] in the submenu to add a remote target."))
		if !picker {
			lines = append(lines, "", cHint("Press any key to return"))
		}
		return lines
	}

	header := fmt.Sprintf("%-3s %-15s %-16s %-9s %-9s %5s %-10s %s",
		"#", "Hostname", "IP", "OS", "Protocol", "Port", "Status", "Notes")
	lines = append(lines, "  "+TableHeaderStyle.Render(header))
	lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorBorder).Render(
		strings.Repeat("─", 86)))

	for i, t := range m.remoteState.targets {
		row := fmt.Sprintf("%-3d %-15s %-16s %-9s %-9s %5d %-10s %s",
			i+1, truncRemote(t.Hostname, 15), truncRemote(t.IPAddress, 16),
			t.OSType, t.Protocol, t.Port,
			renderStatus(t.Status), truncRemote(t.Notes, 30))

		if i == m.remoteState.listCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+row))
		} else {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}

	lines = append(lines, "")
	if picker {
		lines = append(lines, cHint("Enter: select  Esc: cancel"))
	} else {
		lines = append(lines, cHint("Up/Down: navigate  Esc: return"))
	}
	return lines
}

// renderStatus returns a styled string for a target status.
func renderStatus(s remote.Status) string {
	switch s {
	case remote.StatusOnline:
		return "online"
	case remote.StatusOffline:
		return "offline"
	case remote.StatusError:
		return "error"
	}
	return "untested"
}

func (m Model) remoteViewSelectTarget(width int) []string {
	return m.remoteViewTargetList(width, true)
}

func (m Model) remoteViewBatchPick(width int) []string {
	title := "Batch Operation — Select Targets"
	if m.remoteState.view == remoteViewDeployPickTargets {
		title = "Deploy Tool — Select Targets"
	}
	lines := []string{cSectionLabel(title), cRule(width), ""}

	for i, t := range m.remoteState.targets {
		checked := i < len(m.remoteState.checkAll) && m.remoteState.checkAll[i]
		box := "[ ]"
		boxFg := ColorTextMuted
		if checked {
			box = "[x]"
			boxFg = ColorSuccess
		}
		boxStr := lipgloss.NewStyle().Foreground(boxFg).Render(box)
		row := fmt.Sprintf("%-15s %-16s %-9s %-9s %s",
			truncRemote(t.Hostname, 15), truncRemote(t.IPAddress, 16),
			t.OSType, t.Protocol, renderStatus(t.Status))

		if i == m.remoteState.listCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+box+" "+row))
		} else {
			lines = append(lines, "    "+boxStr+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Space: toggle  A: select all  N: deselect all  Enter: run  Esc: cancel"))
	return lines
}

func (m Model) remoteViewRemoveConfirm(width int) []string {
	t := m.remoteState.current
	if t == nil {
		return []string{cSectionLabel("Remove Target"), cRule(width), "  " +
			ErrorStyle.Render("No target selected.")}
	}
	return []string{
		cSectionLabel("Remove Target"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("Remove target %s (%s)?", t.Hostname, t.IPAddress)),
		"",
		"  " + WarningStyle.Render("(y/n)"),
	}
}

// ---------------------------------------------------------------------------
// Add-target confirmation
// ---------------------------------------------------------------------------

func (m Model) remoteViewAddConfirm(width int) []string {
	d := m.remoteState.draft
	auth := d.AuthMethod
	if auth == "key" && d.KeyPath != "" {
		auth = "key (" + d.KeyPath + ")"
	}
	return []string{
		cSectionLabel("Add Target — Confirm"), cRule(width),
		"",
		cField("Hostname", lipgloss.NewStyle().Foreground(ColorText).Render(d.Hostname)),
		cField("IP", lipgloss.NewStyle().Foreground(ColorText).Render(d.IPAddress)),
		cField("OS", lipgloss.NewStyle().Foreground(ColorText).Render(d.OSType)),
		cField("Protocol", lipgloss.NewStyle().Foreground(ColorText).Render(d.Protocol)),
		cField("Port", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", d.Port))),
		cField("Username", lipgloss.NewStyle().Foreground(ColorText).Render(d.Username)),
		cField("Auth", lipgloss.NewStyle().Foreground(ColorText).Render(auth)),
		cField("Notes", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(d.Notes)),
		"",
		"  " + WarningStyle.Render("Save target? (y/n)"),
	}
}

// ---------------------------------------------------------------------------
// Running view
// ---------------------------------------------------------------------------

func (m Model) remoteViewRunning() []string {
	return []string{
		cSectionLabel(m.remoteState.operationName), cRule(80),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.remoteState.elapsed)),
		"",
		cHint("Network operations can take several minutes. Please wait."),
	}
}

// ---------------------------------------------------------------------------
// Result views
// ---------------------------------------------------------------------------

func (m Model) remoteViewConnResult(width int) []string {
	r := m.remoteState.connResult
	if r == nil {
		return []string{cSectionLabel("Connectivity Result"), cRule(width),
			"", "  " + ErrorStyle.Render("No result data."),
			"", cHint("Press any key to return")}
	}
	statusStr := SuccessStyle.Render("✓ online")
	if r.Status != remote.StatusOnline {
		statusStr = ErrorStyle.Render("✗ " + string(r.Status))
	}
	lines := []string{
		cSectionLabel("Connectivity Test"), cRule(width),
		"",
		cField("Target", lipgloss.NewStyle().Foreground(ColorText).Render(r.Target.DisplayName())),
		cField("Status", statusStr),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Millisecond).String())),
	}
	if r.Output != "" {
		lines = append(lines, cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.Output)))
	}
	if r.Error != "" {
		lines = append(lines, "", "  "+ErrorStyle.Render("Error: "+r.Error))
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewOpResult(width int) []string {
	lines := []string{cSectionLabel("Operation Complete"), cRule(width), ""}

	if m.remoteState.errorMsg != "" {
		lines = append(lines, "  "+ErrorStyle.Render("Error: "+m.remoteState.errorMsg),
			"", cHint("Press any key to return"))
		return lines
	}

	if m.remoteState.triageResult != nil {
		lines = append(lines, m.remoteViewTriageStepList(width)...)
	} else if m.remoteState.collectionRes != nil {
		lines = append(lines, m.remoteViewCollectionResult(width)...)
	} else if m.remoteState.acquisition != nil {
		lines = append(lines, m.remoteViewAcquireResult(width)...)
	} else if m.remoteState.memoryResult != nil {
		lines = append(lines, m.remoteViewMemoryResult(width)...)
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewTriageStepList(width int) []string {
	steps := m.remoteState.triageResult
	lines := []string{
		"  " + SuccessStyle.Render("Remote Quick Triage complete."),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.remoteState.triageOutDir)),
		"",
		cSectionLabel("Steps"),
	}
	for _, s := range steps {
		var statusStr string
		switch s.Status {
		case "success":
			statusStr = SuccessStyle.Render("success")
		case "partial":
			statusStr = WarningStyle.Render("partial")
		default:
			statusStr = ErrorStyle.Render("failed")
		}
		row := fmt.Sprintf("  %-32s %-8s %4ds  %s",
			truncRemote(s.Name, 32), statusStr, int(s.Duration.Seconds()),
			lipgloss.NewStyle().Foreground(ColorTextMuted).Render(s.OutFile))
		lines = append(lines, row)
		if s.Error != "" {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(s.Error))
		}
	}
	return lines
}

func (m Model) remoteViewCollectionResult(width int) []string {
	r := m.remoteState.collectionRes
	lines := []string{
		"  " + SuccessStyle.Render("Collection complete."),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutputDir)),
		cField("Files", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d", len(r.Files)))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
	}
	for _, f := range r.Files {
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"• "+filepath.Base(f)))
	}
	if len(r.Failed) > 0 {
		lines = append(lines, "", cSectionLabel("Failed"))
		for name, err := range r.Failed {
			lines = append(lines, "  "+ErrorStyle.Render("✗ "+name+": "+err))
		}
	}
	return lines
}

func (m Model) remoteViewAcquireResult(width int) []string {
	r := m.remoteState.acquisition
	return []string{
		"  " + SuccessStyle.Render("File acquired."),
		"",
		cField("Source", lipgloss.NewStyle().Foreground(ColorText).Render(r.Source)),
		cField("Destination", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Destination)),
		cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.SHA256)),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(formatRemoteBytes(r.Bytes))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
	}
}

func (m Model) remoteViewMemoryResult(width int) []string {
	r := m.remoteState.memoryResult
	return []string{
		"  " + SuccessStyle.Render("Memory captured."),
		"",
		cField("Destination", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Destination)),
		cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.SHA256)),
		cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(formatRemoteBytes(r.Bytes))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
	}
}

func (m Model) remoteViewHuntResult(width int) []string {
	r := m.remoteState.huntResult
	if r == nil {
		return []string{cSectionLabel("Hunt Result"), cRule(width),
			"", "  " + ErrorStyle.Render("No result data."),
			"", cHint("Press any key to return")}
	}
	lines := []string{
		cSectionLabel("Remote Hunt Snapshot"), cRule(width),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutputDir)),
		cField("Findings", lipgloss.NewStyle().Foreground(ColorWarning).Render(
			fmt.Sprintf("%d", len(r.Findings)))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
		"",
	}
	max := 12
	if len(r.Findings) == 0 {
		lines = append(lines, "  "+SuccessStyle.Render("No anomalies detected."))
	} else {
		lines = append(lines, cSectionLabel("Findings"))
		for i, f := range r.Findings {
			if i >= max {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					fmt.Sprintf("... %d more — see %s", len(r.Findings)-max, r.OutputDir)))
				break
			}
			lines = append(lines, "  "+formatRemoteFinding(f))
		}
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewIOCResult(width int) []string {
	r := m.remoteState.iocSweepResult
	if r == nil {
		return []string{cSectionLabel("IOC Sweep"), cRule(width),
			"", "  " + ErrorStyle.Render("No result data."),
			"", cHint("Press any key to return")}
	}
	lines := []string{
		cSectionLabel("IOC Sweep Result"), cRule(width),
		"",
		cField("Target", lipgloss.NewStyle().Foreground(ColorText).Render(r.Target.DisplayName())),
		cField("IOC", lipgloss.NewStyle().Foreground(ColorText).Render(string(r.IOC.Type)+":"+r.IOC.Value)),
		cField("Hits", lipgloss.NewStyle().Foreground(ColorWarning).Render(
			fmt.Sprintf("%d", len(r.Findings)))),
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
	}
	if r.Error != "" {
		lines = append(lines, "", "  "+ErrorStyle.Render("Error: "+r.Error))
	}
	if len(r.Findings) > 0 {
		lines = append(lines, "", cSectionLabel("Hits"))
		max := 15
		for i, f := range r.Findings {
			if i >= max {
				lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
					fmt.Sprintf("... %d more — see %s", len(r.Findings)-max, r.OutputDir)))
				break
			}
			lines = append(lines, "  "+formatRemoteFinding(f))
		}
	} else if r.Error == "" {
		lines = append(lines, "", "  "+SuccessStyle.Render("No matches found."))
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewBatchResult(width int) []string {
	if len(m.remoteState.batchTriage) > 0 {
		return m.remoteViewBatchTriageResult(width)
	}
	return m.remoteViewBatchIOCResult(width)
}

func (m Model) remoteViewBatchTriageResult(width int) []string {
	results := m.remoteState.batchTriage
	successes, failures := 0, 0
	for _, r := range results {
		if r.Error == "" {
			successes++
		} else {
			failures++
		}
	}
	lines := []string{
		cSectionLabel("Batch Triage Complete"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("Successful: %d/%d   Failed: %d/%d",
				successes, len(results), failures, len(results))),
		"",
	}
	for _, r := range results {
		var icon string
		if r.Error == "" {
			icon = lipgloss.NewStyle().Foreground(ColorSuccess).Render("[✓]")
		} else {
			icon = lipgloss.NewStyle().Foreground(ColorError).Render("[✗]")
		}
		row := fmt.Sprintf("%-20s %-15s %4ds  %s",
			truncRemote(r.Target.Hostname, 20),
			truncRemote(r.Target.IPAddress, 15),
			int(r.Duration.Seconds()),
			lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.OutputDir))
		lines = append(lines, "  "+icon+" "+row)
		if r.Error != "" {
			lines = append(lines, "    "+ErrorStyle.Render(r.Error))
		}
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewBatchIOCResult(width int) []string {
	results := m.remoteState.batchIOC
	totalHits := 0
	hostsWithHits := 0
	for _, r := range results {
		if len(r.Findings) > 0 {
			hostsWithHits++
			totalHits += len(r.Findings)
		}
	}
	lines := []string{
		cSectionLabel("Batch IOC Sweep Complete"), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("Total hits: %d across %d hosts (of %d scanned)",
				totalHits, hostsWithHits, len(results))),
		"",
	}
	for _, r := range results {
		hits := len(r.Findings)
		hitsStr := lipgloss.NewStyle().Foreground(ColorTextMuted).Render("0 hits")
		if hits > 0 {
			hitsStr = lipgloss.NewStyle().Foreground(ColorError).Render(fmt.Sprintf("%d hits", hits))
		}
		lines = append(lines, fmt.Sprintf("  %-20s  %s",
			truncRemote(r.Target.Hostname, 20), hitsStr))
		if r.Error != "" {
			lines = append(lines, "    "+ErrorStyle.Render(r.Error))
		}
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

func (m Model) remoteViewDeployResult(width int) []string {
	results := m.remoteState.deployRes
	deployed, failed := 0, 0
	for _, r := range results {
		if r.Error == "" {
			deployed++
		} else {
			failed++
		}
	}
	lines := []string{
		cSectionLabel("Tool Deployment — " + m.remoteState.deployTool), cRule(width),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("Deployed: %d/%d   Failed: %d/%d",
				deployed, len(results), failed, len(results))),
		"",
	}
	for _, r := range results {
		var icon string
		if r.Error == "" {
			icon = lipgloss.NewStyle().Foreground(ColorSuccess).Render("[✓]")
		} else {
			icon = lipgloss.NewStyle().Foreground(ColorError).Render("[✗]")
		}
		row := fmt.Sprintf("%-20s %-30s %s",
			truncRemote(r.Target.Hostname, 20),
			truncRemote(r.RemotePath, 30),
			lipgloss.NewStyle().Foreground(ColorTextMuted).Render(formatRemoteBytes(r.Bytes)))
		lines = append(lines, "  "+icon+" "+row)
		if r.Error != "" {
			lines = append(lines, "    "+ErrorStyle.Render(r.Error))
		}
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func formatRemoteFinding(f remote.Finding) string {
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

func formatRemoteBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func truncRemote(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
