package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ridgelinecyberdefence/vanguard/internal/disk"
)

// diskContent renders the active Disk Collection panel view.
func (m Model) diskContent(width int) []string {
	lines := []string{
		"",
		cBreadcrumb("Home > Disk Artifact Collection"),
		"",
	}

	switch m.diskState.view {
	case diskViewNeedCase:
		lines = append(lines, m.diskViewNeedCase(width)...)
	case diskViewNeedKape:
		lines = append(lines, m.diskViewNeedKape(width)...)
	case diskViewNeedEZ:
		lines = append(lines, m.diskViewNeedEZ(width)...)
	case diskViewNeedUAC:
		lines = append(lines, m.diskViewNeedUAC(width)...)
	case diskViewError:
		lines = append(lines, m.diskViewError(width)...)

	case diskViewKapeConfirm:
		lines = append(lines, m.diskViewKapeConfirm(width)...)
	case diskViewKapeCustomTargets:
		lines = append(lines, m.diskSimpleInputView("KAPE — Custom Targets",
			"Enter target name(s) (comma-separated):")...)
	case diskViewKapeRunning:
		lines = append(lines, m.diskViewRunning("KAPE — "+m.diskState.operationName)...)
	case diskViewKapeDone:
		lines = append(lines, m.diskViewSingleResult("KAPE Collection Complete")...)

	case diskViewSourceSelect:
		lines = append(lines, m.diskViewSourceSelect(width)...)
	case diskViewSourceCustomPath:
		lines = append(lines, m.diskSimpleInputView("Custom Source Path",
			"Path to artifact directory:")...)
	case diskViewSinglePluginRunning:
		lines = append(lines, m.diskViewRunning(m.diskState.operationName)...)
	case diskViewSinglePluginDone:
		lines = append(lines, m.diskViewSingleResult("Parser Complete — "+m.diskState.operationName)...)

	case diskViewAllParsersRunning:
		lines = append(lines, m.diskViewAllParsersRunning(width)...)
	case diskViewAllParsersDone:
		lines = append(lines, m.diskViewAllParsersDone(width)...)

	case diskViewUACConfirm:
		lines = append(lines, m.diskViewUACConfirm(width)...)
	case diskViewUACProfileSelect:
		lines = append(lines, m.diskViewUACProfileSelect(width)...)
	case diskViewUACRunning:
		lines = append(lines, m.diskViewRunning(m.diskState.operationName)...)
	case diskViewUACDone:
		lines = append(lines, m.diskViewSingleResult("UAC Collection Complete")...)

	case diskViewLnxConfirm:
		lines = append(lines, m.diskViewLnxConfirm(width)...)
	case diskViewLnxAppPath:
		lines = append(lines, m.diskSimpleInputView("Application Logs",
			"Path (blank for common defaults):")...)
	case diskViewLnxRunning:
		lines = append(lines, m.diskViewRunning(m.diskState.operationName)...)
	case diskViewLnxDone:
		lines = append(lines, m.diskViewSingleResult("Collection Complete — "+m.diskState.operationName)...)

	case diskViewManualSrc:
		lines = append(lines, m.diskSimpleInputView("Targeted File Copy",
			"Source path (file or directory):")...)
	case diskViewManualDesc:
		lines = append(lines, m.diskSimpleInputView("Targeted File Copy",
			"Description (what is this artifact):")...)
	case diskViewManualRunning:
		lines = append(lines, m.diskViewRunning("Targeted File Copy")...)
	case diskViewManualDone:
		lines = append(lines, m.diskViewManualDone(width)...)

	case diskViewBrowse:
		lines = append(lines, m.diskViewBrowse(width)...)
	}

	return lines
}

// ---------------------------------------------------------------------------
// Prerequisite views
// ---------------------------------------------------------------------------

func (m Model) diskViewNeedCase(width int) []string {
	return []string{
		cSectionLabel("Disk Artifact Collection"), cRule(width),
		"",
		"  " + ErrorStyle.Render("No active case."),
		"",
		"  " + WarningStyle.Render("Create one now? (y/n)"),
		"",
		cHint("A case is required to organise disk-collection output."),
	}
}

func (m Model) diskViewNeedKape(width int) []string {
	return []string{
		cSectionLabel("KAPE Required"), cRule(width),
		"",
		"  " + ErrorStyle.Render("KAPE is not installed."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"KAPE is a free forensic collection tool by Eric Zimmerman."),
		"",
		cHint("Download from: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape"),
		cHint("Extract to: bin/windows/kape/"),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render("Expected structure:"),
		cHint("  bin/windows/kape/kape.exe"),
		cHint("  bin/windows/kape/Targets/"),
		cHint("  bin/windows/kape/Modules/"),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) diskViewNeedEZ(width int) []string {
	missing := m.diskEZ().MissingBinaries()
	out := []string{
		cSectionLabel("EZ Tools Required"), cRule(width),
		"",
		"  " + ErrorStyle.Render("EZ Tools not installed."),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Download the full EZ Tools suite from:"),
		cHint("  https://ericzimmerman.github.io/#!index.md"),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(
			"Or use Get-ZimmermanTools.ps1:"),
		cHint("  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1' -OutFile Get-ZimmermanTools.ps1"),
		cHint("  .\\Get-ZimmermanTools.ps1 -Dest bin\\windows\\ez-tools\\"),
		"",
	}
	if len(missing) > 0 {
		out = append(out, cSectionLabel("Missing binaries"))
		for _, b := range missing {
			out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render("• "+b))
		}
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

func (m Model) diskViewNeedUAC(width int) []string {
	return []string{
		cSectionLabel("UAC Required"), cRule(width),
		"",
		"  " + ErrorStyle.Render("UAC (Unix-like Artifacts Collector) is not installed."),
		"",
		cHint("Download from: https://github.com/tclahr/uac/releases"),
		cHint("Extract to: bin/linux/uac/"),
		cHint("Expected: bin/linux/uac/uac"),
		"",
		cHint("Press any key to return"),
	}
}

func (m Model) diskViewError(width int) []string {
	out := []string{
		cSectionLabel("Disk Collection"), cRule(width),
		"",
	}
	for _, line := range strings.Split(m.diskState.errorMsg, "\n") {
		out = append(out, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(line))
	}
	out = append(out, "", cHint("Press any key to return"))
	return out
}

// ---------------------------------------------------------------------------
// KAPE views
// ---------------------------------------------------------------------------

func (m Model) diskViewKapeConfirm(width int) []string {
	desc := kapeDescription(m.diskState.preset)
	lines := []string{
		cSectionLabel("KAPE Collection — " + m.diskState.operationName), cRule(width),
		"",
		cField("Source", lipgloss.NewStyle().Foreground(ColorText).Render(disk.SystemDrive())),
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(
			"output/"+m.diskCaseID()+"/disk/{timestamp}/...")),
		"",
	}
	if desc != "" {
		for _, line := range strings.Split(desc, "\n") {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(line))
		}
		lines = append(lines, "")
	}
	if !m.ctx.Elevated {
		lines = append(lines,
			"  "+WarningStyle.Render("KAPE typically requires Administrator privileges."), "")
	}
	lines = append(lines, "  "+WarningStyle.Render("Proceed? (y/n)"))
	return lines
}

func kapeDescription(preset string) string {
	switch preset {
	case "sans":
		return "Comprehensive triage collection: event logs, registry hives,\nprefetch, amcache, shimcache, $MFT, jump lists, LNK files,\nbrowser data, PowerShell logs, scheduled tasks, SRUM, etc.\n\nMay take 15-30 minutes."
	case "full":
		return "Broader collection beyond SANS triage — more artifact types.\n\nMay take 30-60 minutes."
	case "evtx":
		return "Windows event logs only (.evtx)."
	case "registry":
		return "Registry hives only: SAM, SYSTEM, SOFTWARE, SECURITY,\nNTUSER.DAT, UsrClass.dat."
	case "browser":
		return "Web browser artifacts only — Chrome, Edge, Firefox, IE.\nIncludes history, cookies, downloads, cache."
	}
	return ""
}

// ---------------------------------------------------------------------------
// Source select
// ---------------------------------------------------------------------------

func (m Model) diskViewSourceSelect(width int) []string {
	lines := []string{
		cSectionLabel(m.diskState.operationName + " — Parse Source"), cRule(width),
		"",
	}
	for i, opt := range m.diskState.sourceOptions {
		shortcut := fmt.Sprintf("[%d]", i+1)
		if i == m.diskState.sourceCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).
				Render("> "+shortcut+" "+opt))
		} else {
			lines = append(lines, "    "+
				lipgloss.NewStyle().Foreground(ColorAccent).Render(shortcut)+" "+
				lipgloss.NewStyle().Foreground(ColorText).Render(opt))
		}
	}

	// Hint where the auto-detected paths point.
	if latest := disk.LatestKapeCollection(m.ctx.RootDir, m.diskCaseID()); latest != "" {
		lines = append(lines, "")
		lines = append(lines, cHint("Latest KAPE: "+latest))
	}
	if latest := disk.LatestTriageCollection(m.ctx.RootDir, m.diskCaseID()); latest != "" {
		lines = append(lines, cHint("Latest triage: "+latest))
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  Esc: cancel"))
	return lines
}

// ---------------------------------------------------------------------------
// Common running view
// ---------------------------------------------------------------------------

func (m Model) diskViewRunning(title string) []string {
	return []string{
		cSectionLabel(title), cRule(80),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸] Running..."),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"Elapsed: "+formatElapsed(m.diskState.elapsed)),
		"",
		cHint("Long-running collections may take many minutes. Please wait."),
	}
}

// ---------------------------------------------------------------------------
// Single result view
// ---------------------------------------------------------------------------

func (m Model) diskViewSingleResult(title string) []string {
	lines := []string{
		cSectionLabel(title), cRule(80),
		"",
	}
	r := m.diskState.singleResult
	if r == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}

	switch r.Status {
	case disk.StatusSuccess:
		lines = append(lines, "  "+SuccessStyle.Render("Operation succeeded."))
	case disk.StatusPartial:
		lines = append(lines, "  "+WarningStyle.Render("Operation completed with warnings."))
	case disk.StatusFailed:
		lines = append(lines, "  "+ErrorStyle.Render("Operation failed."))
	case disk.StatusSkipped:
		lines = append(lines, "  "+WarningStyle.Render("Operation skipped."))
	}

	lines = append(lines,
		"",
		cField("Duration", lipgloss.NewStyle().Foreground(ColorText).Render(
			r.Duration.Truncate(time.Second).String())),
	)
	if r.OutputDir != "" {
		lines = append(lines, cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(r.OutputDir)))
	}
	if r.OutputFile != "" {
		lines = append(lines, cField("Main file", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.OutputFile)))
	}
	if r.Files > 0 {
		lines = append(lines, cField("Files", lipgloss.NewStyle().Foreground(ColorText).Render(
			fmt.Sprintf("%d", r.Files))))
	}
	if r.Bytes > 0 {
		lines = append(lines, cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(
			formatDiskBytes(r.Bytes))))
	}

	if r.Error != "" {
		lines = append(lines, "", "  "+ErrorStyle.Render("Error: "+r.Error))
	}
	for _, w := range r.Warnings {
		lines = append(lines, "  "+WarningStyle.Render("⚠ "+w))
	}

	if r.Status == disk.StatusSuccess && strings.HasPrefix(m.diskState.action, "disk_kape_") {
		lines = append(lines, "")
		lines = append(lines, cHint("Run [7] Parse with EZ Tools to process the collected artifacts."))
	}

	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// All-parsers running / done views
// ---------------------------------------------------------------------------

func (m Model) diskViewAllParsersRunning(width int) []string {
	lines := []string{
		cSectionLabel("EZ Tools — Full Parse"), cRule(width),
		"",
		cField("Source", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.diskState.sourcePath)),
		"  " + lipgloss.NewStyle().Foreground(ColorBorder).Render(strings.Repeat("─", 50)),
	}
	for i, step := range m.diskState.allSteps {
		var status disk.Status = disk.StatusPending
		if i < len(m.diskState.allStatuses) {
			status = m.diskState.allStatuses[i]
		}
		dur := time.Duration(0)
		if i < len(m.diskState.allDurations) {
			dur = m.diskState.allDurations[i]
		}
		lines = append(lines, "  "+formatParserStatus(step.Name, status, dur))
	}
	lines = append(lines, "")
	lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextSecondary).
		Render("Elapsed: "+formatElapsed(m.diskState.elapsed)))
	return lines
}

func (m Model) diskViewAllParsersDone(width int) []string {
	lines := []string{
		cSectionLabel("EZ Tools — Full Parse Complete"), cRule(width),
		"",
		cField("Source", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(m.diskState.sourcePath)),
		"",
	}

	successes, partials, failures := 0, 0, 0
	for _, r := range m.diskState.allResults {
		switch r.Status {
		case disk.StatusSuccess:
			successes++
		case disk.StatusPartial:
			partials++
		case disk.StatusFailed:
			failures++
		}
	}
	summary := fmt.Sprintf("%d succeeded · %d partial · %d failed", successes, partials, failures)
	lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorText).Render(summary))
	lines = append(lines, "")

	for _, r := range m.diskState.allResults {
		lines = append(lines, "  "+formatParserResult(r))
		if r.Error != "" {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Error))
		}
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// UAC views
// ---------------------------------------------------------------------------

func (m Model) diskViewUACConfirm(width int) []string {
	lines := []string{
		cSectionLabel("UAC Collection — " + m.diskState.operationName), cRule(width),
		"",
		cField("Profile", lipgloss.NewStyle().Foreground(ColorPrimary).Render(m.diskState.uacProfile)),
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(
			"output/"+m.diskCaseID()+"/disk/{timestamp}/uac/")),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"UAC collects process listing, network connections, open files, user"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"accounts, packages, cron jobs, systemd units, logs, shell history,"),
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			"docker info, etc."),
		"",
	}
	if !m.ctx.Elevated {
		lines = append(lines, "  "+WarningStyle.Render("Run as root to collect everything UAC supports."), "")
	}
	lines = append(lines, "  "+WarningStyle.Render("Proceed? (y/n)"))
	return lines
}

func (m Model) diskViewUACProfileSelect(width int) []string {
	lines := []string{
		cSectionLabel("UAC — Custom Profile"), cRule(width),
		"",
	}
	for i, p := range m.diskState.uacProfiles {
		if i == m.diskState.uacCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> "+p))
		} else {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(p))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Enter: select  Esc: cancel"))
	return lines
}

// ---------------------------------------------------------------------------
// Linux confirm view
// ---------------------------------------------------------------------------

func (m Model) diskViewLnxConfirm(width int) []string {
	lines := []string{
		cSectionLabel(m.diskState.operationName), cRule(width),
		"",
		cField("Output", lipgloss.NewStyle().Foreground(ColorPrimary).Render(
			"output/"+m.diskCaseID()+"/disk/{timestamp}/...")),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			lnxDescription(m.diskState.action)),
		"",
	}
	if !m.ctx.Elevated {
		lines = append(lines, "  "+WarningStyle.Render("Some files require root to read; collection will skip what it can't access."), "")
	}
	lines = append(lines, "  "+WarningStyle.Render("Proceed? (y/n)"))
	return lines
}

func lnxDescription(action string) string {
	switch action {
	case "disk_lnx_syslog":
		return "Copies /var/log syslog/messages/kern.log/dmesg + apt history."
	case "disk_lnx_auth":
		return "Copies auth.log/secure + wtmp/btmp/lastlog and runs last/lastb/who/w."
	case "disk_lnx_weblogs":
		return "Copies Apache/Nginx/lighttpd/Caddy logs and config directories."
	case "disk_lnx_journal":
		return "Dumps systemd journal: full JSON, errors, warnings, sshd, docker, boots."
	case "disk_lnx_userhomes":
		return "Per-user collection: shells, ssh, gnupg, cloud creds, docker/kube configs, history, file listing."
	case "disk_lnx_history":
		return "Bash/Zsh/Fish history files for every user."
	case "disk_lnx_ssh":
		return "Each user's .ssh directory plus /etc/ssh config and public host keys (no private keys)."
	case "disk_lnx_cron":
		return "System cron config (/etc/crontab + cron.d/daily/hourly/weekly/monthly), per-user crontabs, /var/spool/cron."
	case "disk_lnx_packages":
		return "Installed packages (dpkg/rpm/pip/npm/snap/flatpak), package logs, repo configuration."
	case "disk_lnx_systemd":
		return "All units, unit files, timers, /etc/systemd, /usr/lib/systemd, current systemctl status."
	case "disk_lnx_network":
		return "Interfaces, routes, ARP, listening sockets, iptables/nftables, sysctl, resolv.conf, hosts."
	case "disk_lnx_docker":
		return "docker ps/images/networks/volumes, container inspect, per-container logs, podman/k8s if present."
	}
	return ""
}

// ---------------------------------------------------------------------------
// Manual copy done view
// ---------------------------------------------------------------------------

func (m Model) diskViewManualDone(width int) []string {
	lines := []string{
		cSectionLabel("Targeted File Copy Complete"), cRule(width),
		"",
	}
	r := m.diskState.manualResult
	if r == nil {
		lines = append(lines, "  "+ErrorStyle.Render("No result data."))
		lines = append(lines, "", cHint("Press any key to return"))
		return lines
	}
	if !r.Success {
		lines = append(lines,
			"  "+ErrorStyle.Render("Copy failed: "+r.Error),
			"", cHint("Press any key to return"))
		return lines
	}
	lines = append(lines,
		"  "+SuccessStyle.Render("Artifact copied."),
		"",
		cField("Source", lipgloss.NewStyle().Foreground(ColorText).Render(r.Source)),
		cField("Destination", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Destination)),
	)
	if r.SHA256 != "" {
		lines = append(lines,
			cField("SHA256", lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.SHA256)))
	}
	if r.IsDir {
		lines = append(lines,
			cField("Files", lipgloss.NewStyle().Foreground(ColorText).Render(fmt.Sprintf("%d", r.Files))),
			cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(formatDiskBytes(r.Bytes))),
		)
	} else {
		lines = append(lines,
			cField("Size", lipgloss.NewStyle().Foreground(ColorText).Render(formatDiskBytes(r.Bytes))))
	}
	if r.Description != "" {
		lines = append(lines,
			cField("Description", lipgloss.NewStyle().Foreground(ColorText).Render(r.Description)))
	}
	lines = append(lines, "", cHint("Press any key to return"))
	return lines
}

// ---------------------------------------------------------------------------
// Browse view
// ---------------------------------------------------------------------------

func (m Model) diskViewBrowse(width int) []string {
	lines := []string{
		cSectionLabel("Evidence Directory — output/" + m.diskCaseID() + "/disk/"),
		cRule(width),
		"",
	}
	if len(m.diskState.browseFlat) == 0 {
		lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorTextMuted).Render(
			"(no evidence collected yet)"))
		lines = append(lines, "", cHint("Esc to return"))
		return lines
	}
	maxRows := 18
	start := 0
	if m.diskState.browseCursor >= maxRows {
		start = m.diskState.browseCursor - maxRows + 1
	}
	end := start + maxRows
	if end > len(m.diskState.browseFlat) {
		end = len(m.diskState.browseFlat)
	}

	for i := start; i < end; i++ {
		node := m.diskState.browseFlat[i]
		indent := strings.Repeat("  ", node.Depth)
		marker := "  "
		if node.IsDir {
			if node.Expanded {
				marker = "▾ "
			} else {
				marker = "▸ "
			}
		}
		display := indent + marker + node.Name
		size := ""
		if node.IsDir {
			if node.Expanded && node.Files > 0 {
				size = fmt.Sprintf("(%d files, %s)", node.Files, formatDiskBytes(node.Bytes))
			}
		} else {
			size = formatDiskBytes(node.Bytes)
		}

		row := fmt.Sprintf("%-50s %s", truncDisk(display, 50), size)
		if i == m.diskState.browseCursor {
			lines = append(lines, "  "+lipgloss.NewStyle().Foreground(ColorHighlight).Bold(true).Render("> "+row))
		} else {
			lines = append(lines, "    "+lipgloss.NewStyle().Foreground(ColorText).Render(row))
		}
	}
	lines = append(lines, "")
	lines = append(lines, cHint("Up/Down: navigate  Enter/Space: expand  Esc: return"))
	return lines
}

// ---------------------------------------------------------------------------
// Simple input view
// ---------------------------------------------------------------------------

func (m Model) diskSimpleInputView(title, prompt string) []string {
	return []string{
		cSectionLabel(title), cRule(80),
		"",
		"  " + lipgloss.NewStyle().Foreground(ColorText).Render(prompt),
		"",
		"  " + m.diskState.input.View(),
		"",
		cHint("Enter: submit  Esc: cancel"),
	}
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

func formatDiskBytes(b int64) string {
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

func formatParserStatus(name string, status disk.Status, dur time.Duration) string {
	icon := lipgloss.NewStyle().Foreground(ColorTextMuted).Render("[ ]")
	nameStr := lipgloss.NewStyle().Foreground(ColorTextMuted).Render(name)
	durStr := ""

	switch status {
	case disk.StatusRunning:
		icon = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render("[▸]")
		nameStr = lipgloss.NewStyle().Foreground(ColorPrimary).Bold(true).Render(name)
		durStr = lipgloss.NewStyle().Foreground(ColorPrimary).Render("running...")
	case disk.StatusSuccess:
		icon = lipgloss.NewStyle().Foreground(ColorSuccess).Render("[✓]")
		nameStr = lipgloss.NewStyle().Foreground(ColorText).Render(name)
		durStr = lipgloss.NewStyle().Foreground(ColorTextSecondary).Render(
			fmt.Sprintf("%d sec", int(dur.Seconds())))
	case disk.StatusPartial:
		icon = lipgloss.NewStyle().Foreground(ColorWarning).Render("[~]")
		nameStr = lipgloss.NewStyle().Foreground(ColorText).Render(name)
		durStr = lipgloss.NewStyle().Foreground(ColorWarning).Render("partial")
	case disk.StatusFailed:
		icon = lipgloss.NewStyle().Foreground(ColorError).Render("[✗]")
		nameStr = lipgloss.NewStyle().Foreground(ColorError).Render(name)
		durStr = lipgloss.NewStyle().Foreground(ColorError).Render("failed")
	case disk.StatusSkipped:
		icon = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("[-]")
		nameStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(name)
		durStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("skipped")
	}

	return fmt.Sprintf("%s %-36s %s", icon, nameStr, durStr)
}

func formatParserResult(r disk.CollectionResult) string {
	var statusStr string
	switch r.Status {
	case disk.StatusSuccess:
		statusStr = SuccessStyle.Render("success")
	case disk.StatusPartial:
		statusStr = WarningStyle.Render("partial")
	case disk.StatusFailed:
		statusStr = ErrorStyle.Render("failed")
	case disk.StatusSkipped:
		statusStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render("skipped")
	default:
		statusStr = lipgloss.NewStyle().Foreground(ColorTextMuted).Render(r.Status.String())
	}
	out := r.OutputFile
	if out == "" {
		out = r.OutputDir
	}
	return fmt.Sprintf("%-32s %-10s %3ds  %s",
		lipgloss.NewStyle().Foreground(ColorText).Render(r.Name),
		statusStr,
		int(r.Duration.Seconds()),
		lipgloss.NewStyle().Foreground(ColorTextMuted).Render(filepath.Base(out)))
}

func truncDisk(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
