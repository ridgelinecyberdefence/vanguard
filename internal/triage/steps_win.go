package triage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// WindowsSteps returns the ordered list of Windows triage collection steps.
//
// Each step writes to its own SubDir under the run's output directory so a
// later step doesn't shadow an earlier one when the analyst opens the case
// folder. Multiple commands inside a step share that subdir.
func WindowsSteps() []StepDef {
	return []StepDef{
		{Name: "System Information", SubDir: "system", RunFunc: winSystemInfo},
		{Name: "Process Listing", SubDir: "processes", RunFunc: winProcesses},
		{Name: "Network Connections", SubDir: "network", RunFunc: winNetworkConns},
		{Name: "Network Configuration", SubDir: "network_config", RunFunc: winNetworkConfig},
		{Name: "Event Log Collection", SubDir: "eventlogs", RunFunc: winEventLogs},
		{Name: "Persistence Mechanisms", SubDir: "persistence", RunFunc: winPersistence},
		{Name: "User Activity", SubDir: "users", RunFunc: winUserActivity},
		{Name: "Browser Artifacts", SubDir: "browser", RunFunc: winBrowserArtifacts},
		{Name: "Installed Software", SubDir: "software", RunFunc: winInstalledSoftware},
		{Name: "Security Posture", SubDir: "security", RunFunc: winSecurityPosture},
	}
}

// WindowsFullTriageIndices returns the indices for a full triage run.
func WindowsFullTriageIndices() []int {
	return []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
}

// WindowsProcessNetworkIndices returns indices for Process & Network Snapshot.
func WindowsProcessNetworkIndices() []int {
	return []int{1, 2, 3}
}

// WindowsEventLogIndices returns indices for Event Log Collection only.
func WindowsEventLogIndices() []int {
	return []int{4}
}

// WindowsPersistenceIndices returns indices for Persistence Check.
func WindowsPersistenceIndices() []int {
	return []int{5}
}

// WindowsUserActivityIndices returns indices for User Activity.
func WindowsUserActivityIndices() []int {
	return []int{6}
}

// WindowsSystemInfoIndices returns indices for System Information + Installed Software.
func WindowsSystemInfoIndices() []int {
	return []int{0, 8, 9}
}

// WindowsBrowserIndices returns indices for Browser Artifacts.
func WindowsBrowserIndices() []int {
	return []int{7}
}

// ---------------------------------------------------------------------------
// Step implementations
// ---------------------------------------------------------------------------

type cmdSpec struct {
	outFile  string
	shell    bool   // if true, use runShell; if false use runPS
	ps       bool   // if true, use runPS
	command  string // shell command or PS command
	args     []string
	exe      string // direct exec.Command target (alternative to shell/ps)
	optional bool   // if true, failure doesn't drop the step to Partial/Failed
}

func runStepCommands(ctx context.Context, outDir string, logger *logging.Logger, name string, cmds []cmdSpec) StepResult {
	result := StepResult{Name: name, Status: StepSuccess}
	succeeded := 0
	requiredTotal := 0
	requiredSucceeded := 0

	for _, c := range cmds {
		outPath := ""
		if c.outFile != "" {
			outPath = filepath.Join(outDir, c.outFile)
		}
		if !c.optional {
			requiredTotal++
		}

		var err error
		if c.ps {
			_, err = runPS(ctx, outPath, c.command)
		} else if c.shell {
			_, err = runShell(ctx, outPath, c.command)
		} else if c.exe != "" {
			_, err = runCommand(ctx, outPath, c.exe, c.args...)
		} else {
			_, err = runShell(ctx, outPath, c.command)
		}

		if err != nil {
			// outFile may be long when callers pass an absolute path; keep the
			// warning compact by showing only the file's basename.
			warning := fmt.Sprintf("%s: %s", filepath.Base(c.outFile),
				cleanProcessError(err))
			result.Warnings = append(result.Warnings, warning)
			if logger != nil {
				if c.optional {
					logger.Info("triage", "%s — %s (optional): %v", name, c.outFile, err)
				} else {
					logger.Warn("triage", "%s — %s: %v", name, c.outFile, err)
				}
			}
		} else {
			succeeded++
			if !c.optional {
				requiredSucceeded++
			}
		}
	}

	// Status is driven by the REQUIRED commands only. Optional commands
	// (whoami, Get-ComputerInfo on locked-down hosts, etc.) record warnings
	// but don't downgrade the step.
	switch {
	case requiredTotal == 0 && succeeded == 0:
		result.Status = StepFailed
	case requiredTotal == 0:
		result.Status = StepSuccess
	case requiredSucceeded == 0:
		result.Status = StepFailed
	case requiredSucceeded < requiredTotal:
		result.Status = StepPartial
	}

	return result
}

// cleanProcessError converts an exec error message into a one-line, TUI-safe
// summary. Multi-line stderr from underlying tools (the source of leakage like
// "The system cannot find the path specified.") is collapsed to its first
// non-empty line so the message fits a single warning row.
func cleanProcessError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return line
	}
	return msg
}

// ---------------------------------------------------------------------------
// System Information
// ---------------------------------------------------------------------------

func winSystemInfo(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	envPath := filepath.Join(outDir, "environment.txt")
	hotfixPath := filepath.Join(outDir, "hotfixes.csv")
	driversPath := filepath.Join(outDir, "drivers.csv")
	domainPath := filepath.Join(outDir, "domain_info.txt")

	cmds := []cmdSpec{
		{outFile: "systeminfo.txt", exe: "systeminfo"},
		{outFile: "hostname.txt", exe: "hostname"},
		// whoami /all returns 1 on locked-down accounts (group SIDs not
		// resolvable, no privilege table). Mark optional so its failure
		// doesn't drag the whole step to Partial.
		{outFile: "whoami.txt", exe: "whoami", args: []string{"/all"}, optional: true},
		// Get-ComputerInfo is slow and can fail on Server Core / Nano —
		// useful when it works but not worth failing the step over.
		{outFile: "computerinfo.txt", ps: true, optional: true,
			command: "Get-ComputerInfo | Format-List *"},
		{ps: true, command: fmt.Sprintf(
			"Get-ChildItem Env: | Format-Table -AutoSize | Out-File -Encoding UTF8 -FilePath '%s'",
			envPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-HotFix | Select-Object HotFixID,Description,InstalledOn,InstalledBy | Export-Csv -NoTypeInformation -Path '%s'",
			hotfixPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName | Export-Csv -NoTypeInformation -Path '%s'",
			driversPath)},
		// gpresult /r prints to stdout — capture via runCommand. Returns
		// non-zero on workgroup hosts; mark optional.
		{outFile: "gpresult.txt", exe: "gpresult", args: []string{"/r"}, optional: true},
		// Domain info via .NET reflection so we don't depend on RSAT.
		{ps: true, optional: true, command: fmt.Sprintf(
			"try { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Format-List | Out-File -Encoding UTF8 -FilePath '%s' } catch { 'Not domain joined' | Out-File -Encoding UTF8 -FilePath '%s' }",
			domainPath, domainPath)},
	}
	return runStepCommands(ctx, outDir, logger, "System Information", cmds)
}

// ---------------------------------------------------------------------------
// Process Listing
// ---------------------------------------------------------------------------

func winProcesses(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	// wmic.exe is deprecated and removed entirely on Windows 11 24H2 / Server
	// 2025. Everything that used to require wmic now goes through
	// Get-CimInstance — same WMI surface, available on every supported build.
	detailedPath := filepath.Join(outDir, "processes_detailed.csv")
	cmdlinePath := filepath.Join(outDir, "processes_cmdline.csv")
	treePath := filepath.Join(outDir, "processes_tree.txt")
	modulesPath := filepath.Join(outDir, "open_files.csv")

	cmds := []cmdSpec{
		{outFile: "processes.csv", exe: "tasklist", args: []string{"/v", "/fo", "csv"}},
		{ps: true, command: fmt.Sprintf(
			"Get-Process | Select-Object Id,ProcessName,Path,Company,CPU,WorkingSet64,StartTime | Export-Csv -NoTypeInformation -Path '%s'",
			detailedPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath,CreationDate | Export-Csv -NoTypeInformation -Path '%s'",
			cmdlinePath)},
		{ps: true, command: fmt.Sprintf(
			"Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-Table -AutoSize | Out-File -Encoding UTF8 -FilePath '%s'",
			treePath)},
		// Process module / loaded-DLL listing — useful for IOC matching but
		// hits PerfMon ACL on locked-down hosts. Optional.
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-Process | Where-Object { $_.Modules } | ForEach-Object { $proc = $_; $_.Modules | ForEach-Object { [PSCustomObject]@{ProcessName=$proc.Name;PID=$proc.Id;Module=$_.FileName} } } | Export-Csv -NoTypeInformation -Path '%s'",
			modulesPath)},
	}

	return runStepCommands(ctx, outDir, logger, "Process Listing", cmds)
}

// ---------------------------------------------------------------------------
// Network Connections
// ---------------------------------------------------------------------------

func winNetworkConns(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	tcpPath := filepath.Join(outDir, "tcpconnections.csv")
	udpPath := filepath.Join(outDir, "udpendpoints.csv")

	cmds := []cmdSpec{
		{outFile: "netstat.txt", exe: "netstat", args: []string{"-anob"}},
		{ps: true,
			command: fmt.Sprintf(
				"Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -NoTypeInformation -Path '%s'",
				tcpPath)},
		{ps: true,
			command: fmt.Sprintf(
				"Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Export-Csv -NoTypeInformation -Path '%s'",
				udpPath)},
	}
	return runStepCommands(ctx, outDir, logger, "Network Connections", cmds)
}

// ---------------------------------------------------------------------------
// Network Configuration
// ---------------------------------------------------------------------------

func winNetworkConfig(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	dnsPath := filepath.Join(outDir, "dns_cache.csv")
	sharesPath := filepath.Join(outDir, "shares.csv")
	firewallRulesPath := filepath.Join(outDir, "firewall_rules.csv")
	netProfilesPath := filepath.Join(outDir, "network_profiles.csv")

	cmds := []cmdSpec{
		{outFile: "ipconfig.txt", exe: "ipconfig", args: []string{"/all"}},
		{outFile: "routes.txt", exe: "route", args: []string{"print"}},
		{outFile: "arp_cache.txt", exe: "arp", args: []string{"-a"}},
		{outFile: "dns_cache.txt", exe: "ipconfig", args: []string{"/displaydns"}, optional: true},
		{outFile: "firewall_profiles.txt", exe: "netsh",
			args: []string{"advfirewall", "show", "allprofiles"}},
		{outFile: "firewall_rules.txt", exe: "netsh",
			args: []string{"advfirewall", "firewall", "show", "rule", "name=all"}},
		{ps: true, command: fmt.Sprintf(
			"Get-DnsClientCache | Export-Csv -NoTypeInformation -Path '%s'", dnsPath)},
		// SMB shares + active sessions hosted on this box.
		{ps: true, command: fmt.Sprintf(
			"Get-SmbShare | Select-Object Name,Path,Description,ScopeName,CurrentUsers | Export-Csv -NoTypeInformation -Path '%s'",
			sharesPath)},
		// `net session` requires admin and lists inbound connections to this
		// host's shares — a useful lateral-movement signal but not a hard
		// requirement for the step.
		{outFile: "sessions.txt", exe: "net", args: []string{"session"}, optional: true},
		// Structured firewall rules for filtering / diffing across hosts.
		{ps: true, command: fmt.Sprintf(
			"Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile | Export-Csv -NoTypeInformation -Path '%s'",
			firewallRulesPath)},
		// Connected network profile types (Public/Private/Domain) help spot
		// hosts that are unexpectedly on a public network.
		{ps: true, command: fmt.Sprintf(
			"Get-NetConnectionProfile | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity | Export-Csv -NoTypeInformation -Path '%s'",
			netProfilesPath)},
	}
	return runStepCommands(ctx, outDir, logger, "Network Configuration", cmds)
}

// ---------------------------------------------------------------------------
// Event Log Collection
// ---------------------------------------------------------------------------

func winEventLogs(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	// Old code wrapped channel + path in single quotes and pushed the whole
	// command through `cmd /c`. cmd.exe doesn't recognise single quotes, so
	// they were passed literally to wevtutil — the channel name "'Security'"
	// doesn't exist and wevtutil exits 15000 ("The specified channel could
	// not be found"). Calling exec.Command with separate args avoids the
	// shell entirely, which is also safer (no path-injection surface).
	logs := []struct {
		name     string // .evtx output filename
		channel  string // Windows event log channel
		critical bool   // failure of a non-critical log doesn't downgrade the step
	}{
		{"Security.evtx", "Security", true},
		{"System.evtx", "System", true},
		{"Application.evtx", "Application", true},
		{"PowerShell-Operational.evtx", "Microsoft-Windows-PowerShell/Operational", true},
		{"Sysmon.evtx", "Microsoft-Windows-Sysmon/Operational", false},
		{"TaskScheduler.evtx", "Microsoft-Windows-TaskScheduler/Operational", false},
		{"WinRM.evtx", "Microsoft-Windows-WinRM/Operational", false},
		{"RDP-LocalSession.evtx", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", false},
		{"Defender-Operational.evtx", "Microsoft-Windows-Windows Defender/Operational", false},
		{"Bits-Client.evtx", "Microsoft-Windows-Bits-Client/Operational", false},
		{"DNS-Client.evtx", "Microsoft-Windows-DNS-Client/Operational", false},
		{"Firewall.evtx", "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", false},
	}

	// Make sure the output directory exists before wevtutil tries to write
	// to it — wevtutil won't create parent directories, returns 15007 if the
	// path doesn't resolve.
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return StepResult{Name: "Event Log Collection", Status: StepFailed,
			Warnings: []string{fmt.Sprintf("mkdir %s: %v", outDir, err)}}
	}

	result := StepResult{Name: "Event Log Collection", Status: StepSuccess}
	criticalTotal := 0
	criticalSucceeded := 0

	for _, log := range logs {
		// filepath.FromSlash normalises any inadvertent forward slashes to
		// the platform separator. filepath.Join already does this for the
		// pieces it composes, but a defensive call documents the intent.
		// filepath.Abs guarantees an absolute path even if outDir was passed
		// in as relative — wevtutil resolves paths against its own cwd, not
		// ours, so a relative path can land in an unexpected place.
		outPath := filepath.FromSlash(filepath.Join(outDir, log.name))
		if abs, err := filepath.Abs(outPath); err == nil {
			outPath = abs
		}

		_, err := runCommand(ctx, "", "wevtutil", "epl", log.channel, outPath)
		if err != nil && !fileExistsAndNonEmpty(outPath) {
			// Try the file-copy fallback: live .evtx files are at
			// C:\Windows\System32\winevt\Logs\<channel-encoded>.evtx, with
			// `/` in the channel name represented on disk as `%4`. This
			// works against locked logs as long as VanGuard runs elevated
			// (the volume shadow copy isn't required at the file-level).
			fallbackSrc := filepath.Join(`C:\Windows\System32\winevt\Logs`,
				channelToFileName(log.channel)+".evtx")
			if copyErr := runCopyFile(fallbackSrc, outPath); copyErr == nil {
				err = nil
			}
		}

		if log.critical {
			criticalTotal++
		}
		if err != nil {
			// Exit code 15007 = ERROR_EVT_CHANNEL_NOT_FOUND — the channel
			// simply isn't registered on this host (e.g. Sysmon not installed).
			// Suppress the warning for non-critical channels so the analyst
			// doesn't wade through noise for optional components.
			channelMissing := strings.Contains(err.Error(), "15007")
			if log.critical || !channelMissing {
				warning := fmt.Sprintf("%s: %s", log.name, cleanProcessError(err))
				result.Warnings = append(result.Warnings, warning)
			}
			if logger != nil {
				if log.critical {
					logger.Warn("triage", "event log %s: %v", log.channel, err)
				} else if channelMissing {
					logger.Info("triage", "event log %s: channel not found (component not installed)", log.channel)
				} else {
					logger.Info("triage",
						"event log %s not available (often expected): %v", log.channel, err)
				}
			}
		} else if log.critical {
			criticalSucceeded++
		}
	}

	switch {
	case criticalTotal == 0:
		result.Status = StepSuccess
	case criticalSucceeded == 0:
		result.Status = StepFailed
	case criticalSucceeded < criticalTotal:
		result.Status = StepPartial
	}
	return result
}

// channelToFileName converts a Windows event log channel name to the on-disk
// .evtx filename. Channels with `/` in their name (e.g.
// `Microsoft-Windows-PowerShell/Operational`) are stored with `%4` in the
// filename instead. Used as a fallback when wevtutil epl fails.
func channelToFileName(channel string) string {
	return strings.ReplaceAll(channel, "/", "%4")
}

// fileExistsAndNonEmpty returns true if path points at a regular file with
// at least one byte. Used to recognise wevtutil partial successes (the
// process exits non-zero but still writes a valid .evtx).
func fileExistsAndNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
}

// ---------------------------------------------------------------------------
// Persistence Mechanisms
// ---------------------------------------------------------------------------

func winPersistence(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	startupPath := filepath.Join(outDir, "startup_commands.csv")
	servicesPath := filepath.Join(outDir, "services.csv")
	wmiFiltersPath := filepath.Join(outDir, "wmi_filters.csv")
	wmiConsumersPath := filepath.Join(outDir, "wmi_consumers.csv")
	wmiBindingsPath := filepath.Join(outDir, "wmi_bindings.csv")
	tasksXMLPath := filepath.Join(outDir, "scheduled_tasks_xml.txt")

	cmds := []cmdSpec{
		{ps: true, command: fmt.Sprintf(
			"Get-CimInstance Win32_StartupCommand | Export-Csv -NoTypeInformation -Path '%s'",
			startupPath)},
		{outFile: "run_hklm.reg", exe: "reg",
			args: []string{"export", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, filepath.Join(outDir, "run_hklm.reg"), "/y"}},
		{outFile: "run_hkcu.reg", exe: "reg",
			args: []string{"export", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, filepath.Join(outDir, "run_hkcu.reg"), "/y"}},
		{outFile: "runonce_hklm.reg", exe: "reg",
			args: []string{"export", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, filepath.Join(outDir, "runonce_hklm.reg"), "/y"}},
		{outFile: "runonce_hkcu.reg", exe: "reg",
			args: []string{"export", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, filepath.Join(outDir, "runonce_hkcu.reg"), "/y"}},
		{outFile: "scheduled_tasks.csv", exe: "schtasks",
			args: []string{"/query", "/fo", "csv", "/v"}},
		// Full Task Scheduler XML for enabled tasks — surfaces the action
		// command line, principal, triggers; harder to spoof than schtasks
		// /query output. Optional because Export-ScheduledTask isn't on
		// every Server SKU.
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $_ | Export-ScheduledTask } | Out-File -Encoding UTF8 -FilePath '%s'",
			tasksXMLPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-Service | Select-Object Name,DisplayName,Status,StartType,BinaryPathName | Export-Csv -NoTypeInformation -Path '%s'",
			servicesPath)},
		// WMI persistence triad — filter, consumer, and the binding that
		// links them. Defenders care about the binding most because that's
		// what triggers the consumer when the filter fires.
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation -Path '%s'",
			wmiFiltersPath)},
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation -Path '%s'",
			wmiConsumersPath)},
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer | Export-Csv -NoTypeInformation -Path '%s'",
			wmiBindingsPath)},
	}

	// reg export writes to the file directly — clear outFile so we don't double-write.
	for i := range cmds {
		if cmds[i].exe == "reg" {
			cmds[i].outFile = ""
		}
	}

	return runStepCommands(ctx, outDir, logger, "Persistence Mechanisms", cmds)
}

// ---------------------------------------------------------------------------
// User Activity
// ---------------------------------------------------------------------------

func winUserActivity(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	usersPath := filepath.Join(outDir, "local_users.csv")
	adminPath := filepath.Join(outDir, "admin_group.csv")
	recentFilesPath := filepath.Join(outDir, "recent_files.csv")
	psHistoryPath := filepath.Join(outDir, "powershell_history.txt")

	cmds := []cmdSpec{
		{ps: true, command: fmt.Sprintf(
			"Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description | Export-Csv -NoTypeInformation -Path '%s'",
			usersPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation -Path '%s'",
			adminPath)},
		// `net session` requires admin; on workstations it usually returns
		// "no entries". Optional so we don't punish the step.
		{outFile: "active_sessions.txt", exe: "net", args: []string{"session"}, optional: true},
		{outFile: "logged_on_users.txt", shell: true, command: "query user"},
		{outFile: "recent_docs.txt", ps: true, optional: true,
			command: "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs' -ErrorAction SilentlyContinue | Format-List"},
		// .lnk files in each user's Recent folder — quick view of what was
		// touched recently across the box.
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-ChildItem 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk' -ErrorAction SilentlyContinue | Select-Object Name,FullName,LastWriteTime,Length | Export-Csv -NoTypeInformation -Path '%s'",
			recentFilesPath)},
		// PowerShell ConsoleHost history for every user. PSReadLine writes
		// commands here automatically — high-value forensic data.
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-ChildItem 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ('=== ' + $_.FullName + ' ==='); Get-Content $_.FullName -ErrorAction SilentlyContinue } | Out-File -Encoding UTF8 -FilePath '%s'",
			psHistoryPath)},
	}
	return runStepCommands(ctx, outDir, logger, "User Activity", cmds)
}

// ---------------------------------------------------------------------------
// Browser Artifacts
// ---------------------------------------------------------------------------

func winBrowserArtifacts(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	result := StepResult{Name: "Browser Artifacts", Status: StepSuccess}
	succeeded := 0

	type browserFile struct {
		envVar  string
		relPath string
		outName string
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	files := []browserFile{
		{envVar: localAppData, relPath: `Google\Chrome\User Data\Default\History`, outName: "chrome_history.db"},
		{envVar: localAppData, relPath: `Google\Chrome\User Data\Default\Downloads`, outName: "chrome_downloads.db"},
		{envVar: localAppData, relPath: `Microsoft\Edge\User Data\Default\History`, outName: "edge_history.db"},
	}

	for _, f := range files {
		src := filepath.Join(f.envVar, f.relPath)
		dst := filepath.Join(outDir, f.outName)
		if err := runCopyFile(src, dst); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s: %s", f.outName, cleanProcessError(err)))
		} else {
			succeeded++
		}
	}

	// Firefox profiles — use glob.
	firefoxProfiles, _ := filepath.Glob(filepath.Join(appData, `Mozilla\Firefox\Profiles\*\places.sqlite`))
	for i, p := range firefoxProfiles {
		dst := filepath.Join(outDir, fmt.Sprintf("firefox_places_%d.db", i))
		if err := runCopyFile(p, dst); err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("firefox_places: %v", err))
		} else {
			succeeded++
		}
	}

	if succeeded == 0 {
		result.Status = StepPartial
		if len(result.Warnings) > 0 {
			result.Warnings = append([]string{"No browser databases could be copied (files may be locked)."}, result.Warnings...)
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// Installed Software
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Security Posture — Defender state and Trusted Root certificates.
// ---------------------------------------------------------------------------
//
// Defender exclusion paths and unexpected Trusted Root certs are common
// signals of compromise: attackers add an exclusion for their staging
// directory or install a custom root CA so they can MITM HTTPS traffic.
// All commands are optional — Defender cmdlets aren't present on hosts
// using a third-party AV product.
func winSecurityPosture(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	detectionsPath := filepath.Join(outDir, "defender_detections.csv")
	exclusionsPath := filepath.Join(outDir, "defender_exclusions.csv")
	prefsPath := filepath.Join(outDir, "defender_preferences.txt")
	certsPath := filepath.Join(outDir, "trusted_root_certs.csv")

	cmds := []cmdSpec{
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-MpThreatDetection -ErrorAction SilentlyContinue | Export-Csv -NoTypeInformation -Path '%s'",
			detectionsPath)},
		{ps: true, optional: true, command: fmt.Sprintf(
			"$p = Get-MpPreference -ErrorAction SilentlyContinue; if ($p) { $p.ExclusionPath | ForEach-Object { [PSCustomObject]@{ExclusionPath=$_} } | Export-Csv -NoTypeInformation -Path '%s' }",
			exclusionsPath)},
		{ps: true, optional: true, command: fmt.Sprintf(
			"Get-MpPreference -ErrorAction SilentlyContinue | Format-List | Out-File -Encoding UTF8 -FilePath '%s'",
			prefsPath)},
		{ps: true, command: fmt.Sprintf(
			"Get-ChildItem Cert:\\LocalMachine\\Root | Select-Object Thumbprint,Subject,Issuer,NotBefore,NotAfter | Export-Csv -NoTypeInformation -Path '%s'",
			certsPath)},
	}
	return runStepCommands(ctx, outDir, logger, "Security Posture", cmds)
}

func winInstalledSoftware(ctx context.Context, outDir string, logger *logging.Logger) StepResult {
	x64Path := filepath.Join(outDir, "installed_software.csv")
	x86Path := filepath.Join(outDir, "installed_software_x86.csv")

	cmds := []cmdSpec{
		{ps: true,
			command: fmt.Sprintf(
				"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Export-Csv -NoTypeInformation -Path '%s'",
				x64Path)},
		{ps: true,
			command: fmt.Sprintf(
				"Get-ItemProperty HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Export-Csv -NoTypeInformation -Path '%s'",
				x86Path)},
	}
	return runStepCommands(ctx, outDir, logger, "Installed Software", cmds)
}
