package hunting

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// ---------------------------------------------------------------------------
// Suspicious pattern lists
// ---------------------------------------------------------------------------

// LOLBins — Living Off the Land Binaries commonly abused by attackers.
var windowsLOLBins = []string{
	"certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
	"msiexec.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe",
	"wmic.exe", "powershell.exe", "cmd.exe", "schtasks.exe",
	"at.exe", "sc.exe", "net.exe", "net1.exe", "psexec.exe",
	"installutil.exe", "regasm.exe", "msbuild.exe", "cmstp.exe",
	"esentutl.exe", "expand.exe", "extrac32.exe", "findstr.exe",
	"forfiles.exe", "hh.exe", "ieexec.exe", "infdefaultinstall.exe",
	"makecab.exe", "mavinject.exe", "microsoft.workflow.compiler.exe",
	"mmc.exe", "msconfig.exe", "msdeploy.exe", "msdt.exe",
	"pcalua.exe", "presentationhost.exe", "replace.exe",
	"rpcping.exe", "runscripthelper.exe", "scriptrunner.exe",
	"syncappvpublishingserver.exe", "verclsid.exe", "xwizard.exe",
}

// Encoded command patterns.
var encodedCmdPatterns = []string{
	"-enc ", "-encodedcommand ", "-e ", "frombase64string",
	"[convert]::frombase64", "[system.convert]::frombase64",
}

// Suspicious process names.
var suspiciousProcessNames = []string{
	"mimikatz", "lazagne", "rubeus", "seatbelt", "sharphound",
	"bloodhound", "cobalt", "beacon", "meterpreter", "nc.exe",
	"ncat.exe", "netcat", "psexesvc", "procdump", "nanodump",
}

// Suspicious network ports (C2, mining, etc.).
var suspiciousPortsWin = []int{
	4444, 5555, 8888, 1234, 6666, 7777, 9999, // common C2
	3389, // RDP (outbound is suspicious)
	4443, 8443, // alternate HTTPS C2
	31337, 12345, 54321, // backdoor
}

// Named pipe patterns for known tools.
var namedPipePatterns = []string{
	`\MSSE-`, `\msagent_`, `\postex_`, // Cobalt Strike
	`\status_`, `\mojo.`, `\chrome.`,  // Cobalt Strike variants
	`\winsock`, `\ntsvcs`,             // PsExec
	`\meterpreter`, `\msf`,           // Metasploit
	`\evil`, `\implant`, `\c2`,       // generic
}

// ---------------------------------------------------------------------------
// Windows live hunting operations
// ---------------------------------------------------------------------------

// WinSuspiciousProcesses scans for LOLBin abuse, encoded commands,
// orphaned processes, and known malicious tool names.
func WinSuspiciousProcesses(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Suspicious Processes"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. Get all processes with command lines.
	procFile := filepath.Join(outDir, "processes_raw.txt")
	psCmd := `Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate | ConvertTo-Csv -NoTypeInformation`
	out, err := runPS(ctx, procFile, psCmd)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("process enumeration: %v", err))
	}

	outLower := strings.ToLower(out)

	// 2. Check for LOLBin processes with suspicious command lines.
	lolbinFile := filepath.Join(outDir, "lolbin_detections.txt")
	var lolbinHits []string
	for _, lolbin := range windowsLOLBins {
		if strings.Contains(outLower, strings.ToLower(lolbin)) {
			lolbinHits = append(lolbinHits, lolbin)
		}
	}
	if len(lolbinHits) > 0 {
		_ = os.WriteFile(lolbinFile, []byte(strings.Join(lolbinHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "medium",
			Title:    fmt.Sprintf("LOLBin processes detected: %s", strings.Join(lolbinHits, ", ")),
			Source:   "live_proc",
			MITRE:    "T1218",
		})
	}

	// 3. Check for encoded commands.
	encodedFile := filepath.Join(outDir, "encoded_commands.txt")
	var encodedHits []string
	for _, pattern := range encodedCmdPatterns {
		if strings.Contains(outLower, strings.ToLower(pattern)) {
			encodedHits = append(encodedHits, pattern)
		}
	}
	if len(encodedHits) > 0 {
		_ = os.WriteFile(encodedFile, []byte(strings.Join(encodedHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Encoded/obfuscated command line arguments detected",
			Source:   "live_proc",
			MITRE:    "T1059.001",
		})
	}

	// 4. Check for known malicious tool names.
	malwareFile := filepath.Join(outDir, "known_tools.txt")
	var toolHits []string
	for _, tool := range suspiciousProcessNames {
		if strings.Contains(outLower, strings.ToLower(tool)) {
			toolHits = append(toolHits, tool)
		}
	}
	if len(toolHits) > 0 {
		_ = os.WriteFile(malwareFile, []byte(strings.Join(toolHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "critical",
			Title:    fmt.Sprintf("Known attack tools detected: %s", strings.Join(toolHits, ", ")),
			Source:   "live_proc",
			MITRE:    "T1588.002",
		})
	}

	// 5. Check for processes running from temp directories.
	tempFile := filepath.Join(outDir, "temp_processes.txt")
	tempPaths := []string{`\temp\`, `\tmp\`, `\appdata\local\temp\`, `\downloads\`}
	var tempHits []string
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, tp := range tempPaths {
			if strings.Contains(lower, tp) {
				tempHits = append(tempHits, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(tempHits) > 0 {
		_ = os.WriteFile(tempFile, []byte(strings.Join(tempHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "medium",
			Title:    fmt.Sprintf("%d processes running from temp/download directories", len(tempHits)),
			Source:   "live_proc",
			MITRE:    "T1204",
		})
	}

	status := ScanSuccess
	if len(findings) > 0 {
		status = ScanPartial
	}

	return ScanResult{
		Name:     name,
		Status:   status,
		Duration: time.Since(start),
		Output:   outDir,
		Findings: findings,
		Warnings: warnings,
	}
}

// WinNetworkAnomalies detects suspicious network connections.
func WinNetworkAnomalies(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Network Anomalies"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. Get established connections with process info.
	connFile := filepath.Join(outDir, "connections.txt")
	psCmd := `Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | ConvertTo-Csv -NoTypeInformation`
	out, err := runPS(ctx, connFile, psCmd)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("connection enumeration: %v", err))
	}

	// 2. Check for suspicious ports.
	suspPortFile := filepath.Join(outDir, "suspicious_ports.txt")
	var portHits []string
	for _, port := range suspiciousPortsWin {
		portStr := fmt.Sprintf(",%d,", port)
		if strings.Contains(out, portStr) {
			portHits = append(portHits, fmt.Sprintf("port %d", port))
		}
	}
	if len(portHits) > 0 {
		_ = os.WriteFile(suspPortFile, []byte(strings.Join(portHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("Suspicious port connections: %s", strings.Join(portHits, ", ")),
			Source:   "live_net",
			MITRE:    "T1571",
		})
	}

	// 3. Check for connections from temp directories.
	tempConnFile := filepath.Join(outDir, "temp_connections.txt")
	psCmd2 := `Get-NetTCPConnection -State Established | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p.Path -like '*\Temp\*' -or $p.Path -like '*\tmp\*' -or $p.Path -like '*\Downloads\*') { "$($_.RemoteAddress):$($_.RemotePort) - $($p.Path)" } }`
	out2, err := runPS(ctx, tempConnFile, psCmd2)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("temp connection check: %v", err))
	}
	if strings.TrimSpace(out2) != "" {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Network connections from temp/download directories",
			Source:   "live_net",
			MITRE:    "T1071",
		})
	}

	// 4. DNS cache dump.
	dnsFile := filepath.Join(outDir, "dns_cache.txt")
	_, _ = runPS(ctx, dnsFile, `Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation`)

	// 5. Listening ports.
	listenFile := filepath.Join(outDir, "listening_ports.txt")
	_, _ = runPS(ctx, listenFile, `Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} | ConvertTo-Csv -NoTypeInformation`)

	status := ScanSuccess
	if len(findings) > 0 {
		status = ScanPartial
	}

	return ScanResult{
		Name:     name,
		Status:   status,
		Duration: time.Since(start),
		Output:   outDir,
		Findings: findings,
		Warnings: warnings,
	}
}

// WinScheduledTasks audits scheduled tasks for suspicious entries.
func WinScheduledTasks(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Scheduled Task Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Get all scheduled tasks with actions.
	taskFile := filepath.Join(outDir, "scheduled_tasks.csv")
	psCmd := `Get-ScheduledTask | ForEach-Object { $task = $_; $task.Actions | ForEach-Object { [PSCustomObject]@{ TaskName=$task.TaskName; TaskPath=$task.TaskPath; State=$task.State; Execute=$_.Execute; Arguments=$_.Arguments; Author=$task.Author; Date=$task.Date } } } | ConvertTo-Csv -NoTypeInformation`
	out, err := runPS(ctx, taskFile, psCmd)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("task enumeration: %v", err))
	}

	outLower := strings.ToLower(out)

	// Check for tasks executing from suspicious paths.
	suspPaths := []string{`\temp\`, `\tmp\`, `\appdata\`, `\downloads\`, `\public\`}
	var suspTasks []string
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		for _, sp := range suspPaths {
			if strings.Contains(lower, sp) {
				suspTasks = append(suspTasks, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(suspTasks) > 0 {
		suspFile := filepath.Join(outDir, "suspicious_tasks.txt")
		_ = os.WriteFile(suspFile, []byte(strings.Join(suspTasks, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d scheduled tasks with suspicious paths", len(suspTasks)),
			Source:   "live_schtask",
			MITRE:    "T1053.005",
		})
	}

	// Check for encoded commands in task actions.
	for _, enc := range encodedCmdPatterns {
		if strings.Contains(outLower, strings.ToLower(enc)) {
			findings = append(findings, Finding{
				Severity: "critical",
				Title:    "Scheduled task with encoded command detected",
				Source:   "live_schtask",
				MITRE:    "T1053.005",
			})
			break
		}
	}

	status := ScanSuccess
	if len(findings) > 0 {
		status = ScanPartial
	}

	return ScanResult{
		Name:     name,
		Status:   status,
		Duration: time.Since(start),
		Output:   outDir,
		Findings: findings,
		Warnings: warnings,
	}
}

// WinAutorunsAudit audits autorun/startup entries.
func WinAutorunsAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Autoruns & Startup Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Registry Run keys.
	runKeyFile := filepath.Join(outDir, "registry_run_keys.txt")
	psCmd := `@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') | ForEach-Object { "--- $_"; if (Test-Path $_) { Get-ItemProperty $_ | Out-String } }`
	out, err := runPS(ctx, runKeyFile, psCmd)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("registry run keys: %v", err))
	}

	// Check for suspicious entries in Run keys.
	outLower := strings.ToLower(out)
	suspPaths := []string{`\temp\`, `\tmp\`, `\appdata\local\temp\`, `\downloads\`, `\public\`}
	for _, sp := range suspPaths {
		if strings.Contains(outLower, sp) {
			findings = append(findings, Finding{
				Severity: "high",
				Title:    "Autorun entry pointing to suspicious path",
				Source:   "live_autoruns",
				MITRE:    "T1547.001",
			})
			break
		}
	}

	// Startup folder contents.
	startupFile := filepath.Join(outDir, "startup_folder.txt")
	_, _ = runPS(ctx, startupFile, `@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object { "--- $_"; if (Test-Path $_) { Get-ChildItem $_ -Force | Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize | Out-String } }`)

	// WMI event subscriptions (persistence).
	wmiFile := filepath.Join(outDir, "wmi_subscriptions.txt")
	wmiOut, _ := runPS(ctx, wmiFile, `Get-WMIObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query | Format-List | Out-String; Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate | Format-List | Out-String`)
	if strings.TrimSpace(wmiOut) != "" && !strings.Contains(wmiOut, "Get-WMIObject : ") {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "WMI event subscriptions detected (potential persistence)",
			Source:   "live_autoruns",
			MITRE:    "T1546.003",
		})
	}

	status := ScanSuccess
	if len(findings) > 0 {
		status = ScanPartial
	}

	return ScanResult{
		Name:     name,
		Status:   status,
		Duration: time.Since(start),
		Output:   outDir,
		Findings: findings,
		Warnings: warnings,
	}
}

// WinServiceAnomalies detects service anomalies (unquoted paths, non-standard paths).
func WinServiceAnomalies(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Service Anomaly Detection"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Get all services with binary paths.
	svcFile := filepath.Join(outDir, "services.csv")
	psCmd := `Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName | ConvertTo-Csv -NoTypeInformation`
	out, err := runPS(ctx, svcFile, psCmd)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("service enumeration: %v", err))
	}

	// Check for unquoted service paths with spaces.
	unquotedFile := filepath.Join(outDir, "unquoted_paths.txt")
	var unquoted []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " ") && !strings.HasPrefix(strings.TrimSpace(line), `"`) {
			fields := strings.Split(line, ",")
			if len(fields) >= 5 {
				pathField := fields[4]
				if strings.Contains(pathField, " ") && !strings.HasPrefix(pathField, `"`) && strings.Contains(pathField, `\`) {
					unquoted = append(unquoted, strings.TrimSpace(line))
				}
			}
		}
	}
	if len(unquoted) > 0 {
		_ = os.WriteFile(unquotedFile, []byte(strings.Join(unquoted, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "medium",
			Title:    fmt.Sprintf("%d services with unquoted paths (potential hijack)", len(unquoted)),
			Source:   "live_services",
			MITRE:    "T1574.009",
		})
	}

	// Check for services running from non-standard paths.
	nonStdFile := filepath.Join(outDir, "non_standard_services.txt")
	suspSvcPaths := []string{`\temp\`, `\tmp\`, `\appdata\`, `\downloads\`, `\users\public\`}
	var nonStd []string
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		for _, sp := range suspSvcPaths {
			if strings.Contains(lower, sp) {
				nonStd = append(nonStd, strings.TrimSpace(line))
				break
			}
		}
	}
	if len(nonStd) > 0 {
		_ = os.WriteFile(nonStdFile, []byte(strings.Join(nonStd, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d services running from non-standard paths", len(nonStd)),
			Source:   "live_services",
			MITRE:    "T1543.003",
		})
	}

	status := ScanSuccess
	if len(findings) > 0 {
		status = ScanPartial
	}

	return ScanResult{
		Name:     name,
		Status:   status,
		Duration: time.Since(start),
		Output:   outDir,
		Findings: findings,
		Warnings: warnings,
	}
}
