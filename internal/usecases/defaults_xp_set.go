package usecases

// crossPlatformUseCases returns UC-XP-001 / 002 / 003. Each one carries
// platform-specific steps (with Step.Platform set) so the runner can pick the
// right command at execution time without the use case author duplicating
// definitions.
func crossPlatformUseCases() []UseCase {
	return []UseCase{
		ucXPIOCSweep(),
		ucXPYARAHunt(),
		ucXPBaseline(),
	}
}

// ---------------------------------------------------------------------------
// UC-XP-001 IOC Sweep
// ---------------------------------------------------------------------------

func ucXPIOCSweep() UseCase {
	return UseCase{
		Name:          "IOC Sweep",
		ID:            "UC-XP-001",
		Description:   "Search the local host for indicators (file hash, filename, IP, domain). Optionally batch from an IOC file.",
		Platform:      PlatformXP,
		Severity:      SeverityVaries,
		EstimatedTime: "15-30 minutes",
		MITREAttack:   []string{"T1057", "T1083"},
		Parameters: []UseCaseParameter{
			{Name: "ioc_value", Description: "Indicator value (hash / filename / IP / domain)", Required: true, Type: "string"},
			{Name: "ioc_type", Description: "Type: filehash | filename | ip | domain", Required: true, Type: "selection", Default: "filename"},
			{Name: "ioc_file", Description: "Optional CSV with type,value rows for batch sweep", Type: "path"},
		},
		Phases: []UseCasePhase{
			{
				Name: "Filename sweep",
				Steps: []UseCaseStep{
					{Name: "Windows file search", Type: StepCommand, Platform: PlatformWindows, Optional: true, Timeout: 1200,
						Command: `Get-ChildItem -Path C:\,D:\ -Recurse -Filter '{ioc_value}' -ErrorAction SilentlyContinue -File | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Linux file search", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 1200,
						Command: `find / -xdev -name '{ioc_value}' 2>/dev/null`},
				},
			},
			{
				Name: "Hash sweep",
				Steps: []UseCaseStep{
					{Name: "Windows hash search (scoped)", Type: StepCommand, Platform: PlatformWindows, Optional: true, Timeout: 1800,
						Command: `$h='{ioc_value}'; foreach ($r in 'C:\Windows\Temp','C:\Users','C:\ProgramData','C:\Windows\System32') { Get-ChildItem -Path $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 200MB } | Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue | Where-Object { $_.Hash -ieq $h } | Select-Object Hash,Path } | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Linux hash search (scoped)", Type: StepCommand, Platform: PlatformLinux, Optional: true, Timeout: 1800,
						Command: `H='{ioc_value}'; for r in /tmp /var/tmp /opt /usr/local /home /root; do find "$r" -xdev -type f -size -200M 2>/dev/null | while read f; do echo "$(sha256sum "$f" 2>/dev/null)"; done; done | grep -i "^${H} " || true`},
				},
			},
			{
				Name: "Network IOC sweep",
				Steps: []UseCaseStep{
					{Name: "Windows IP/domain check", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `$v='{ioc_value}'; Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $v } | ConvertTo-Csv -NoTypeInformation; Get-DnsClientCache | Where-Object { $_.Entry -match $v -or $_.Data -eq $v } | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Linux IP/domain check", Type: StepCommand, Platform: PlatformLinux, Optional: true,
						Command: `V='{ioc_value}'; ss -tupan 2>/dev/null | grep -F "$V"; grep -RF "$V" /var/log 2>/dev/null | head -200`},
				},
			},
		},
		AnalysisGuide: []string{
			"Hash sweeps cap each file at 200MB to keep runtime bounded — re-run with explicit paths for larger files.",
			"For batch sweeps from an IOC file, call this use case once per row from a wrapper script.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-XP-002 YARA Hunt
// ---------------------------------------------------------------------------

func ucXPYARAHunt() UseCase {
	return UseCase{
		Name:          "YARA Hunt",
		ID:            "UC-XP-002",
		Description:   "Run YARA against a target path using bundled rules or a user-supplied rules file. Uses Loki when available, falls back to standalone yara.",
		Platform:      PlatformXP,
		Severity:      SeverityVaries,
		EstimatedTime: "20-40 minutes",
		MITREAttack:   []string{"T1518.001"},
		Parameters: []UseCaseParameter{
			{Name: "yara_rules", Description: "Path to YARA rules file (.yar/.yara)", Required: true, Type: "path"},
			{Name: "scan_path", Description: "Directory to scan", Required: true, Type: "path", Default: "C:\\"},
		},
		Phases: []UseCasePhase{
			{
				Name: "Rule validation",
				Steps: []UseCaseStep{
					{Name: "Confirm rules file exists (Windows)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Test-Path -Path '{yara_rules}'`},
					{Name: "Confirm rules file exists (Linux)", Type: StepCommand, Platform: PlatformLinux,
						Command: `[ -f '{yara_rules}' ] && echo OK || echo MISSING`},
				},
			},
			{
				Name: "Scan",
				Steps: []UseCaseStep{
					{Name: "Loki scan (Windows)", Type: StepTool, Tool: "loki-win", Platform: PlatformWindows, Optional: true, Timeout: 1800,
						Command: `--folder '{scan_path}' --no-tui --logfolder {output_dir}`},
					{Name: "Loki scan (Linux)", Type: StepTool, Tool: "loki-lnx", Platform: PlatformLinux, Optional: true, Timeout: 1800,
						Command: `--folder '{scan_path}' --no-tui --logfolder {output_dir}`},
					{Name: "yara fallback (any)", Type: StepCommand, Platform: PlatformBoth, Optional: true, Timeout: 1800,
						Command: `yara -r -m '{yara_rules}' '{scan_path}'`},
				},
			},
		},
		AnalysisGuide: []string{
			"Loki produces a CSV alongside its log — easier to filter than raw yara output.",
			"For broader hunts, run this use case per-rule-pack rather than concatenating many rules into one file.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-XP-003 Baseline Comparison
// ---------------------------------------------------------------------------

func ucXPBaseline() UseCase {
	return UseCase{
		Name:          "Baseline Comparison",
		ID:            "UC-XP-003",
		Description:   "Capture today's process / service / autorun / port / user state for diffing against a JSON baseline snapshot.",
		Platform:      PlatformXP,
		Severity:      SeverityMedium,
		EstimatedTime: "30-45 minutes",
		Parameters: []UseCaseParameter{
			{Name: "baseline_file", Description: "Path to a previous JSON baseline snapshot (optional — first run captures only)", Type: "path"},
		},
		Phases: []UseCasePhase{
			{
				Name: "Process inventory",
				Steps: []UseCaseStep{
					{Name: "Windows processes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath | ConvertTo-Json -Depth 3`},
					{Name: "Linux processes", Type: StepCommand, Platform: PlatformLinux,
						Command: `ps -eo pid,ppid,user,cmd --no-headers | awk '{printf "{\"pid\":%s,\"ppid\":%s,\"user\":\"%s\",\"cmd\":\"", $1, $2, $3; for(i=4;i<=NF;i++){gsub(/"/, "\\\"", $i); printf "%s ", $i;} printf "\"}\n";}'`},
				},
			},
			{
				Name: "Service / autorun inventory",
				Steps: []UseCaseStep{
					{Name: "Windows services", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json`},
					{Name: "Windows autoruns", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json`},
					{Name: "Linux services", Type: StepCommand, Platform: PlatformLinux,
						Command: `systemctl list-unit-files --type=service --no-pager 2>/dev/null`},
					{Name: "Linux cron snapshot", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/crontab 2>/dev/null; for u in $(getent passwd | cut -d: -f1); do echo "=== $u ==="; crontab -u "$u" -l 2>/dev/null; done`},
				},
			},
			{
				Name: "Network & user inventory",
				Steps: []UseCaseStep{
					{Name: "Windows listeners", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json`},
					{Name: "Linux listeners", Type: StepCommand, Platform: PlatformLinux,
						Command: `ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null`},
					{Name: "Windows users", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID | ConvertTo-Json`},
					{Name: "Linux users", Type: StepCommand, Platform: PlatformLinux,
						Command: `cat /etc/passwd`},
				},
			},
		},
		AnalysisGuide: []string{
			"Save today's outputs as the baseline file for future runs (manual diff with jq/diff is fine for ad-hoc investigations).",
			"Track day-over-day deltas for processes/services/listeners/users to spot creeping persistence.",
		},
	}
}
