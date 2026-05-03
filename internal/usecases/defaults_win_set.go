package usecases

// windowsUseCases returns UC-WIN-001 through UC-WIN-013.
//
// Step commands favour native PowerShell / built-in tools (Get-CimInstance,
// Get-WinEvent, schtasks, reg.exe) so the use case still produces value when
// no third-party tool is installed. Tool-based steps (Hayabusa, Chainsaw)
// live in their own phase and are marked Optional so a missing tool doesn't
// fail the whole investigation.
func windowsUseCases() []UseCase {
	return []UseCase{
		ucWinRansomware(),
		ucWinBEC(),
		ucWinLateral(),
		ucWinPersistence(),
		ucWinCredentialTheft(),
		ucWinExfil(),
		ucWinInsider(),
		ucWinPowerShell(),
		ucWinLOLBins(),
		ucWinInitialAccess(),
		ucWinFullTriage(),
		ucWinTimeline(),
		ucWinADAttacks(),
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-001 Ransomware Investigation
// ---------------------------------------------------------------------------

func ucWinRansomware() UseCase {
	return UseCase{
		Name:          "Ransomware Investigation",
		ID:            "UC-WIN-001",
		Description:   "Comprehensive ransomware incident response — encryption timeline, persistence mechanisms, lateral movement, and recovery sabotage detection.",
		Platform:      PlatformWindows,
		Severity:      SeverityCritical,
		EstimatedTime: "45-60 minutes",
		MITREAttack:   []string{"T1486", "T1490", "T1083", "T1082", "T1021"},
		Prerequisites: []string{"Administrator access", "Active case"},
		Parameters: []UseCaseParameter{
			{Name: "incident_start", Description: "Approximate start time of incident (YYYY-MM-DD HH:MM)", Type: "datetime"},
			{Name: "ransom_extension", Description: "Ransomware file extension if known (e.g., .encrypted, .locked)", Type: "string"},
		},
		Phases: []UseCasePhase{
			{
				Name: "Initial Triage",
				Steps: []UseCaseStep{
					{Name: "Process snapshot", Type: StepCommand, Platform: PlatformWindows,
						Command:     `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation`,
						Description: "All running processes"},
					{Name: "Network connections", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Ransom note search", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem -Path C:\ -Recurse -Include *readme*,*ransom*,*decrypt*,*restore*,*recover* -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
					{Name: "Encrypted file search", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\Users -Recurse -Include *.encrypted,*.locked,*{ransom_extension} -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
					{Name: "Disk space", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Persistence Analysis",
				Steps: []UseCaseStep{
					{Name: "Startup items", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Scheduled tasks", Type: StepCommand, Platform: PlatformWindows,
						Command: `schtasks /query /fo csv /v`},
					{Name: "Services", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Registry run keys", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | ConvertTo-Json`},
					{Name: "WMI subscriptions", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ConvertTo-Json; Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ConvertTo-Json`},
				},
			},
			{
				Name: "Recovery Sabotage Detection",
				Steps: []UseCaseStep{
					{Name: "VSS status", Type: StepCommand, Platform: PlatformWindows,
						Command: `vssadmin list shadows`},
					{Name: "Boot config", Type: StepCommand, Platform: PlatformWindows,
						Command: `bcdedit /enum`},
					{Name: "Service install/change events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='System';ID=7045,7036} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "VSS deletion events", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Application';ID=8193,8194} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Lateral Movement",
				Steps: []UseCaseStep{
					{Name: "Logon events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625,4648,4672} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "RDP sessions", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'} -MaxEvents 100 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Admin shares accessed", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140,5145} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "PsExec artifacts", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'PSEXESVC' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Hayabusa Scan",
				Steps: []UseCaseStep{
					{Name: "Hayabusa critical scan", Type: StepTool, Tool: "hayabusa-win", Platform: PlatformWindows, Optional: true,
						Command: `csv-timeline --directory C:\Windows\System32\winevt\Logs --min-level high --no-wizard --UTC --no-summary --output {output_dir}/hayabusa_timeline.csv`,
						Timeout: 1800,
						Description: "Comprehensive event-log scan via Hayabusa"},
				},
			},
		},
		Output: UseCaseOutput{Format: "html", IncludeTimeline: true},
		AnalysisGuide: []string{
			"Look for mass file modification events within short time windows.",
			"Check for vssadmin.exe, wmic.exe, bcdedit.exe execution in process logs.",
			"Identify the initial encryption start time from USN journal if available.",
			"Map lateral movement via RDP/PsExec/WMI event correlation.",
			"Check for data exfiltration BEFORE encryption (double extortion).",
		},
		FollowUp: []string{
			"UC-WIN-003: Lateral Movement Detection (expand scope)",
			"UC-WIN-005: Credential Theft Investigation (check for credential harvesting)",
			"UC-WIN-010: Initial Access Investigation (identify entry point)",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-002 Business Email Compromise
// ---------------------------------------------------------------------------

func ucWinBEC() UseCase {
	return UseCase{
		Name:          "Business Email Compromise",
		ID:            "UC-WIN-002",
		Description:   "BEC investigation — email artifact collection, OAuth token abuse, suspicious mailbox rules, and credential exposure.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "30-45 minutes",
		MITREAttack:   []string{"T1078.004", "T1556.006", "T1098.002", "T1114.003"},
		Phases: []UseCasePhase{
			{
				Name: "Email Artifacts",
				Steps: []UseCaseStep{
					{Name: "Mail file inventory", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem -Path C:\Users -Recurse -Include *.msg,*.eml,*.pst,*.ost -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
					{Name: "Outlook profile registry", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `reg query "HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles" /s 2>$null`},
					{Name: "Inbox rules (PST/OST scan stub)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\Users -Recurse -Include *.ost,*.pst -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Credential Exposure",
				Steps: []UseCaseStep{
					{Name: "Saved credentials", Type: StepCommand, Platform: PlatformWindows,
						Command: `cmdkey /list`},
					{Name: "Certificate store (My)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem Cert:\CurrentUser\My | Select-Object Subject,Issuer,Thumbprint,NotAfter | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Saved browser passwords path inventory", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data","$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Logon Analysis",
				Steps: []UseCaseStep{
					{Name: "Successful logons", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Failed logons", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Explicit credential use", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Browser & Token Artifacts",
				Steps: []UseCaseStep{
					{Name: "Browser history files", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History","$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History","$env:APPDATA\Mozilla\Firefox\Profiles" -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
					{Name: "OAuth refresh tokens (Office)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\IdentityCache","$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Look for impossible-travel logon patterns (different geographies within minutes).",
			"Inspect Outlook for hidden inbox rules (auto-forward, auto-delete, delete-without-prompt).",
			"Check for unusual MFA disable or registration events.",
			"Search saved-credential dumps for cached refresh tokens.",
		},
		FollowUp: []string{"UC-WIN-005: Credential Theft Investigation", "UC-WIN-010: Initial Access Investigation"},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-003 Lateral Movement Detection
// ---------------------------------------------------------------------------

func ucWinLateral() UseCase {
	return UseCase{
		Name:          "Lateral Movement Detection",
		ID:            "UC-WIN-003",
		Description:   "Identify how an attacker moved between hosts: auth events, remote-execution artifacts, network shares, and execution evidence.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "30-45 minutes",
		MITREAttack:   []string{"T1021.001", "T1021.002", "T1021.006", "T1047", "T1543.003"},
		Phases: []UseCasePhase{
			{
				Name: "Authentication Events",
				Steps: []UseCaseStep{
					{Name: "Type 3 (network) logons", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -eq 3 } | Select-Object TimeCreated,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Type 10 (RDP) logons", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Properties[8].Value -eq 10 } | Select-Object TimeCreated,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Failed logons", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Explicit credentials (4648)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4648} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Remote Execution",
				Steps: []UseCaseStep{
					{Name: "PsExec service installs", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'PSEXESVC|PAExec' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "WMI activity", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "WinRM events", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Network & Share Activity",
				Steps: []UseCaseStep{
					{Name: "Netstat", Type: StepCommand, Platform: PlatformWindows,
						Command: `netstat -anob`},
					{Name: "SMB session events", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=5140,5145} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Execution Evidence",
				Steps: []UseCaseStep{
					{Name: "Recent processes (4688)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Service installs", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Cluster Type 3 logons by source IP — concentrated activity from one host suggests pivoting.",
			"Match 4624/4634 pairs to detect impersonated session lifecycles (silver-ticket fingerprint).",
			"PSEXESVC service installs are a strong PsExec indicator.",
		},
		FollowUp: []string{"UC-WIN-005: Credential Theft Investigation", "UC-WIN-013: Active Directory Attacks"},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-004 Persistence Discovery
// ---------------------------------------------------------------------------

func ucWinPersistence() UseCase {
	return UseCase{
		Name:          "Persistence Discovery",
		ID:            "UC-WIN-004",
		Description:   "Find every common persistence mechanism: autoruns, services, scheduled tasks, WMI subscriptions, DLL hijacks, and browser extensions.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "20-30 minutes",
		MITREAttack:   []string{"T1547.001", "T1543.003", "T1053.005", "T1546.003"},
		Phases: []UseCasePhase{
			{
				Name: "Registry Autoruns",
				Steps: []UseCaseStep{
					{Name: "Run / RunOnce keys", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4`},
					{Name: "Image File Execution Options", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Where-Object { $_.Debugger } | ConvertTo-Json`},
					{Name: "Winlogon shell/userinit", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object Shell,Userinit,Notify | ConvertTo-Json`},
				},
			},
			{
				Name: "Scheduled Tasks & Services",
				Steps: []UseCaseStep{
					{Name: "Scheduled tasks", Type: StepCommand, Platform: PlatformWindows,
						Command: `schtasks /query /fo csv /v`},
					{Name: "Services (full)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Drivers", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-CimInstance Win32_SystemDriver | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "WMI & Startup Folders",
				Steps: []UseCaseStep{
					{Name: "WMI event filters", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ConvertTo-Json`},
					{Name: "WMI consumers", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ConvertTo-Json`},
					{Name: "WMI bindings", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | ConvertTo-Json`},
					{Name: "Startup folders", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "DLL Hijack & Browser Extensions",
				Steps: []UseCaseStep{
					{Name: "DLL search-order hijack candidates", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:USERPROFILE\AppData","C:\ProgramData" -Recurse -Filter *.dll -ErrorAction SilentlyContinue -File | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
					{Name: "Chrome extensions", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" -Directory -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Edge extensions", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" -Directory -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Filter scheduled tasks by Author/Principal — anomalies often run as SYSTEM with non-standard authors.",
			"Check Image File Execution Options Debugger entries — common hijack vector.",
			"Compare WMI subscription bindings against a known-clean baseline.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-005 Credential Theft Investigation
// ---------------------------------------------------------------------------

func ucWinCredentialTheft() UseCase {
	return UseCase{
		Name:          "Credential Theft Investigation",
		ID:            "UC-WIN-005",
		Description:   "LSASS access, SAM/SECURITY hive abuse, DCSync, Kerberoasting / AS-REP roasting, and credential-file evidence.",
		Platform:      PlatformWindows,
		Severity:      SeverityCritical,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1003.001", "T1003.002", "T1003.006", "T1558.003", "T1558.004"},
		Phases: []UseCasePhase{
			{
				Name: "LSASS Access",
				Steps: []UseCaseStep{
					{Name: "Object access on lsass.exe", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4656,4663} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'lsass.exe' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Sysmon process access (10)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=10} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'lsass.exe' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Hive Access & DCSync",
				Steps: []UseCaseStep{
					{Name: "SAM/SECURITY hive access", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4663} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'SAM|SECURITY|SYSTEM\\config' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "DCSync indicator (4662)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4662} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Kerberos Anomalies",
				Steps: []UseCaseStep{
					{Name: "Kerberoasting (4769 RC4)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '0x17' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "AS-REP roasting (4768 no pre-auth)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'PreAuthType\s+0' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Credential Files",
				Steps: []UseCaseStep{
					{Name: "Mimikatz / kirbi / ccache files", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\ -Recurse -Include *.kirbi,*.ccache,mimikatz*,*.dmp -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 900},
					{Name: "NTDS dump search", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\ -Recurse -Include ntds*,SAM,SYSTEM -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch 'C:\\Windows\\System32\\config' } | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 900},
				},
			},
		},
		AnalysisGuide: []string{
			"LSASS access from non-system processes is highly suspicious.",
			"DCSync replication GUIDs indicate domain controller credential extraction.",
			"4769 events with encryption type 0x17 (RC4) point to Kerberoasting.",
		},
		FollowUp: []string{"UC-WIN-013: Active Directory Attacks"},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-006 Data Exfiltration
// ---------------------------------------------------------------------------

func ucWinExfil() UseCase {
	return UseCase{
		Name:          "Data Exfiltration",
		ID:            "UC-WIN-006",
		Description:   "Detect data theft via cloud storage, USB devices, archive creation, and unusual network volume.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "30-40 minutes",
		MITREAttack:   []string{"T1052.001", "T1567.002", "T1560.001", "T1041"},
		Phases: []UseCasePhase{
			{
				Name: "USB Device Activity",
				Steps: []UseCaseStep{
					{Name: "USB plug events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational';ID=2003,2102} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "USB device registry", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.PsPath -ErrorAction SilentlyContinue } | ConvertTo-Json -Depth 3`},
				},
			},
			{
				Name: "Cloud Storage Activity",
				Steps: []UseCaseStep{
					{Name: "OneDrive / Dropbox / GDrive processes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'onedrive|dropbox|googledrivefs|googledrive|box.com|mega' } | Select-Object ProcessId,Name,CommandLine | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Cloud-storage executables on disk", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path 'C:\Users','C:\Program Files','C:\Program Files (x86)' -Recurse -Include onedrive.exe,dropbox.exe,googledrivefs.exe,box.exe -File -ErrorAction SilentlyContinue | Select-Object FullName,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 300},
				},
			},
			{
				Name: "Archive Creation & Large File Access",
				Steps: []UseCaseStep{
					{Name: "Archive tool execution", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '7z\.exe|winrar\.exe|rar\.exe|tar\.exe|zip\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recently created archives", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\Users -Recurse -Include *.zip,*.rar,*.7z,*.tar,*.gz -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
				},
			},
			{
				Name: "Network Volume",
				Steps: []UseCaseStep{
					{Name: "Active connections", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Per-process network counters", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Spikes in OneDrive/Dropbox upload activity outside business hours warrant investigation.",
			"Archive-tool execution by user accounts that don't normally compress files is a strong signal.",
			"USB device plug events near termination dates correlate with insider exfiltration.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-007 Insider Threat Investigation
// ---------------------------------------------------------------------------

func ucWinInsider() UseCase {
	return UseCase{
		Name:          "Insider Threat Investigation",
		ID:            "UC-WIN-007",
		Description:   "User activity timeline, file access patterns, USB usage, print events, off-hours activity, and data hoarding indicators.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "45-60 minutes",
		MITREAttack:   []string{"T1078", "T1052.001", "T1213.002"},
		Phases: []UseCasePhase{
			{
				Name: "User Activity Timeline",
				Steps: []UseCaseStep{
					{Name: "Logons and logoffs", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4634,4647} -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,@{n='Properties';e={$_.Properties.Value -join '|'}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recent files (UserAssist)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 3`},
					{Name: "Recent docs", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -ErrorAction SilentlyContinue | ConvertTo-Json`},
				},
			},
			{
				Name: "File & USB Activity",
				Steps: []UseCaseStep{
					{Name: "USB plug events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational';ID=2003,2102} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recently modified docs", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) } | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 300},
				},
			},
			{
				Name: "Print & Email Activity",
				Steps: []UseCaseStep{
					{Name: "Print events", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PrintService/Operational';ID=307} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Outlook OST/PST inventory", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\Users -Recurse -Include *.ost,*.pst -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 300},
				},
			},
			{
				Name: "Off-Hours & Hoarding",
				Steps: []UseCaseStep{
					{Name: "Logon timestamps for filtering", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object @{n='Hour';e={$_.TimeCreated.Hour}},TimeCreated,Id,@{n='User';e={$_.Properties[5].Value}} | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Large user-profile files", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB } | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
						Timeout: 600},
				},
			},
		},
		AnalysisGuide: []string{
			"Compare logon times to the user's baseline working hours.",
			"Sustained large-file access by an individual outside their role is hoarding behaviour.",
			"USB activity near a resignation date is a significant red flag.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-008 PowerShell Attack Investigation
// ---------------------------------------------------------------------------

func ucWinPowerShell() UseCase {
	return UseCase{
		Name:          "PowerShell Attack Investigation",
		ID:            "UC-WIN-008",
		Description:   "Script-block / module / transcript log analysis, encoded-command detection, download cradles, AMSI bypass.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1059.001", "T1027.010", "T1140"},
		Phases: []UseCasePhase{
			{
				Name: "Script-Block & Module Logs",
				Steps: []UseCaseStep{
					{Name: "Script-block logging (4104)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Module logging (4103)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4103} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Encoded Command & Download Cradles",
				Steps: []UseCaseStep{
					{Name: "Encoded-command processes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '-encodedcommand|-enc |-e ' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Download cradles", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'IEX|Invoke-Expression|DownloadString|Invoke-WebRequest|Net.WebClient' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Defense Evasion",
				Steps: []UseCaseStep{
					{Name: "AMSI bypass strings", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'amsiInitFailed|System.Management.Automation.AmsiUtils' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Constrained Language Mode (53504)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=53504} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "PS transcript logs", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:USERPROFILE\Documents\PowerShell_transcript*","C:\Transcripts" -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Decode -enc base64 payloads from 4688/4104 to identify the actual command.",
			"AMSI-bypass strings in 4104 events are highly indicative of attack tooling.",
			"Download cradles + child process spawning is a strong fileless-attack pattern.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-009 LOLBins Investigation
// ---------------------------------------------------------------------------

func ucWinLOLBins() UseCase {
	return UseCase{
		Name:          "LOLBins Investigation",
		ID:            "UC-WIN-009",
		Description:   "Process executions of common Living-off-the-Land binaries (certutil, mshta, regsvr32, rundll32, wmic, cmstp, msbuild, bitsadmin, wscript, cscript, msiexec, installutil, forfiles).",
		Platform:      PlatformWindows,
		Severity:      SeverityMedium,
		EstimatedTime: "25-35 minutes",
		MITREAttack:   []string{"T1218", "T1218.005", "T1218.010", "T1218.011", "T1105", "T1047"},
		Phases: []UseCasePhase{
			{
				Name: "LOLBin Execution Survey",
				Steps: []UseCaseStep{
					{Name: "certutil", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'certutil\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "mshta / hta", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'mshta\.exe|\.hta' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "regsvr32", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'regsvr32\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "rundll32", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'rundll32\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "wmic", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'wmic\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Misc LOLBins", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'cmstp\.exe|msbuild\.exe|bitsadmin\.exe|wscript\.exe|cscript\.exe|msiexec\.exe|installutil\.exe|forfiles\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"certutil with -urlcache or -decode flags is high-fidelity malicious behaviour.",
			"regsvr32 /s /u /i: with a remote URL is the classic squiblydoo pattern.",
			"mshta with HTTP URLs frequently downloads payloads from attacker infrastructure.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-010 Initial Access Investigation
// ---------------------------------------------------------------------------

func ucWinInitialAccess() UseCase {
	return UseCase{
		Name:          "Initial Access Investigation",
		ID:            "UC-WIN-010",
		Description:   "Identify the initial entry point: phishing artifacts, exploit indicators, external RDP/VPN logons, USB first-insert.",
		Platform:      PlatformWindows,
		Severity:      SeverityHigh,
		EstimatedTime: "35-45 minutes",
		MITREAttack:   []string{"T1566", "T1190", "T1078", "T1091"},
		Phases: []UseCasePhase{
			{
				Name: "Phishing Artifacts",
				Steps: []UseCaseStep{
					{Name: "Office child processes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe' -and $_.Message -match 'cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recent downloads", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Exploit Indicators",
				Steps: []UseCaseStep{
					{Name: "Application crashes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Application';ID=1000,1001} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Service-spawned shells", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'services\.exe' -and $_.Message -match 'cmd\.exe|powershell\.exe' } | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "External Logon Vectors",
				Steps: []UseCaseStep{
					{Name: "RDP logons (TerminalServices)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';ID=21,25} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "VPN connections", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Application'} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.ProviderName -match 'RasClient|VPN' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "USB first-insert", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue | Select-Object FriendlyName,PSChildName | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"Office spawning shells points to a malicious document.",
			"services.exe launching cmd/powershell suggests an exploit + service-handler abuse.",
			"Cross-reference RDP successes with the firewall to confirm Internet-exposed entry.",
		},
		FollowUp: []string{"UC-WIN-001: Ransomware Investigation", "UC-WIN-005: Credential Theft Investigation"},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-011 Full System Triage
// ---------------------------------------------------------------------------

func ucWinFullTriage() UseCase {
	return UseCase{
		Name:          "Full System Triage",
		ID:            "UC-WIN-011",
		Description:   "Comprehensive triage: system info, processes, network, event logs, persistence, users, services, recent files. Equivalent to Quick Triage [4] full run plus tool scans.",
		Platform:      PlatformWindows,
		Severity:      SeverityMedium,
		EstimatedTime: "60-90 minutes",
		Phases: []UseCasePhase{
			{
				Name: "System Snapshot",
				Steps: []UseCaseStep{
					{Name: "systeminfo", Type: StepCommand, Platform: PlatformWindows,
						Command: `systeminfo`},
					{Name: "Hostname / OS", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber,InstallDate,LastBootUpTime`},
					{Name: "Whoami", Type: StepCommand, Platform: PlatformWindows,
						Command: `whoami /all`},
				},
			},
			{
				Name: "Processes & Network",
				Steps: []UseCaseStep{
					{Name: "Processes", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation`},
					{Name: "TCP", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
					{Name: "UDP", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Routes & ARP", Type: StepCommand, Platform: PlatformWindows,
						Command: `route print; arp -a`},
				},
			},
			{
				Name: "Persistence & Users",
				Steps: []UseCaseStep{
					{Name: "Run keys", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | ConvertTo-Json`},
					{Name: "Scheduled tasks", Type: StepCommand, Platform: PlatformWindows,
						Command: `schtasks /query /fo csv /v`},
					{Name: "Services", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Local users", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID,Description | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Local groups", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-LocalGroup | Select-Object Name,SID,Description | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Logged-on", Type: StepCommand, Platform: PlatformWindows,
						Command: `query user 2>$null; quser 2>$null`},
				},
			},
			{
				Name: "Optional Tool Scans",
				Steps: []UseCaseStep{
					{Name: "Hayabusa scan", Type: StepTool, Tool: "hayabusa-win", Optional: true, Timeout: 1800,
						Command: `csv-timeline --directory C:\Windows\System32\winevt\Logs --min-level high --no-wizard --UTC --no-summary --output {output_dir}/hayabusa_timeline.csv`},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-012 Timeline Analysis
// ---------------------------------------------------------------------------

func ucWinTimeline() UseCase {
	return UseCase{
		Name:          "Timeline Analysis",
		ID:            "UC-WIN-012",
		Description:   "Build a chronological view across event logs, prefetch, registry timestamps, and (if collected) MFT/Amcache. Run after a triage or KAPE collection.",
		Platform:      PlatformWindows,
		Severity:      SeverityMedium,
		EstimatedTime: "45-60 minutes",
		Phases: []UseCasePhase{
			{
				Name: "Event Log Timeline",
				Steps: []UseCaseStep{
					{Name: "Recent security events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 2000 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recent system events", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents 1000 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Application errors", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2,3} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Prefetch & Recent Activity",
				Steps: []UseCaseStep{
					{Name: "Prefetch listing", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Select-Object Name,CreationTime,LastWriteTime,Length | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Recent docs registry", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PsPath } | ConvertTo-Json -Depth 4`},
				},
			},
			{
				Name: "Tool-Assisted Timeline",
				Steps: []UseCaseStep{
					{Name: "Hayabusa timeline", Type: StepTool, Tool: "hayabusa-win", Optional: true, Timeout: 1800,
						Command: `csv-timeline --directory C:\Windows\System32\winevt\Logs --min-level low --no-wizard --UTC --no-summary --output {output_dir}/hayabusa_timeline.csv`},
				},
			},
		},
		AnalysisGuide: []string{
			"Sort all CSV outputs together in Timeline Explorer for the cleanest cross-source view.",
			"Check the Analysis menu's Build Super Timeline action for a fully merged CSV.",
		},
	}
}

// ---------------------------------------------------------------------------
// UC-WIN-013 Active Directory Attacks
// ---------------------------------------------------------------------------

func ucWinADAttacks() UseCase {
	return UseCase{
		Name:          "Active Directory Attacks",
		ID:            "UC-WIN-013",
		Description:   "DCSync, Kerberoasting, AS-REP roasting, golden/silver tickets, password spray, AdminSDHolder + GPO modification.",
		Platform:      PlatformWindows,
		Severity:      SeverityCritical,
		EstimatedTime: "45-60 minutes",
		MITREAttack:   []string{"T1003.006", "T1558.003", "T1558.004", "T1110.003", "T1098", "T1484.001"},
		Phases: []UseCasePhase{
			{
				Name: "Replication / DCSync",
				Steps: []UseCaseStep{
					{Name: "Replication GUIDs in 4662", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4662} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Kerberos Ticket Anomalies",
				Steps: []UseCaseStep{
					{Name: "Kerberoasting (4769 RC4)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match '0x17' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "AS-REP roasting (4768 no pre-auth)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'PreAuthType\s+0' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "Golden-ticket lifetime anomalies", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
			{
				Name: "Password Spray & Privilege Modification",
				Steps: []UseCaseStep{
					{Name: "Pre-auth failures (4771)", Type: StepCommand, Platform: PlatformWindows,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4771} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "AdminSDHolder modifications", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=4738,5136} -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'AdminSDHolder' } | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
					{Name: "GPO modifications (5136)", Type: StepCommand, Platform: PlatformWindows, Optional: true,
						Command: `Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136} -MaxEvents 500 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation`},
				},
			},
		},
		AnalysisGuide: []string{
			"4662 replication GUIDs: 1131f6aa* (DS-Replication-Get-Changes), 1131f6ad* (DS-Replication-Get-Changes-All).",
			"Distributed 4771 across many accounts at low rate is classic password spray.",
			"AdminSDHolder + GPO write events deserve immediate investigation.",
		},
	}
}
