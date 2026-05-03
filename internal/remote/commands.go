package remote

import (
	"github.com/ridgelinecyberdefence/vanguard/internal/security"
)

// CommandSpec is one step of a remote collection or hunt — a logical name, an
// output filename to land the stdout under, and the command itself.
//
// Commands are kept here (rather than reused verbatim from internal/triage)
// because the remote transport requires plain shell / PowerShell strings,
// while the local triage code calls exec.Command with separate argv. Both
// paths cover the same ground but speak the language each transport needs.
type CommandSpec struct {
	Name    string // human-friendly step label
	OutFile string // filename relative to per-host output dir
	Command string // shell (Linux) or PowerShell (Windows) one-liner
}

// CommandSet is an ordered collection of CommandSpec, with a label used in
// the TUI progress display.
type CommandSet struct {
	Label    string
	Commands []CommandSpec
}

// ---------------------------------------------------------------------------
// Quick triage — Windows
// ---------------------------------------------------------------------------

// WindowsTriageCommands returns the PowerShell command set used by remote
// Quick Triage on a Windows target. Each command writes its output to STDOUT,
// which the caller saves to OutFile.
func WindowsTriageCommands() CommandSet {
	return CommandSet{
		Label: "Windows Quick Triage",
		Commands: []CommandSpec{
			{Name: "System Info", OutFile: "systeminfo.txt",
				Command: `systeminfo`},
			{Name: "Hostname / OS", OutFile: "hostname.txt",
				Command: `hostname; (Get-CimInstance Win32_OperatingSystem | Format-List Caption,Version,BuildNumber,InstallDate,LastBootUpTime | Out-String)`},
			{Name: "Whoami", OutFile: "whoami.txt",
				Command: `whoami /all`},
			{Name: "Processes", OutFile: "processes.csv",
				Command: `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Network — TCP", OutFile: "tcp_connections.csv",
				Command: `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Network — UDP", OutFile: "udp_endpoints.csv",
				Command: `Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
			{Name: "IP Configuration", OutFile: "ipconfig.txt",
				Command: `ipconfig /all`},
			{Name: "Routes & ARP", OutFile: "routes.txt",
				Command: `route print; arp -a`},
			{Name: "Persistence — Run Keys", OutFile: "run_keys.txt",
				Command: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List | Out-String`},
			{Name: "Persistence — Scheduled Tasks", OutFile: "scheduled_tasks.csv",
				Command: `Get-ScheduledTask | ForEach-Object { Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Select-Object @{n='TaskName';e={$_.TaskName}},@{n='TaskPath';e={$_.TaskPath}},LastRunTime,NextRunTime,LastTaskResult } | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Persistence — Services", OutFile: "services.csv",
				Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Local Users", OutFile: "local_users.csv",
				Command: `Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID,Description | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Local Groups", OutFile: "local_groups.csv",
				Command: `Get-LocalGroup | Select-Object Name,SID,Description | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Logged-on Users", OutFile: "logged_on.txt",
				Command: `query user 2>$null; quser 2>$null`},
			{Name: "Installed Software", OutFile: "installed_software.csv",
				Command: `Get-CimInstance Win32_Product -ErrorAction SilentlyContinue | Select-Object Name,Version,Vendor,InstallDate | ConvertTo-Csv -NoTypeInformation`},
		},
	}
}

// ---------------------------------------------------------------------------
// Quick triage — Linux
// ---------------------------------------------------------------------------

// LinuxTriageCommands returns the shell command set for remote Quick Triage
// on a Linux target. Each command writes its output to STDOUT.
func LinuxTriageCommands() CommandSet {
	return CommandSet{
		Label: "Linux Quick Triage",
		Commands: []CommandSpec{
			{Name: "System Info", OutFile: "systeminfo.txt",
				Command: `uname -a; hostnamectl 2>/dev/null; cat /etc/os-release 2>/dev/null; uptime`},
			{Name: "Whoami / id", OutFile: "whoami.txt",
				Command: `whoami; id; groups`},
			{Name: "Processes", OutFile: "processes.txt",
				Command: `ps auxwwf`},
			{Name: "Process /proc binaries", OutFile: "proc_exe.txt",
				Command: `ls -la /proc/*/exe 2>/dev/null`},
			{Name: "Network — sockets", OutFile: "sockets.txt",
				Command: `ss -tulpan 2>/dev/null || netstat -tulpan 2>/dev/null`},
			{Name: "Network — interfaces", OutFile: "interfaces.txt",
				Command: `ip addr show; ip route show; ip neigh show`},
			{Name: "Logged-on users", OutFile: "logged_on.txt",
				Command: `who; w; last -50; lastb -50 2>/dev/null`},
			{Name: "Persistence — cron", OutFile: "cron.txt",
				Command: `cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do echo "--- $u ---"; crontab -u $u -l 2>/dev/null; done`},
			{Name: "Persistence — systemd timers", OutFile: "systemd_timers.txt",
				Command: `systemctl list-timers --all --no-pager 2>/dev/null`},
			{Name: "Persistence — systemd services", OutFile: "systemd_services.txt",
				Command: `systemctl list-units --all --type=service --no-pager 2>/dev/null`},
			{Name: "Persistence — rc.local / init.d", OutFile: "rc_init.txt",
				Command: `ls -la /etc/init.d/ 2>/dev/null; cat /etc/rc.local 2>/dev/null`},
			{Name: "Kernel modules", OutFile: "kernel_modules.txt",
				Command: `lsmod 2>/dev/null`},
			{Name: "Open files (root only)", OutFile: "lsof.txt",
				Command: `lsof -nP 2>/dev/null | head -2000`},
			{Name: "User accounts", OutFile: "users.txt",
				Command: `cat /etc/passwd; echo '---'; cat /etc/group`},
			{Name: "Sudoers", OutFile: "sudoers.txt",
				Command: `cat /etc/sudoers 2>/dev/null; ls -la /etc/sudoers.d/ 2>/dev/null`},
			{Name: "Installed packages", OutFile: "packages.txt",
				Command: `dpkg -l 2>/dev/null || rpm -qa --last 2>/dev/null`},
			{Name: "Shell history (root)", OutFile: "root_history.txt",
				Command: `cat /root/.bash_history 2>/dev/null; cat /root/.zsh_history 2>/dev/null`},
		},
	}
}

// ---------------------------------------------------------------------------
// Event log collection — Windows only
// ---------------------------------------------------------------------------

// WindowsEventLogChannels lists the event log channels collected by the
// remote-event-log step. Each channel is exported on the remote host with
// `wevtutil epl` and copied back.
func WindowsEventLogChannels() []struct{ FileName, Channel string } {
	return []struct{ FileName, Channel string }{
		{"Security.evtx", "Security"},
		{"System.evtx", "System"},
		{"Application.evtx", "Application"},
		{"PowerShell-Operational.evtx", "Microsoft-Windows-PowerShell/Operational"},
		{"Sysmon.evtx", "Microsoft-Windows-Sysmon/Operational"},
		{"TaskScheduler.evtx", "Microsoft-Windows-TaskScheduler/Operational"},
		{"WinRM.evtx", "Microsoft-Windows-WinRM/Operational"},
		{"RDP-LocalSession.evtx", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"},
	}
}

// WindowsRegistryHives lists the SYSTEM-wide hives the registry-collection
// step exports. NTUSER.DAT and UsrClass.dat are picked up per-user separately.
func WindowsRegistryHives() []struct{ FileName, KeyPath string } {
	return []struct{ FileName, KeyPath string }{
		{"SAM", `HKLM\SAM`},
		{"SYSTEM", `HKLM\SYSTEM`},
		{"SOFTWARE", `HKLM\SOFTWARE`},
		{"SECURITY", `HKLM\SECURITY`},
	}
}

// ---------------------------------------------------------------------------
// Hunting snapshots
// ---------------------------------------------------------------------------

// WindowsHuntCommands returns the per-snapshot commands used by remote hunting
// (Process / Network / Persistence). Each map entry holds a CommandSet whose
// commands run server-side; analysis happens in detect.go.
var WindowsHuntCommands = map[string]CommandSet{
	"processes": {
		Label: "Windows Process Snapshot",
		Commands: []CommandSpec{
			{Name: "Processes", OutFile: "processes.csv",
				Command: `Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ParentProcessId,CommandLine,ExecutablePath,CreationDate | ConvertTo-Csv -NoTypeInformation`},
		},
	},
	"network": {
		Label: "Windows Network Snapshot",
		Commands: []CommandSpec{
			{Name: "TCP", OutFile: "tcp.csv",
				Command: `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
			{Name: "UDP", OutFile: "udp.csv",
				Command: `Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Csv -NoTypeInformation`},
			{Name: "DNS Cache", OutFile: "dns_cache.csv",
				Command: `Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation`},
		},
	},
	"persistence": {
		Label: "Windows Persistence Snapshot",
		Commands: []CommandSpec{
			{Name: "Run Keys", OutFile: "run_keys.txt",
				Command: `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue | Format-List | Out-String`},
			{Name: "Scheduled Tasks", OutFile: "scheduled_tasks.csv",
				Command: `Get-ScheduledTask | ForEach-Object { Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Select-Object @{n='TaskName';e={$_.TaskName}},@{n='TaskPath';e={$_.TaskPath}},LastRunTime,NextRunTime,LastTaskResult } | ConvertTo-Csv -NoTypeInformation`},
			{Name: "Services", OutFile: "services.csv",
				Command: `Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | ConvertTo-Csv -NoTypeInformation`},
			{Name: "WMI Subscriptions — Filters", OutFile: "wmi_filters.txt",
				Command: `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Format-List | Out-String`},
			{Name: "WMI Subscriptions — Consumers", OutFile: "wmi_consumers.txt",
				Command: `Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Format-List | Out-String`},
		},
	},
}

// LinuxHuntCommands mirrors WindowsHuntCommands for SSH targets.
var LinuxHuntCommands = map[string]CommandSet{
	"processes": {
		Label: "Linux Process Snapshot",
		Commands: []CommandSpec{
			{Name: "Processes", OutFile: "processes.txt",
				Command: `ps auxwwf`},
			{Name: "Process binaries", OutFile: "proc_exe.txt",
				Command: `ls -la /proc/*/exe 2>/dev/null`},
		},
	},
	"network": {
		Label: "Linux Network Snapshot",
		Commands: []CommandSpec{
			{Name: "Sockets", OutFile: "sockets.txt",
				Command: `ss -tulpan 2>/dev/null || netstat -tulpan 2>/dev/null`},
			{Name: "Interfaces / routes", OutFile: "interfaces.txt",
				Command: `ip addr show; ip route show; ip neigh show`},
		},
	},
	"persistence": {
		Label: "Linux Persistence Snapshot",
		Commands: []CommandSpec{
			{Name: "Cron", OutFile: "cron.txt",
				Command: `cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do echo "--- $u ---"; crontab -u $u -l 2>/dev/null; done`},
			{Name: "Systemd", OutFile: "systemd.txt",
				Command: `systemctl list-units --all --type=service --no-pager 2>/dev/null; systemctl list-timers --all --no-pager 2>/dev/null`},
			{Name: "rc.local / init.d", OutFile: "rc_init.txt",
				Command: `cat /etc/rc.local 2>/dev/null; ls -la /etc/init.d/ 2>/dev/null`},
			{Name: "Kernel modules", OutFile: "kernel_modules.txt",
				Command: `lsmod 2>/dev/null`},
			{Name: "authorized_keys", OutFile: "authorized_keys.txt",
				Command: `for h in /root /home/*; do echo "=== $h ==="; cat "$h/.ssh/authorized_keys" 2>/dev/null; done`},
		},
	},
}

// ---------------------------------------------------------------------------
// IOC sweep search builders
// ---------------------------------------------------------------------------

// IOCType identifies what kind of indicator the user is sweeping for.
type IOCType string

const (
	IOCFileHash    IOCType = "filehash"
	IOCFileName    IOCType = "filename"
	IOCIPAddress   IOCType = "ip"
	IOCDomain      IOCType = "domain"
)

// IOC describes one indicator with its type and value.
type IOC struct {
	Type  IOCType
	Value string
}

// BuildIOCCommand returns the shell/PowerShell snippet that searches for ioc on
// a target with the given OS. Search is intentionally scoped (not whole-disk)
// to keep run-time bounded; callers tighten further by selecting a subset.
//
// SECURITY: The IOC value flows into a command line that runs through
// PowerShell or sh on the remote host. We validate the value against the
// declared IOC type before constructing the command — a hash that isn't pure
// hex, an IP that isn't dotted-quad, or a domain that doesn't match the FQDN
// shape is rejected (returns an empty command), so attacker-controlled input
// can never reach the shell. escapeForPS / escapeForSh remain as a second
// layer of quoting safety.
func BuildIOCCommand(osType string, ioc IOC) (string, string) {
	clean := sanitizeIOCValue(ioc)
	if clean == "" {
		return "Rejected IOC", ""
	}
	ioc.Value = clean
	if osType == "windows" {
		return buildWindowsIOC(ioc)
	}
	return buildLinuxIOC(ioc)
}

// sanitizeIOCValue validates an IOC against its declared type and returns the
// cleaned value, or "" when the input doesn't match the expected shape.
func sanitizeIOCValue(ioc IOC) string {
	switch ioc.Type {
	case IOCFileHash:
		return security.SanitizeHash(ioc.Value)
	case IOCIPAddress:
		return security.SanitizeIPAddress(ioc.Value)
	case IOCDomain:
		return security.SanitizeDomain(ioc.Value)
	case IOCFileName:
		// Filenames may include wildcards (* / ?) and path separators.
		// SanitizeFilePath strips shell metas while preserving those.
		return security.SanitizeFilePath(ioc.Value)
	}
	return security.SanitizeShellArg(ioc.Value)
}

func buildWindowsIOC(ioc IOC) (label, command string) {
	switch ioc.Type {
	case IOCFileHash:
		// Scope to common executable locations to keep the scan tractable.
		return "FileHash sweep",
			`$h = '` + escapeForPS(ioc.Value) + `'; $roots = 'C:\Windows\Temp','C:\Users','C:\ProgramData','C:\Windows\System32'; foreach ($r in $roots) { Get-ChildItem -Path $r -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 200MB } | Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue | Where-Object { $_.Hash -ieq $h } | Select-Object Hash,Path,@{n='Length';e={(Get-Item $_.Path -ErrorAction SilentlyContinue).Length}},@{n='LastWrite';e={(Get-Item $_.Path -ErrorAction SilentlyContinue).LastWriteTimeUtc}} } | ConvertTo-Csv -NoTypeInformation`
	case IOCFileName:
		return "FileName sweep",
			`$pat = '` + escapeForPS(ioc.Value) + `'; $roots = 'C:\','D:\'; foreach ($r in $roots) { Get-ChildItem -Path $r -Recurse -Filter $pat -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTimeUtc } | ConvertTo-Csv -NoTypeInformation`
	case IOCIPAddress:
		return "IP sweep",
			`$ip = '` + escapeForPS(ioc.Value) + `'; Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $ip } | ConvertTo-Csv -NoTypeInformation; Get-DnsClientCache | Where-Object { $_.Data -eq $ip } | ConvertTo-Csv -NoTypeInformation`
	case IOCDomain:
		return "Domain sweep",
			`$d = '` + escapeForPS(ioc.Value) + `'; Get-DnsClientCache | Where-Object { $_.Entry -match $d -or $_.Name -match $d } | ConvertTo-Csv -NoTypeInformation; Get-Content C:\Windows\System32\drivers\etc\hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match $d }`
	}
	return "Unknown IOC", ""
}

func buildLinuxIOC(ioc IOC) (label, command string) {
	switch ioc.Type {
	case IOCFileHash:
		return "FileHash sweep",
			`H='` + escapeForSh(ioc.Value) + `'; for r in /tmp /var/tmp /opt /usr/local /home /root; do find "$r" -xdev -type f -size -200M 2>/dev/null | while read f; do echo "$(sha256sum "$f" 2>/dev/null)" ; done; done | grep -i "^${H} " || true`
	case IOCFileName:
		return "FileName sweep",
			`PAT='` + escapeForSh(ioc.Value) + `'; find / -xdev -name "$PAT" 2>/dev/null`
	case IOCIPAddress:
		return "IP sweep",
			`IP='` + escapeForSh(ioc.Value) + `'; ss -tulpan 2>/dev/null | grep -F "$IP"; grep -RF "$IP" /var/log 2>/dev/null | head -200`
	case IOCDomain:
		return "Domain sweep",
			`D='` + escapeForSh(ioc.Value) + `'; cat /etc/hosts 2>/dev/null | grep -F "$D"; grep -RF "$D" /var/log 2>/dev/null | head -200`
	}
	return "Unknown IOC", ""
}

// escapeForPS escapes a value for embedding in a single-quoted PowerShell string.
func escapeForPS(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// escapeForSh escapes a value for embedding in a single-quoted shell string.
func escapeForSh(s string) string {
	out := make([]byte, 0, len(s)+4)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
