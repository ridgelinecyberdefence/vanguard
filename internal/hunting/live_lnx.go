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
// Linux suspicious pattern lists
// ---------------------------------------------------------------------------

// Suspicious process indicators.
var linuxSuspiciousProcs = []string{
	"mimikatz", "lazagne", "linpeas", "pspy", "chisel",
	"socat", "ncat", "cryptominer", "xmrig", "minerd",
	"kinsing", "kdevtmpfsi", "dbused",
}

// Reverse shell patterns in command lines.
var reverseShellPatterns = []string{
	"/dev/tcp/", "/dev/udp/", "bash -i", "sh -i",
	"nc -e", "ncat -e", "python -c 'import socket",
	"python3 -c 'import socket", "perl -e 'use Socket",
	"ruby -rsocket", "php -r '$sock=fsockopen",
	"mkfifo", "0<&196", "exec 196<>/dev/tcp",
}

// Crypto mining indicators.
var cryptoMiningPatterns = []string{
	"stratum+tcp", "stratum+ssl", "pool.minexmr",
	"xmrpool", "moneropool", "nicehash", "hashvault",
	"-o pool.", "--donate-level", "randomx",
}

// Suspicious network ports.
var suspiciousPortsLnx = []int{
	4444, 5555, 8888, 1234, 6666, 7777, 9999, // C2
	6667, 6668, 6669, // IRC
	3333, 45700, // mining
	31337, 12345, 54321, // backdoor
}

// Known-good SUID binaries (common across distros).
var knownGoodSUID = map[string]bool{
	"/usr/bin/sudo":           true,
	"/usr/bin/su":             true,
	"/usr/bin/passwd":         true,
	"/usr/bin/chsh":           true,
	"/usr/bin/chfn":           true,
	"/usr/bin/newgrp":         true,
	"/usr/bin/gpasswd":        true,
	"/usr/bin/mount":          true,
	"/usr/bin/umount":         true,
	"/usr/bin/ping":           true,
	"/usr/bin/pkexec":         true,
	"/usr/bin/crontab":        true,
	"/usr/bin/ssh-agent":      true,
	"/usr/bin/at":             true,
	"/usr/bin/fusermount":     true,
	"/usr/bin/fusermount3":    true,
	"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,
	"/usr/lib/openssh/ssh-keysign":                true,
	"/usr/lib/policykit-1/polkit-agent-helper-1":  true,
	"/usr/sbin/pppd":         true,
	"/usr/sbin/unix_chkpwd":  true,
	"/bin/su":                 true,
	"/bin/mount":              true,
	"/bin/umount":             true,
	"/bin/ping":               true,
}

// ---------------------------------------------------------------------------
// Linux live hunting operations
// ---------------------------------------------------------------------------

// LnxSuspiciousProcesses scans for malicious processes, deleted binaries,
// crypto miners, and reverse shells.
func LnxSuspiciousProcesses(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Suspicious Processes"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. Full process listing.
	procFile := filepath.Join(outDir, "processes.txt")
	out, err := runShell(ctx, procFile, "ps auxwwf")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("ps: %v", err))
	}
	outLower := strings.ToLower(out)

	// 2. Check for deleted binaries (/proc/*/exe -> (deleted)).
	deletedFile := filepath.Join(outDir, "deleted_binaries.txt")
	delOut, _ := runShell(ctx, deletedFile, `find /proc -maxdepth 2 -name exe -exec ls -la {} \; 2>/dev/null | grep '(deleted)'`)
	if strings.TrimSpace(delOut) != "" {
		lines := strings.Split(strings.TrimSpace(delOut), "\n")
		findings = append(findings, Finding{
			Severity: "critical",
			Title:    fmt.Sprintf("%d processes running from deleted binaries", len(lines)),
			Source:   "live_proc",
			MITRE:    "T1070.004",
		})
	}

	// 3. Known malicious tool names.
	var toolHits []string
	for _, tool := range linuxSuspiciousProcs {
		if strings.Contains(outLower, strings.ToLower(tool)) {
			toolHits = append(toolHits, tool)
		}
	}
	if len(toolHits) > 0 {
		hitFile := filepath.Join(outDir, "known_tools.txt")
		_ = os.WriteFile(hitFile, []byte(strings.Join(toolHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "critical",
			Title:    fmt.Sprintf("Known attack tools detected: %s", strings.Join(toolHits, ", ")),
			Source:   "live_proc",
			MITRE:    "T1588.002",
		})
	}

	// 4. Reverse shell patterns.
	for _, pattern := range reverseShellPatterns {
		if strings.Contains(outLower, strings.ToLower(pattern)) {
			findings = append(findings, Finding{
				Severity: "critical",
				Title:    "Reverse shell pattern detected in process list",
				Source:   "live_proc",
				MITRE:    "T1059.004",
			})
			break
		}
	}

	// 5. Crypto mining patterns.
	for _, pattern := range cryptoMiningPatterns {
		if strings.Contains(outLower, strings.ToLower(pattern)) {
			findings = append(findings, Finding{
				Severity: "high",
				Title:    "Crypto mining indicators detected",
				Source:   "live_proc",
				MITRE:    "T1496",
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

// LnxNetworkAnomalies detects suspicious network connections.
func LnxNetworkAnomalies(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Network Anomalies"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. Active connections.
	connFile := filepath.Join(outDir, "connections.txt")
	out, err := runShell(ctx, connFile, "ss -tulpan")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("ss: %v", err))
	}

	// 2. Check for suspicious ports.
	var portHits []string
	for _, port := range suspiciousPortsLnx {
		portStr := fmt.Sprintf(":%d ", port)
		portStr2 := fmt.Sprintf(":%d\n", port)
		if strings.Contains(out, portStr) || strings.Contains(out, portStr2) {
			portHits = append(portHits, fmt.Sprintf("port %d", port))
		}
	}
	if len(portHits) > 0 {
		portFile := filepath.Join(outDir, "suspicious_ports.txt")
		_ = os.WriteFile(portFile, []byte(strings.Join(portHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("Suspicious port connections: %s", strings.Join(portHits, ", ")),
			Source:   "live_net",
			MITRE:    "T1571",
		})
	}

	// 3. Check for mining pool connections.
	outLower := strings.ToLower(out)
	for _, pattern := range cryptoMiningPatterns {
		if strings.Contains(outLower, strings.ToLower(pattern)) {
			findings = append(findings, Finding{
				Severity: "high",
				Title:    "Connection to crypto mining pool detected",
				Source:   "live_net",
				MITRE:    "T1496",
			})
			break
		}
	}

	// 4. Established connections with process info.
	estFile := filepath.Join(outDir, "established.txt")
	_, _ = runShell(ctx, estFile, "ss -tp state established")

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

// LnxCronAudit audits all cron jobs for suspicious entries.
func LnxCronAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Cron Job Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. System crontabs.
	cronFile := filepath.Join(outDir, "system_crons.txt")
	out, _ := runShell(ctx, cronFile, `cat /etc/crontab 2>/dev/null; echo "---"; for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do echo "=== $d ==="; ls -la "$d" 2>/dev/null; for f in "$d"/*; do echo "--- $f ---"; cat "$f" 2>/dev/null; done; done`)

	// 2. Per-user crontabs.
	userCronFile := filepath.Join(outDir, "user_crons.txt")
	userOut, _ := runShell(ctx, userCronFile, `for user in $(cut -d: -f1 /etc/passwd); do echo "=== $user ==="; crontab -u "$user" -l 2>/dev/null; done`)

	combined := strings.ToLower(out + "\n" + userOut)

	// Check for suspicious patterns.
	suspCronPatterns := []string{
		"/dev/tcp/", "curl ", "wget ", "python -c", "python3 -c",
		"base64 -d", "bash -i", "nc -e", "/tmp/", "chmod 777",
	}
	var suspHits []string
	for _, pattern := range suspCronPatterns {
		if strings.Contains(combined, pattern) {
			suspHits = append(suspHits, pattern)
		}
	}
	if len(suspHits) > 0 {
		suspFile := filepath.Join(outDir, "suspicious_crons.txt")
		_ = os.WriteFile(suspFile, []byte(strings.Join(suspHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("Suspicious cron entries detected (patterns: %s)", strings.Join(suspHits, ", ")),
			Source:   "live_cron",
			MITRE:    "T1053.003",
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

// LnxSystemdAudit audits systemd services for suspicious entries.
func LnxSystemdAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Systemd Service Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. List all enabled services.
	svcFile := filepath.Join(outDir, "enabled_services.txt")
	_, err := runShell(ctx, svcFile, "systemctl list-unit-files --type=service --state=enabled 2>/dev/null")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("systemctl: %v", err))
	}

	// 2. Failed services (potential indicator of tampering).
	failFile := filepath.Join(outDir, "failed_services.txt")
	failOut, _ := runShell(ctx, failFile, "systemctl --failed 2>/dev/null")
	if strings.TrimSpace(failOut) != "" && !strings.Contains(failOut, "0 loaded") {
		findings = append(findings, Finding{
			Severity: "info",
			Title:    "Failed systemd services detected",
			Source:   "live_systemd",
		})
	}

	// 3. Custom user services.
	customFile := filepath.Join(outDir, "custom_services.txt")
	customOut, _ := runShell(ctx, customFile, `find /etc/systemd/system/ /usr/lib/systemd/system/ -name '*.service' -newer /usr/lib/systemd/system/basic.target 2>/dev/null`)

	// Check for suspicious ExecStart values.
	suspPaths := []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/root/."}
	combined := strings.ToLower(customOut)
	for _, sp := range suspPaths {
		if strings.Contains(combined, sp) {
			findings = append(findings, Finding{
				Severity: "high",
				Title:    "Systemd service with suspicious path detected",
				Source:   "live_systemd",
				MITRE:    "T1543.002",
			})
			break
		}
	}

	// 4. Systemd timers.
	timerFile := filepath.Join(outDir, "timers.txt")
	_, _ = runShell(ctx, timerFile, "systemctl list-timers --all 2>/dev/null")

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

// LnxSUIDSGIDAudit finds SUID/SGID binaries and flags unknown ones.
func LnxSUIDSGIDAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "SUID/SGID File Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Find all SUID/SGID files.
	suidFile := filepath.Join(outDir, "suid_sgid_files.txt")
	out, err := runShell(ctx, suidFile, `find / -perm /6000 -type f 2>/dev/null`)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("find: %v", err))
	}

	// Compare against known-good list.
	unknownFile := filepath.Join(outDir, "unknown_suid.txt")
	var unknown []string
	for _, line := range strings.Split(out, "\n") {
		path := strings.TrimSpace(line)
		if path == "" {
			continue
		}
		if !knownGoodSUID[path] {
			unknown = append(unknown, path)
		}
	}
	if len(unknown) > 0 {
		_ = os.WriteFile(unknownFile, []byte(strings.Join(unknown, "\n")), 0o644)

		severity := "medium"
		if len(unknown) > 10 {
			severity = "high"
		}
		findings = append(findings, Finding{
			Severity: severity,
			Title:    fmt.Sprintf("%d unknown SUID/SGID files detected", len(unknown)),
			Source:   "live_suid",
			MITRE:    "T1548.001",
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

// LnxOpenPortAudit scans for open/listening ports.
func LnxOpenPortAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Open Port Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Listening ports with process info.
	listenFile := filepath.Join(outDir, "listening_ports.txt")
	out, err := runShell(ctx, listenFile, "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("port scan: %v", err))
	}

	// Check for suspicious listening ports.
	var portHits []string
	for _, port := range suspiciousPortsLnx {
		portStr := fmt.Sprintf(":%d ", port)
		if strings.Contains(out, portStr) {
			portHits = append(portHits, fmt.Sprintf("port %d", port))
		}
	}
	if len(portHits) > 0 {
		portFile := filepath.Join(outDir, "suspicious_listeners.txt")
		_ = os.WriteFile(portFile, []byte(strings.Join(portHits, "\n")), 0o644)
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("Suspicious listening ports: %s", strings.Join(portHits, ", ")),
			Source:   "live_ports",
			MITRE:    "T1571",
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

// LnxKernelModuleAudit audits loaded kernel modules.
func LnxKernelModuleAudit(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Kernel Module Audit"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. List loaded modules.
	modFile := filepath.Join(outDir, "loaded_modules.txt")
	_, err := runShell(ctx, modFile, "lsmod")
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("lsmod: %v", err))
	}

	// 2. Check for unsigned modules.
	unsignedFile := filepath.Join(outDir, "module_info.txt")
	unsignedOut, _ := runShell(ctx, unsignedFile, `for mod in $(lsmod | awk 'NR>1{print $1}'); do echo "=== $mod ==="; modinfo "$mod" 2>/dev/null | grep -E 'filename|description|author|sig'; done`)

	// Check for out-of-tree or unsigned modules.
	if strings.Contains(unsignedOut, "intree: N") || strings.Contains(unsignedOut, "sig_hashalgo: (none)") {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Out-of-tree or unsigned kernel modules detected",
			Source:   "live_kmod",
			MITRE:    "T1547.006",
		})
	}

	// 3. Check for recently loaded modules (via dmesg).
	dmesgFile := filepath.Join(outDir, "module_dmesg.txt")
	_, _ = runShell(ctx, dmesgFile, `dmesg 2>/dev/null | grep -i 'module\|insmod\|modprobe'`)

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

// LnxLoginAnomalies checks for brute force attempts, UID 0 accounts, etc.
func LnxLoginAnomalies(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "User Login Anomalies"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// 1. Check for multiple UID 0 accounts.
	uid0File := filepath.Join(outDir, "uid0_accounts.txt")
	uid0Out, _ := runShell(ctx, uid0File, `awk -F: '$3 == 0' /etc/passwd`)
	uid0Lines := strings.Split(strings.TrimSpace(uid0Out), "\n")
	if len(uid0Lines) > 1 && uid0Lines[0] != "" {
		findings = append(findings, Finding{
			Severity: "critical",
			Title:    fmt.Sprintf("%d accounts with UID 0 (root-equivalent)", len(uid0Lines)),
			Source:   "live_logins",
			MITRE:    "T1098",
		})
	}

	// 2. Recent login failures.
	failFile := filepath.Join(outDir, "login_failures.txt")
	failOut, _ := runShell(ctx, failFile, `lastb -n 100 2>/dev/null || journalctl -u sshd --no-pager -n 200 2>/dev/null | grep -i 'failed\|invalid'`)
	failLines := strings.Split(strings.TrimSpace(failOut), "\n")
	if len(failLines) > 20 && failLines[0] != "" {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d recent login failures (potential brute force)", len(failLines)),
			Source:   "live_logins",
			MITRE:    "T1110",
		})
	}

	// 3. Currently logged in users.
	whoFile := filepath.Join(outDir, "logged_in.txt")
	_, _ = runShell(ctx, whoFile, "w; echo '---'; last -n 50")

	// 4. Users with no password.
	noPwFile := filepath.Join(outDir, "no_password.txt")
	noPwOut, _ := runShell(ctx, noPwFile, `awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null`)
	if strings.TrimSpace(noPwOut) != "" {
		noPwLines := strings.Split(strings.TrimSpace(noPwOut), "\n")
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d accounts with no password set", len(noPwLines)),
			Source:   "live_logins",
			MITRE:    "T1078",
		})
	}

	// 5. SSH authorized keys across all users.
	sshFile := filepath.Join(outDir, "authorized_keys.txt")
	_, _ = runShell(ctx, sshFile, `find /home /root -name authorized_keys -exec echo "=== {} ===" \; -exec cat {} \; 2>/dev/null`)

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

// LnxHiddenFiles scans for hidden files and directories in suspicious locations.
func LnxHiddenFiles(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Hidden Files & Directories"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Check for hidden files in /tmp, /dev/shm, /var/tmp.
	hiddenFile := filepath.Join(outDir, "hidden_files.txt")
	out, err := runShell(ctx, hiddenFile, `find /tmp /dev/shm /var/tmp -name '.*' -not -name '.' -not -name '..' 2>/dev/null`)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("find: %v", err))
	}

	if strings.TrimSpace(out) != "" {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		findings = append(findings, Finding{
			Severity: "medium",
			Title:    fmt.Sprintf("%d hidden files in /tmp, /dev/shm, /var/tmp", len(lines)),
			Source:   "live_hidden",
			MITRE:    "T1564.001",
		})
	}

	// Check for hidden directories in web roots.
	webHiddenFile := filepath.Join(outDir, "web_hidden.txt")
	webOut, _ := runShell(ctx, webHiddenFile, `find /var/www /srv/www -name '.*' -type d 2>/dev/null`)
	if strings.TrimSpace(webOut) != "" {
		findings = append(findings, Finding{
			Severity: "high",
			Title:    "Hidden directories found in web root",
			Source:   "live_hidden",
			MITRE:    "T1564.001",
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

// LnxImmutableFiles detects files with the immutable attribute set.
func LnxImmutableFiles(ctx context.Context, outDir string, logger *logging.Logger) ScanResult {
	name := "Immutable File Detection"
	start := time.Now()

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	var findings []Finding
	var warnings []string

	// Scan key directories for immutable files.
	immFile := filepath.Join(outDir, "immutable_files.txt")
	out, err := runShell(ctx, immFile, `lsattr -R /tmp /var/tmp /dev/shm /usr/bin /usr/sbin 2>/dev/null | grep -E '^....i'`)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("lsattr: %v", err))
	}

	if strings.TrimSpace(out) != "" {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		findings = append(findings, Finding{
			Severity: "high",
			Title:    fmt.Sprintf("%d files with immutable attribute (potential rootkit)", len(lines)),
			Source:   "live_immutable",
			MITRE:    "T1222.002",
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
