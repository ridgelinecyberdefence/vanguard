package remote

import (
	"strings"
)

// Severity levels used by Finding (kept as plain strings to match the case
// database schema and the local hunting findings).
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding describes one anomaly or IOC hit detected in remote-collected data.
// It mirrors the local internal/hunting Finding so the case DB row format
// stays consistent.
type Finding struct {
	Severity string
	Title    string
	Detail   string
	Source   string // e.g. "remote_processes", "ioc_sweep"
	Host     string // hostname/IP of the source target
}

// ---------------------------------------------------------------------------
// Process anomaly patterns — kept in sync with internal/hunting/live_*.go
// ---------------------------------------------------------------------------

// suspiciousProcPatterns are case-insensitive substrings indicative of
// potentially malicious activity in process command lines or paths.
var suspiciousProcPatterns = []struct {
	Pattern  string
	Severity string
	Reason   string
}{
	// LOLBins commonly abused by attackers.
	{"powershell.exe -enc", SeverityHigh, "PowerShell with encoded command (LOLBin)"},
	{"powershell.exe -e ", SeverityHigh, "PowerShell with encoded command (LOLBin)"},
	{"powershell.exe -nop", SeverityMedium, "PowerShell -NoProfile"},
	{"frombase64string", SeverityHigh, "Base64 deobfuscation in command line"},
	{"-windowstyle hidden", SeverityHigh, "Hidden PowerShell window"},
	{"downloadstring", SeverityHigh, "Inline web download (PowerShell)"},
	{"invoke-expression", SeverityHigh, "Invoke-Expression — common in fileless"},
	{"iex(", SeverityHigh, "IEX abbreviation — fileless execution"},
	{"certutil -urlcache", SeverityCritical, "certutil URL cache abuse (LOLBin)"},
	{"bitsadmin /transfer", SeverityHigh, "BITS used for file transfer"},
	{"rundll32 javascript:", SeverityCritical, "rundll32 JavaScript handler"},
	{"mshta http", SeverityCritical, "mshta with remote URL"},
	{"regsvr32 /s /n /u /i:", SeverityCritical, "regsvr32 SCT abuse"},
	{"wmic process call create", SeverityHigh, "WMIC remote process creation"},
	{"schtasks /create", SeverityMedium, "Scheduled task creation"},

	// Suspicious paths.
	{`\appdata\local\temp\`, SeverityMedium, "Process running from user temp"},
	{`\windows\temp\`, SeverityMedium, "Process running from Windows temp"},
	{`\programdata\`, SeverityLow, "Process running from ProgramData"},

	// Linux / cross-platform.
	{"nc -e", SeverityCritical, "netcat reverse-shell flag"},
	{"bash -i >& /dev/tcp/", SeverityCritical, "Bash reverse shell"},
	{"python -c 'import socket", SeverityHigh, "Python socket one-liner (likely reverse shell)"},
	{"perl -e", SeverityMedium, "Perl one-liner (suspicious in production)"},
	{"/tmp/.", SeverityMedium, "Hidden binary running from /tmp"},
	{"/dev/shm/", SeverityHigh, "Process running from /dev/shm (memory tmpfs)"},
	{"chmod 777", SeverityLow, "Loose permission set"},
	{"wget http", SeverityLow, "Inline wget (verify legitimacy)"},
	{"curl -o", SeverityLow, "Inline curl download"},
}

// AnalyzeProcessOutput scans CSV/text process listings for known-bad patterns.
// It returns one Finding per matching line.
func AnalyzeProcessOutput(host, output string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.TrimSpace(lower) == "" {
			continue
		}
		for _, p := range suspiciousProcPatterns {
			if !strings.Contains(lower, strings.ToLower(p.Pattern)) {
				continue
			}
			findings = append(findings, Finding{
				Severity: p.Severity,
				Title:    p.Reason,
				Detail:   strings.TrimSpace(line),
				Source:   "remote_processes",
				Host:     host,
			})
			break // one finding per line is enough
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Network anomaly patterns
// ---------------------------------------------------------------------------

// suspiciousPorts flags well-known attacker ports / common C2 indicators.
var suspiciousPorts = map[string]string{
	":4444 ": "Metasploit default reverse handler",
	":1337 ": "Common script-kiddie listener",
	":31337 ": "Common backdoor port",
	":8080 ":  "Common alt-HTTP / proxy",
	":6667 ":  "IRC (sometimes used for C2)",
	":2222 ":  "Alt-SSH (sometimes attacker SSH)",
}

// AnalyzeNetworkOutput scans connection lists for suspicious indicators.
func AnalyzeNetworkOutput(host, output string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// External + system-process correlation is hard from a CSV alone, so
		// we focus on suspicious port matches here.
		for portFrag, reason := range suspiciousPorts {
			if strings.Contains(line, portFrag) {
				findings = append(findings, Finding{
					Severity: SeverityMedium,
					Title:    "Suspicious port: " + reason,
					Detail:   trimmed,
					Source:   "remote_network",
					Host:     host,
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Persistence anomaly patterns
// ---------------------------------------------------------------------------

var suspiciousPersistencePatterns = []struct {
	Pattern  string
	Severity string
	Reason   string
}{
	{"powershell -enc", SeverityHigh, "Persistence with encoded PowerShell"},
	{`\appdata\`, SeverityMedium, "Autorun pointing to AppData"},
	{`\temp\`, SeverityMedium, "Autorun pointing to a temp directory"},
	{`\programdata\`, SeverityMedium, "Autorun pointing to ProgramData"},
	{"/tmp/", SeverityMedium, "Cron pointing to /tmp"},
	{"/var/tmp/", SeverityMedium, "Cron pointing to /var/tmp"},
	{"/dev/shm/", SeverityHigh, "Persistence pointing to /dev/shm"},
	{"http://", SeverityHigh, "Inline HTTP URL in autorun"},
	{"nc -e", SeverityCritical, "Reverse shell in persistence mechanism"},
	{"bash -i", SeverityHigh, "Interactive bash in persistence mechanism"},
}

// AnalyzePersistenceOutput scans persistence-mechanism dumps for IoCs.
func AnalyzePersistenceOutput(host, output string) []Finding {
	var findings []Finding
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if strings.TrimSpace(lower) == "" {
			continue
		}
		for _, p := range suspiciousPersistencePatterns {
			if strings.Contains(lower, strings.ToLower(p.Pattern)) {
				findings = append(findings, Finding{
					Severity: p.Severity,
					Title:    p.Reason,
					Detail:   strings.TrimSpace(line),
					Source:   "remote_persistence",
					Host:     host,
				})
				break
			}
		}
	}
	return findings
}
