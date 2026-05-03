// Package mitre exposes a small static catalog of MITRE ATT&CK technique IDs
// and the tactic groupings used for VanGuard's analysis output.
//
// The catalog is intentionally focused — only the techniques produced by
// VanGuard's own detection logic and reported in the HTML report. Add entries
// here when a detector starts emitting a new technique ID so the report's
// human-readable name shows up automatically.
package mitre

import "sort"

// Tactic identifies an ATT&CK kill-chain phase.
type Tactic string

const (
	TacticInitialAccess     Tactic = "Initial Access"
	TacticExecution         Tactic = "Execution"
	TacticPersistence       Tactic = "Persistence"
	TacticPrivilegeEscalation Tactic = "Privilege Escalation"
	TacticDefenseEvasion    Tactic = "Defense Evasion"
	TacticCredentialAccess  Tactic = "Credential Access"
	TacticDiscovery         Tactic = "Discovery"
	TacticLateralMovement   Tactic = "Lateral Movement"
	TacticCollection        Tactic = "Collection"
	TacticCommandControl    Tactic = "Command and Control"
	TacticExfiltration      Tactic = "Exfiltration"
	TacticImpact            Tactic = "Impact"
)

// TacticOrder is the canonical kill-chain order used for display.
var TacticOrder = []Tactic{
	TacticInitialAccess,
	TacticExecution,
	TacticPersistence,
	TacticPrivilegeEscalation,
	TacticDefenseEvasion,
	TacticCredentialAccess,
	TacticDiscovery,
	TacticLateralMovement,
	TacticCollection,
	TacticCommandControl,
	TacticExfiltration,
	TacticImpact,
}

// Technique describes a single ATT&CK technique entry.
type Technique struct {
	ID     string
	Name   string
	Tactic Tactic
}

// Techniques is the master technique → name + tactic map.
//
// Sub-techniques use the dotted form (e.g. "T1110.001"); their parent ID may
// also appear when used standalone.
var Techniques = map[string]Technique{
	// Initial Access
	"T1078":     {"T1078", "Valid Accounts", TacticInitialAccess},
	"T1078.001": {"T1078.001", "Valid Accounts: Default Accounts", TacticInitialAccess},
	"T1078.003": {"T1078.003", "Valid Accounts: Local Accounts", TacticInitialAccess},
	"T1110":     {"T1110", "Brute Force", TacticInitialAccess},
	"T1110.001": {"T1110.001", "Brute Force: Password Guessing", TacticInitialAccess},
	"T1110.003": {"T1110.003", "Brute Force: Password Spraying", TacticInitialAccess},
	"T1190":     {"T1190", "Exploit Public-Facing Application", TacticInitialAccess},
	"T1566":     {"T1566", "Phishing", TacticInitialAccess},
	"T1566.001": {"T1566.001", "Spearphishing Attachment", TacticInitialAccess},
	"T1566.002": {"T1566.002", "Spearphishing Link", TacticInitialAccess},

	// Execution
	"T1059":     {"T1059", "Command and Scripting Interpreter", TacticExecution},
	"T1059.001": {"T1059.001", "PowerShell", TacticExecution},
	"T1059.003": {"T1059.003", "Windows Command Shell", TacticExecution},
	"T1059.004": {"T1059.004", "Unix Shell", TacticExecution},
	"T1047":     {"T1047", "Windows Management Instrumentation", TacticExecution},
	"T1204":     {"T1204", "User Execution", TacticExecution},
	"T1204.002": {"T1204.002", "Malicious File", TacticExecution},

	// Persistence
	"T1053":     {"T1053", "Scheduled Task/Job", TacticPersistence},
	"T1053.003": {"T1053.003", "Cron", TacticPersistence},
	"T1053.005": {"T1053.005", "Scheduled Task", TacticPersistence},
	"T1136":     {"T1136", "Create Account", TacticPersistence},
	"T1136.001": {"T1136.001", "Create Account: Local Account", TacticPersistence},
	"T1543":     {"T1543", "Create or Modify System Process", TacticPersistence},
	"T1543.003": {"T1543.003", "Windows Service", TacticPersistence},
	"T1547":     {"T1547", "Boot or Logon Autostart Execution", TacticPersistence},
	"T1547.001": {"T1547.001", "Registry Run Keys", TacticPersistence},
	"T1546":     {"T1546", "Event Triggered Execution", TacticPersistence},
	"T1546.003": {"T1546.003", "WMI Event Subscription", TacticPersistence},

	// Defense Evasion
	"T1027":     {"T1027", "Obfuscated Files or Information", TacticDefenseEvasion},
	"T1027.010": {"T1027.010", "Command Obfuscation", TacticDefenseEvasion},
	"T1070":     {"T1070", "Indicator Removal", TacticDefenseEvasion},
	"T1070.001": {"T1070.001", "Clear Windows Event Logs", TacticDefenseEvasion},
	"T1070.004": {"T1070.004", "File Deletion", TacticDefenseEvasion},
	"T1574":     {"T1574", "Hijack Execution Flow", TacticDefenseEvasion},
	"T1574.001": {"T1574.001", "DLL Search Order Hijacking", TacticDefenseEvasion},

	// Credential Access
	"T1003":     {"T1003", "OS Credential Dumping", TacticCredentialAccess},
	"T1003.001": {"T1003.001", "LSASS Memory", TacticCredentialAccess},
	"T1003.002": {"T1003.002", "Security Account Manager", TacticCredentialAccess},
	"T1003.006": {"T1003.006", "DCSync", TacticCredentialAccess},
	"T1552":     {"T1552", "Unsecured Credentials", TacticCredentialAccess},
	"T1552.001": {"T1552.001", "Credentials in Files", TacticCredentialAccess},

	// Lateral Movement
	"T1021":     {"T1021", "Remote Services", TacticLateralMovement},
	"T1021.001": {"T1021.001", "Remote Desktop Protocol", TacticLateralMovement},
	"T1021.002": {"T1021.002", "SMB/Windows Admin Shares", TacticLateralMovement},
	"T1021.004": {"T1021.004", "SSH", TacticLateralMovement},
	"T1021.006": {"T1021.006", "Windows Remote Management", TacticLateralMovement},

	// Command and Control
	"T1071":     {"T1071", "Application Layer Protocol", TacticCommandControl},
	"T1071.001": {"T1071.001", "Web Protocols", TacticCommandControl},
	"T1105":     {"T1105", "Ingress Tool Transfer", TacticCommandControl},

	// Impact
	"T1486": {"T1486", "Data Encrypted for Impact", TacticImpact},
	"T1490": {"T1490", "Inhibit System Recovery", TacticImpact},
}

// Lookup returns the friendly name for a technique ID, falling back to the ID
// itself when no entry exists. Useful in templates.
func Lookup(id string) string {
	if t, ok := Techniques[id]; ok {
		return t.Name
	}
	return id
}

// TacticOf returns the tactic for a technique ID, or "" if unknown.
func TacticOf(id string) Tactic {
	if t, ok := Techniques[id]; ok {
		return t.Tactic
	}
	return ""
}

// GroupByTactic returns techniques grouped by tactic in TacticOrder. Within a
// tactic, entries are sorted by ID. ids may contain duplicates — they are
// folded by ID before grouping.
func GroupByTactic(ids []string) map[Tactic][]Technique {
	seen := map[string]bool{}
	out := map[Tactic][]Technique{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		t, ok := Techniques[id]
		if !ok {
			t = Technique{ID: id, Name: id}
		}
		out[t.Tactic] = append(out[t.Tactic], t)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].ID < out[k][j].ID })
	}
	return out
}
