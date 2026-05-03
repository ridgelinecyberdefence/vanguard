// Package analysis implements the parsing, correlation, and reporting layer
// behind the Analysis & Reporting [7] menu.
//
// It composes:
//   - the EZ Tools parsers from internal/disk (no duplication),
//   - case-database queries from internal/case for finding aggregation,
//   - the MITRE technique catalog from internal/mitre for mapping output,
//   - lightweight first-party log parsers (auth/syslog/web/journal) for the
//     workflows where there's no upstream tool worth wrapping.
package analysis

import (
	"path/filepath"
	"time"
)

// Severity mirrors the case-DB severity strings so detection code in this
// package stays decoupled from the SQL layer.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Finding is the package-local representation of a detection. Callers convert
// to / from casemanager.Finding when persisting.
type Finding struct {
	Severity       string
	Title          string
	Description    string
	MITRETechnique string
	IOCType        string
	IOCValue       string
	Source         string // logical source (e.g. "auth_log", "evtx_logon")
	Host           string
	Timestamp      time.Time
}

// AnalysisResult is the standard outcome of any analysis step — a small
// summary plus the structured findings it produced.
type AnalysisResult struct {
	Name      string
	Source    string // path to the data source consumed
	OutputDir string
	Lines     []string // rendered summary text for the TUI
	Findings  []Finding
	Duration  time.Duration
	Error     string
	Success   bool
}

// CollectionTimestamp returns the standard "20060102_150405" suffix used for
// per-run output directories.
func CollectionTimestamp() string {
	return time.Now().Format("20060102_150405")
}

// AnalysisDir returns output/{case}/analysis/{ts}/{subdir}.
func AnalysisDir(rootDir, caseID, ts, subdir string) string {
	return filepath.Join(rootDir, "output", caseID, "analysis", ts, subdir)
}

// ReportsDir returns output/{case}/reports — used by HTML / CSV / IOC exports.
func ReportsDir(rootDir, caseID string) string {
	return filepath.Join(rootDir, "output", caseID, "reports")
}
