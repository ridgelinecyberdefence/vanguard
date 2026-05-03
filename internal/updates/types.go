// Package updates handles keeping VanGuard's external dependencies fresh:
// tool binaries (GitHub releases) and rule sets (repo archives), plus the
// air-gapped offline-bundle create/apply flow and a self-version check
// against the VanGuard release feed.
//
// The package layers on top of internal/tools — it doesn't replicate the
// download or extraction logic. What's added here:
//
//   - Backup-then-restore semantics: every update operation snapshots the
//     existing payload and rolls back on failure.
//   - Per-rule-set timestamp tracking via .vanguard_updated marker files,
//     since the GitHub-release version metadata doesn't apply to rule
//     repositories (we track them as branch:* in tool state).
//   - YARA custom-rules preservation: rules/yara/custom/ survives updates.
//   - Offline bundle manifest format with SHA256 verification.
package updates

import "time"

// ItemKind classifies one update target.
type ItemKind string

const (
	ItemTool      ItemKind = "tool"      // binary from github_release
	ItemRuleSet   ItemKind = "rules"     // repo_archive set
	ItemVanGuard  ItemKind = "vanguard"  // VanGuard itself (self-check only)
)

// Status describes one update target's freshness.
type Status string

const (
	StatusUpToDate     Status = "up_to_date"
	StatusUpdateAvail  Status = "update_available"
	StatusNotInstalled Status = "not_installed"
	StatusUnknown      Status = "unknown" // checked but not determinable
	StatusError        Status = "error"
)

// CheckResult is one row in the "check for updates" report.
type CheckResult struct {
	Name           string
	ToolID         string  // tools.Tool.ID; empty for VanGuard
	Kind           ItemKind
	InstalledLabel string  // "v0.73.0", "2026-04-15", or "" when not installed
	LatestLabel    string  // "v0.73.3", "2026-05-01", "" if unknown
	Status         Status
	Reason         string  // human-friendly explanation when Status=error/unknown
}

// CheckReport bundles many CheckResult rows plus the run timestamp.
type CheckReport struct {
	GeneratedAt time.Time
	Results     []CheckResult
}

// CountByStatus returns (uptodate, updateAvailable, notInstalled, errors).
func (r *CheckReport) CountByStatus() (int, int, int, int) {
	var u, a, n, e int
	for _, c := range r.Results {
		switch c.Status {
		case StatusUpToDate:
			u++
		case StatusUpdateAvail:
			a++
		case StatusNotInstalled:
			n++
		case StatusError, StatusUnknown:
			e++
		}
	}
	return u, a, n, e
}

// UpdateOutcome is what one apply-update operation returns.
type UpdateOutcome struct {
	Name       string
	Kind       ItemKind
	From       string
	To         string
	Duration   time.Duration
	Success    bool
	Error      string
}
