package updates

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// Manager orchestrates the update workflows. It holds references to the
// existing ToolManager (so we don't reinvent download / extract logic) plus
// the analyst-host root directory.
type Manager struct {
	RootDir     string
	Tools       *tools.ToolManager
	Logger      *logging.Logger
}

// New constructs an update Manager.
func New(rootDir string, tm *tools.ToolManager, logger *logging.Logger) *Manager {
	return &Manager{RootDir: rootDir, Tools: tm, Logger: logger}
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

// CheckAll fans out across every registered tool (including rule sets) and
// returns one CheckResult per item. Network failures land as CheckResult
// rows with Status=StatusError so the report still surfaces what's known.
//
// Writes the global last-check marker on every invocation (regardless of
// whether any individual lookup succeeded) so the menu's "Last update check"
// line reflects activity, not success.
func (m *Manager) CheckAll() *CheckReport {
	rep := &CheckReport{GeneratedAt: time.Now()}
	defer func() {
		if err := WriteLastCheck(m.RootDir, rep.GeneratedAt); err != nil && m.Logger != nil {
			m.Logger.Warn("updates", "writing last-check marker: %v", err)
		}
	}()

	for _, s := range m.Tools.GetStatus() {
		t := m.Tools.GetTool(s.ID)
		if t == nil {
			continue
		}
		// Manual-only tools have no upstream we can poll.
		if t.GitHubRepo == "" || strings.EqualFold(t.LocalPath, "") {
			continue
		}

		switch isRuleSet(t.LocalPath) {
		case true:
			rep.Results = append(rep.Results, m.checkRuleSet(t))
		case false:
			rep.Results = append(rep.Results, m.checkTool(t))
		}
	}
	return rep
}

// checkTool is the github_release path: compare InstalledVersion to the
// latest release tag.
func (m *Manager) checkTool(t *tools.Tool) CheckResult {
	r := CheckResult{
		Name:           t.Name,
		ToolID:         t.ID,
		Kind:           ItemTool,
		InstalledLabel: t.InstalledVersion,
	}
	if !t.Installed {
		r.Status = StatusNotInstalled
		r.InstalledLabel = "(not installed)"
	}
	// CheckForUpdates does network calls; we re-use it via the ToolManager.
	updates, err := m.Tools.CheckForUpdates()
	if err != nil {
		r.Status = StatusError
		r.Reason = err.Error()
		return r
	}
	for _, u := range updates {
		if u.ID != t.ID {
			continue
		}
		r.LatestLabel = u.LatestVersion
		if t.Installed {
			r.Status = StatusUpdateAvail
		} else {
			r.Status = StatusNotInstalled
		}
		return r
	}
	// No update entry — either up to date OR not installed (CheckForUpdates
	// only returns entries that differ from InstalledVersion).
	r.LatestLabel = t.InstalledVersion
	if t.Installed {
		r.Status = StatusUpToDate
	} else {
		r.Status = StatusNotInstalled
	}
	return r
}

// checkRuleSet is the repo_archive path: compare the marker timestamp to the
// branch's latest commit time on GitHub.
func (m *Manager) checkRuleSet(t *tools.Tool) CheckResult {
	r := CheckResult{
		Name:   t.Name,
		ToolID: t.ID,
		Kind:   ItemRuleSet,
	}
	installedAt := ReadTimestamp(m.RootDir, t.LocalPath)
	if installedAt.IsZero() && !t.Installed {
		r.Status = StatusNotInstalled
		r.InstalledLabel = "(not installed)"
		return r
	}
	if !installedAt.IsZero() {
		r.InstalledLabel = installedAt.UTC().Format("2006-01-02")
	} else {
		// Installed but no marker (legacy / hand-placed). Treat as unknown
		// installed date — still let the user trigger an update.
		r.InstalledLabel = "(unknown)"
	}

	branch := repoBranch(t)
	commitAt, err := LatestCommit(t.GitHubRepo, branch)
	if err != nil {
		r.Status = StatusError
		r.Reason = err.Error()
		return r
	}
	r.LatestLabel = commitAt.UTC().Format("2006-01-02")
	if installedAt.IsZero() || commitAt.After(installedAt) {
		r.Status = StatusUpdateAvail
	} else {
		r.Status = StatusUpToDate
	}
	return r
}

// repoBranch returns the configured branch for a tool, or "main" by default.
// Mirrors the helper in internal/tools but kept local so we don't widen its
// public API.
func repoBranch(t *tools.Tool) string {
	if t.RepoBranch != "" {
		return t.RepoBranch
	}
	return "main"
}

func isRuleSet(localPath string) bool {
	// Rule sets are directory-based and live under rules/.
	return strings.HasSuffix(localPath, "/") &&
		strings.HasPrefix(strings.ToLower(localPath), "rules/")
}

// ---------------------------------------------------------------------------
// Apply (single tool / single rule set)
// ---------------------------------------------------------------------------

// UpdateTool runs the backup-then-restore wrapper around ToolManager.DownloadTool.
func (m *Manager) UpdateTool(toolID string) UpdateOutcome {
	t := m.Tools.GetTool(toolID)
	if t == nil {
		return UpdateOutcome{Name: toolID, Success: false,
			Error: "unknown tool: " + toolID}
	}
	out := UpdateOutcome{Name: t.Name, Kind: ItemTool, From: t.InstalledVersion}
	started := time.Now()

	dest := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
	backup, err := backupPath(dest)
	if err != nil {
		out.Error = "backup failed: " + err.Error()
		out.Duration = time.Since(started)
		return out
	}

	if err := m.Tools.DownloadTool(toolID); err != nil {
		// Restore the backup so we leave the user no worse off.
		if backup != "" {
			_ = restoreBackup(backup, dest)
		}
		out.Error = err.Error()
		out.Duration = time.Since(started)
		return out
	}

	out.To = m.refreshedVersion(toolID)
	out.Success = true
	out.Duration = time.Since(started)
	if backup != "" {
		_ = removeBackup(backup)
	}
	return out
}

// UpdateRuleSet wraps DownloadTool with a backup of the existing rules tree
// and (for YARA) restores rules/yara/custom/ after the new tree is in place.
// Also writes the .vanguard_updated marker so future checks compare against
// "now" rather than the upstream commit time.
func (m *Manager) UpdateRuleSet(toolID string) UpdateOutcome {
	t := m.Tools.GetTool(toolID)
	if t == nil {
		return UpdateOutcome{Name: toolID, Success: false,
			Error: "unknown rule set: " + toolID}
	}
	out := UpdateOutcome{Name: t.Name, Kind: ItemRuleSet}
	started := time.Now()

	dest := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
	dest = strings.TrimRight(dest, string(os.PathSeparator)) // for Stat / Rename

	// YARA gets its custom/ dir snapshotted out before the swap so user rules
	// survive the update.
	customSnap := ""
	if toolID == "yara-rules" {
		if cs, err := snapshotYaraCustom(dest); err == nil {
			customSnap = cs
		}
	}

	backup, err := backupPath(dest)
	if err != nil {
		out.Error = "backup failed: " + err.Error()
		out.Duration = time.Since(started)
		return out
	}

	if err := m.Tools.DownloadTool(toolID); err != nil {
		if backup != "" {
			_ = restoreBackup(backup, dest)
		}
		out.Error = err.Error()
		out.Duration = time.Since(started)
		return out
	}

	// Restore the YARA custom dir on top of the freshly extracted set.
	if customSnap != "" {
		_ = restoreYaraCustom(customSnap, dest)
		_ = os.RemoveAll(customSnap)
	}

	if err := WriteTimestamp(m.RootDir, t.LocalPath, time.Now().UTC()); err != nil && m.Logger != nil {
		m.Logger.Warn("updates", "writing timestamp marker for %s: %v", t.Name, err)
	}
	out.From = "(previous)"
	out.To = time.Now().UTC().Format("2006-01-02")
	out.Success = true
	out.Duration = time.Since(started)
	if backup != "" {
		_ = removeBackup(backup)
	}
	return out
}

// refreshedVersion looks up the tool's InstalledVersion after a successful
// DownloadTool. Returns "" when not available.
func (m *Manager) refreshedVersion(toolID string) string {
	if t := m.Tools.GetTool(toolID); t != nil {
		return t.InstalledVersion
	}
	return ""
}

// ---------------------------------------------------------------------------
// Backup helpers
// ---------------------------------------------------------------------------

// backupPath renames path → path.bak (a directory or a file). Returns the
// backup path. When path doesn't exist, returns "" so callers know there's
// nothing to restore.
func backupPath(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	bak := path + ".bak"
	// Best-effort: clean up any stale bak from a previous failed run.
	_ = os.RemoveAll(bak)
	if err := os.Rename(path, bak); err != nil {
		return "", fmt.Errorf("rename %s -> %s: %w", path, bak, err)
	}
	return bak, nil
}

// restoreBackup undoes a backupPath call. Used on failure paths.
func restoreBackup(bak, original string) error {
	_ = os.RemoveAll(original)
	return os.Rename(bak, original)
}

// removeBackup deletes a successful-update backup once the new payload is in.
func removeBackup(bak string) error {
	return os.RemoveAll(bak)
}

// ---------------------------------------------------------------------------
// YARA custom-dir preservation
// ---------------------------------------------------------------------------

// snapshotYaraCustom moves rules/yara/custom/ to a sibling temp dir before an
// update, returning the temp path or "" if the custom dir doesn't exist.
func snapshotYaraCustom(rulesDir string) (string, error) {
	src := filepath.Join(rulesDir, "custom")
	if _, err := os.Stat(src); err != nil {
		return "", nil
	}
	tmp, err := os.MkdirTemp(filepath.Dir(rulesDir), "vg-yara-custom-")
	if err != nil {
		return "", err
	}
	dest := filepath.Join(tmp, "custom")
	if err := os.Rename(src, dest); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	return dest, nil
}

// restoreYaraCustom moves the previously-snapshotted custom dir back into the
// fresh rules tree. Best-effort — failure is logged by the caller.
func restoreYaraCustom(snap, rulesDir string) error {
	dest := filepath.Join(rulesDir, "custom")
	_ = os.RemoveAll(dest)
	if err := os.Rename(snap, dest); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tiny streaming-copy helper used by the bundle code below.
// ---------------------------------------------------------------------------

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
