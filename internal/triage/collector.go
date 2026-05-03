package triage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// StepStatus tracks a single collection step's progress.
type StepStatus int

const (
	StepPending StepStatus = iota
	StepRunning
	StepSuccess
	StepPartial // some commands failed
	StepFailed
	StepSkipped
)

func (s StepStatus) String() string {
	switch s {
	case StepPending:
		return "pending"
	case StepRunning:
		return "running"
	case StepSuccess:
		return "success"
	case StepPartial:
		return "partial"
	case StepFailed:
		return "failed"
	case StepSkipped:
		return "skipped"
	}
	return "unknown"
}

// StepResult reports the outcome of a single collection step.
type StepResult struct {
	Index    int
	Name     string
	Status   StepStatus
	Duration time.Duration
	Files    int
	Bytes    int64
	Warnings []string
}

// CollectionSummary is the final report for a triage run.
type CollectionSummary struct {
	Hostname     string
	CaseID       string
	CaseName     string
	Analyst      string
	Organization string
	Platform     string
	Elevated     bool
	StartedAt    time.Time
	FinishedAt   time.Time
	Duration     time.Duration
	OutputDir    string
	Steps        []StepResult
	TotalFiles   int
	TotalBytes   int64
}

// StepDef defines a collection step — a named function that writes artifacts
// into a subdirectory of the triage output.
type StepDef struct {
	Name    string
	SubDir  string
	RunFunc func(ctx context.Context, outDir string, logger *logging.Logger) StepResult
}

// ProgressMsg is sent via a channel to update the TUI as steps run.
type ProgressMsg struct {
	StepIndex int
	Result    *StepResult // nil while running, non-nil when complete
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

// Collector orchestrates triage collection steps.
type Collector struct {
	Platform     string
	RootDir      string
	CaseID       string
	CaseName     string
	Hostname     string
	Analyst      string
	Organization string
	Elevated     bool
	Logger       *logging.Logger
}

// NewCollector creates a triage collector.
func NewCollector(rootDir, caseID, hostname, analyst, platform string, elevated bool, logger *logging.Logger) *Collector {
	return &Collector{
		Platform: platform,
		RootDir:  rootDir,
		CaseID:   caseID,
		Hostname: hostname,
		Analyst:  analyst,
		Elevated: elevated,
		Logger:   logger,
	}
}

// Steps returns the platform-appropriate step definitions.
func (c *Collector) Steps() []StepDef {
	if c.Platform == "windows" {
		return WindowsSteps()
	}
	return LinuxSteps()
}

// OutputDir returns the triage output directory for this run.
func (c *Collector) OutputDir(timestamp string) string {
	return filepath.Join(c.RootDir, "output", c.CaseID, "triage", timestamp)
}

// Run executes the given step indices. Progress is reported via progressCh.
// The channel is closed when all steps complete.
//
// parentCtx is the cancellation root for the whole collection. Each step
// derives a 5-minute child context from it, so cancelling parentCtx
// (e.g. via the web frontend's task manager) aborts the in-flight
// command and exits the loop before the next step runs. Pass
// context.Background() when no cancellation is needed (e.g. TUI).
func (c *Collector) Run(parentCtx context.Context, stepIndices []int, progressCh chan<- ProgressMsg) CollectionSummary {
	allSteps := c.Steps()
	ts := time.Now().Format("20060102_150405")
	outDir := c.OutputDir(ts)

	summary := CollectionSummary{
		Hostname:     c.Hostname,
		CaseID:       c.CaseID,
		CaseName:     c.CaseName,
		Analyst:      c.Analyst,
		Organization: c.Organization,
		Platform:     c.Platform,
		Elevated:     c.Elevated,
		StartedAt:    time.Now(),
		OutputDir:    outDir,
	}

	// Pre-fill step results.
	results := make([]StepResult, len(allSteps))
	for i, s := range allSteps {
		results[i] = StepResult{Index: i, Name: s.Name, Status: StepSkipped}
	}

	for _, idx := range stepIndices {
		if idx < 0 || idx >= len(allSteps) {
			continue
		}
		results[idx].Status = StepPending
	}

	// Execute selected steps sequentially.
	for _, idx := range stepIndices {
		// Cancellation check between steps. We don't interrupt a step
		// mid-execution from this loop — that's the per-step ctx's job —
		// but we do skip every remaining step the moment the analyst
		// clicks Cancel so the run finishes promptly.
		select {
		case <-parentCtx.Done():
			results[idx].Status = StepSkipped
			results[idx].Warnings = append(results[idx].Warnings,
				"cancelled before this step started")
			if progressCh != nil {
				r := results[idx]
				progressCh <- ProgressMsg{StepIndex: idx, Result: &r}
			}
			continue
		default:
		}
		if idx < 0 || idx >= len(allSteps) {
			continue
		}
		step := allSteps[idx]

		// Signal running.
		results[idx].Status = StepRunning
		if progressCh != nil {
			progressCh <- ProgressMsg{StepIndex: idx, Result: nil}
		}

		// Create output subdirectory.
		stepDir := filepath.Join(outDir, step.SubDir)
		if err := os.MkdirAll(stepDir, 0o700); err != nil {
			results[idx].Status = StepFailed
			results[idx].Warnings = append(results[idx].Warnings,
				fmt.Sprintf("failed to create directory: %v", err))
			if progressCh != nil {
				r := results[idx]
				progressCh <- ProgressMsg{StepIndex: idx, Result: &r}
			}
			continue
		}

		// Multiple steps can share a SubDir (System Information + Installed
		// Software both use "system"; Network Connections + Network
		// Configuration both use "network"). Counting stepDir after the run
		// would attribute another step's files to this one and inflate the
		// totals when summed. Snapshot the whole outDir before/after each
		// step and use the delta — robust to subdir collisions.
		filesBefore, bytesBefore := countDirContents(outDir)

		// Run with 5 minute overall timeout per step, derived from the
		// parent context so a cancel from outside also aborts the
		// active command (when the step uses exec.CommandContext).
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
		start := time.Now()
		result := step.RunFunc(ctx, stepDir, c.Logger)
		cancel()

		result.Index = idx
		result.Name = step.Name
		result.Duration = time.Since(start)

		filesAfter, bytesAfter := countDirContents(outDir)
		result.Files = filesAfter - filesBefore
		if result.Files < 0 {
			result.Files = 0
		}
		result.Bytes = bytesAfter - bytesBefore
		if result.Bytes < 0 {
			result.Bytes = 0
		}

		results[idx] = result

		if progressCh != nil {
			r := result
			progressCh <- ProgressMsg{StepIndex: idx, Result: &r}
		}
	}

	summary.FinishedAt = time.Now()
	summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
	summary.Steps = results

	// Canonical totals: walk the entire output tree once at the end. The
	// per-step delta accounting above can drift when a later step rewrites
	// or removes files from an earlier step's directory — the on-disk walk
	// is authoritative for what the analyst will actually see in the case.
	summary.TotalFiles, summary.TotalBytes = countDirContents(outDir)

	// Write summary file.
	c.writeSummary(outDir, &summary)

	if progressCh != nil {
		close(progressCh)
	}

	return summary
}

// writeSummary creates the collection_summary.txt file.
func (c *Collector) writeSummary(outDir string, s *CollectionSummary) {
	path := filepath.Join(outDir, "collection_summary.txt")

	var b strings.Builder
	b.WriteString("VanGuard Quick Triage — Collection Summary\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	b.WriteString(fmt.Sprintf("Hostname:      %s\n", s.Hostname))
	b.WriteString(fmt.Sprintf("Case ID:       %s\n", s.CaseID))
	if s.CaseName != "" {
		b.WriteString(fmt.Sprintf("Case Name:     %s\n", s.CaseName))
	}
	if s.Analyst != "" {
		b.WriteString(fmt.Sprintf("Analyst:       %s\n", s.Analyst))
	} else {
		b.WriteString("Analyst:       (not configured — set via Configuration > Edit Analyst Name)\n")
	}
	if s.Organization != "" {
		b.WriteString(fmt.Sprintf("Organization:  %s\n", s.Organization))
	}
	b.WriteString(fmt.Sprintf("Platform:      %s\n", s.Platform))
	b.WriteString(fmt.Sprintf("Elevated:      %v\n", s.Elevated))
	b.WriteString(fmt.Sprintf("Started:       %s\n", s.StartedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("Finished:      %s\n", s.FinishedAt.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("Duration:      %s\n", s.Duration.Truncate(time.Second)))
	b.WriteString(fmt.Sprintf("Output Dir:    %s\n", s.OutputDir))
	b.WriteString(fmt.Sprintf("Total Files:   %d\n", s.TotalFiles))
	b.WriteString(fmt.Sprintf("Total Size:    %s\n", formatBytes(s.TotalBytes)))
	b.WriteString("\n" + strings.Repeat("-", 50) + "\n")
	b.WriteString(fmt.Sprintf("%-30s %-10s %8s %6s %10s\n",
		"Step", "Status", "Duration", "Files", "Size"))
	b.WriteString(strings.Repeat("-", 50) + "\n")

	for _, r := range s.Steps {
		if r.Status == StepSkipped {
			continue
		}
		b.WriteString(fmt.Sprintf("%-30s %-10s %8s %6d %10s\n",
			r.Name, r.Status, r.Duration.Truncate(time.Second), r.Files, formatBytes(r.Bytes)))
		for _, w := range r.Warnings {
			b.WriteString(fmt.Sprintf("  WARNING: %s\n", w))
		}
	}

	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

// ---------------------------------------------------------------------------
// Command execution helpers
// ---------------------------------------------------------------------------

// runCommand executes a single command with a context timeout.
// It writes stdout to outFile. Returns any error and stderr content.
func runCommand(ctx context.Context, outFile string, cmdName string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)
	out, err := cmd.CombinedOutput()

	if outFile != "" && len(out) > 0 {
		_ = os.WriteFile(outFile, out, 0o644)
	}

	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// runShell executes a shell command string. On Windows uses cmd /c, on Linux uses sh -c.
func runShell(ctx context.Context, outFile, command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	out, err := cmd.CombinedOutput()

	if outFile != "" && len(out) > 0 {
		_ = os.WriteFile(outFile, out, 0o644)
	}

	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

// runPS runs a PowerShell command. Windows only.
func runPS(ctx context.Context, outFile, psCommand string) (string, error) {
	return runCommand(ctx, outFile,
		"powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCommand)
}

// runCopyFile copies src to dst, ignoring errors (best effort).
func runCopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func countDirContents(dir string) (int, int64) {
	var count int
	var total int64
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		count++
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return count, total
}

// FormatBytesPublic formats a byte count for display.
func FormatBytesPublic(b int64) string {
	return formatBytes(b)
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
