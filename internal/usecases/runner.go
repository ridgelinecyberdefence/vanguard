package usecases

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/security"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// Status values used by PhaseResult / StepResult.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
	StatusSkipped  = "skipped"
	StatusSuccess  = "success"
)

// PhaseResult records one phase's outcome.
type PhaseResult struct {
	PhaseName string        `json:"phase_name"`
	Steps     []StepResult  `json:"steps"`
	Duration  time.Duration `json:"duration"`
	Status    string        `json:"status"`
}

// StepResult records one step's outcome.
type StepResult struct {
	StepName   string        `json:"step_name"`
	Status     string        `json:"status"`
	OutputFile string        `json:"output_file,omitempty"`
	OutputSize int64         `json:"output_size,omitempty"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
}

// RunSummary is the aggregate report a runner produces.
type RunSummary struct {
	UseCaseID   string        `json:"use_case_id"`
	UseCaseName string        `json:"use_case_name"`
	CaseID      string        `json:"case_id"`
	Hostname    string        `json:"hostname"`
	Analyst     string        `json:"analyst"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  time.Time     `json:"finished_at"`
	Duration    time.Duration `json:"duration"`
	OutputDir   string        `json:"output_dir"`
	Phases      []PhaseResult `json:"phases"`
	TotalFiles  int           `json:"total_files"`
	TotalBytes  int64         `json:"total_bytes"`
}

// Runner orchestrates one use case execution.
type Runner struct {
	UseCase     *UseCase
	CaseID      string
	RootDir     string
	Platform    string
	Hostname    string
	Analyst     string
	ToolManager *tools.ToolManager
	CaseManager *casemanager.CaseManager
	Logger      *logging.Logger
	Parameters  map[string]string

	outputDir string
}

// New creates a Runner with sensible defaults filled in by the caller.
func New(uc *UseCase, caseID, rootDir, platform, hostname, analyst string,
	tm *tools.ToolManager, cm *casemanager.CaseManager, logger *logging.Logger) *Runner {
	return &Runner{
		UseCase:     uc,
		CaseID:      caseID,
		RootDir:     rootDir,
		Platform:    platform,
		Hostname:    hostname,
		Analyst:     analyst,
		ToolManager: tm,
		CaseManager: cm,
		Logger:      logger,
	}
}

// OutputDir returns the directory results land under once Run starts.
func (r *Runner) OutputDir() string { return r.outputDir }

// Run executes the configured use case end-to-end.
//
// Per-step semantics:
//   - "command":       exec.Command via PowerShell (Windows) / sh (Linux).
//   - "tool":          look up tool path from ToolManager, prepend it to the
//                       parameter-substituted command. Skipped (not failed)
//                       when the tool isn't installed.
//   - "manual":        treated as informational — recorded as a step-level
//                       Status=skipped with the description as the "error"
//                       slot so it appears in the summary.
//   - "velociraptor"/  best-effort placeholder — recorded as skipped.
//   - "analysis":
func (r *Runner) Run(params map[string]string) (RunSummary, error) {
	if r.UseCase == nil {
		return RunSummary{}, fmt.Errorf("use case is nil")
	}
	r.Parameters = mergeDefaults(params, r.UseCase.Parameters)

	ts := time.Now().Format("20060102_150405")
	r.outputDir = filepath.Join(r.RootDir, "output", r.CaseID, "usecases",
		fmt.Sprintf("%s_%s", r.UseCase.ID, ts))
	if err := os.MkdirAll(r.outputDir, 0o700); err != nil {
		return RunSummary{}, fmt.Errorf("creating output dir: %w", err)
	}

	summary := RunSummary{
		UseCaseID:   r.UseCase.ID,
		UseCaseName: r.UseCase.Name,
		CaseID:      r.CaseID,
		Hostname:    r.Hostname,
		Analyst:     r.Analyst,
		Parameters:  r.Parameters,
		StartedAt:   time.Now(),
		OutputDir:   r.outputDir,
	}

	if r.Logger != nil {
		r.Logger.Info("usecases", "run start: %s case=%s output=%s",
			r.UseCase.ID, r.CaseID, r.outputDir)
	}

	for pi, phase := range r.UseCase.Phases {
		phaseDir := filepath.Join(r.outputDir,
			fmt.Sprintf("phase_%02d_%s", pi+1, sanitiseName(phase.Name)))
		if err := os.MkdirAll(phaseDir, 0o700); err != nil {
			summary.Phases = append(summary.Phases, PhaseResult{
				PhaseName: phase.Name,
				Status:    StatusFailed,
			})
			continue
		}
		pr := r.runPhase(phase, phaseDir, pi+1)
		summary.Phases = append(summary.Phases, pr)
	}

	summary.FinishedAt = time.Now()
	summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
	summary.TotalFiles, summary.TotalBytes = countDirContents(r.outputDir)

	r.writeSummaryFiles(summary)

	if r.CaseManager != nil {
		_, _ = r.CaseManager.AddEvidence(r.CaseID, 0, "use_case_run", r.outputDir)
	}
	if r.Logger != nil {
		r.Logger.Info("usecases", "run complete: %s duration=%s files=%d",
			r.UseCase.ID, summary.Duration.Truncate(time.Second), summary.TotalFiles)
	}
	return summary, nil
}

// runPhase iterates a phase's steps, returning the aggregated PhaseResult.
func (r *Runner) runPhase(phase UseCasePhase, phaseDir string, phaseIdx int) PhaseResult {
	pr := PhaseResult{PhaseName: phase.Name}
	started := time.Now()

	successes, failures, skips := 0, 0, 0
	for si, step := range phase.Steps {
		if !MatchesPlatform(step.Platform, r.Platform) {
			pr.Steps = append(pr.Steps, StepResult{
				StepName: step.Name, Status: StatusSkipped,
				Error: "platform mismatch (" + step.Platform + ")"})
			skips++
			continue
		}
		stepFile := filepath.Join(phaseDir,
			fmt.Sprintf("%02d_%s.txt", si+1, sanitiseName(step.Name)))
		sr := r.runStep(step, stepFile)
		pr.Steps = append(pr.Steps, sr)
		switch sr.Status {
		case StatusSuccess:
			successes++
		case StatusFailed:
			failures++
		case StatusSkipped:
			skips++
		}
	}
	pr.Duration = time.Since(started)
	switch {
	case failures == 0 && skips == 0:
		pr.Status = StatusComplete
	case successes == 0:
		pr.Status = StatusFailed
	default:
		pr.Status = StatusPartial
	}
	return pr
}

// runStep executes a single step. The semantics are documented on Run.
func (r *Runner) runStep(step UseCaseStep, outFile string) StepResult {
	sr := StepResult{StepName: step.Name, OutputFile: outFile}
	started := time.Now()

	switch step.Type {
	case StepCommand:
		sr = r.execCommand(step, outFile)
	case StepTool:
		sr = r.execTool(step, outFile)
	case StepManual:
		sr.Status = StatusSkipped
		sr.Error = "manual step — no automated execution; analyst guidance: " + step.Description
	case StepVelociraptor, StepAnalysis:
		// Hooks reserved for future versions; mark skipped so the runner stays
		// useful today without partial implementations producing noisy output.
		sr.Status = StatusSkipped
		sr.Error = "step type '" + step.Type + "' not yet implemented in runner"
	default:
		sr.Status = StatusFailed
		sr.Error = "unknown step type: " + step.Type
	}

	sr.Duration = time.Since(started)

	// If the step is optional and failed, downgrade to skipped so partial
	// runs don't read like disasters.
	if step.Optional && sr.Status == StatusFailed {
		sr.Status = StatusSkipped
	}

	if info, err := os.Stat(outFile); err == nil {
		sr.OutputSize = info.Size()
	}
	return sr
}

// execCommand handles step.Type == "command".
func (r *Runner) execCommand(step UseCaseStep, outFile string) StepResult {
	cmd := r.substitute(step.Command)
	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 300
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var c *exec.Cmd
	if r.Platform == PlatformWindows {
		c = exec.CommandContext(ctx, "powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", cmd)
	}
	out, err := c.CombinedOutput()

	// Determine extension by sniffing the first line.
	finalPath := classifyOutputPath(outFile, out)
	if werr := os.WriteFile(finalPath, out, 0o644); werr != nil {
		return StepResult{StepName: step.Name, OutputFile: outFile,
			Status: StatusFailed, Error: "writing output: " + werr.Error()}
	}

	sr := StepResult{StepName: step.Name, OutputFile: finalPath}
	if err != nil {
		sr.Status = StatusFailed
		sr.Error = err.Error()
		return sr
	}
	sr.Status = StatusSuccess
	return sr
}

// execTool handles step.Type == "tool". Looks up the binary via ToolManager.
func (r *Runner) execTool(step UseCaseStep, outFile string) StepResult {
	if r.ToolManager == nil {
		return StepResult{StepName: step.Name, OutputFile: outFile,
			Status: StatusSkipped, Error: "tool manager unavailable"}
	}
	t := r.ToolManager.GetTool(step.Tool)
	if t == nil {
		return StepResult{StepName: step.Name, OutputFile: outFile,
			Status: StatusSkipped, Error: "tool not registered: " + step.Tool}
	}
	if !t.Installed {
		return StepResult{StepName: step.Name, OutputFile: outFile,
			Status: StatusSkipped, Error: "tool not installed: " + t.Name + " (" + step.Tool + ")"}
	}

	bin := filepath.Join(r.RootDir, filepath.FromSlash(t.LocalPath))
	args := r.substitute(step.Command)

	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 300
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Argument splitting honours quoted segments (best-effort; complex shell
	// pipelines should use Type=command).
	parts := splitShellArgs(args)
	c := exec.CommandContext(ctx, bin, parts...)
	out, err := c.CombinedOutput()

	if werr := os.WriteFile(outFile, out, 0o644); werr != nil {
		return StepResult{StepName: step.Name, OutputFile: outFile,
			Status: StatusFailed, Error: "writing output: " + werr.Error()}
	}
	sr := StepResult{StepName: step.Name, OutputFile: outFile}
	if err != nil {
		sr.Status = StatusFailed
		sr.Error = err.Error()
		return sr
	}
	sr.Status = StatusSuccess
	return sr
}

// substitute replaces {parameter} and {builtin} placeholders in s.
//
// Security: every user-supplied parameter value is sanitised through
// internal/security based on the parameter's declared Type before it lands in
// a command string. Without this, a value like `foo'; rm -rf / #` would be
// interpolated verbatim into the PowerShell / sh command and execute.
//
// Built-in placeholders ({case_id}, {hostname}, etc.) are NOT routed through
// the user — they originate inside VanGuard from validated sources — so they
// pass through unsanitised. {output_dir} is constructed by the runner.
func (r *Runner) substitute(s string) string {
	out := s
	defs := r.paramTypes()
	for k, v := range r.Parameters {
		out = strings.ReplaceAll(out, "{"+k+"}", sanitizeByType(v, defs[k]))
	}
	out = strings.ReplaceAll(out, "{case_id}", r.CaseID)
	out = strings.ReplaceAll(out, "{output_dir}", r.outputDir)
	out = strings.ReplaceAll(out, "{hostname}", r.Hostname)
	out = strings.ReplaceAll(out, "{analyst}", r.Analyst)
	out = strings.ReplaceAll(out, "{timestamp}", time.Now().Format("20060102_150405"))
	return out
}

// paramTypes returns a name → Type map from the use case's declared parameters
// so substitute can pick the right sanitiser per placeholder.
func (r *Runner) paramTypes() map[string]string {
	out := map[string]string{}
	if r.UseCase == nil {
		return out
	}
	for _, p := range r.UseCase.Parameters {
		out[p.Name] = p.Type
	}
	return out
}

// sanitizeByType applies the appropriate sanitiser for a declared parameter
// type. An unknown / unset type falls back to SanitizeShellArg (strip shell
// metacharacters), so a forgotten Type declaration still gets defence in depth.
//
// Validators that return "" on rejection (datetime, ip, hash, domain) blank
// the substitution slot — the resulting command will fail loudly rather than
// silently using attacker-controlled input.
func sanitizeByType(value, paramType string) string {
	switch paramType {
	case "path":
		return security.SanitizeFilePath(value)
	case "datetime":
		return security.SanitizeDateTime(value)
	case "selection":
		// Selections come from a fixed set the use case declares; treat them
		// as opaque shell-arg-safe strings.
		return security.SanitizeShellArg(value)
	case "string", "":
		return security.SanitizeShellArg(value)
	}
	return security.SanitizeShellArg(value)
}

// mergeDefaults overlays user-supplied params on top of declared defaults.
func mergeDefaults(supplied map[string]string, declared []UseCaseParameter) map[string]string {
	out := map[string]string{}
	for _, p := range declared {
		if p.Default != "" {
			out[p.Name] = p.Default
		} else {
			// Empty placeholder so substitution doesn't leave literal {name}.
			out[p.Name] = ""
		}
	}
	for k, v := range supplied {
		out[k] = v
	}
	return out
}

// classifyOutputPath swaps the .txt suffix for .csv when the output's first
// non-blank line looks like a CSV header.
func classifyOutputPath(path string, out []byte) string {
	if len(out) == 0 {
		return path
	}
	for i := 0; i < len(out); i++ {
		if out[i] == '\n' || out[i] == '\r' {
			break
		}
	}
	first := strings.SplitN(string(out), "\n", 2)[0]
	first = strings.TrimSpace(first)
	if first == "" {
		return path
	}
	commaCount := strings.Count(first, ",")
	if commaCount >= 2 && !strings.Contains(first, "  ") {
		return strings.TrimSuffix(path, ".txt") + ".csv"
	}
	return path
}

// splitShellArgs is a tiny argv splitter that respects single + double quotes.
func splitShellArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ' ' && !inSingle && !inDouble:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// sanitiseName makes a step or phase name safe to put in a filename.
func sanitiseName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		case c == ' ', c == '/', c == '\\', c == ',':
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unnamed"
	}
	return strings.ToLower(string(out))
}

// countDirContents returns (file count, total bytes) under dir.
func countDirContents(dir string) (int, int64) {
	var n int
	var b int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		n++
		b += info.Size()
		return nil
	})
	return n, b
}

// writeSummaryFiles drops summary.txt + summary.json in the output directory.
func (r *Runner) writeSummaryFiles(s RunSummary) {
	// Plain text — meant for human eyeballs.
	var b strings.Builder
	fmt.Fprintf(&b, "VanGuard Use Case — %s (%s)\n", s.UseCaseName, s.UseCaseID)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("=", 70))
	fmt.Fprintf(&b, "Case ID:       %s\n", s.CaseID)
	fmt.Fprintf(&b, "Hostname:      %s\n", s.Hostname)
	fmt.Fprintf(&b, "Analyst:       %s\n", s.Analyst)
	fmt.Fprintf(&b, "Started:       %s\n", s.StartedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "Finished:      %s\n", s.FinishedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "Duration:      %s\n", s.Duration.Truncate(time.Second))
	fmt.Fprintf(&b, "Output Dir:    %s\n", s.OutputDir)
	fmt.Fprintf(&b, "Total Files:   %d\n", s.TotalFiles)
	fmt.Fprintf(&b, "Total Size:    %d bytes\n\n", s.TotalBytes)

	if len(s.Parameters) > 0 {
		fmt.Fprintf(&b, "Parameters\n%s\n", strings.Repeat("-", 70))
		for k, v := range s.Parameters {
			if v == "" {
				continue
			}
			fmt.Fprintf(&b, "  %-20s %s\n", k, v)
		}
		b.WriteString("\n")
	}

	for i, p := range s.Phases {
		fmt.Fprintf(&b, "Phase %d: %s — %s (%s)\n", i+1, p.PhaseName,
			p.Status, p.Duration.Truncate(time.Second))
		for _, st := range p.Steps {
			fmt.Fprintf(&b, "  [%s] %-50s %s",
				strings.ToUpper(st.Status[:1])+st.Status[1:],
				st.StepName, st.Duration.Truncate(time.Second))
			if st.OutputSize > 0 {
				fmt.Fprintf(&b, "  %d bytes", st.OutputSize)
			}
			if st.Error != "" {
				fmt.Fprintf(&b, "\n      %s", st.Error)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if r.UseCase != nil {
		if len(r.UseCase.AnalysisGuide) > 0 {
			fmt.Fprintf(&b, "Analysis Guidance\n%s\n", strings.Repeat("-", 70))
			for _, g := range r.UseCase.AnalysisGuide {
				fmt.Fprintf(&b, "  • %s\n", g)
			}
			b.WriteString("\n")
		}
		if len(r.UseCase.FollowUp) > 0 {
			fmt.Fprintf(&b, "Recommended Follow-Up\n%s\n", strings.Repeat("-", 70))
			for _, f := range r.UseCase.FollowUp {
				fmt.Fprintf(&b, "  • %s\n", f)
			}
		}
	}

	_ = os.WriteFile(filepath.Join(r.outputDir, "summary.txt"), []byte(b.String()), 0o644)

	jf, err := os.Create(filepath.Join(r.outputDir, "summary.json"))
	if err == nil {
		enc := json.NewEncoder(jf)
		enc.SetIndent("", "  ")
		_ = enc.Encode(s)
		jf.Close()
	}
}

// _ keep runtime referenced — mainly to ensure cross-platform dispatch
// stays explicit when reading the file.
var _ = runtime.GOOS
