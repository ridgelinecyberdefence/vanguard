package hunting

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ScanStatus tracks a scan operation's progress.
type ScanStatus int

const (
	ScanPending ScanStatus = iota
	ScanRunning
	ScanSuccess
	ScanPartial
	ScanFailed
	ScanSkipped
)

func (s ScanStatus) String() string {
	switch s {
	case ScanPending:
		return "pending"
	case ScanRunning:
		return "running"
	case ScanSuccess:
		return "success"
	case ScanPartial:
		return "partial"
	case ScanFailed:
		return "failed"
	case ScanSkipped:
		return "skipped"
	}
	return "unknown"
}

// Finding represents a single detection or anomaly.
type Finding struct {
	Severity string // "critical", "high", "medium", "low", "info"
	Title    string
	Detail   string
	Source   string // tool/operation that found it
	MITRE    string // MITRE ATT&CK technique ID (e.g., T1059)
}

// ScanResult reports the outcome of a single scan or hunt operation.
type ScanResult struct {
	Name     string
	Status   ScanStatus
	Duration time.Duration
	Output   string // path to output file or directory
	Findings []Finding
	Warnings []string
	Lines    int    // number of output lines / detections
	// ToolOutput is the raw stdout+stderr captured from the external tool,
	// truncated for safe transport. Surfaced verbatim in the SPA when a
	// scan fails so the analyst can see the tool's own error message
	// instead of a generic "exit status 2".
	ToolOutput string
}

// maxToolOutputBytes caps how much captured stdout/stderr we hand to the
// frontend. Loki and friends can be chatty (megabytes of "scanned: …"
// lines on a deep walk); the SPA renders this in a <pre> block, so we
// truncate to keep WS payloads + DOM size sensible.
const maxToolOutputBytes = 16 * 1024

// ScanSummary is the final report for a hunting session.
type ScanSummary struct {
	CaseID     string
	Platform   string
	StartedAt  time.Time
	FinishedAt time.Time
	Duration   time.Duration
	OutputDir  string
	Results    []ScanResult
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

// Scanner orchestrates threat hunting and scanning operations.
type Scanner struct {
	Platform    string
	RootDir     string
	CaseID      string
	Elevated    bool
	Logger      *logging.Logger
	ToolManager *tools.ToolManager
}

// NewScanner creates a hunting scanner.
func NewScanner(rootDir, caseID, platform string, elevated bool, logger *logging.Logger, tm *tools.ToolManager) *Scanner {
	return &Scanner{
		Platform:    platform,
		RootDir:     rootDir,
		CaseID:      caseID,
		Elevated:    elevated,
		Logger:      logger,
		ToolManager: tm,
	}
}

// OutputDir returns the hunting output directory for this run.
func (s *Scanner) OutputDir(timestamp string) string {
	return filepath.Join(s.RootDir, "output", s.CaseID, "threat_hunting", timestamp)
}

// ---------------------------------------------------------------------------
// Tool binary helpers
// ---------------------------------------------------------------------------

func (s *Scanner) hayabusaBin() string {
	id := "hayabusa-win"
	if s.Platform == "linux" {
		id = "hayabusa-lnx"
	}
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool(id)
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

func (s *Scanner) chainsawBin() string {
	id := "chainsaw-win"
	if s.Platform == "linux" {
		id = "chainsaw-lnx"
	}
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool(id)
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

func (s *Scanner) lokiBin() string {
	id := "loki-win"
	if s.Platform == "linux" {
		id = "loki-lnx"
	}
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool(id)
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

func (s *Scanner) yaraRulesDir() string {
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool("yara-rules")
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

func (s *Scanner) sigmaRulesDir() string {
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool("sigma-rules")
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

func (s *Scanner) hayabusaRulesDir() string {
	if s.ToolManager == nil {
		return ""
	}
	t := s.ToolManager.GetTool("hayabusa-rules")
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(s.RootDir, t.LocalPath)
}

// ToolAvailable checks whether a tool is installed.
func (s *Scanner) ToolAvailable(toolID string) bool {
	if s.ToolManager == nil {
		return false
	}
	t := s.ToolManager.GetTool(toolID)
	return t != nil && t.Installed
}

// ---------------------------------------------------------------------------
// Tool-based scans
// ---------------------------------------------------------------------------

// RunHayabusa executes a Hayabusa scan with the given mode.
// Modes: "full", "critical", "lateral", "persist", "timeline".
//
// `--no-wizard` is required: without it, Hayabusa 2.x prompts on stdin for
// "Update rules now?" and hangs indefinitely when invoked from a non-TTY
// caller (the symptom is "0 second scans with empty output"). cmd.Dir is
// set to the binary's directory so Hayabusa can resolve its bundled
// `rules/` tree when no `-r` override is provided.
func (s *Scanner) RunHayabusa(parentCtx context.Context, mode, targetDir, outDir string) ScanResult {
	name := "Hayabusa — " + mode
	bin := s.hayabusaBin()
	if bin == "" {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{"Hayabusa binary not found"}}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	// Hayabusa resolves rules/ and config/ relative to its own directory.
	// A missing rules/ dir means the archive wasn't fully extracted or the
	// post-install update-rules hook didn't run — surface the cause rather
	// than letting Hayabusa exit silently with no output.
	hayabusaDir := filepath.Dir(bin)
	if _, err := os.Stat(filepath.Join(hayabusaDir, "rules")); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{
			"Hayabusa rules directory not found — run 'hayabusa update-rules' or re-download via Configuration > Download Required Tools",
		}}
	}

	// Pre-flight the target directory. Hayabusa exits cleanly with no
	// output when handed a directory that holds no .evtx files, which
	// looks identical to "scan ran but found nothing" — surface the real
	// reason instead. The check also logs the file count so the analyst
	// can see in the log whether the scan actually had data to chew on.
	if err := s.preflightEvtxDir(targetDir, "Hayabusa"); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{err.Error()}}
	}

	outFile := filepath.Join(outDir, fmt.Sprintf("hayabusa_%s.csv", mode))

	args := []string{
		"csv-timeline",
		"-d", targetDir,
		"-o", outFile,
		"--no-wizard",
		"--no-color",
		"--UTC",
		"-q",
	}

	switch mode {
	case "critical":
		args = append(args, "-m", "critical", "-m", "high")
	case "lateral":
		args = append(args, "-m", "medium", "--include-tag", "lateral-movement")
	case "persist":
		args = append(args, "-m", "medium", "--include-tag", "persistence")
	case "timeline":
		args = append(args, "-m", "low")
	}

	// Hayabusa 3.x looks for `rules/` and `config/` relative to its own
	// argv[0], shipped inside the release archive (and refreshed via
	// `hayabusa update-rules` post-install). Passing `-r` to point at
	// VanGuard's separate rules/hayabusa/ tree breaks 3.x because it
	// validates the layout against the bundled config.json — which only
	// exists alongside the binary. runScannerTool already pins
	// cmd.Dir = filepath.Dir(bin) so the bundled assets resolve.

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	start := time.Now()
	result := s.runScannerTool(ctx, bin, args, outFile)
	result.Name = name
	result.Duration = time.Since(start)
	result.Output = outFile

	// Count output lines as detection count.
	if data, err := os.ReadFile(outFile); err == nil {
		lines := strings.Split(string(data), "\n")
		result.Lines = len(lines) - 1 // subtract header
		if result.Lines < 0 {
			result.Lines = 0
		}
		if result.Lines > 0 && result.Status == ScanSuccess {
			result.Findings = append(result.Findings, Finding{
				Severity: "info",
				Title:    fmt.Sprintf("Hayabusa detected %d events (%s mode)", result.Lines, mode),
				Source:   "hayabusa",
			})
		}
	}

	// If the tool ran (no exec error) but the output file is missing or
	// empty, the scan effectively failed silently. Mark partial and attach
	// the captured stdout/stderr so the analyst can see why.
	if info, statErr := os.Stat(outFile); statErr != nil || info.Size() == 0 {
		if result.Status == ScanSuccess {
			result.Status = ScanPartial
		}
		result.Warnings = append(result.Warnings,
			"output file is empty or missing — Hayabusa produced no detections")
	}

	return result
}

// RunChainsaw executes a Chainsaw hunt against the target directory.
//
// Chainsaw's CLI changed across versions: v1 used --rules / --sigma, v2+ uses
// -s with an explicit --mapping file. We try variants in descending modernity
// order and return the first one that produces output (or aggregate stderr
// from every attempt when all fail).
func (s *Scanner) RunChainsaw(parentCtx context.Context, targetDir, outDir string) ScanResult {
	name := "Chainsaw Hunt"
	bin := s.chainsawBin()
	if bin == "" {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{"Chainsaw binary not found — install via Configuration > Download Required Tools."}}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	if err := s.preflightEvtxDir(targetDir, "Chainsaw"); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{err.Error()}}
	}

	sigmaDir := s.sigmaRulesDir()
	mapping := findChainsawMapping(bin)
	outFile := filepath.Join(outDir, "chainsaw_hunt.csv")

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	start := time.Now()
	result := s.tryChainsawInvocations(ctx, bin, targetDir, outFile, sigmaDir, mapping)
	result.Name = name
	result.Duration = time.Since(start)
	result.Output = outFile

	// Surface "ran but produced nothing" the same way as Hayabusa.
	if info, statErr := os.Stat(outFile); statErr != nil || info.Size() == 0 {
		if result.Status == ScanSuccess {
			result.Status = ScanPartial
		}
		result.Warnings = append(result.Warnings,
			"output file is empty or missing — Chainsaw produced no detections")
	}
	return result
}

// preflightEvtxDir validates that targetDir exists and contains at least
// one .evtx file, then logs the file count. Used by every event-log scanner
// (Hayabusa, Chainsaw, Sigma) to give a fast, attributable error before we
// fork an external tool whose own "no logs found" exit codes are noisy and
// inconsistent across versions.
//
// scannerLabel is folded into the error message so the user knows which
// scanner pre-flight failed when they run several back-to-back.
func (s *Scanner) preflightEvtxDir(targetDir, scannerLabel string) error {
	info, err := os.Stat(targetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("event log directory not found: %s", targetDir)
		}
		return fmt.Errorf("stat %s: %w", targetDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", targetDir)
	}
	count := countEvtxFiles(targetDir)
	if count == 0 {
		return fmt.Errorf(
			"no .evtx files found in %s — run Quick Triage first or "+
				"point %s at C:\\Windows\\System32\\winevt\\Logs",
			targetDir, scannerLabel)
	}
	if s.Logger != nil {
		s.Logger.Info("hunt",
			"%s pre-flight: %d .evtx files in %s", scannerLabel, count, targetDir)
	}
	return nil
}

// countEvtxFiles returns the number of .evtx files in dir and its immediate
// subdirectories. Counts only — for scanner pre-flight, not parsing.
func countEvtxFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".evtx") {
			count++
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, se := range sub {
			if !se.IsDir() && strings.EqualFold(filepath.Ext(se.Name()), ".evtx") {
				count++
			}
		}
	}
	return count
}

// dirContainsExt reports whether dir (or any subdirectory, one level deep)
// holds at least one file with the given extension. Case-insensitive.
func dirContainsExt(dir, ext string) bool {
	ext = strings.ToLower(ext)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.ToLower(filepath.Ext(e.Name())) == ext {
			return true
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, se := range sub {
			if !se.IsDir() && strings.ToLower(filepath.Ext(se.Name())) == ext {
				return true
			}
		}
	}
	return false
}

// findChainsawMapping locates the bundled sigma-event-logs mapping YAML that
// Chainsaw v2+ requires when scanning Sigma rules. Returns "" if none found.
func findChainsawMapping(chainsawBin string) string {
	chainsawDir := filepath.Dir(chainsawBin)
	candidates := []string{
		filepath.Join(chainsawDir, "mappings", "sigma-event-logs-all.yml"),
		filepath.Join(chainsawDir, "mappings", "sigma-event-logs-all.yaml"),
		filepath.Join(chainsawDir, "mappings", "sigma-event-logs.yml"),
		filepath.Join(chainsawDir, "sigma-event-logs-all.yml"),
		filepath.Join(chainsawDir, "sigma-event-logs.yml"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	// Walk one level deep — handles `chainsaw-v2.x/mappings/...` layouts left
	// behind by archive extraction.
	entries, err := os.ReadDir(chainsawDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(chainsawDir, e.Name())
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, se := range subEntries {
			lname := strings.ToLower(se.Name())
			if strings.Contains(lname, "sigma-event-logs") &&
				(strings.HasSuffix(lname, ".yml") || strings.HasSuffix(lname, ".yaml")) {
				return filepath.Join(sub, se.Name())
			}
		}
		// "mappings" dir is a strong hint.
		if strings.EqualFold(e.Name(), "mappings") {
			for _, se := range subEntries {
				lname := strings.ToLower(se.Name())
				if strings.HasSuffix(lname, ".yml") || strings.HasSuffix(lname, ".yaml") {
					return filepath.Join(sub, se.Name())
				}
			}
		}
	}
	return ""
}

// tryChainsawInvocations runs Chainsaw against targetDir using a series of
// flag patterns spanning v1 → v2+. Returns the first invocation that exits
// cleanly OR exits non-zero with output (Chainsaw uses 1 for "found
// detections", which is success). Aggregates stderr from every failed
// attempt into the warnings so the user sees what actually broke.
//
// Each invocation pins cmd.Dir to the chainsaw binary's directory so it can
// resolve its bundled mappings/rules tree relative to argv[0] when no
// explicit override is on the command line.
func (s *Scanner) tryChainsawInvocations(ctx context.Context, bin, targetDir, outFile, sigmaDir, mapping string) ScanResult {
	type variant struct {
		label string
		args  []string
	}
	var variants []variant

	// Bundled rules + mappings shipped inside the Chainsaw release archive
	// take precedence: Chainsaw v2 validates Sigma input against its own
	// mapping schema and rejects rule trees that don't match. The release
	// archive ships a known-compatible pair (rules/, mappings/) so we use
	// those before reaching for VanGuard's external rules/sigma/.
	//
	// CSV variants are tried first (Chainsaw v2.x --csv flag); if the binary
	// doesn't support --csv they exit non-zero and the non-CSV fallbacks run.
	binDir := filepath.Dir(bin)
	bundledRules := filepath.Join(binDir, "rules")
	bundledSigma := filepath.Join(binDir, "rules", "sigma")
	bundledMapping := findChainsawMapping(bin) // already walks bin's dir
	if dirExists(bundledSigma) && bundledMapping != "" {
		variants = append(variants, variant{
			label: "bundled (sigma + mapping, csv)",
			args: []string{"hunt", targetDir,
				"-s", bundledSigma,
				"--mapping", bundledMapping,
				"--csv",
				"--output", outFile},
		})
		variants = append(variants, variant{
			label: "bundled (sigma + mapping)",
			args: []string{"hunt", targetDir,
				"-s", bundledSigma,
				"--mapping", bundledMapping,
				"--output", outFile},
		})
	}
	if dirExists(bundledRules) {
		variants = append(variants, variant{
			label: "bundled (rules, csv)",
			args: []string{"hunt", targetDir,
				"--rules", bundledRules,
				"--csv",
				"--output", outFile},
		})
		variants = append(variants, variant{
			label: "bundled (rules)",
			args: []string{"hunt", targetDir,
				"--rules", bundledRules,
				"--output", outFile},
		})
	}

	// Fallbacks — VanGuard's external rules/sigma/ tree, then the
	// no-rules default. Useful when the analyst has overridden the
	// shipped rules with their own pack.
	if sigmaDir != "" && mapping != "" {
		variants = append(variants, variant{
			label: "external (-s + --mapping, csv)",
			args:  []string{"hunt", targetDir, "-s", sigmaDir, "--mapping", mapping, "--csv", "--output", outFile},
		})
		variants = append(variants, variant{
			label: "external (-s + --mapping)",
			args:  []string{"hunt", targetDir, "-s", sigmaDir, "--mapping", mapping, "--output", outFile},
		})
	}
	if sigmaDir != "" {
		variants = append(variants, variant{
			label: "external (-s, csv)",
			args:  []string{"hunt", targetDir, "-s", sigmaDir, "--csv", "--output", outFile},
		})
		variants = append(variants, variant{
			label: "external (-s)",
			args:  []string{"hunt", targetDir, "-s", sigmaDir, "--output", outFile},
		})
		variants = append(variants, variant{
			label: "v1 (--rules + --sigma)",
			args:  []string{"hunt", targetDir, "--rules", sigmaDir, "--sigma", sigmaDir, "--output", outFile},
		})
	}
	// Final fallback: hunt without rules — relies on Chainsaw's built-in detections.
	variants = append(variants, variant{
		label: "default (csv)",
		args:  []string{"hunt", targetDir, "--csv", "--output", outFile},
	})
	variants = append(variants, variant{
		label: "default (no rules)",
		args:  []string{"hunt", targetDir, "--output", outFile},
	})

	var attempts []string
	var lastOut string
	for _, v := range variants {
		select {
		case <-ctx.Done():
			return ScanResult{Status: ScanFailed,
				ToolOutput: lastOut,
				Warnings:   append(attempts, "scan timed out before any invocation succeeded")}
		default:
		}
		if s.Logger != nil {
			s.Logger.Info("hunt", "exec: %s %s (cwd=%s)", bin,
				strings.Join(v.args, " "), binDir)
		}
		start := time.Now()
		out, err := runCmdCaptureIn(ctx, binDir, bin, v.args...)
		dur := time.Since(start)
		lastOut = out
		if s.Logger != nil {
			outSize := int64(0)
			if info, statErr := os.Stat(outFile); statErr == nil {
				outSize = info.Size()
			}
			s.Logger.Info("hunt",
				"chainsaw %s completed in %s, stdout=%d bytes, output_file=%d bytes, exit=%v",
				v.label, dur, len(out), outSize, err)
		}
		if err == nil {
			// Clean exit. Chainsaw's stdout/stderr noise is irrelevant on success.
			r := ScanResult{Status: ScanSuccess, ToolOutput: truncateToolOutput([]byte(out))}
			if len(out) > 0 {
				r.Lines = strings.Count(out, "\n")
			}
			return r
		}
		// Exit code 1 = found detections (treat as partial-success). Anything
		// else = real failure — record stderr and try the next pattern.
		if exitCode(err) == 1 && len(out) > 0 {
			r := ScanResult{Status: ScanPartial, Lines: strings.Count(out, "\n"),
				ToolOutput: truncateToolOutput([]byte(out))}
			r.Warnings = append(r.Warnings, "chainsaw reported detections (exit 1)")
			return r
		}
		first := firstLine(out)
		attempts = append(attempts,
			fmt.Sprintf("Chainsaw %s failed (%s): %s", v.label, exitSummary(err), first))
	}

	return ScanResult{
		Status:     ScanFailed,
		ToolOutput: truncateToolOutput([]byte(lastOut)),
		Warnings:   attempts,
	}
}

// runCmdCaptureIn runs cmd with cwd=dir and returns combined stdout+stderr
// plus the error. Cwd matters for tools that resolve bundled assets relative
// to argv[0] (Chainsaw v2 mappings, Hayabusa rules).
func runCmdCaptureIn(ctx context.Context, dir, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// exitCode extracts the numeric exit code from an *exec.ExitError, or -1 if
// the error wasn't a process exit (timeout, fork failure, etc.).
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// exitSummary returns a short representation of an exec error suitable for
// embedding in a user-facing warning. Hides the noisy "exit status " prefix.
func exitSummary(err error) string {
	if err == nil {
		return "ok"
	}
	return strings.TrimPrefix(err.Error(), "exit status ")
}

// firstLine returns the first non-empty line of s, trimmed. Used to surface
// the most relevant line of stderr when a tool fails verbosely.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 200 {
			line = line[:200] + "..."
		}
		return line
	}
	return ""
}

// RunLoki executes a Loki IOC scan.
//
// loki-rs v2.x uses --folder (not --path) and requires --no-tui to
// suppress the interactive terminal UI when running programmatically.
func (s *Scanner) RunLoki(parentCtx context.Context, targetDir, outDir string) ScanResult {
	name := "Loki IOC Scan"
	bin := s.lokiBin()
	if bin == "" {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{"Loki binary not found"}}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	outFile := filepath.Join(outDir, "loki_scan.log")
	helpStr := probeHelp(bin)

	args := []string{"--folder", targetDir, "--no-tui"}
	// Log-output flag: loki-rs uses --logfolder; some builds use -l or -o.
	switch {
	case strings.Contains(helpStr, "--logfolder"):
		args = append(args, "--logfolder", outDir)
	case strings.Contains(helpStr, "-l "):
		args = append(args, "-l", outFile)
	case strings.Contains(helpStr, "--output") || strings.Contains(helpStr, " -o "):
		args = append(args, "-o", outFile)
	}

	ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
	defer cancel()

	start := time.Now()
	result := s.runScannerTool(ctx, bin, args, outFile)
	result.Name = name
	result.Duration = time.Since(start)
	result.Output = outFile

	// Loki often writes its log next to the binary (loki.log) instead of
	// the path we requested. Persist the captured stdout so the analyst
	// always has something to open via the output_file link.
	if !fileExistsAndNonEmpty(outFile) && result.ToolOutput != "" {
		_ = os.WriteFile(outFile, []byte(result.ToolOutput), 0o644)
	}
	return result
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// fileExistsAndNonEmpty reports whether path is a regular file with
// at least one byte. Avoids "ran but produced nothing" false positives
// where a tool exits 0 but didn't actually write to its output file.
func fileExistsAndNonEmpty(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// probeHelp runs `<bin> --help` with a 5-second cap and returns the
// captured output. Errors are swallowed — an empty string just means we
// fall through to the default invocation.
func probeHelp(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--help")
	cmd.Dir = filepath.Dir(bin)
	out, _ := cmd.CombinedOutput()
	return string(out)
}

// RunYARA executes a YARA rule scan on the target directory.
//
// scanType is "custom" or "all":
//   - "custom" — only rules under rules/yara/custom/.
//   - "all"    — every .yar/.yara file in rules/yara/ (recursive).
//
// Two scanning engines are supported. We prefer Loki (it carries a built-in
// YARA engine and matches our existing IOC tooling), falling back to a
// standalone `yara` / `yara.exe` binary placed under bin/<platform>/.
// Either path captures the tool's stdout/stderr verbatim into ToolOutput so
// the SPA can show the analyst exactly what failed.
func (s *Scanner) RunYARA(parentCtx context.Context, scanType, targetDir, outDir string) ScanResult {
	name := "YARA Scan (" + scanType + ")"
	baseRules := s.yaraRulesDir()
	if baseRules == "" {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{"YARA rules not installed — download via Update page"}}
	}
	rulesDir := baseRules
	if scanType == "custom" {
		rulesDir = filepath.Join(baseRules, "custom")
	}
	if !dirHasFiles(rulesDir) {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{
			fmt.Sprintf("no YARA rule files in %s", rulesDir),
		}}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}
	outFile := filepath.Join(outDir, "yara_scan.txt")

	// Engine 1 — Loki. loki-rs v2.x uses --folder and --no-tui.
	// Loki-RS loads its bundled signature set automatically; no external YARA
	// path flag is needed or accepted.
	if bin := s.lokiBin(); bin != "" {
		helpStr := probeHelp(bin)
		args := []string{"--folder", targetDir, "--no-tui"}
		if strings.Contains(helpStr, "--logfolder") {
			args = append(args, "--logfolder", outDir)
		} else if strings.Contains(helpStr, "--output") || strings.Contains(helpStr, " -o ") {
			args = append(args, "-o", outFile)
		}

		ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()

		start := time.Now()
		result := s.runScannerTool(ctx, bin, args, outFile)
		result.Name = name
		result.Duration = time.Since(start)
		result.Output = outFile
		// Persist captured output if Loki didn't write the requested file.
		if !fileExistsAndNonEmpty(outFile) && result.ToolOutput != "" {
			_ = os.WriteFile(outFile, []byte(result.ToolOutput), 0o644)
		}
		return result
	}

	// Engine 2 — standalone yara binary. Walk rules/yara/ for .yar/.yara
	// files and run yara once per file, concatenating stdout. Less
	// efficient than a compiled rule pack, but doesn't require the
	// analyst to keep a .yarc bundle in sync with the rule sources.
	yaraBin := findStandaloneYARA(s.RootDir, s.Platform)
	if yaraBin == "" {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{
			"no YARA scanning engine available — install Loki via Configuration > " +
				"Download Required Tools, or place a yara binary under bin/" + s.Platform,
		}}
	}

	var ruleFiles []string
	_ = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		if ext == ".yar" || ext == ".yara" {
			ruleFiles = append(ruleFiles, path)
		}
		return nil
	})
	if len(ruleFiles) == 0 {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{
			fmt.Sprintf("no .yar / .yara files under %s", rulesDir),
		}}
	}

	ctx, cancel := context.WithTimeout(parentCtx, 30*time.Minute)
	defer cancel()

	start := time.Now()
	var allOut strings.Builder
	failures := 0
	for _, rule := range ruleFiles {
		select {
		case <-ctx.Done():
			break
		default:
		}
		out, err := runCmdCaptureIn(ctx, filepath.Dir(yaraBin),
			yaraBin, "-r", rule, targetDir)
		allOut.WriteString(out)
		if err != nil {
			failures++
		}
	}
	dur := time.Since(start)

	combined := allOut.String()
	_ = os.WriteFile(outFile, []byte(combined), 0o644)

	status := ScanSuccess
	var warnings []string
	if failures > 0 {
		status = ScanPartial
		warnings = append(warnings, fmt.Sprintf("%d / %d rule files exited non-zero",
			failures, len(ruleFiles)))
	}
	return ScanResult{
		Name:       name,
		Status:     status,
		Duration:   dur,
		Output:     outFile,
		Lines:      strings.Count(combined, "\n"),
		Warnings:   warnings,
		ToolOutput: truncateToolOutput([]byte(combined)),
	}
}

// findStandaloneYARA searches bin/<platform>/ for a YARA binary. Returns
// "" if no candidate exists. Looks for the common Windows / Linux
// executable names across releases.
func findStandaloneYARA(rootDir, platform string) string {
	candidates := []string{"yara.exe", "yara64.exe", "yara"}
	for _, name := range candidates {
		p := filepath.Join(rootDir, "bin", platform, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// dirHasFiles returns true if dir contains at least one regular file at
// the top level or one directory level deep. Used as a pre-flight before
// invoking a tool that expects a populated rules tree.
func dirHasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub, err := os.ReadDir(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		for _, se := range sub {
			if !se.IsDir() {
				return true
			}
		}
	}
	return false
}

// RunSigma executes a Sigma rule detection using Chainsaw. Shares the
// multi-variant invocation strategy with RunChainsaw — the only difference
// is we refuse to run when no Sigma rules are available.
func (s *Scanner) RunSigma(parentCtx context.Context, targetDir, outDir string) ScanResult {
	name := "Sigma Detection"
	bin := s.chainsawBin()
	if bin == "" {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{"Chainsaw binary not found (required for Sigma rule scanning)."}}
	}

	sigmaDir := s.sigmaRulesDir()
	if sigmaDir == "" {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{
				"Sigma rules not found in rules/sigma/.",
				"Download via Configuration > Download Required Tools, or place rules manually."}}
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ScanResult{Name: name, Status: ScanFailed,
			Warnings: []string{fmt.Sprintf("mkdir: %v", err)}}
	}

	if err := s.preflightEvtxDir(targetDir, "Sigma"); err != nil {
		return ScanResult{Name: name, Status: ScanFailed, Warnings: []string{err.Error()}}
	}

	mapping := findChainsawMapping(bin)
	outFile := filepath.Join(outDir, "sigma_detection.txt")

	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer cancel()

	start := time.Now()
	result := s.tryChainsawInvocations(ctx, bin, targetDir, outFile, sigmaDir, mapping)
	result.Name = name
	result.Duration = time.Since(start)
	result.Output = outFile
	if info, statErr := os.Stat(outFile); statErr != nil || info.Size() == 0 {
		if result.Status == ScanSuccess {
			result.Status = ScanPartial
		}
		result.Warnings = append(result.Warnings,
			"output file is empty or missing — Sigma scan produced no detections")
	}
	return result
}

// ---------------------------------------------------------------------------
// Execution helpers
// ---------------------------------------------------------------------------

// runScannerTool is the shared external-tool runner for the scanner. It
// blocks on cmd.CombinedOutput() until completion (no fire-and-forget) and
// pins cmd.Dir to the tool's own directory — many tools (Chainsaw, Hayabusa,
// Loki) resolve their bundled rules/mappings relative to argv[0]'s parent
// when no explicit override is on the command line.
//
// outFile is informational: it's used for log output ("wrote N bytes to
// <path>") and isn't required to exist.
func (s *Scanner) runScannerTool(ctx context.Context, bin string, args []string, outFile string) ScanResult {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(bin)

	if s.Logger != nil {
		s.Logger.Info("hunt", "exec: %s %s (cwd=%s)",
			bin, strings.Join(args, " "), cmd.Dir)
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	dur := time.Since(start)

	result := ScanResult{Status: ScanSuccess}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Status = ScanFailed
			result.Warnings = append(result.Warnings, "scan timed out")
		} else {
			// Many tools return non-zero when they find detections.
			result.Status = ScanPartial
			result.Warnings = append(result.Warnings, fmt.Sprintf("exit: %v", err))
		}
	}

	if s.Logger != nil {
		outSize := int64(0)
		if outFile != "" {
			if info, statErr := os.Stat(outFile); statErr == nil {
				outSize = info.Size()
			}
		}
		s.Logger.Info("hunt",
			"completed in %s, stdout=%d bytes, output_file=%s (%d bytes), exit=%v",
			dur, len(out), outFile, outSize, err)
	}

	// Surface the tool's own stdout/stderr to the caller — without this
	// the SPA can only show "exit status 2" with no clue what actually
	// failed (wrong flag, missing rules dir, locked file, etc.).
	result.ToolOutput = truncateToolOutput(out)

	return result
}

// truncateToolOutput collapses an arbitrary tool capture to at most
// maxToolOutputBytes, with a "[truncated …]" footer so the analyst knows
// they're looking at a tail rather than the full output.
func truncateToolOutput(out []byte) string {
	if len(out) <= maxToolOutputBytes {
		return string(out)
	}
	// Keep the tail — the most recent output is usually the most
	// diagnostic (final error line, summary). 200-byte head also kept so
	// the analyst sees how the run started.
	const headBytes = 200
	tail := maxToolOutputBytes - headBytes
	return string(out[:headBytes]) +
		fmt.Sprintf("\n\n[... %d bytes truncated ...]\n\n", len(out)-maxToolOutputBytes) +
		string(out[len(out)-tail:])
}

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

	return string(out), err
}

func runPS(ctx context.Context, outFile, psCommand string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCommand)
	out, err := cmd.CombinedOutput()

	if outFile != "" && len(out) > 0 {
		_ = os.WriteFile(outFile, out, 0o644)
	}

	return string(out), err
}

func runCommand(ctx context.Context, outFile, cmdName string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)
	out, err := cmd.CombinedOutput()

	if outFile != "" && len(out) > 0 {
		_ = os.WriteFile(outFile, out, 0o644)
	}

	return string(out), err
}

// FormatBytesPublic formats a byte count for display.
func FormatBytesPublic(b int64) string {
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
