package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/hunting"
	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// huntRunState tracks a single in-flight or most-recent scan, mirroring the
// triage handler's pattern. Only one log/IOC scan runs at a time.
type huntRunState struct {
	mu        sync.Mutex
	running   bool
	scanType  string
	startedAt time.Time
	last      *hunting.ScanResult
}

var huntState huntRunState

// handleHuntRun — POST /api/hunt/run.
//
// Body: {scan_type, target, custom_path?}
//
//	scan_type: hayabusa_full | hayabusa_critical | hayabusa_lateral |
//	           hayabusa_persistence | hayabusa_timeline |
//	           chainsaw_hunt | chainsaw_sigma |
//	           loki_scan | yara_custom | yara_all
//	target:    live | collected | custom
//	custom_path: required when target=custom
//
// Returns 202 + {status:"started"} immediately. Progress + completion
// stream over the WebSocket as hunt_progress / hunt_complete events.
func handleHuntRun(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	if ctx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	var req struct {
		ScanType   string `json:"scan_type"`
		Target     string `json:"target"`
		CustomPath string `json:"custom_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ScanType == "" {
		writeError(w, http.StatusBadRequest, "scan_type is required")
		return
	}
	if req.Target == "" {
		req.Target = "collected"
	}

	huntState.mu.Lock()
	if huntState.running {
		huntState.mu.Unlock()
		writeError(w, http.StatusConflict,
			"a scan is already in progress — wait for it to finish")
		return
	}
	huntState.running = true
	huntState.scanType = req.ScanType
	huntState.startedAt = time.Now()
	huntState.last = nil
	huntState.mu.Unlock()

	scanner := hunting.NewScanner(
		ctx.RootDir, ctx.ActiveCase.ID, ctx.Platform,
		ctx.Elevated, ctx.Logger, ctx.ToolManager)

	targetDir, err := resolveHuntTarget(req.Target, req.CustomPath, ctx.RootDir, ctx.ActiveCase.ID, ctx.Platform)
	if err != nil {
		clearHuntRunning()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ts := time.Now().Format("20060102_150405")
	outDir := scanner.OutputDir(ts)
	if mkErr := os.MkdirAll(outDir, 0o700); mkErr != nil {
		clearHuntRunning()
		writeError(w, http.StatusInternalServerError, "creating output dir: "+mkErr.Error())
		return
	}

	// Register a cancellable task so the SPA's floating cancel bar can
	// stop the scan mid-flight. The task's ctx is threaded into every
	// scanner call below so a cancel propagates to the running tool
	// process via exec.CommandContext.
	taskID, taskCtx, _ := StartTask(prettyScanName(req.ScanType))

	go runHuntInGoroutine(taskCtx, taskID, scanner, req.ScanType, targetDir, outDir, ctx.ActiveCase.ID)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "started",
		"scan":       prettyScanName(req.ScanType),
		"target":     targetDir,
		"output_dir": outDir,
		"task_id":    taskID,
	})
}

func clearHuntRunning() {
	huntState.mu.Lock()
	huntState.running = false
	huntState.mu.Unlock()
}

// resolveHuntTarget converts a {target, custom_path} pair into the directory
// the scanner should walk. The "live" target points at the OS event-log
// store; "collected" walks back through the case's triage subtree to the
// most recent eventlogs/ directory.
func resolveHuntTarget(target, customPath, rootDir, caseID, platform string) (string, error) {
	switch target {
	case "live", "":
		if platform == "windows" {
			return `C:\Windows\System32\winevt\Logs`, nil
		}
		return "/var/log", nil
	case "custom":
		if customPath == "" {
			return "", badRequest("custom_path is required when target=custom")
		}
		if info, err := os.Stat(customPath); err != nil || !info.IsDir() {
			return "", badRequest("custom_path is not a readable directory: " + customPath)
		}
		return customPath, nil
	case "collected":
		// Look for the most recent triage run with event logs.
		triageBase := filepath.Join(rootDir, "output", caseID, "triage")
		entries, err := os.ReadDir(triageBase)
		if err != nil {
			return "", badRequest("no collected artifacts under " + triageBase + " — run Quick Triage first")
		}
		// Sort newest first by name (timestamps sort lexicographically).
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, n := range names {
			candidate := filepath.Join(triageBase, n, "eventlogs")
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate, nil
			}
		}
		return "", badRequest("no eventlogs/ subdirectory found in any collected triage run")
	}
	return "", badRequest("unknown target: " + target)
}

// runHuntInGoroutine invokes the scanner method matching scanType and emits
// progress + completion events. Each scan_type maps to one of Hayabusa's
// modes, Chainsaw hunt/sigma, Loki, or YARA.
func runHuntInGoroutine(taskCtx context.Context, taskID string, s *hunting.Scanner, scanType, targetDir, outDir, caseID string) {
	defer clearHuntRunning()

	scanName := prettyScanName(scanType)
	broadcastProgress("hunt_progress", map[string]interface{}{
		"scan":     scanName,
		"status":   "running",
		"progress": "Starting " + scanName + "...",
	})

	started := time.Now()
	var result hunting.ScanResult
	switch scanType {
	case "hayabusa_full":
		result = runHayabusaScan(taskCtx, "full", targetDir, outDir)
	case "hayabusa_critical":
		result = runHayabusaScan(taskCtx, "critical", targetDir, outDir)
	case "hayabusa_lateral":
		result = runHayabusaScan(taskCtx, "lateral", targetDir, outDir)
	case "hayabusa_persistence":
		result = runHayabusaScan(taskCtx, "persist", targetDir, outDir)
	case "hayabusa_timeline":
		result = runHayabusaScan(taskCtx, "timeline", targetDir, outDir)
	case "chainsaw_hunt":
		result = s.RunChainsaw(taskCtx, targetDir, outDir)
	case "chainsaw_sigma":
		result = s.RunSigma(taskCtx, targetDir, outDir)
	case "loki_scan":
		result = runLokiScan(taskCtx, targetDir, outDir)
	case "yara_custom":
		result = runYARAScan(taskCtx, "custom", targetDir, outDir)
	case "yara_all":
		result = runYARAScan(taskCtx, "all", targetDir, outDir)
	default:
		CompleteTask(taskID, "failed")
		broadcastProgress("hunt_complete", map[string]interface{}{
			"scan":     scanName,
			"duration": int(time.Since(started).Seconds()),
			"status":   "failed",
			"error":    "unknown scan_type: " + scanType,
		})
		return
	}

	// If the task ctx fired (analyst clicked Cancel), report cancelled
	// status so the SPA can render the right outcome instead of a
	// generic "exit status -1" failure.
	if taskCtx.Err() != nil {
		CompleteTask(taskID, "cancelled")
		broadcastProgress("hunt_complete", map[string]interface{}{
			"scan":     scanName,
			"duration": int(time.Since(started).Seconds()),
			"status":   "cancelled",
			"error":    "scan cancelled by user",
		})
		return
	}
	CompleteTask(taskID, "completed")

	huntState.mu.Lock()
	huntState.last = &result
	huntState.mu.Unlock()

	// Register the scan output as evidence on the active case (best-effort —
	// failure here doesn't invalidate the on-disk artifacts).
	if appCtx := getAppCtx(); appCtx != nil && appCtx.CaseManager != nil &&
		appCtx.ActiveCase != nil && appCtx.ActiveCase.ID == caseID && result.Output != "" {
		_, _ = appCtx.CaseManager.AddEvidence(caseID, 0, "threat_hunting", result.Output)
	}

	counts := countFindings(result.Findings)
	// Hayabusa rolls per-rule severity into the CSV directly; tally those too
	// when result.Output points at a CSV.
	if extra, ok := tallyHayabusaCSV(result.Output); ok {
		mergeCounts(counts, extra)
	}

	payload := map[string]interface{}{
		"scan":        scanName,
		"status":      result.Status.String(),
		"duration":    int(result.Duration.Seconds()),
		"findings":    counts,
		"output_file": result.Output,
		"output_size": fileSize(result.Output),
		"lines":       result.Lines,
	}
	if result.ToolOutput != "" {
		payload["tool_output"] = result.ToolOutput
	}
	if len(result.Warnings) > 0 {
		payload["warnings"] = result.Warnings
		if result.Status == hunting.ScanFailed {
			payload["error"] = strings.Join(result.Warnings, "; ")
		}
	}
	broadcastProgress("hunt_complete", payload)
}

// prettyScanName turns a scan_type slug into a title-cased label for display.
func prettyScanName(s string) string {
	r := strings.NewReplacer("_", " ")
	parts := strings.Fields(r.Replace(s))
	for i, p := range parts {
		switch p {
		case "yara":
			parts[i] = "YARA"
		case "loki":
			parts[i] = "Loki"
		case "hayabusa":
			parts[i] = "Hayabusa"
		case "chainsaw":
			parts[i] = "Chainsaw"
		case "ioc":
			parts[i] = "IOC"
		case "sigma":
			parts[i] = "Sigma"
		default:
			if len(p) > 0 {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
	}
	return strings.Join(parts, " ")
}

// countFindings tallies severity buckets for the SPA's stat row.
func countFindings(fs []hunting.Finding) map[string]int {
	out := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range fs {
		sev := strings.ToLower(f.Severity)
		if _, ok := out[sev]; ok {
			out[sev]++
		} else {
			out["info"]++
		}
	}
	return out
}

func mergeCounts(dst, src map[string]int) {
	for k, v := range src {
		dst[k] += v
	}
}

// tallyHayabusaCSV opens a Hayabusa csv-timeline output and counts rows by
// the "Level" column. Returns (nil, false) when the file isn't a Hayabusa
// CSV — every other scanner returns a different shape.
func tallyHayabusaCSV(path string) (map[string]int, bool) {
	if path == "" || !strings.HasSuffix(strings.ToLower(path), ".csv") {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil, false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, false
	}
	header := strings.Split(lines[0], ",")
	levelIdx := -1
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), "Level") {
			levelIdx = i
			break
		}
	}
	if levelIdx < 0 {
		return nil, false
	}
	out := map[string]int{}
	for _, raw := range lines[1:] {
		if raw == "" {
			continue
		}
		fields := strings.Split(raw, ",")
		if levelIdx >= len(fields) {
			continue
		}
		sev := strings.ToLower(strings.Trim(strings.TrimSpace(fields[levelIdx]), "\""))
		switch sev {
		case "crit", "critical":
			out["critical"]++
		case "high":
			out["high"]++
		case "med", "medium":
			out["medium"]++
		case "low":
			out["low"]++
		case "info", "informational":
			out["info"]++
		}
	}
	return out, true
}

func fileSize(p string) int64 {
	if p == "" {
		return 0
	}
	if info, err := os.Stat(p); err == nil {
		return info.Size()
	}
	return 0
}

// huntFileNonEmpty reports whether path is a non-empty regular file.
func huntFileNonEmpty(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// capHuntOutput truncates raw tool stdout/stderr to 16 KB for safe WS transport.
func capHuntOutput(out []byte) string {
	const max = 16 * 1024
	if len(out) <= max {
		return string(out)
	}
	const head = 200
	return string(out[:head]) +
		fmt.Sprintf("\n\n[... %d bytes truncated ...]\n\n", len(out)-max) +
		string(out[len(out)-(max-head):])
}

// huntBinPath returns the absolute path for a tool binary, or "" if not installed.
func huntBinPath(toolID string) string {
	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ToolManager == nil {
		return ""
	}
	t := appCtx.ToolManager.GetTool(toolID)
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(appCtx.RootDir, t.LocalPath)
}

// runHayabusaScan invokes hayabusa csv-timeline directly.
//
// cmd.Dir is pinned to the binary's own directory so Hayabusa resolves its
// bundled rules/ and config/ trees relative to argv[0]. --no-wizard is
// required: without it Hayabusa 2.x prompts stdin and hangs when called
// from a non-TTY process.
func runHayabusaScan(parentCtx context.Context, scanType, evtxDir, outputDir string) hunting.ScanResult {
	name := "Hayabusa — " + scanType
	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ToolManager == nil {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"application context not available"}}
	}

	toolID := "hayabusa-win"
	if appCtx.Platform == "linux" {
		toolID = "hayabusa-lnx"
	}
	bin := huntBinPath(toolID)
	if bin == "" {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"Hayabusa not installed — download via Configuration > Download Required Tools"}}
	}
	hayabusaDir := filepath.Dir(bin)

	if _, err := os.Stat(filepath.Join(hayabusaDir, "rules")); err != nil {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{
				"Hayabusa rules directory not found — run 'hayabusa update-rules' or re-download via Configuration > Download Required Tools",
			}}
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"mkdir: " + err.Error()}}
	}
	outFile := filepath.Join(outputDir, "hayabusa_"+scanType+".csv")

	args := []string{
		"csv-timeline",
		"-d", evtxDir,
		"-o", outFile,
		"--no-wizard",
		"--no-color",
		"--UTC",
		"-q",
	}
	switch scanType {
	case "critical":
		args = append(args, "-m", "critical", "-m", "high")
	case "lateral":
		args = append(args, "-m", "medium", "--include-tag", "lateral-movement")
	case "persist":
		args = append(args, "-m", "medium", "--include-tag", "persistence")
	case "timeline":
		args = append(args, "-m", "low")
	// "full" — no level filter; scan everything
	}

	execCtx, execCancel := context.WithTimeout(parentCtx, 10*time.Minute)
	defer execCancel()

	execRes := appCtx.ToolManager.ExecuteToolContext(execCtx, toolID, args, hayabusaDir)

	result := hunting.ScanResult{
		Name:       name,
		Duration:   execRes.Duration,
		Output:     outFile,
		ToolOutput: capHuntOutput([]byte(execRes.Combined)),
	}
	switch {
	case execCtx.Err() == context.DeadlineExceeded:
		result.Status = hunting.ScanFailed
		result.Warnings = []string{"scan timed out"}
	case execRes.Error != nil:
		result.Status = hunting.ScanPartial
		result.Warnings = []string{fmt.Sprintf("exit: %v", execRes.Error)}
	default:
		result.Status = hunting.ScanSuccess
	}

	if data, readErr := os.ReadFile(outFile); readErr == nil {
		lines := strings.Split(string(data), "\n")
		result.Lines = len(lines) - 1
		if result.Lines < 0 {
			result.Lines = 0
		}
		if result.Lines > 0 {
			result.Findings = append(result.Findings, hunting.Finding{
				Severity: "info",
				Title:    fmt.Sprintf("Hayabusa detected %d events (%s mode)", result.Lines, scanType),
				Source:   "hayabusa",
			})
		}
	}
	if !huntFileNonEmpty(outFile) {
		if result.Status == hunting.ScanSuccess {
			result.Status = hunting.ScanPartial
		}
		result.Warnings = append(result.Warnings,
			"output file is empty or missing — Hayabusa produced no detections")
	}
	return result
}

// runLokiScan invokes loki-rs with --folder and --no-tui.
//
// loki-rs v2.x removed all subcommands and the --path flag; the only
// supported invocation for non-interactive use is:
//
//	loki --folder <dir> --no-tui [--logfolder <dir>]
func runLokiScan(parentCtx context.Context, scanPath, outputDir string) hunting.ScanResult {
	name := "Loki IOC Scan"
	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ToolManager == nil {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"application context not available"}}
	}

	toolID := "loki-win"
	if appCtx.Platform == "linux" {
		toolID = "loki-lnx"
	}
	bin := huntBinPath(toolID)
	if bin == "" {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"Loki not installed — download via Configuration > Download Required Tools"}}
	}

	// Signatures are required — loki-util downloads them on first run.
	// If missing, try loki-util update before failing with a clear message.
	lokiDir := filepath.Dir(bin)
	if _, statErr := os.Stat(filepath.Join(lokiDir, "signatures", "yara")); os.IsNotExist(statErr) {
		var utilPath string
		for _, utilName := range []string{"loki-util.exe", "loki-util"} {
			if p := filepath.Join(lokiDir, utilName); fileExists(p) {
				utilPath = p
				break
			}
		}
		if utilPath != "" {
			if appCtx.Logger != nil {
				appCtx.Logger.Info("hunt", "Loki signatures missing — running loki-util update")
			}
			utilCmd := exec.Command(utilPath, "update")
			utilCmd.Dir = lokiDir
			utilOut, utilErr := utilCmd.CombinedOutput()
			if appCtx.Logger != nil {
				appCtx.Logger.Info("hunt", "loki-util update: err=%v output=%d bytes", utilErr, len(utilOut))
			}
		}
		if _, statErr2 := os.Stat(filepath.Join(lokiDir, "signatures", "yara")); os.IsNotExist(statErr2) {
			return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
				Warnings: []string{
					"Loki signatures not found — run loki-util update from " + lokiDir +
						" or click Update YARA Rules on the Update page",
				}}
		}
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return hunting.ScanResult{Name: name, Status: hunting.ScanFailed,
			Warnings: []string{"mkdir: " + err.Error()}}
	}
	outFile := filepath.Join(outputDir, "loki_scan.log")

	// Probe --help to discover which log-output flag this build accepts.
	// Fall back gracefully: if neither flag appears just omit it and let
	// Loki write loki.log next to its binary, then save captured stdout.
	helpCtx, helpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer helpCancel()
	helpCmd := exec.CommandContext(helpCtx, bin, "--help")
	helpCmd.Dir = filepath.Dir(bin)
	helpOut, _ := helpCmd.CombinedOutput()
	helpStr := string(helpOut)

	args := []string{"--folder", scanPath, "--no-tui"}
	switch {
	case strings.Contains(helpStr, "--logfolder"):
		args = append(args, "--logfolder", outputDir)
	case strings.Contains(helpStr, " -l "):
		args = append(args, "-l", outFile)
	case strings.Contains(helpStr, "--output") || strings.Contains(helpStr, " -o "):
		args = append(args, "-o", outFile)
	}

	execCtx, execCancel := context.WithTimeout(parentCtx, 15*time.Minute)
	defer execCancel()

	execRes := appCtx.ToolManager.ExecuteToolContext(execCtx, toolID, args, "")

	toolOut := capHuntOutput([]byte(execRes.Combined))
	result := hunting.ScanResult{
		Name:       name,
		Duration:   execRes.Duration,
		Output:     outFile,
		ToolOutput: toolOut,
	}
	if execRes.Error != nil {
		result.Status = hunting.ScanPartial
		result.Warnings = []string{fmt.Sprintf("exit: %v", execRes.Error)}
	} else {
		result.Status = hunting.ScanSuccess
	}

	// Loki sometimes writes its log next to the binary instead of the path
	// we requested. Persist captured stdout so the analyst always has output.
	if !huntFileNonEmpty(outFile) && toolOut != "" {
		_ = os.WriteFile(outFile, []byte(toolOut), 0o644)
	}
	return result
}

// runYARAScan uses Loki as the YARA engine (loki-rs carries a built-in YARA
// scanner and loads its bundled signature set automatically).
func runYARAScan(parentCtx context.Context, scanType, scanPath, outputDir string) hunting.ScanResult {
	result := runLokiScan(parentCtx, scanPath, outputDir)
	result.Name = "YARA Scan (" + scanType + ")"
	return result
}

// ============================================================
// Live hunting — synchronous endpoints, JSON only (no WebSocket).
// ============================================================

// handleHuntLive — POST /api/hunt/live. Body: {check: "<id>"}.
// Returns within seconds; no WebSocket plumbing needed because the native
// commands these checks invoke complete fast (process listing, netstat).
//
// Response shape:
//
//	{
//	  "check":      "processes",
//	  "scan":       "Suspicious Processes",
//	  "status":     "success",
//	  "duration":   2,
//	  "total":      0,
//	  "suspicious": <findings.length>,
//	  "findings":   [{severity, detail, process, pid, ...}, ...]
//	}
func handleHuntLive(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}

	var req struct {
		Check string `json:"check"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Check == "" {
		writeError(w, http.StatusBadRequest, "check is required")
		return
	}

	check, ok := liveCheckFor(ctx.Platform, req.Check)
	if !ok {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("unknown live check %q for platform %s", req.Check, ctx.Platform))
		return
	}

	// Live checks write small artifacts to disk. Use a per-run tmp under the
	// case if there is one, otherwise OS temp — avoids polluting the project
	// dir when the analyst hasn't created a case yet.
	outDir := liveOutputDir(ctx.RootDir, req.Check)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}

	runCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result := check(runCtx, outDir, ctx.Logger)

	findings := make([]map[string]interface{}, 0, len(result.Findings))
	for _, f := range result.Findings {
		row := map[string]interface{}{
			"severity": f.Severity,
			"title":    f.Title,
			"detail":   f.Detail,
			"source":   f.Source,
		}
		if f.MITRE != "" {
			row["mitre"] = f.MITRE
		}
		findings = append(findings, row)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"check":      req.Check,
		"scan":       result.Name,
		"status":     result.Status.String(),
		"duration":   int(result.Duration.Seconds()),
		"total":      result.Lines,
		"suspicious": len(findings),
		"findings":   findings,
		"warnings":   result.Warnings,
	})
}

// liveCheckFor returns the live-hunt function matching (platform, check) or
// (nil, false) when the combination isn't supported.
//
// Some check IDs from the SPA (dll_hijack, named_pipes) aren't implemented
// in internal/hunting; those return false here so the SPA gets a clear 400.
func liveCheckFor(platform, check string) (
	func(ctx context.Context, outDir string, logger *logging.Logger) hunting.ScanResult, bool) {

	if platform == "windows" {
		switch check {
		case "processes":
			return hunting.WinSuspiciousProcesses, true
		case "network":
			return hunting.WinNetworkAnomalies, true
		case "tasks":
			return hunting.WinScheduledTasks, true
		case "autoruns":
			return hunting.WinAutorunsAudit, true
		case "services":
			return hunting.WinServiceAnomalies, true
		}
		return nil, false
	}
	switch check {
	case "processes":
		return hunting.LnxSuspiciousProcesses, true
	case "network", "ports":
		// "ports" is a separate audit; "network" reuses the same anomaly
		// scanner. We keep them as distinct labels in the SPA but route
		// "ports" to the dedicated open-port audit.
		if check == "ports" {
			return hunting.LnxOpenPortAudit, true
		}
		return hunting.LnxNetworkAnomalies, true
	case "cron":
		return hunting.LnxCronAudit, true
	case "systemd":
		return hunting.LnxSystemdAudit, true
	case "suid":
		return hunting.LnxSUIDSGIDAudit, true
	case "kernel":
		return hunting.LnxKernelModuleAudit, true
	case "logins":
		return hunting.LnxLoginAnomalies, true
	case "hidden":
		return hunting.LnxHiddenFiles, true
	}
	return nil, false
}

// liveOutputDir picks a scratch path for live-hunt artifacts. With an active
// case, outputs land under the case's threat_hunting/live/ tree so they're
// reviewable alongside other scans. Without one, fall back to OS temp.
func liveOutputDir(rootDir, check string) string {
	if appCtx := getAppCtx(); appCtx != nil && appCtx.ActiveCase != nil {
		ts := time.Now().Format("20060102_150405")
		return filepath.Join(rootDir, "output", appCtx.ActiveCase.ID,
			"threat_hunting", "live", ts+"_"+check)
	}
	return filepath.Join(osTempDir(), "vanguard-live-"+check+"-"+
		time.Now().Format("20060102150405"))
}

func osTempDir() string {
	if runtime.GOOS == "windows" {
		if v := os.Getenv("TEMP"); v != "" {
			return v
		}
		return `C:\Windows\Temp`
	}
	return "/tmp"
}
