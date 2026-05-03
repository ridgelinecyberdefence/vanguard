package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/app"
	"github.com/ridgelinecyberdefence/vanguard/internal/memory"
)

// memoryRunState tracks one in-flight capture/analyze operation. Same shape
// as the triage / hunt state holders so the SPA's "is something running?"
// check can be answered uniformly.
type memoryRunState struct {
	captureMu     sync.Mutex
	capturing     bool
	captureTool   string
	captureStart  time.Time
	analyzeMu     sync.Mutex
	analyzing     bool
	analyzePlugin string
	analyzeStart  time.Time
}

var memState memoryRunState

// handleMemoryDumps — GET /api/memory/dumps. Lists every dump file under
// output/<case>/memory/ via the shared ListDumps helper.
func handleMemoryDumps(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	if ctx.ActiveCase == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	dir := filepath.Join(ctx.RootDir, "output", ctx.ActiveCase.ID, "memory")
	dumps, _ := memory.ListDumps(dir)

	out := make([]map[string]interface{}, 0, len(dumps))
	for _, d := range dumps {
		out = append(out, map[string]interface{}{
			"name":   d.Name,
			"path":   d.Path,
			"size":   d.Size,
			"format": d.Format,
			"date":   d.Modified.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// resolveDumpPath turns a user-supplied dump path into an absolute,
// verified path that Volatility3 can open. Returns ("", searchList,
// error) when nothing exists at any candidate location so the handler
// can surface the full search list to the analyst.
//
// Resolution rules:
//   - Absolute path → stat-check and return as-is.
//   - Relative path containing a separator → resolve against the
//     process cwd via filepath.Abs, then stat-check.
//   - Bare filename (no separator) → walk a prioritised search list:
//     case memory dir → output dir → root dir → analyst's
//     Downloads / Desktop / Documents.
//
// The bare-filename branch saves analysts from typing the full path when
// they pasted a dump into the obvious places.
func resolveDumpPath(input string, ctx *app.Context) (string, []string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil, fmt.Errorf("empty dump path")
	}

	// Absolute path — single stat-check, done.
	if filepath.IsAbs(input) {
		if _, err := os.Stat(input); err == nil {
			return input, nil, nil
		}
		return "", []string{input},
			fmt.Errorf("memory dump file not found: %s", input)
	}

	// Has a separator → resolve against cwd, then stat. Catches
	// "Downloads\memory.raw" pastes from File Explorer.
	if strings.ContainsAny(input, `/\`) {
		abs, err := filepath.Abs(input)
		if err != nil {
			return "", []string{input},
				fmt.Errorf("could not resolve %q: %w", input, err)
		}
		if _, err := os.Stat(abs); err == nil {
			return abs, nil, nil
		}
		return "", []string{abs},
			fmt.Errorf("memory dump file not found: %s", abs)
	}

	// Bare filename — try every well-known location.
	candidates := dumpSearchPaths(input, ctx)
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, candidates, nil
		}
	}
	return "", candidates,
		fmt.Errorf("memory dump file %q not found at any known location", input)
}

// dumpSearchPaths returns the ordered list of locations to probe when
// resolving a bare filename. Active-case memory directory wins (highest
// confidence), followed by the project tree, then the analyst's home
// folders. Empty path components from missing env vars are filtered out.
func dumpSearchPaths(filename string, ctx *app.Context) []string {
	var out []string
	if ctx != nil && ctx.ActiveCase != nil {
		out = append(out, filepath.Join(ctx.RootDir,
			"output", ctx.ActiveCase.ID, "memory", filename))
	}
	if ctx != nil {
		out = append(out,
			filepath.Join(ctx.RootDir, "output", filename),
			filepath.Join(ctx.RootDir, filename),
		)
	}
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	if home != "" {
		out = append(out,
			filepath.Join(home, "Downloads", filename),
			filepath.Join(home, "Desktop", filename),
			filepath.Join(home, "Documents", filename),
		)
	}
	return out
}

// handleMemoryCapture — POST /api/memory/capture. Body: {tool, output_name?}.
//
// Drives the shared CaptureManager in a goroutine and emits memory_progress
// / memory_complete WebSocket events. Mirrors the TUI's flow but without
// the per-second progress poll (the SPA's progress card is simpler).
func handleMemoryCapture(w http.ResponseWriter, r *http.Request) {
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
		Tool       string `json:"tool"`
		OutputName string `json:"output_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Tool == "" {
		writeError(w, http.StatusBadRequest, "tool is required")
		return
	}
	if !ctx.Elevated {
		writeError(w, http.StatusBadRequest,
			"memory capture requires Administrator/root — relaunch VanGuard elevated")
		return
	}

	tool, ext, ok := mapMemoryTool(req.Tool)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown capture tool: "+req.Tool)
		return
	}

	memState.captureMu.Lock()
	if memState.capturing {
		memState.captureMu.Unlock()
		writeError(w, http.StatusConflict, "a memory capture is already in progress")
		return
	}
	memState.capturing = true
	memState.captureTool = req.Tool
	memState.captureStart = time.Now()
	memState.captureMu.Unlock()

	cm := memory.NewCaptureManager(
		ctx.RootDir, ctx.ActiveCase.ID, ctx.Hostname, ctx.Platform,
		ctx.Logger, ctx.ToolManager,
	)

	// Resolve binary + output path. For LiME we go through RunLiME below.
	var binPath, outPath string
	if tool == memory.ToolLiME {
		binPath = cm.LimeKoPath()
	} else {
		toolID := memoryToolID(tool)
		binPath = cm.ToolPath(toolID)
		if binPath == "" {
			memState.captureMu.Lock()
			memState.capturing = false
			memState.captureMu.Unlock()
			writeError(w, http.StatusBadRequest,
				fmt.Sprintf("%s is not installed — Configuration > Download Required Tools", req.Tool))
			return
		}
	}
	if req.OutputName != "" && !strings.ContainsAny(req.OutputName, `\/:*?"<>|`) {
		outPath = filepath.Join(cm.OutputDir(), req.OutputName)
	} else {
		outPath = cm.SuggestedOutputPath(ext)
	}

	go runMemoryCapture(cm, tool, binPath, outPath, req.Tool)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":      "started",
		"tool":        req.Tool,
		"output_path": outPath,
	})
}

func runMemoryCapture(cm *memory.CaptureManager, tool memory.CaptureTool, binPath, outPath, toolName string) {
	defer func() {
		memState.captureMu.Lock()
		memState.capturing = false
		memState.captureMu.Unlock()
	}()

	broadcastProgress("memory_progress", map[string]interface{}{
		"tool": toolName, "status": "running",
		"progress": "Starting " + toolName + " capture...",
	})

	runCtx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	var result memory.CaptureResult
	if tool == memory.ToolLiME {
		result = cm.RunLiME(runCtx, binPath, outPath, nil)
	} else {
		req := memory.CaptureRequest{Tool: tool, BinPath: binPath, OutputPath: outPath}
		result = cm.Run(runCtx, req, nil)
	}

	payload := map[string]interface{}{
		"tool":        toolName,
		"output_file": result.OutputPath,
		"size":        result.Size,
		"sha256":      result.SHA256,
		"duration":    int(result.Duration.Seconds()),
	}
	if !result.Success {
		payload["status"] = "failed"
		payload["error"] = result.Error
	} else {
		payload["status"] = "complete"
		// Register evidence on success.
		if appCtx := getAppCtx(); appCtx != nil && appCtx.CaseManager != nil && appCtx.ActiveCase != nil {
			_, _ = appCtx.CaseManager.AddEvidence(
				appCtx.ActiveCase.ID, 0, "memory_dump", result.OutputPath)
		}
	}
	broadcastProgress("memory_complete", payload)
}

// mapMemoryTool resolves the SPA's tool identifier to the typed
// memory.CaptureTool plus the conventional file extension. Returns ok=false
// for unknown identifiers so the caller can surface a clean 400.
func mapMemoryTool(s string) (memory.CaptureTool, string, bool) {
	switch s {
	case "dumpit":
		return memory.ToolDumpIt, "dmp", true
	case "winpmem":
		return memory.ToolWinPmem, "raw", true
	case "belkasoft":
		return memory.ToolBelkasoft, "dmp", true
	case "magnet":
		return memory.ToolMagnetRAM, "raw", true
	case "avml":
		return memory.ToolAVML, "lime", true
	case "lime":
		return memory.ToolLiME, "lime", true
	}
	return "", "", false
}

// memoryToolID maps the typed CaptureTool to the corresponding tool registry
// ID — needed because the registry uses platform-suffixed IDs like
// "winpmem-win" / "avml-lnx".
func memoryToolID(t memory.CaptureTool) string {
	switch t {
	case memory.ToolDumpIt:
		return "dumpit-win"
	case memory.ToolWinPmem:
		return "winpmem"
	case memory.ToolBelkasoft:
		return "belkasoft_ram"
	case memory.ToolMagnetRAM:
		return "magnet_ram"
	case memory.ToolAVML:
		return "avml-lnx"
	case memory.ToolLiME:
		return "lime-lnx"
	}
	return ""
}

// handleMemoryAnalyze — POST /api/memory/analyze. Body: {plugin, dump_path,
// yara_rules?}. Runs Volatility3 against the dump in a goroutine and emits
// analysis_progress / analysis_complete events.
func handleMemoryAnalyze(w http.ResponseWriter, r *http.Request) {
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
		Plugin    string `json:"plugin"`
		DumpPath  string `json:"dump_path"`
		YaraRules string `json:"yara_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.DumpPath == "" {
		writeError(w, http.StatusBadRequest, "dump_path is required")
		return
	}
	if req.Plugin == "" {
		writeError(w, http.StatusBadRequest, "plugin is required")
		return
	}

	// Volatility3 resolves -f against its own cwd, not VanGuard's, so a
	// bare filename or relative path the analyst pastes from File Explorer
	// silently turns into a "file not found" error inside Python. Resolve
	// to an absolute, verified path here and reject early with a clear
	// message that names every location we searched.
	resolvedPath, searched, err := resolveDumpPath(req.DumpPath, ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"%s — searched: %s", err.Error(), strings.Join(searched, " | ")))
		return
	}
	req.DumpPath = resolvedPath

	memState.analyzeMu.Lock()
	if memState.analyzing {
		memState.analyzeMu.Unlock()
		writeError(w, http.StatusConflict, "a memory analysis is already in progress")
		return
	}
	memState.analyzing = true
	memState.analyzePlugin = req.Plugin
	memState.analyzeStart = time.Now()
	memState.analyzeMu.Unlock()

	runner := memory.NewVolatilityRunner(ctx.RootDir, ctx.Logger)
	if !runner.HasVolatilityScript() {
		memState.analyzeMu.Lock()
		memState.analyzing = false
		memState.analyzeMu.Unlock()
		writeError(w, http.StatusBadRequest,
			"Volatility3 not installed — Configuration > Diagnose Volatility3 to inspect, then Download Required Tools")
		return
	}
	if !runner.HasPython() {
		memState.analyzeMu.Lock()
		memState.analyzing = false
		memState.analyzeMu.Unlock()
		writeError(w, http.StatusBadRequest,
			"Python 3 not found — install system Python 3 or place a portable interpreter under lib/python-embedded/")
		return
	}

	outDir := memory.AnalysisOutputDir(ctx.RootDir, ctx.ActiveCase.ID)
	go runMemoryAnalyze(runner, req.Plugin, req.DumpPath, req.YaraRules, outDir)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "started",
		"plugin":     req.Plugin,
		"output_dir": outDir,
	})
}

func runMemoryAnalyze(runner *memory.VolatilityRunner, plugin, dumpPath, yaraRules, outDir string) {
	defer func() {
		memState.analyzeMu.Lock()
		memState.analyzing = false
		memState.analyzeMu.Unlock()
	}()

	broadcastProgress("analysis_progress", map[string]interface{}{
		"plugin":   plugin,
		"status":   "running",
		"progress": "Running " + plugin + " against " + filepath.Base(dumpPath),
	})

	runCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// "auto" → run the platform's full analysis set; otherwise run a single
	// plugin. Behaviour mirrors the TUI's auto-profile button.
	var output strings.Builder
	switch plugin {
	case "auto":
		var plugins []string
		appCtx := getAppCtx()
		if appCtx != nil && appCtx.Platform == "windows" {
			plugins = memory.WindowsFullAnalysisPlugins()
		} else {
			plugins = memory.LinuxFullAnalysisPlugins()
		}
		req := memory.AnalysisRequest{DumpFile: dumpPath, OutputDir: outDir, Plugins: plugins}
		summary := runner.RunFullAnalysis(runCtx, req, nil)
		output.WriteString(fmt.Sprintf("Plugins: %d  Detected OS: %s\n", len(plugins), summary.DetectedOS))
		output.WriteString(fmt.Sprintf("Processes: %d  Connections: %d  Suspicious: %d  Services: %d\n",
			summary.Processes, summary.Connections, summary.Suspicious, summary.Services))
		if summary.Error != "" {
			output.WriteString("\nError: " + summary.Error + "\n")
		}
		reportPath, _ := generateMemoryReport(&summary)
		broadcastProgress("analysis_complete", map[string]interface{}{
			"plugin":     plugin,
			"output":     output.String(),
			"output_dir": outDir,
			"duration":   int(summary.Duration.Seconds()),
			"findings":   len(summary.Findings),
			"report":     reportPath,
		})
		registerAnalysisEvidence(outDir)
		return
	default:
		var extra []string
		if yaraRules != "" && (plugin == "yarascan" || strings.HasSuffix(plugin, "yarascan.YaraScan")) {
			extra = []string{"--yara-file", yaraRules}
		}
		result := runner.RunPlugin(runCtx, dumpPath, plugin, outDir, extra...)
		payload := map[string]interface{}{
			"plugin":     plugin,
			"output_dir": outDir,
			"output":     fmt.Sprintf("Plugin: %s\nStatus: %s\nLines: %d\nOut: %s",
				plugin, result.Status, result.Lines, result.OutFile),
			"out_file": result.OutFile,
			"lines":    result.Lines,
			"duration": int(result.Duration.Seconds()),
		}
		if result.Error != "" {
			payload["error"] = result.Error
		}
		broadcastProgress("analysis_complete", payload)
		registerAnalysisEvidence(outDir)
		return
	}
}

// handleMemoryPlugins — GET /api/memory/plugins[?os=windows|linux|mac].
// Serves the Volatility3 plugin catalogue (memory.Vol3Plugins) so the SPA
// browser can render an organized, searchable list. The optional `os`
// query parameter filters to one OS family — cross-platform plugins (OS
// "all") are always included.
func handleMemoryPlugins(w http.ResponseWriter, r *http.Request) {
	osFamily := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
	plugins := memory.PluginsForOS(osFamily)
	writeJSON(w, http.StatusOK, plugins)
}

// registerAnalysisEvidence adds the analysis output dir to the case
// evidence log. Best-effort — failures here only affect the case DB.
func registerAnalysisEvidence(outDir string) {
	appCtx := getAppCtx()
	if appCtx == nil || appCtx.CaseManager == nil || appCtx.ActiveCase == nil {
		return
	}
	_, _ = appCtx.CaseManager.AddEvidence(
		appCtx.ActiveCase.ID, 0, "memory_analysis", outDir)
}

// generateMemoryReport builds an HTML summary of a completed full-analysis run
// and writes it to memory_analysis_report.html in OutputDir. Uses pre-computed
// findings from the AnalysisSummary; enumerates CSV files for the output table.
func generateMemoryReport(summary *memory.AnalysisSummary) (string, error) {
	reportFile := filepath.Join(summary.OutputDir, "memory_analysis_report.html")

	type findingRow struct{ Severity, Source, Detail string }
	var findings []findingRow
	for _, f := range summary.Findings {
		detail := f.Detail
		if f.Process != "" {
			detail = fmt.Sprintf("%s (PID %d): %s", f.Process, f.PID, detail)
		}
		src := f.Source
		if src == "" {
			src = f.Title
		}
		findings = append(findings, findingRow{f.Severity, src, detail})
	}
	// Surface aggregate stats as informational findings when not already raised.
	if summary.Connections > 0 && !hasFindingSource(summary.Findings, "Network") {
		findings = append(findings, findingRow{
			"info", "Network",
			fmt.Sprintf("%d network connections found", summary.Connections),
		})
	}
	if summary.Suspicious > 0 && !hasFindingSource(summary.Findings, "Malfind") {
		findings = append(findings, findingRow{
			"critical", "Malfind",
			fmt.Sprintf("%d injected code regions detected", summary.Suspicious),
		})
	}

	type outputFile struct {
		Name, Size string
		Rows       int
	}
	var outputFiles []outputFile
	if entries, err := os.ReadDir(summary.OutputDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".csv") {
				continue
			}
			info, _ := e.Info()
			rows := 0
			if data, readErr := os.ReadFile(filepath.Join(summary.OutputDir, e.Name())); readErr == nil {
				rows = max(0, len(strings.Split(strings.TrimSpace(string(data)), "\n"))-1)
			}
			outputFiles = append(outputFiles, outputFile{e.Name(), formatMemSize(info.Size()), rows})
		}
	}

	critCount, highCount, medCount, infoCount := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		default:
			infoCount++
		}
	}

	severityColor := map[string]string{
		"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "info": "#3b82f6",
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Memory Analysis Report</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; background:#0b0e13; color:#e4e7ec; padding:40px; }
.container { max-width:1200px; margin:0 auto; }
h1 { font-size:24px; color:#e07a3a; margin-bottom:4px; }
h2 { font-size:18px; color:#fff; margin:28px 0 12px; padding-bottom:8px; border-bottom:1px solid #2a3245; }
.subtitle { font-size:13px; color:#8891a5; margin-bottom:24px; }
.stats { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-bottom:24px; }
.stat { background:#1e2433; border:1px solid #2a3245; border-radius:8px; padding:14px; text-align:center; }
.stat .count { font-size:28px; font-weight:700; }
.stat .label { font-size:11px; color:#8891a5; text-transform:uppercase; margin-top:4px; }
.critical .count { color:#ef4444; }
.high .count { color:#f97316; }
.medium .count { color:#eab308; }
.info .count { color:#3b82f6; }
.meta { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin-bottom:24px; }
.meta-card { background:#1e2433; border:1px solid #2a3245; border-radius:8px; padding:14px; }
.meta-card .label { font-size:11px; color:#8891a5; text-transform:uppercase; margin-bottom:4px; }
.meta-card .value { font-size:15px; font-weight:600; word-break:break-all; }
.finding { padding:12px 16px; margin-bottom:8px; border-radius:6px; border-left:4px solid; background:#1e2433; }
.finding.critical { border-color:#ef4444; }
.finding.high { border-color:#f97316; }
.finding.medium { border-color:#eab308; }
.finding.info { border-color:#3b82f6; }
.finding .severity { font-size:11px; font-weight:700; text-transform:uppercase; margin-bottom:2px; }
.finding .source { font-size:13px; font-weight:600; color:#fff; }
.finding .detail { font-size:13px; color:#b4bcc9; margin-top:2px; }
table { width:100%%; border-collapse:collapse; font-size:13px; }
th { text-align:left; padding:8px 12px; font-size:11px; text-transform:uppercase; color:#8891a5; background:#1e2433; border-bottom:1px solid #2a3245; }
td { padding:8px 12px; border-bottom:1px solid #1e2433; }
.mono { font-family:'Consolas','JetBrains Mono',monospace; font-size:12px; }
.footer { margin-top:40px; padding-top:12px; border-top:1px solid #2a3245; font-size:12px; color:#6b7588; text-align:center; }
.no-findings { padding:20px; text-align:center; color:#22c55e; font-size:15px; background:#1e2433; border-radius:8px; }
</style>
</head>
<body>
<div class="container">
<h1>MEMORY ANALYSIS REPORT</h1>
<div class="subtitle">Generated %s &mdash; VanGuard by RidgeLine Cyber</div>
<div class="meta">
<div class="meta-card"><div class="label">Memory Dump</div><div class="value mono">%s</div></div>
<div class="meta-card"><div class="label">Detected OS</div><div class="value">%s</div></div>
<div class="meta-card"><div class="label">Plugins Executed</div><div class="value">%d</div></div>
</div>
<h2>Threat Summary</h2>
<div class="stats">
<div class="stat critical"><div class="count">%d</div><div class="label">Critical</div></div>
<div class="stat high"><div class="count">%d</div><div class="label">High</div></div>
<div class="stat medium"><div class="count">%d</div><div class="label">Medium</div></div>
<div class="stat info"><div class="count">%d</div><div class="label">Informational</div></div>
</div>`,
		time.Now().Format("2006-01-02 15:04:05"),
		filepath.Base(summary.DumpFile),
		summary.DetectedOS,
		len(summary.Plugins),
		critCount, highCount, medCount, infoCount,
	)

	b.WriteString("<h2>Key Findings</h2>")
	if len(findings) > 0 {
		for _, f := range findings {
			col := severityColor[f.Severity]
			if col == "" {
				col = "#3b82f6"
			}
			fmt.Fprintf(&b,
				`<div class="finding %s"><div class="severity" style="color:%s">%s</div>`+
					`<div class="source">%s</div><div class="detail">%s</div></div>`,
				f.Severity, col, strings.ToUpper(f.Severity), f.Source, f.Detail,
			)
		}
	} else {
		b.WriteString(`<div class="no-findings">No suspicious indicators detected in initial analysis.<br>` +
			`Review individual plugin outputs for detailed data.</div>`)
	}

	b.WriteString(`<h2>Plugin Outputs</h2><table><tr><th>Plugin Output</th><th>Records</th><th>Size</th></tr>`)
	for _, f := range outputFiles {
		fmt.Fprintf(&b, `<tr><td class="mono">%s</td><td>%d</td><td>%s</td></tr>`, f.Name, f.Rows, f.Size)
	}
	b.WriteString(`</table>`)

	b.WriteString(`<div class="footer">VanGuard DFIR Toolkit &mdash; RidgeLine Cyber<br>` +
		`CSV files contain full plugin data for detailed analysis in Timeline Explorer or Excel.</div>` +
		`</div></body></html>`)

	err := os.WriteFile(reportFile, []byte(b.String()), 0o644)
	return reportFile, err
}

// hasFindingSource returns true when any finding has the given source (case-insensitive).
func hasFindingSource(findings []memory.Finding, source string) bool {
	for _, f := range findings {
		if strings.EqualFold(f.Source, source) {
			return true
		}
	}
	return false
}

// formatMemSize formats a byte count as a human-readable string.
func formatMemSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
