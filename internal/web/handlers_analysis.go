package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/analysis"
)

// handleAnalysisFindings — GET /api/analysis/findings. Returns every finding
// recorded against the active case. Empty array when no active case or no
// findings yet.
func handleAnalysisFindings(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}
	if ctx.ActiveCase == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	findings, err := ctx.CaseManager.ListFindings(ctx.ActiveCase.ID)
	if err != nil || findings == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

// handleAnalysisAction — POST /api/analysis/<verb>. Single dispatcher for
// the 8 analysis actions. Each branch invokes the matching internal/analysis
// function, writes its output under output/<case>/analysis/, registers the
// product as evidence on success, and returns {status, message, output_path}.
//
// Failures still come back with status:"error" and a clear message rather
// than 5xx — the SPA's progress card renders that inline.
func handleAnalysisAction(w http.ResponseWriter, r *http.Request) {
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
	if ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}

	verb := analysisVerbFromPath(r.URL.Path)

	switch verb {
	case "super_timeline":
		runSuperTimeline(w, ctx)
	case "correlate":
		runCorrelate(w, ctx)
	case "mitre_map":
		runMITREMap(w, ctx)
	case "exec_summary":
		runExecSummary(w, ctx)
	case "export_findings":
		runExportFindings(w, ctx)
	case "export_timeline":
		runExportTimeline(w, ctx)
	case "export_iocs":
		runExportIOCs(w, ctx)
	default:
		writeError(w, http.StatusBadRequest, "unknown analysis action: "+verb)
	}
}

// runSuperTimeline walks every parsed CSV under output/<case>/analysis and
// merges them into one chronological super-timeline CSV.
func runSuperTimeline(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	outDir := analysisOutDir(c, "super_timeline")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}
	res, err := analysis.BuildSuperTimeline(c.RootDir, c.ActiveCase.ID, outDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	registerEvidence(c, "analysis_super_timeline", res.OutputFile)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("Super timeline built: %d events from %d sources", res.TotalEvents, len(res.BySource)),
		"output_path": res.OutputFile,
		"event_count": res.TotalEvents,
		"sources":     res.BySource,
	})
}

// runCorrelate runs the cross-finding correlator and writes the formatted
// result to a .txt under output/<case>/analysis/correlation/.
func runCorrelate(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	findings, err := c.CaseManager.ListFindings(c.ActiveCase.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	res := analysis.CorrelateFindings(findings)
	lines := analysis.FormatCorrelation(res)

	outDir := analysisOutDir(c, "correlation")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	outPath := filepath.Join(outDir, "correlation.txt")
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	registerEvidence(c, "analysis_correlation", outPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("Correlated %d findings", len(findings)),
		"output_path": outPath,
	})
}

// runMITREMap groups findings by MITRE ATT&CK technique and writes a text
// report. Trivial implementation — useful for handing to a SOC / IR lead.
func runMITREMap(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	findings, err := c.CaseManager.ListFindings(c.ActiveCase.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	res := analysis.BuildMITREMapping(findings)
	lines := analysis.FormatMITREMapping(res)

	outDir := analysisOutDir(c, "mitre")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	outPath := filepath.Join(outDir, "mitre_mapping.txt")
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	registerEvidence(c, "analysis_mitre_map", outPath)
	techniqueCount := 0
	if res != nil {
		techniqueCount = res.Unique
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("MITRE mapping: %d techniques across %d findings", techniqueCount, len(findings)),
		"output_path": outPath,
		"techniques":  techniqueCount,
	})
}

func runExecSummary(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	path, err := analysis.GenerateExecutiveSummary(c.RootDir, c.CaseManager, c.ActiveCase)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	registerEvidence(c, "analysis_exec_summary", path)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     "Executive summary generated",
		"output_path": path,
	})
}

func runExportFindings(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	path, err := analysis.ExportFindingsCSV(c.RootDir, c.CaseManager, c.ActiveCase.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	findings, _ := c.CaseManager.ListFindings(c.ActiveCase.ID)
	registerEvidence(c, "analysis_export_findings", path)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("Exported %d findings", len(findings)),
		"output_path": path,
		"count":       len(findings),
	})
}

func runExportTimeline(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	path, err := analysis.ExportTimelineCSV(c.RootDir, c.ActiveCase.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	registerEvidence(c, "analysis_export_timeline", path)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     "Timeline exported to CSV",
		"output_path": path,
	})
}

func runExportIOCs(w http.ResponseWriter, ctx interface{}) {
	c := getAppCtx()
	res, err := analysis.ExportIOCs(c.RootDir, c.CaseManager, c.ActiveCase.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "error", "message": err.Error()})
		return
	}
	if res == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"message": "No IOCs found in case findings",
		})
		return
	}
	registerEvidence(c, "analysis_export_iocs", res.CSVPath)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("Exported %d IOCs (CSV / TXT / STIX)", res.Total),
		"output_path": res.CSVPath,
		"txt_path":    res.TXTPath,
		"stix_path":   res.STIXPath,
		"by_type":     res.ByType,
		"total":       res.Total,
	})
}

// handleHTMLReport — POST /api/analysis/html_report.
//
// Generates a self-contained HTML report for the active case containing all
// findings, evidence chain, and timeline. Uses inline HTML (no template file
// required) so it works on first install without any additional assets.
func handleHTMLReport(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	appCtx := getAppCtx()
	if appCtx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	if appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}
	if appCtx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}

	c := appCtx.ActiveCase
	outDir := filepath.Join(appCtx.RootDir, "output", c.ID, "reports")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating reports dir: "+err.Error())
		return
	}
	reportFile := filepath.Join(outDir, fmt.Sprintf("VanGuard_Report_%s_%s.html",
		c.ID, time.Now().Format("20060102_150405")))

	findings, _ := appCtx.CaseManager.ListFindings(c.ID)
	evidence, _ := appCtx.CaseManager.ListEvidence(c.ID)
	timeline, _ := appCtx.CaseManager.ListTimelineEvents(c.ID)

	sevCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		sev := strings.ToLower(f.Severity)
		if _, ok := sevCounts[sev]; ok {
			sevCounts[sev]++
		}
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>VanGuard DFIR Report — ` + template.HTMLEscapeString(c.Name) + `</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0b0e13;color:#e4e7ec;padding:40px}
.container{max-width:1200px;margin:0 auto}
h1{font-size:28px;color:#e07a3a;margin-bottom:4px}
h2{font-size:20px;color:#fff;margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid #2a3245}
.subtitle{font-size:14px;color:#6b7588;margin-bottom:24px}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.meta-card{background:#1e2433;border:1px solid #2a3245;border-radius:8px;padding:16px}
.meta-card .label{font-size:11px;color:#6b7588;text-transform:uppercase;letter-spacing:.8px;margin-bottom:4px}
.meta-card .value{font-size:18px;font-weight:700}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.stat{background:#1e2433;border:1px solid #2a3245;border-radius:8px;padding:12px;text-align:center}
.stat .count{font-size:24px;font-weight:700}
.stat .label{font-size:11px;color:#6b7588;text-transform:uppercase}
.critical .count{color:#ef4444}.high .count{color:#f97316}
.medium .count{color:#eab308}.low .count{color:#22c55e}.info .count{color:#3b82f6}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:24px}
th{text-align:left;padding:10px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#6b7588;background:#1e2433;border-bottom:1px solid #2a3245}
td{padding:10px 14px;border-bottom:1px solid #1e2433}
tr:hover td{background:#252c3b}
.badge{padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}
.badge-critical{background:rgba(239,68,68,.12);color:#ef4444}
.badge-high{background:rgba(249,115,22,.12);color:#f97316}
.badge-medium{background:rgba(234,179,8,.12);color:#eab308}
.badge-low{background:rgba(34,197,94,.12);color:#22c55e}
.badge-info{background:rgba(59,130,246,.12);color:#3b82f6}
.mono{font-family:'Consolas',monospace;font-size:12px}
.footer{margin-top:48px;padding-top:16px;border-top:1px solid #2a3245;font-size:12px;color:#6b7588;text-align:center}
</style>
</head>
<body>
<div class="container">
<h1>VANGUARD DFIR REPORT</h1>
`)
	sb.WriteString(fmt.Sprintf(`<div class="subtitle">Generated %s by VanGuard — RidgeLine Cyber</div>
<div class="meta">
<div class="meta-card"><div class="label">Case Name</div><div class="value">%s</div></div>
<div class="meta-card"><div class="label">Case ID</div><div class="value mono">%s</div></div>
<div class="meta-card"><div class="label">Classification</div><div class="value">%s</div></div>
<div class="meta-card"><div class="label">Analyst</div><div class="value">%s</div></div>
<div class="meta-card"><div class="label">Organization</div><div class="value">%s</div></div>
<div class="meta-card"><div class="label">Status</div><div class="value">%s</div></div>
</div>
<h2>Finding Summary</h2>
<div class="stats">
<div class="stat critical"><div class="count">%d</div><div class="label">Critical</div></div>
<div class="stat high"><div class="count">%d</div><div class="label">High</div></div>
<div class="stat medium"><div class="count">%d</div><div class="label">Medium</div></div>
<div class="stat low"><div class="count">%d</div><div class="label">Low</div></div>
<div class="stat info"><div class="count">%d</div><div class="label">Info</div></div>
</div>
`,
		time.Now().Format("2006-01-02 15:04:05"),
		template.HTMLEscapeString(c.Name),
		template.HTMLEscapeString(c.ID),
		template.HTMLEscapeString(c.Classification),
		template.HTMLEscapeString(c.Analyst),
		template.HTMLEscapeString(c.Organization),
		template.HTMLEscapeString(c.Status),
		sevCounts["critical"], sevCounts["high"], sevCounts["medium"],
		sevCounts["low"], sevCounts["info"],
	))

	// Findings table.
	if len(findings) > 0 {
		sb.WriteString(`<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>MITRE</th><th>IOC</th><th>Discovered</th></tr>
`)
		for _, f := range findings {
			badgeClass := "badge-" + strings.ToLower(f.Severity)
			ioc := ""
			if f.IOCType != "" && f.IOCValue != "" {
				ioc = template.HTMLEscapeString(f.IOCType + ": " + f.IOCValue)
			}
			sb.WriteString(fmt.Sprintf(
				`<tr><td><span class="badge %s">%s</span></td><td>%s</td>`+
					`<td class="mono">%s</td><td class="mono">%s</td><td>%s</td></tr>
`,
				badgeClass,
				template.HTMLEscapeString(strings.ToUpper(f.Severity)),
				template.HTMLEscapeString(f.Title),
				template.HTMLEscapeString(f.MITRETechnique),
				ioc,
				f.DiscoveredAt.Format("2006-01-02 15:04"),
			))
		}
		sb.WriteString("</table>\n")
	} else {
		sb.WriteString("<h2>Findings</h2><p style=\"color:#6b7588\">No findings recorded.</p>\n")
	}

	// Evidence chain table.
	if len(evidence) > 0 {
		sb.WriteString(`<h2>Evidence Chain</h2>
<table><tr><th>Type</th><th>Path</th><th>SHA256</th><th>Collected</th></tr>
`)
		for _, ev := range evidence {
			hashShort := ev.FileHashSHA256
			if len(hashShort) > 16 {
				hashShort = hashShort[:16] + "…"
			}
			sb.WriteString(fmt.Sprintf(
				`<tr><td>%s</td><td class="mono">%s</td>`+
					`<td class="mono">%s</td><td>%s</td></tr>
`,
				template.HTMLEscapeString(ev.EvidenceType),
				template.HTMLEscapeString(ev.FilePath),
				template.HTMLEscapeString(hashShort),
				ev.CollectedAt.Format("2006-01-02 15:04"),
			))
		}
		sb.WriteString("</table>\n")
	}

	// Timeline table.
	if len(timeline) > 0 {
		sb.WriteString(`<h2>Timeline</h2>
<table><tr><th>Timestamp</th><th>Source</th><th>Event</th><th>Description</th></tr>
`)
		for _, evt := range timeline {
			sb.WriteString(fmt.Sprintf(
				`<tr><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>
`,
				evt.Timestamp.Format("2006-01-02 15:04:05"),
				template.HTMLEscapeString(evt.Source),
				template.HTMLEscapeString(evt.EventType),
				template.HTMLEscapeString(evt.Description),
			))
		}
		sb.WriteString("</table>\n")
	}

	sb.WriteString(fmt.Sprintf(`<div class="footer">
VanGuard DFIR Toolkit v%s — RidgeLine Cyber<br>
<a href="https://ridgelinecyber.com" style="color:#e07a3a">ridgelinecyber.com</a>
</div>
</div>
</body>
</html>`, template.HTMLEscapeString(appCtx.Version)))

	if err := os.WriteFile(reportFile, []byte(sb.String()), 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "writing report: "+err.Error())
		return
	}
	registerEvidence(appCtx, "analysis_report_html", reportFile)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("HTML report generated (%d findings, %d evidence items)", len(findings), len(evidence)),
		"output_path": reportFile,
		"size":        fileSizeOf(reportFile),
	})
}

// handleAnalysisGeneric returns a clean 200 stub for analysis verbs that are
// not yet fully implemented. Lets the SPA show "coming soon" without parsing
// an error body.
func handleAnalysisGeneric(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Analysis feature available in v0.2.0",
	})
}

// analysisOutDir returns output/<case>/analysis/<kind>.
func analysisOutDir(c interface{}, kind string) string {
	x := getAppCtx()
	return filepath.Join(x.RootDir, "output", x.ActiveCase.ID, "analysis", kind)
}

// registerEvidence is a tiny helper for the analysis dispatcher — every
// successful operation writes its output into the case evidence log.
func registerEvidence(c interface{}, kind, path string) {
	x := getAppCtx()
	if x == nil || x.CaseManager == nil || x.ActiveCase == nil || path == "" {
		return
	}
	_, _ = x.CaseManager.AddEvidence(x.ActiveCase.ID, 0, kind, path)
}

// fileSizeOf returns the file size in bytes, or 0 on stat failure.
func fileSizeOf(path string) int64 {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// analysisVerbFromPath strips "/api/analysis/" off the request URL.
func analysisVerbFromPath(p string) string {
	const prefix = "/api/analysis/"
	if len(p) <= len(prefix) {
		return ""
	}
	return p[len(prefix):]
}

// Re-export the JSON encode helper so the unused import warning doesn't
// fire when none of the branches above end up calling it directly.
var _ = json.Marshal
