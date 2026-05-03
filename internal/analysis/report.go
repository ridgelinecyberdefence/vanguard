package analysis

import (
	_ "embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/mitre"
)

//go:embed templates/report.html.tmpl
var reportHTMLTemplate string

// ReportData is the input passed to the HTML template.
type ReportData struct {
	Case               *casemanager.Case
	Targets            []casemanager.Target
	Findings           []ReportFinding
	Evidence           []casemanager.Evidence
	IOCs               []ReportIOC
	MITREMatrix        *MITREMappingResult
	MITREMatrixOrdered []TacticEntry
	SeverityCounts     SeverityCounts
	Summary            string
	Version            string
	GeneratedAt        string

	// IntegrityWarning is non-empty when the pre-report evidence integrity
	// check found modified or missing files. Templates render it as a
	// prominent banner so the report consumer can't miss the caveat.
	IntegrityWarning string
	IntegritySummary casemanager.IntegritySummary
}

// ReportFinding flattens casemanager.Finding + technique name for the template.
type ReportFinding struct {
	casemanager.Finding
	MITRETechniqueName string
}

// ReportIOC counts unique IOCs across all findings.
type ReportIOC struct {
	Type  string
	Value string
	Count int
}

// SeverityCounts is a precomputed bucket of finding counts for the
// "X critical, Y high…" pill row in the executive summary.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// TacticEntry is the template-friendly form of a tactic + technique-count list.
// We pre-flatten so the template doesn't need to iterate map keys (which
// html/template can do but the order is unstable).
type TacticEntry struct {
	Tactic mitre.Tactic
	Items  []MITRECount
}

// GenerateHTMLReport renders the case's findings + evidence + targets + MITRE
// mapping to a single self-contained HTML file under output/{case}/reports/.
func GenerateHTMLReport(rootDir, version string, cm *casemanager.CaseManager, c *casemanager.Case) (string, error) {
	if cm == nil || c == nil {
		return "", fmt.Errorf("case manager and case are required")
	}
	findings, err := cm.ListFindings(c.ID)
	if err != nil {
		return "", err
	}
	targets, err := cm.ListTargets(c.ID)
	if err != nil {
		return "", err
	}
	evidence, err := cm.ListEvidence(c.ID)
	if err != nil {
		return "", err
	}

	data := assembleReportData(c, findings, targets, evidence, version)

	// Pre-report integrity check — run the same verification the [V] menu
	// option does, and if anything is modified or missing, attach a warning
	// banner to the report so consumers see it before they trust the
	// findings. We don't abort report generation on failure: the report's
	// usefulness includes documenting that tampering occurred.
	if intResults, intSummary, intErr := cm.VerifyEvidenceIntegrity(c.ID); intErr == nil {
		data.IntegritySummary = intSummary
		if !intSummary.IsClean() {
			data.IntegrityWarning = fmt.Sprintf(
				"Evidence integrity check failed: %d modified, %d missing of %d total. "+
					"Review the affected files before relying on the findings below.",
				intSummary.Modified, intSummary.Missing, intSummary.Total)
		}
		_ = intResults // surfaced via summary; full results stay in the case DB
	}

	outDir := ReportsDir(rootDir, c.ID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("creating reports dir: %w", err)
	}
	outPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_Report_%s.html",
		c.ID, time.Now().Format("20060102")))

	tpl, err := template.New("report").Parse(reportHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parsing template: %w", err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", outPath, err)
	}
	defer f.Close()

	if err := tpl.Execute(f, data); err != nil {
		return outPath, fmt.Errorf("rendering template: %w", err)
	}
	return outPath, nil
}

// assembleReportData builds the ReportData payload — pure, test-friendly.
func assembleReportData(c *casemanager.Case, findings []casemanager.Finding,
	targets []casemanager.Target, evidence []casemanager.Evidence, version string) ReportData {

	rep := make([]ReportFinding, 0, len(findings))
	severitySorter := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for _, f := range findings {
		rep = append(rep, ReportFinding{
			Finding:            f,
			MITRETechniqueName: mitre.Lookup(f.MITRETechnique),
		})
	}
	sort.Slice(rep, func(i, j int) bool {
		// Sort: severity ascending (critical first), then time descending.
		si := severitySorter[strings.ToLower(rep[i].Severity)]
		sj := severitySorter[strings.ToLower(rep[j].Severity)]
		if si != sj {
			return si < sj
		}
		return rep[i].DiscoveredAt.After(rep[j].DiscoveredAt)
	})

	// IOC aggregation.
	type iocKey struct{ Type, Value string }
	iocCounts := map[iocKey]int{}
	for _, f := range findings {
		if f.IOCType != "" && f.IOCValue != "" {
			iocCounts[iocKey{f.IOCType, f.IOCValue}]++
		}
	}
	iocs := make([]ReportIOC, 0, len(iocCounts))
	for k, v := range iocCounts {
		iocs = append(iocs, ReportIOC{Type: k.Type, Value: k.Value, Count: v})
	}
	sort.Slice(iocs, func(i, j int) bool {
		if iocs[i].Count != iocs[j].Count {
			return iocs[i].Count > iocs[j].Count
		}
		return iocs[i].Type+iocs[i].Value < iocs[j].Type+iocs[j].Value
	})

	matrix := BuildMITREMapping(findings)
	matrixOrdered := make([]TacticEntry, 0, len(matrix.ByTactic))
	for _, t := range mitre.TacticOrder {
		if items := matrix.ByTactic[t]; len(items) > 0 {
			matrixOrdered = append(matrixOrdered, TacticEntry{Tactic: t, Items: items})
		}
	}

	sev := buildSeverityCounts(findings)
	summary := buildExecutiveSummary(c, findings, targets, sev)

	return ReportData{
		Case:               c,
		Targets:            targets,
		Findings:           rep,
		Evidence:           evidence,
		IOCs:               iocs,
		MITREMatrix:        matrix,
		MITREMatrixOrdered: matrixOrdered,
		SeverityCounts:     sev,
		Summary:            summary,
		Version:            version,
		GeneratedAt:        time.Now().UTC().Format("2006-01-02 15:04 UTC"),
	}
}

func buildSeverityCounts(findings []casemanager.Finding) SeverityCounts {
	var s SeverityCounts
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		case "info":
			s.Info++
		}
	}
	return s
}

// buildExecutiveSummary stitches a short narrative from the case data so the
// report's first page reads like a proper summary even when nobody wrote one
// by hand.
func buildExecutiveSummary(c *casemanager.Case, findings []casemanager.Finding,
	targets []casemanager.Target, s SeverityCounts) string {
	if len(findings) == 0 {
		return fmt.Sprintf("Case %s has no findings recorded yet. Investigation in progress.", c.ID)
	}

	var earliest, latest time.Time
	for _, f := range findings {
		if earliest.IsZero() || f.DiscoveredAt.Before(earliest) {
			earliest = f.DiscoveredAt
		}
		if f.DiscoveredAt.After(latest) {
			latest = f.DiscoveredAt
		}
	}
	span := ""
	if !earliest.IsZero() && !latest.IsZero() {
		span = fmt.Sprintf(" Activity spans %s to %s.",
			earliest.Format("2006-01-02 15:04"),
			latest.Format("2006-01-02 15:04"))
	}

	tcount := len(targets)
	tDesc := "no targets registered"
	if tcount > 0 {
		tDesc = fmt.Sprintf("%d target host(s)", tcount)
	}

	return fmt.Sprintf(
		"Investigation %s recorded %d finding(s) across %s — %d critical, %d high, %d medium, %d low.%s "+
			"Detection logic flagged the items above; review each finding manually before drawing conclusions.",
		c.ID, len(findings), tDesc,
		s.Critical, s.High, s.Medium, s.Low, span)
}

// ---------------------------------------------------------------------------
// [K/G] Executive summary — short HTML + plain text
// ---------------------------------------------------------------------------

// GenerateExecutiveSummary writes a short HTML and a parallel TXT version.
// Returns the HTML path (the TXT is alongside).
func GenerateExecutiveSummary(rootDir string, cm *casemanager.CaseManager, c *casemanager.Case) (string, error) {
	findings, err := cm.ListFindings(c.ID)
	if err != nil {
		return "", err
	}
	targets, _ := cm.ListTargets(c.ID)
	sev := buildSeverityCounts(findings)
	summary := buildExecutiveSummary(c, findings, targets, sev)

	outDir := ReportsDir(rootDir, c.ID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", err
	}
	date := time.Now().Format("20060102")
	htmlPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_ExecSummary_%s.html", c.ID, date))
	txtPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_ExecSummary_%s.txt", c.ID, date))

	// Plain text first.
	var b strings.Builder
	fmt.Fprintf(&b, "EXECUTIVE SUMMARY\n")
	fmt.Fprintf(&b, "Investigation: %s\n", c.Name)
	fmt.Fprintf(&b, "Case ID:       %s\n", c.ID)
	fmt.Fprintf(&b, "Analyst:       %s\n", c.Analyst)
	fmt.Fprintf(&b, "Organization:  %s\n", c.Organization)
	fmt.Fprintf(&b, "Classification: %s\n", c.Classification)
	fmt.Fprintf(&b, "Date:          %s\n\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "SUMMARY\n%s\n\n", summary)
	fmt.Fprintf(&b, "KEY METRICS\n")
	fmt.Fprintf(&b, "  Critical findings: %d\n", sev.Critical)
	fmt.Fprintf(&b, "  High findings:     %d\n", sev.High)
	fmt.Fprintf(&b, "  Medium findings:   %d\n", sev.Medium)
	fmt.Fprintf(&b, "  Low findings:      %d\n", sev.Low)
	fmt.Fprintf(&b, "  Targets:           %d\n\n", len(targets))
	if recs := buildRecommendations(findings); len(recs) > 0 {
		fmt.Fprintf(&b, "RECOMMENDATIONS\n")
		for _, r := range recs {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}
	if err := os.WriteFile(txtPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("writing exec summary text: %w", err)
	}

	// Minimal HTML — reuse the report template's brand styling.
	htmlBody := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>VanGuard Executive Summary — %s</title>
<style>
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f7fa; color: #1a1d23; line-height: 1.5; }
  header { background: #0d2137; color: #e3f2fd; padding: 28px 40px; }
  header h1 { margin: 0; font-size: 22px; letter-spacing: 4px; color: #4fc3f7; }
  main { max-width: 800px; margin: 32px auto; padding: 0 24px; }
  section { background: white; border: 1px solid #d8dee5; border-radius: 8px;
            padding: 24px 28px; margin-bottom: 20px; }
  h2 { color: #1565c0; border-bottom: 2px solid #d8dee5; padding-bottom: 8px; }
  ul { padding-left: 20px; }
</style></head>
<body>
<header><h1>V A N G U A R D &nbsp; — &nbsp; Executive Summary</h1></header>
<main>
  <section>
    <h2>Investigation</h2>
    <p><strong>%s</strong> (Case %s)<br>
    Analyst: %s · %s · %s</p>
  </section>
  <section><h2>Summary</h2><p>%s</p></section>
  <section>
    <h2>Key Metrics</h2>
    <ul>
      <li>Critical findings: %d</li>
      <li>High findings: %d</li>
      <li>Medium findings: %d</li>
      <li>Low findings: %d</li>
      <li>Targets: %d</li>
    </ul>
  </section>`,
		template.HTMLEscapeString(c.Name),
		template.HTMLEscapeString(c.Name), template.HTMLEscapeString(c.ID),
		template.HTMLEscapeString(c.Analyst),
		template.HTMLEscapeString(c.Organization),
		template.HTMLEscapeString(c.Classification),
		template.HTMLEscapeString(summary),
		sev.Critical, sev.High, sev.Medium, sev.Low, len(targets))

	if recs := buildRecommendations(findings); len(recs) > 0 {
		htmlBody += "<section><h2>Recommendations</h2><ul>"
		for _, r := range recs {
			htmlBody += "<li>" + template.HTMLEscapeString(r) + "</li>"
		}
		htmlBody += "</ul></section>"
	}
	htmlBody += "</main></body></html>"

	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o644); err != nil {
		return "", fmt.Errorf("writing exec summary HTML: %w", err)
	}
	return htmlPath, nil
}

// buildRecommendations returns short remediation prompts inferred from the
// finding mix. This is heuristic — designed to fill the "what next" section
// of the exec summary.
func buildRecommendations(findings []casemanager.Finding) []string {
	techSeen := map[string]bool{}
	for _, f := range findings {
		if f.MITRETechnique != "" {
			techSeen[f.MITRETechnique] = true
		}
	}
	var out []string
	if techSeen["T1110.001"] {
		out = append(out, "Implement account lockout policies and require MFA on remote-accessible accounts.")
	}
	if techSeen["T1059.001"] || techSeen["T1027.010"] {
		out = append(out, "Enable PowerShell ScriptBlock + Module logging and review encoded-command activity.")
	}
	if techSeen["T1543.003"] {
		out = append(out, "Audit Windows services for non-standard install paths and unsigned binaries.")
	}
	if techSeen["T1136.001"] || techSeen["T1078"] {
		out = append(out, "Audit user account creation and recent successful authentications.")
	}
	if techSeen["T1190"] || techSeen["T1505.003"] {
		out = append(out, "Patch Internet-facing applications and review web access logs for further compromise.")
	}
	if techSeen["T1486"] {
		out = append(out, "Initiate ransomware incident-response procedures: isolate affected hosts and engage backups.")
	}
	if len(out) == 0 {
		out = append(out, "Review individual findings and validate scope before drawing conclusions.")
	}
	return out
}

// ---------------------------------------------------------------------------
// CSV / TXT / STIX exports
// ---------------------------------------------------------------------------

// ExportFindingsCSV writes one CSV row per finding. Returns the path.
func ExportFindingsCSV(rootDir string, cm *casemanager.CaseManager, caseID string) (string, error) {
	findings, err := cm.ListFindings(caseID)
	if err != nil {
		return "", err
	}
	outDir := ReportsDir(rootDir, caseID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(outDir, fmt.Sprintf("VG_%s_Findings_%s.csv",
		caseID, time.Now().Format("20060102")))

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	_ = w.Write([]string{
		"ID", "Severity", "Title", "Description", "MITRETechnique", "MITRETechniqueName",
		"IOCType", "IOCValue", "EvidenceID", "DiscoveredAt",
	})
	for _, fi := range findings {
		_ = w.Write([]string{
			fmt.Sprintf("%d", fi.ID),
			fi.Severity,
			fi.Title,
			fi.Description,
			fi.MITRETechnique,
			mitre.Lookup(fi.MITRETechnique),
			fi.IOCType,
			fi.IOCValue,
			fmt.Sprintf("%d", fi.EvidenceID),
			fi.DiscoveredAt.UTC().Format(time.RFC3339),
		})
	}
	return path, nil
}

// ExportTimelineCSV exports the super timeline for the case. If a previous
// build exists in output/{case}/analysis/.../super_timeline.csv it's copied;
// otherwise BuildSuperTimeline runs first.
func ExportTimelineCSV(rootDir, caseID string) (string, error) {
	ts := CollectionTimestamp()
	outDir := AnalysisDir(rootDir, caseID, ts, "timeline")
	res, err := BuildSuperTimeline(rootDir, caseID, outDir)
	if err != nil {
		return "", err
	}

	// Mirror into reports/.
	reportPath := filepath.Join(ReportsDir(rootDir, caseID),
		fmt.Sprintf("VG_%s_Timeline_%s.csv", caseID, time.Now().Format("20060102")))
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o700); err != nil {
		return "", err
	}
	if err := copyFile(res.OutputFile, reportPath); err != nil {
		return res.OutputFile, err
	}
	return reportPath, nil
}

// ExportIOCs writes CSV, TXT (one IOC per line), and a basic STIX 2.1 bundle.
type IOCExportResult struct {
	CSVPath  string
	TXTPath  string
	STIXPath string
	ByType   map[string]int
	Total    int
}

// ExportIOCs aggregates IOCs from findings and writes them in three formats.
func ExportIOCs(rootDir string, cm *casemanager.CaseManager, caseID string) (*IOCExportResult, error) {
	findings, err := cm.ListFindings(caseID)
	if err != nil {
		return nil, err
	}
	type key struct{ Type, Value string }
	seen := map[key]struct {
		count   int
		context string
		first   time.Time
	}{}
	for _, f := range findings {
		if f.IOCType == "" || f.IOCValue == "" {
			continue
		}
		k := key{f.IOCType, f.IOCValue}
		entry := seen[k]
		entry.count++
		if entry.first.IsZero() || f.DiscoveredAt.Before(entry.first) {
			entry.first = f.DiscoveredAt
			entry.context = f.Title
		}
		seen[k] = entry
	}

	outDir := ReportsDir(rootDir, caseID)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return nil, err
	}
	date := time.Now().Format("20060102")
	csvPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_IOCs_%s.csv", caseID, date))
	txtPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_IOCs_%s.txt", caseID, date))
	stixPath := filepath.Join(outDir, fmt.Sprintf("VG_%s_IOCs_%s.json", caseID, date))

	// CSV.
	{
		f, err := os.Create(csvPath)
		if err != nil {
			return nil, err
		}
		w := csv.NewWriter(f)
		_ = w.Write([]string{"Type", "Value", "Context", "FirstSeen", "Count"})
		for k, v := range seen {
			_ = w.Write([]string{
				k.Type, k.Value, v.context,
				v.first.UTC().Format(time.RFC3339),
				fmt.Sprintf("%d", v.count),
			})
		}
		w.Flush()
		f.Close()
	}

	// TXT — one value per line.
	{
		f, err := os.Create(txtPath)
		if err != nil {
			return nil, err
		}
		for k := range seen {
			fmt.Fprintln(f, k.Value)
		}
		f.Close()
	}

	// STIX 2.1 bundle — minimal indicator objects.
	{
		stix := map[string]interface{}{
			"type":         "bundle",
			"id":           fmt.Sprintf("bundle--%s", caseID),
			"objects":      []interface{}{},
			"spec_version": "2.1",
		}
		objs := []interface{}{}
		for k := range seen {
			pattern := stixPattern(k.Type, k.Value)
			if pattern == "" {
				continue
			}
			objs = append(objs, map[string]interface{}{
				"type":            "indicator",
				"spec_version":    "2.1",
				"id":              fmt.Sprintf("indicator--%s-%s", caseID, sanitiseID(k.Value)),
				"created":         time.Now().UTC().Format(time.RFC3339),
				"modified":        time.Now().UTC().Format(time.RFC3339),
				"name":            seen[k].context,
				"indicator_types": []string{"malicious-activity"},
				"pattern":         pattern,
				"pattern_type":    "stix",
				"valid_from":      seen[k].first.UTC().Format(time.RFC3339),
			})
		}
		stix["objects"] = objs
		f, err := os.Create(stixPath)
		if err != nil {
			return nil, err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(stix)
		f.Close()
	}

	res := &IOCExportResult{
		CSVPath:  csvPath,
		TXTPath:  txtPath,
		STIXPath: stixPath,
		ByType:   map[string]int{},
		Total:    len(seen),
	}
	for k := range seen {
		res.ByType[k.Type]++
	}
	return res, nil
}

// stixPattern returns a STIX 2.1 pattern string for the given IOC type+value,
// or "" if the type isn't in our supported set.
func stixPattern(iocType, value string) string {
	v := strings.ReplaceAll(value, "'", "")
	switch strings.ToLower(iocType) {
	case "sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", v)
	case "md5":
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", v)
	case "ip", "ipv4":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", v)
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", v)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", v)
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", v)
	}
	return ""
}

func sanitiseID(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// FormatIOCExport renders the result for the TUI.
func FormatIOCExport(r *IOCExportResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Unique IOCs: %d", r.Total),
		"",
	}
	for _, kv := range topN(r.ByType, 20) {
		out = append(out, fmt.Sprintf("  %-22s %d", kv.Key, kv.Value))
	}
	out = append(out, "",
		"Exported to:",
		"  "+r.CSVPath,
		"  "+r.TXTPath,
		"  "+r.STIXPath,
	)
	return out
}

// copyFile is a small streaming copy helper used by ExportTimelineCSV.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 64*1024)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr != nil {
			break
		}
	}
	return nil
}
