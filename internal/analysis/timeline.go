package analysis

import (
	"encoding/csv"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// TimelineEntry is one row of the super-timeline CSV.
type TimelineEntry struct {
	Timestamp      time.Time
	Source         string // logical source label (e.g. "EvtxECmd", "MFTECmd", "auth_log")
	EventType      string
	Severity       string
	Description    string
	Details        string
	MITRETechnique string
	Host           string
}

// TimelineResult summarises a super-timeline build.
type TimelineResult struct {
	OutputFile  string
	TotalEvents int
	BySource    map[string]int
	TimeRange   [2]time.Time
}

// BuildSuperTimeline walks output/{case}/analysis (and the related parsed
// directories the EZ Tools / Linux log analysers populate) and merges every
// time-stamped record into a single CSV, sorted by UTC timestamp.
//
// The function is intentionally tolerant — unknown CSV schemas are skipped
// rather than aborting the whole merge, so a missing tool only loses its rows.
func BuildSuperTimeline(rootDir, caseID, outDir string) (*TimelineResult, error) {
	res := &TimelineResult{BySource: map[string]int{}}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return res, fmt.Errorf("creating output dir: %w", err)
	}
	res.OutputFile = filepath.Join(outDir, "super_timeline.csv")

	caseRoot := filepath.Join(rootDir, "output", caseID)

	var entries []TimelineEntry

	// 1. Parsed event log CSV — most volume comes from here.
	if csvPath := FindEventLogCSV(filepath.Join(caseRoot, "analysis")); csvPath != "" {
		err := streamEvtxRows(csvPath, func(row evtxRow) error {
			if row.Timestamp.IsZero() {
				return nil
			}
			entries = append(entries, TimelineEntry{
				Timestamp:   row.Timestamp,
				Source:      "EvtxECmd",
				EventType:   eventIDLabel(row.EventID),
				Severity:    SeverityInfo,
				Description: row.Provider,
				Details:     truncForCSV(row.Payload, 200),
				Host:        row.Channel,
			})
			res.BySource["EvtxECmd"]++
			return nil
		})
		if err == nil {
			// just count what we ingested
		}
	}

	// 2. EZ Tools companion CSVs — accept anything we can date.
	for _, glob := range []string{
		"analysis/*/parsed/mftecmd/*.csv",
		"analysis/*/parsed/pecmd/*.csv",
		"analysis/*/parsed/amcache/*.csv",
		"analysis/*/parsed/shimcache/*.csv",
		"analysis/*/parsed/srum/*.csv",
		"analysis/*/parsed/jumplists/*.csv",
		"analysis/*/parsed/lnkfiles/*.csv",
		"analysis/*/parsed/recmd/*.csv",
		"analysis/*/parsed/recyclebin/*.csv",
		"disk/*/parsed/*/*.csv",
	} {
		matches, _ := filepath.Glob(filepath.Join(caseRoot, glob))
		for _, m := range matches {
			source := guessSourceLabel(m)
			n, _ := streamGenericTimeCSV(m, source, &entries)
			res.BySource[source] += n
		}
	}

	// 3. Hayabusa / Chainsaw findings if present (CSV).
	huntingDir := filepath.Join(caseRoot, "threat_hunting")
	_ = filepath.WalkDir(huntingDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".csv") {
			return nil
		}
		source := "Hayabusa"
		if strings.Contains(strings.ToLower(p), "chainsaw") {
			source = "Chainsaw"
		}
		n, _ := streamGenericTimeCSV(p, source, &entries)
		res.BySource[source] += n
		return nil
	})

	// 4. Memory analysis timeline (Volatility timeliner).
	memDir := filepath.Join(caseRoot, "memory")
	_ = filepath.WalkDir(memDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.EqualFold(d.Name(), "timeline.csv") &&
			!strings.Contains(strings.ToLower(d.Name()), "timeliner") {
			return nil
		}
		n, _ := streamGenericTimeCSV(p, "Volatility3", &entries)
		res.BySource["Volatility3"] += n
		return nil
	})

	// Sort + dedupe-ish (keep duplicates — they're real).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	if len(entries) > 0 {
		res.TimeRange[0] = entries[0].Timestamp
		res.TimeRange[1] = entries[len(entries)-1].Timestamp
	}
	res.TotalEvents = len(entries)

	if err := writeTimelineCSV(res.OutputFile, entries); err != nil {
		return res, err
	}
	return res, nil
}

// guessSourceLabel produces a friendly label from a CSV path like
// "analysis/2026.../parsed/mftecmd/MFT_Output.csv" → "MFTECmd".
func guessSourceLabel(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	switch dir {
	case "mftecmd":
		return "MFTECmd"
	case "pecmd":
		return "PECmd"
	case "amcache":
		return "AmcacheParser"
	case "shimcache":
		return "AppCompatCache"
	case "srum":
		return "SrumECmd"
	case "jumplists":
		return "JLECmd"
	case "lnkfiles":
		return "LECmd"
	case "recmd":
		return "RECmd"
	case "recyclebin":
		return "RBCmd"
	case "evtxecmd":
		return "EvtxECmd"
	}
	return "Parsed"
}

// streamGenericTimeCSV reads a CSV file looking for a "Time*"-flavoured column
// and a description column, appending a TimelineEntry per data row.
func streamGenericTimeCSV(path, source string, out *[]TimelineEntry) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return 0, err
	}

	timeCol := -1
	for i, h := range header {
		lh := strings.ToLower(strings.TrimSpace(h))
		if lh == "timestamp" || lh == "timecreated" || lh == "executed" ||
			lh == "lastrun" || lh == "lastwritetimestamp" || lh == "creationtime" ||
			lh == "modifieddate" || lh == "modified" || strings.HasPrefix(lh, "time") {
			timeCol = i
			break
		}
	}
	if timeCol < 0 {
		return 0, nil // no usable timestamp — silently skip
	}

	count := 0
	added := 0
	maxPerFile := 200_000 // cap per-file ingestion so a 50M-row MFT doesn't blow memory
	for {
		rec, err := r.Read()
		if err != nil {
			break
		}
		count++
		if added >= maxPerFile {
			continue
		}
		if timeCol >= len(rec) {
			continue
		}
		ts := parseTime(rec[timeCol])
		if ts.IsZero() {
			continue
		}
		desc := ""
		if len(rec) > 1 {
			desc = truncForCSV(strings.Join(rec[:min(len(rec), 5)], " | "), 200)
		}
		*out = append(*out, TimelineEntry{
			Timestamp:   ts,
			Source:      source,
			EventType:   "row",
			Severity:    SeverityInfo,
			Description: desc,
		})
		added++
	}
	return added, nil
}

func writeTimelineCSV(path string, entries []TimelineEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"Timestamp", "Source", "EventType", "Severity",
		"Description", "Details", "MITRETechnique", "Host",
	}); err != nil {
		return err
	}
	for _, e := range entries {
		_ = w.Write([]string{
			e.Timestamp.UTC().Format(time.RFC3339),
			e.Source, e.EventType, e.Severity,
			truncForCSV(e.Description, 500),
			truncForCSV(e.Details, 500),
			e.MITRETechnique, e.Host,
		})
	}
	return nil
}

func truncForCSV(s string, max int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FormatTimelineResult renders a TimelineResult for the TUI.
func FormatTimelineResult(r *TimelineResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Events:    %s", commaInt(r.TotalEvents)),
	}
	if !r.TimeRange[0].IsZero() {
		out = append(out, fmt.Sprintf("Time Range:      %s to %s",
			r.TimeRange[0].Format("2006-01-02 15:04"),
			r.TimeRange[1].Format("2006-01-02 15:04")))
	}
	if len(r.BySource) > 0 {
		out = append(out, "", "Events by source:")
		for _, kv := range topN(r.BySource, 12) {
			out = append(out, fmt.Sprintf("  %-22s %s", kv.Key, commaInt(kv.Value)))
		}
	}
	out = append(out, "",
		"Output: "+r.OutputFile,
		"Import into Timeline Explorer or Timesketch for analysis.")
	return out
}
