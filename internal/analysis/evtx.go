package analysis

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// evtxRow is the subset of EvtxECmd CSV columns we use. EvtxECmd's column
// order isn't guaranteed across versions, so we resolve indexes by header
// name at the start of each parse.
type evtxRow struct {
	Timestamp        time.Time
	EventID          int
	Channel          string // log file name without .evtx
	Provider         string
	Level            string
	UserName         string
	TargetUserName   string
	IPAddress        string
	LogonType        string
	ProcessName      string
	ParentProcess    string
	CommandLine      string
	ServiceName      string
	ServiceFileName  string
	Payload          string
}

// evtxColumns indexes the EvtxECmd CSV header. -1 means "column missing".
type evtxColumns struct {
	timestamp, eventID, channel, provider, level     int
	userName, targetUser, ipAddr, logonType          int
	processName, parentProcess, commandLine          int
	serviceName, serviceFileName, payload, mapDescription int
}

// resolveEvtxColumns maps header names to column indexes case-insensitively.
// EvtxECmd ships with both standard column names and a "Payload" / "MapDescription"
// catch-all column carrying the rest.
func resolveEvtxColumns(header []string) evtxColumns {
	idx := func(want ...string) int {
		for _, w := range want {
			lw := strings.ToLower(w)
			for i, h := range header {
				if strings.EqualFold(strings.TrimSpace(h), lw) {
					return i
				}
			}
		}
		return -1
	}
	return evtxColumns{
		timestamp:       idx("TimeCreated"),
		eventID:         idx("EventId", "Id"),
		channel:         idx("Channel"),
		provider:        idx("Provider"),
		level:           idx("Level"),
		userName:        idx("UserName"),
		targetUser:      idx("TargetUserName"),
		ipAddr:          idx("IPAddress", "RemoteHost"),
		logonType:       idx("LogonType"),
		processName:     idx("Executable", "ProcessName", "NewProcessName"),
		parentProcess:   idx("ParentProcessName"),
		commandLine:     idx("CommandLine", "ProcessCommandLine"),
		serviceName:     idx("ServiceName"),
		serviceFileName: idx("ImagePath", "ServiceFileName"),
		payload:         idx("Payload", "PayloadData1"),
		mapDescription:  idx("MapDescription"),
	}
}

func (c evtxColumns) get(rec []string, idx int) string {
	if idx < 0 || idx >= len(rec) {
		return ""
	}
	return rec[idx]
}

// streamEvtxRows opens path and yields one evtxRow per data row to fn. Stops
// on the first fn-returned error. Suitable for multi-million-row CSVs.
func streamEvtxRows(path string, fn func(evtxRow) error) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.FieldsPerRecord = -1

	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	cols := resolveEvtxColumns(header)

	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			// Skip malformed rows rather than abort the whole parse.
			continue
		}
		row := evtxRow{
			Channel:         cols.get(rec, cols.channel),
			Provider:        cols.get(rec, cols.provider),
			Level:           cols.get(rec, cols.level),
			UserName:        cols.get(rec, cols.userName),
			TargetUserName:  cols.get(rec, cols.targetUser),
			IPAddress:       cols.get(rec, cols.ipAddr),
			LogonType:       cols.get(rec, cols.logonType),
			ProcessName:     cols.get(rec, cols.processName),
			ParentProcess:   cols.get(rec, cols.parentProcess),
			CommandLine:     cols.get(rec, cols.commandLine),
			ServiceName:     cols.get(rec, cols.serviceName),
			ServiceFileName: cols.get(rec, cols.serviceFileName),
			Payload:         cols.get(rec, cols.payload),
		}
		if v := cols.get(rec, cols.eventID); v != "" {
			row.EventID, _ = strconv.Atoi(strings.TrimSpace(v))
		}
		if v := cols.get(rec, cols.timestamp); v != "" {
			row.Timestamp = parseTime(v)
		}
		// Carry MapDescription into Payload when Payload itself is empty —
		// that's where EvtxECmd puts the human-readable summary in newer
		// releases.
		if row.Payload == "" {
			row.Payload = cols.get(rec, cols.mapDescription)
		}
		if err := fn(row); err != nil {
			return err
		}
	}
}

// parseTime accepts the ISO-8601 / RFC3339 forms EvtxECmd emits.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05.0000000",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ---------------------------------------------------------------------------
// [2] Event Log Summary & Statistics
// ---------------------------------------------------------------------------

// EventLogSummary is the result of EventLogStats.
type EventLogSummary struct {
	TotalEvents     int
	EarliestEvent   time.Time
	LatestEvent     time.Time
	BySource        map[string]int  // channel → count
	ByEventID       map[string]int  // "channel:id" → count, but presented as id alone in display
	ByEventIDRaw    map[int]int     // event ID → count (channel-merged)
	ByLevel         map[string]int
	ByHour          map[int]int     // 0..23 → count
	ByUser          map[string]int  // top users
	CriticalWarning int
}

// EventLogStats streams the parsed-event-log CSV and produces an EventLogSummary.
func EventLogStats(csvPath string) (*EventLogSummary, error) {
	s := &EventLogSummary{
		BySource:     map[string]int{},
		ByEventIDRaw: map[int]int{},
		ByLevel:      map[string]int{},
		ByHour:       map[int]int{},
		ByUser:       map[string]int{},
	}
	err := streamEvtxRows(csvPath, func(row evtxRow) error {
		s.TotalEvents++
		if !row.Timestamp.IsZero() {
			if s.EarliestEvent.IsZero() || row.Timestamp.Before(s.EarliestEvent) {
				s.EarliestEvent = row.Timestamp
			}
			if row.Timestamp.After(s.LatestEvent) {
				s.LatestEvent = row.Timestamp
			}
			s.ByHour[row.Timestamp.Hour()]++
		}
		if row.Channel != "" {
			s.BySource[row.Channel]++
		}
		if row.EventID > 0 {
			s.ByEventIDRaw[row.EventID]++
		}
		if row.Level != "" {
			s.ByLevel[row.Level]++
			if strings.EqualFold(row.Level, "Critical") || strings.EqualFold(row.Level, "Warning") || strings.EqualFold(row.Level, "Error") {
				s.CriticalWarning++
			}
		}
		if row.TargetUserName != "" {
			s.ByUser[row.TargetUserName]++
		} else if row.UserName != "" {
			s.ByUser[row.UserName]++
		}
		return nil
	})
	return s, err
}

// FormatEventLogSummary renders an EventLogSummary as the multi-line block the
// TUI shows. Pure formatting — no I/O.
func FormatEventLogSummary(s *EventLogSummary) []string {
	if s == nil {
		return []string{"  (no summary data)"}
	}
	var lines []string
	lines = append(lines,
		fmt.Sprintf("Total Events:    %s", commaInt(s.TotalEvents)),
	)
	if !s.EarliestEvent.IsZero() {
		lines = append(lines,
			fmt.Sprintf("Time Range:      %s to %s",
				s.EarliestEvent.Format("2006-01-02 15:04"),
				s.LatestEvent.Format("2006-01-02 15:04")),
		)
	}
	lines = append(lines, "")
	lines = append(lines, "Events by Source:")
	for _, kv := range topN(s.BySource, 10) {
		pct := 0.0
		if s.TotalEvents > 0 {
			pct = float64(kv.Value) / float64(s.TotalEvents) * 100
		}
		lines = append(lines, fmt.Sprintf("  %-22s %s  (%.1f%%)",
			kv.Key, commaInt(kv.Value), pct))
	}
	lines = append(lines, "")
	lines = append(lines, "Top Event IDs:")
	for _, kv := range topNInt(s.ByEventIDRaw, 10) {
		label := eventIDLabel(kv.Key)
		lines = append(lines, fmt.Sprintf("  %-32s %s",
			label, commaInt(kv.Value)))
	}
	if s.CriticalWarning > 0 {
		lines = append(lines, "",
			fmt.Sprintf("Critical/Warning/Error Events: %s (review recommended)",
				commaInt(s.CriticalWarning)))
	}
	return lines
}

// eventIDLabel attaches a short human label to common Windows event IDs.
func eventIDLabel(id int) string {
	switch id {
	case 4624:
		return "4624 (Logon)"
	case 4625:
		return "4625 (Failed Logon)"
	case 4634:
		return "4634 (Logoff)"
	case 4648:
		return "4648 (Explicit Credentials)"
	case 4672:
		return "4672 (Special Privileges)"
	case 4688:
		return "4688 (Process Created)"
	case 4697:
		return "4697 (Service Installed)"
	case 4720:
		return "4720 (User Account Created)"
	case 4732:
		return "4732 (User Added to Group)"
	case 7045:
		return "7045 (Service Installed)"
	case 1:
		return "1 (Sysmon Process Create)"
	case 3:
		return "3 (Sysmon Network Connect)"
	case 11:
		return "11 (Sysmon File Create)"
	case 13:
		return "13 (Sysmon Registry Set)"
	}
	return fmt.Sprintf("%d", id)
}

// ---------------------------------------------------------------------------
// [3] Logon Analysis (4624 / 4625 / 4648)
// ---------------------------------------------------------------------------

// LogonAnalysisResult holds the totals + brute-force candidates for the TUI.
type LogonAnalysisResult struct {
	Successful       int
	Failed           int
	ExplicitCreds    int
	SpecialPriv      int
	NTLMAuth         int
	ByLogonType      map[string]int
	FailuresBySource map[string]int // sourceIP → count
	FailuresByTarget map[string]int // targetUsername → count
	BruteForce       []BruteForceCandidate
	LateralMovement  []LateralMovementHit
	Findings         []Finding
}

// BruteForceCandidate aggregates many failures from a single source.
type BruteForceCandidate struct {
	Source         string
	Failures       int
	UniqueAccounts int
	FirstSeen      time.Time
	LastSeen       time.Time
	Accounts       []string // sample
}

// LateralMovementHit is a Type 3 logon from an unusual source.
type LateralMovementHit struct {
	Source string
	Target string
	Count  int
}

// AnalyzeLogons reads the parsed event log CSV and produces a logon report.
func AnalyzeLogons(csvPath string) (*LogonAnalysisResult, error) {
	r := &LogonAnalysisResult{
		ByLogonType:      map[string]int{},
		FailuresBySource: map[string]int{},
		FailuresByTarget: map[string]int{},
	}

	// Track per-source attempts for brute-force detection.
	type srcStats struct {
		count     int
		accounts  map[string]bool
		firstSeen time.Time
		lastSeen  time.Time
	}
	bySrc := map[string]*srcStats{}
	type movementKey struct{ src, tgt string }
	movement := map[movementKey]int{}

	err := streamEvtxRows(csvPath, func(row evtxRow) error {
		switch row.EventID {
		case 4624:
			r.Successful++
			if row.LogonType != "" {
				r.ByLogonType[logonTypeLabel(row.LogonType)]++
			}
			if row.LogonType == "3" && row.IPAddress != "" && row.IPAddress != "-" && row.IPAddress != "::1" && row.IPAddress != "127.0.0.1" {
				movement[movementKey{src: row.IPAddress, tgt: row.Channel}]++
			}
		case 4625:
			r.Failed++
			if row.IPAddress != "" && row.IPAddress != "-" {
				r.FailuresBySource[row.IPAddress]++
				stats := bySrc[row.IPAddress]
				if stats == nil {
					stats = &srcStats{accounts: map[string]bool{}}
					bySrc[row.IPAddress] = stats
				}
				stats.count++
				if row.TargetUserName != "" {
					stats.accounts[row.TargetUserName] = true
				}
				if !row.Timestamp.IsZero() {
					if stats.firstSeen.IsZero() || row.Timestamp.Before(stats.firstSeen) {
						stats.firstSeen = row.Timestamp
					}
					if row.Timestamp.After(stats.lastSeen) {
						stats.lastSeen = row.Timestamp
					}
				}
			}
			if row.TargetUserName != "" {
				r.FailuresByTarget[row.TargetUserName]++
			}
		case 4648:
			r.ExplicitCreds++
		case 4672:
			r.SpecialPriv++
		case 4776:
			r.NTLMAuth++
		}
		return nil
	})
	if err != nil {
		return r, err
	}

	// Build brute-force candidates from sources with >50 failures.
	for src, stats := range bySrc {
		if stats.count < 50 {
			continue
		}
		accounts := make([]string, 0, len(stats.accounts))
		for a := range stats.accounts {
			accounts = append(accounts, a)
		}
		sort.Strings(accounts)
		if len(accounts) > 6 {
			accounts = accounts[:6]
		}
		c := BruteForceCandidate{
			Source:         src,
			Failures:       stats.count,
			UniqueAccounts: len(stats.accounts),
			FirstSeen:      stats.firstSeen,
			LastSeen:       stats.lastSeen,
			Accounts:       accounts,
		}
		r.BruteForce = append(r.BruteForce, c)

		sev := SeverityHigh
		if stats.count >= 500 {
			sev = SeverityCritical
		}
		r.Findings = append(r.Findings, Finding{
			Severity:       sev,
			Title:          fmt.Sprintf("Brute-force pattern: %d failed logons from %s", stats.count, src),
			Description:    fmt.Sprintf("%d failed logon attempts (event 4625) from source %s targeting %d account(s) over %s.", stats.count, src, len(stats.accounts), stats.lastSeen.Sub(stats.firstSeen).Truncate(time.Minute)),
			MITRETechnique: "T1110.001",
			IOCType:        "ip",
			IOCValue:       src,
			Source:         "evtx_logon",
			Timestamp:      stats.lastSeen,
		})
	}
	sort.Slice(r.BruteForce, func(i, j int) bool {
		return r.BruteForce[i].Failures > r.BruteForce[j].Failures
	})

	// Lateral-movement candidates: Type 3 logons aggregated >5 times.
	for k, n := range movement {
		if n < 5 {
			continue
		}
		r.LateralMovement = append(r.LateralMovement, LateralMovementHit{
			Source: k.src,
			Target: k.tgt,
			Count:  n,
		})
		r.Findings = append(r.Findings, Finding{
			Severity:       SeverityMedium,
			Title:          fmt.Sprintf("Lateral-movement candidate: Type 3 logon %s → %s (%d times)", k.src, k.tgt, n),
			Description:    "Repeated network logons from a workstation source toward a server channel — review for adversary-style lateral movement.",
			MITRETechnique: "T1021.002",
			IOCType:        "ip",
			IOCValue:       k.src,
			Source:         "evtx_logon",
		})
	}
	sort.Slice(r.LateralMovement, func(i, j int) bool {
		return r.LateralMovement[i].Count > r.LateralMovement[j].Count
	})

	return r, nil
}

func logonTypeLabel(t string) string {
	switch t {
	case "2":
		return "Type 2 (Interactive)"
	case "3":
		return "Type 3 (Network)"
	case "4":
		return "Type 4 (Batch)"
	case "5":
		return "Type 5 (Service)"
	case "7":
		return "Type 7 (Unlock)"
	case "8":
		return "Type 8 (NetworkCleartext)"
	case "9":
		return "Type 9 (NewCredentials)"
	case "10":
		return "Type 10 (RemoteInteractive)"
	case "11":
		return "Type 11 (CachedInteractive)"
	}
	return "Type " + t
}

// FormatLogonAnalysis renders LogonAnalysisResult as TUI lines.
func FormatLogonAnalysis(r *LogonAnalysisResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Successful Logons (4624):     %s", commaInt(r.Successful)),
		fmt.Sprintf("Failed Logons (4625):         %s", commaInt(r.Failed)),
		fmt.Sprintf("Explicit Credentials (4648):  %s", commaInt(r.ExplicitCreds)),
		fmt.Sprintf("Special Privileges (4672):    %s", commaInt(r.SpecialPriv)),
	}
	if len(r.ByLogonType) > 0 {
		out = append(out, "", "Logon Types:")
		for _, kv := range topN(r.ByLogonType, 6) {
			out = append(out, fmt.Sprintf("  %-30s %s", kv.Key, commaInt(kv.Value)))
		}
	}
	if r.Failed > 0 {
		out = append(out, "", "Failed-Logon Hot Spots:")
		out = append(out, "  Top sources:")
		for _, kv := range topN(r.FailuresBySource, 5) {
			out = append(out, fmt.Sprintf("    %-22s %s failures", kv.Key, commaInt(kv.Value)))
		}
		out = append(out, "  Top targets:")
		for _, kv := range topN(r.FailuresByTarget, 5) {
			out = append(out, fmt.Sprintf("    %-22s %s failures", kv.Key, commaInt(kv.Value)))
		}
	}
	if len(r.BruteForce) > 0 {
		out = append(out, "", "ALERT — Brute-force pattern(s) detected:")
		for _, b := range r.BruteForce {
			window := ""
			if !b.LastSeen.IsZero() && !b.FirstSeen.IsZero() {
				window = " over " + b.LastSeen.Sub(b.FirstSeen).Truncate(time.Minute).String()
			}
			out = append(out, fmt.Sprintf("  %s → %d accounts (%d failures%s)",
				b.Source, b.UniqueAccounts, b.Failures, window))
			if len(b.Accounts) > 0 {
				out = append(out, fmt.Sprintf("    Targeted: %s", strings.Join(b.Accounts, ", ")))
			}
		}
	}
	if len(r.LateralMovement) > 0 {
		out = append(out, "", "Lateral-movement candidates:")
		for _, l := range r.LateralMovement {
			out = append(out, fmt.Sprintf("  %s → %s via Type 3 (%d times)",
				l.Source, l.Target, l.Count))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// [4] Process Execution Analysis (4688 / Sysmon 1)
// ---------------------------------------------------------------------------

// ProcessAnalysisResult summarises process-creation events.
type ProcessAnalysisResult struct {
	Total            int
	UniqueExecs      int
	SuspiciousPaths  []ProcExecHit
	EncodedPS        []ProcExecHit
	LOLBins          []ProcExecHit
	OfficeSpawnShell []ProcExecHit
	Findings         []Finding
}

// ProcExecHit is one suspicious process-execution row.
type ProcExecHit struct {
	Severity    string
	ProcessName string
	CommandLine string
	Parent      string
	Reason      string
	MITRE       string
}

// AnalyzeProcessExecutions reads parsed event log CSV and builds the report.
func AnalyzeProcessExecutions(csvPath string) (*ProcessAnalysisResult, error) {
	r := &ProcessAnalysisResult{}
	uniq := map[string]bool{}

	suspiciousPaths := []string{
		`\appdata\local\temp\`, `\appdata\roaming\`,
		`\windows\temp\`, `\programdata\`,
		`\users\public\`,
	}
	lolbins := map[string]string{
		"certutil.exe":  "T1105",
		"bitsadmin.exe": "T1105",
		"mshta.exe":     "T1218",
		"regsvr32.exe":  "T1218.010",
		"rundll32.exe":  "T1218.011",
		"wmic.exe":      "T1047",
		"schtasks.exe":  "T1053.005",
		"at.exe":        "T1053.005",
	}
	officeApps := map[string]bool{
		"winword.exe": true, "excel.exe": true, "powerpnt.exe": true,
		"outlook.exe": true,
	}

	err := streamEvtxRows(csvPath, func(row evtxRow) error {
		// Sysmon EID 1 and Security 4688 both create processes.
		if row.EventID != 4688 && row.EventID != 1 {
			return nil
		}
		r.Total++

		exec := strings.ToLower(row.ProcessName)
		cmd := row.CommandLine
		parent := strings.ToLower(row.ParentProcess)
		if exec != "" {
			uniq[exec] = true
		}

		// Suspicious-path execution.
		for _, p := range suspiciousPaths {
			if strings.Contains(exec, p) {
				hit := ProcExecHit{
					Severity:    SeverityHigh,
					ProcessName: row.ProcessName,
					CommandLine: cmd,
					Parent:      row.ParentProcess,
					Reason:      "Process running from suspicious path " + p,
					MITRE:       "T1059",
				}
				r.SuspiciousPaths = append(r.SuspiciousPaths, hit)
				r.Findings = append(r.Findings, procFinding(hit, row.Timestamp))
				break
			}
		}

		// Encoded PowerShell.
		lowerCmd := strings.ToLower(cmd)
		if strings.Contains(lowerCmd, "powershell") &&
			(strings.Contains(lowerCmd, " -enc") ||
				strings.Contains(lowerCmd, " -e ") ||
				strings.Contains(lowerCmd, "-encodedcommand")) {
			hit := ProcExecHit{
				Severity:    SeverityCritical,
				ProcessName: row.ProcessName,
				CommandLine: cmd,
				Parent:      row.ParentProcess,
				Reason:      "Encoded PowerShell command",
				MITRE:       "T1059.001",
			}
			r.EncodedPS = append(r.EncodedPS, hit)
			r.Findings = append(r.Findings, procFinding(hit, row.Timestamp))
		}

		// LOLBin execution.
		base := lastPathSegment(exec)
		if mitre, ok := lolbins[base]; ok {
			hit := ProcExecHit{
				Severity:    SeverityHigh,
				ProcessName: row.ProcessName,
				CommandLine: cmd,
				Parent:      row.ParentProcess,
				Reason:      "LOLBin: " + base,
				MITRE:       mitre,
			}
			r.LOLBins = append(r.LOLBins, hit)
			r.Findings = append(r.Findings, procFinding(hit, row.Timestamp))
		}

		// Office app spawning shell.
		if officeApps[lastPathSegment(parent)] &&
			(strings.HasSuffix(exec, "cmd.exe") || strings.HasSuffix(exec, "powershell.exe") ||
				strings.HasSuffix(exec, "wscript.exe") || strings.HasSuffix(exec, "cscript.exe")) {
			hit := ProcExecHit{
				Severity:    SeverityCritical,
				ProcessName: row.ProcessName,
				CommandLine: cmd,
				Parent:      row.ParentProcess,
				Reason:      "Office application spawning shell",
				MITRE:       "T1204.002",
			}
			r.OfficeSpawnShell = append(r.OfficeSpawnShell, hit)
			r.Findings = append(r.Findings, procFinding(hit, row.Timestamp))
		}
		return nil
	})
	r.UniqueExecs = len(uniq)
	return r, err
}

func procFinding(hit ProcExecHit, ts time.Time) Finding {
	return Finding{
		Severity:       hit.Severity,
		Title:          hit.Reason + ": " + lastPathSegment(strings.ToLower(hit.ProcessName)),
		Description:    fmt.Sprintf("Process: %s\nParent: %s\nCmdLine: %s", hit.ProcessName, hit.Parent, hit.CommandLine),
		MITRETechnique: hit.MITRE,
		Source:         "evtx_proc",
		Timestamp:      ts,
	}
}

func lastPathSegment(p string) string {
	// Both forward + backslash paths show up in event logs.
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// FormatProcessAnalysis renders ProcessAnalysisResult for the TUI.
func FormatProcessAnalysis(r *ProcessAnalysisResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Process Creation Events: %s", commaInt(r.Total)),
		fmt.Sprintf("Unique Executables:            %s", commaInt(r.UniqueExecs)),
	}
	hitGroup := func(label string, hits []ProcExecHit, max int) {
		if len(hits) == 0 {
			return
		}
		out = append(out, "", label+":")
		for i, h := range hits {
			if i >= max {
				out = append(out, fmt.Sprintf("  ... %d more (see findings)", len(hits)-max))
				break
			}
			out = append(out, fmt.Sprintf("  [%s] %s", strings.ToUpper(h.Severity), h.ProcessName))
			if h.CommandLine != "" {
				cmd := h.CommandLine
				if len(cmd) > 80 {
					cmd = cmd[:80] + "…"
				}
				out = append(out, "      cmd: "+cmd)
			}
			if h.Parent != "" {
				out = append(out, "      parent: "+h.Parent)
			}
		}
	}
	hitGroup("Execution from Suspicious Paths", r.SuspiciousPaths, 5)
	hitGroup("Encoded PowerShell Commands", r.EncodedPS, 5)
	hitGroup("LOLBin Execution", r.LOLBins, 5)
	hitGroup("Office Application Spawning Shell", r.OfficeSpawnShell, 5)
	return out
}

// ---------------------------------------------------------------------------
// [5] Service Installation Analysis (7045 / 4697)
// ---------------------------------------------------------------------------

// ServiceAnalysisResult summarises service-installation events.
type ServiceAnalysisResult struct {
	Total       int
	Suspicious  []ServiceHit
	Findings    []Finding
}

// ServiceHit is one flagged service installation.
type ServiceHit struct {
	Severity    string
	Name        string
	BinaryPath  string
	Reason      string
	InstalledAt time.Time
}

// AnalyzeServices reads parsed event log CSV and builds the service report.
func AnalyzeServices(csvPath string) (*ServiceAnalysisResult, error) {
	r := &ServiceAnalysisResult{}
	suspiciousPaths := []string{
		`\appdata\`, `\users\public\`, `\windows\temp\`,
		`\programdata\`, `\temp\`,
	}

	err := streamEvtxRows(csvPath, func(row evtxRow) error {
		if row.EventID != 7045 && row.EventID != 4697 {
			return nil
		}
		r.Total++
		bin := row.ServiceFileName
		if bin == "" {
			bin = extractFromPayload(row.Payload, "ImagePath", "ServiceFileName", "ImageName")
		}
		name := row.ServiceName
		if name == "" {
			name = extractFromPayload(row.Payload, "ServiceName", "Name")
		}

		lowerBin := strings.ToLower(bin)
		var reasons []string
		sev := ""
		for _, p := range suspiciousPaths {
			if strings.Contains(lowerBin, p) {
				reasons = append(reasons, "binary in non-standard path "+p)
				sev = SeverityCritical
				break
			}
		}
		if strings.Contains(lowerBin, "powershell") && (strings.Contains(lowerBin, "-enc") || strings.Contains(lowerBin, "-e ")) {
			reasons = append(reasons, "encoded PowerShell in service binary")
			sev = SeverityCritical
		}
		if strings.Contains(lowerBin, "cmd.exe /c") {
			reasons = append(reasons, "service launches via cmd.exe /c")
			if sev == "" {
				sev = SeverityHigh
			}
		}
		if len(reasons) == 0 {
			return nil
		}
		hit := ServiceHit{
			Severity:    sev,
			Name:        name,
			BinaryPath:  bin,
			Reason:      strings.Join(reasons, "; "),
			InstalledAt: row.Timestamp,
		}
		r.Suspicious = append(r.Suspicious, hit)
		r.Findings = append(r.Findings, Finding{
			Severity:       hit.Severity,
			Title:          "Suspicious service installation: " + name,
			Description:    fmt.Sprintf("Binary: %s\nReason: %s", bin, hit.Reason),
			MITRETechnique: "T1543.003",
			Source:         "evtx_service",
			Timestamp:      row.Timestamp,
		})
		return nil
	})
	return r, err
}

// extractFromPayload pulls a "Key: value" pair out of EvtxECmd's freeform
// payload column. Lookups are case-insensitive and try each key in order.
func extractFromPayload(payload string, keys ...string) string {
	for _, k := range keys {
		needle := strings.ToLower(k) + ":"
		idx := strings.Index(strings.ToLower(payload), needle)
		if idx < 0 {
			continue
		}
		v := payload[idx+len(needle):]
		end := strings.IndexAny(v, "\r\n,;")
		if end > 0 {
			v = v[:end]
		}
		return strings.TrimSpace(v)
	}
	return ""
}

// FormatServiceAnalysis renders ServiceAnalysisResult for the TUI.
func FormatServiceAnalysis(r *ServiceAnalysisResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total New Services: %d", r.Total),
		fmt.Sprintf("Flagged:            %d", len(r.Suspicious)),
	}
	if len(r.Suspicious) == 0 {
		out = append(out, "", "  No suspicious service installations found.")
		return out
	}
	out = append(out, "")
	for i, h := range r.Suspicious {
		if i >= 8 {
			out = append(out, fmt.Sprintf("  ... %d more — see findings", len(r.Suspicious)-i))
			break
		}
		out = append(out, fmt.Sprintf("  [%s] Service: %s", strings.ToUpper(h.Severity), h.Name))
		out = append(out, "      Binary: "+h.BinaryPath)
		out = append(out, "      Reason: "+h.Reason)
		if !h.InstalledAt.IsZero() {
			out = append(out, "      Installed: "+h.InstalledAt.Format("2006-01-02 15:04:05"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Tiny shared helpers
// ---------------------------------------------------------------------------

type kv struct {
	Key   string
	Value int
}

type kvi struct {
	Key   int
	Value int
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func topNInt(m map[int]int, n int) []kvi {
	out := make([]kvi, 0, len(m))
	for k, v := range m {
		out = append(out, kvi{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value > out[j].Value })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// commaInt formats n with comma separators.
func commaInt(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	var b strings.Builder
	if n < 0 {
		b.WriteByte('-')
		s = s[1:]
	}
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
