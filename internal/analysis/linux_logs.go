package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Auth log analysis
// ---------------------------------------------------------------------------

// AuthLogResult summarises SSH / sudo / account-change events from
// /var/log/auth.log or /var/log/secure.
type AuthLogResult struct {
	TotalLines     int
	TimeRange      [2]time.Time
	SSHSuccess     int
	SSHFailed      int
	SudoCount      int
	SuCount        int
	AccountCreates int

	FailedBySource map[string]int // sourceIP → count
	BruteForce     []BruteForceCandidate
	SuccessAfterBF []SSHSuccessAfterBF
	SudoByUser     map[string]int
	AccountChanges []string // free-text events worth surfacing
	Findings       []Finding
}

// SSHSuccessAfterBF indicates a successful SSH auth from an IP that previously
// brute-forced the same host.
type SSHSuccessAfterBF struct {
	Source string
	User   string
	When   time.Time
}

// AnalyzeAuthLog scans every regular file under root that looks like an auth
// log (auth.log*, secure*) and aggregates the standard pattern set.
func AnalyzeAuthLog(root string) (*AuthLogResult, error) {
	r := &AuthLogResult{
		FailedBySource: map[string]int{},
		SudoByUser:     map[string]int{},
	}

	files := findAuthLogFiles(root)
	if len(files) == 0 {
		return r, fmt.Errorf("no auth.log/secure files found under %s", root)
	}

	type srcStats struct {
		count     int
		accounts  map[string]bool
		first     time.Time
		last      time.Time
	}
	bySrc := map[string]*srcStats{}

	type successAfter struct {
		when time.Time
		user string
	}
	successPerSrc := map[string][]successAfter{}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			r.TotalLines++
			ts := parseSyslogTimestamp(line)
			if !ts.IsZero() {
				if r.TimeRange[0].IsZero() || ts.Before(r.TimeRange[0]) {
					r.TimeRange[0] = ts
				}
				if ts.After(r.TimeRange[1]) {
					r.TimeRange[1] = ts
				}
			}

			lower := strings.ToLower(line)
			switch {
			case strings.Contains(lower, "sshd") && strings.Contains(lower, "accepted"):
				r.SSHSuccess++
				if src, user := parseSSHAccept(line); src != "" {
					successPerSrc[src] = append(successPerSrc[src], successAfter{when: ts, user: user})
				}
			case strings.Contains(lower, "sshd") && strings.Contains(lower, "failed password"):
				r.SSHFailed++
				if src, user := parseSSHFailed(line); src != "" {
					r.FailedBySource[src]++
					stats := bySrc[src]
					if stats == nil {
						stats = &srcStats{accounts: map[string]bool{}}
						bySrc[src] = stats
					}
					stats.count++
					if user != "" {
						stats.accounts[user] = true
					}
					if !ts.IsZero() {
						if stats.first.IsZero() || ts.Before(stats.first) {
							stats.first = ts
						}
						if ts.After(stats.last) {
							stats.last = ts
						}
					}
				}
			case strings.Contains(lower, "sudo:"):
				r.SudoCount++
				if user := parseSudoUser(line); user != "" {
					r.SudoByUser[user]++
				}
			case strings.Contains(lower, " su:") || strings.HasPrefix(lower, "su:"):
				r.SuCount++
			case strings.Contains(lower, "useradd") || strings.Contains(lower, "new user:") || strings.Contains(lower, "added user"):
				r.AccountCreates++
				r.AccountChanges = append(r.AccountChanges, strings.TrimSpace(line))
				r.Findings = append(r.Findings, Finding{
					Severity:       SeverityHigh,
					Title:          "New account created via auth log",
					Description:    line,
					MITRETechnique: "T1136.001",
					Source:         "auth_log",
					Timestamp:      ts,
				})
			case strings.Contains(lower, "added to group") && (strings.Contains(lower, "sudo") || strings.Contains(lower, "wheel") || strings.Contains(lower, "docker")):
				r.AccountChanges = append(r.AccountChanges, strings.TrimSpace(line))
				r.Findings = append(r.Findings, Finding{
					Severity:       SeverityMedium,
					Title:          "User added to privileged group",
					Description:    line,
					MITRETechnique: "T1098",
					Source:         "auth_log",
					Timestamp:      ts,
				})
			}
		}
		f.Close()
	}

	// Brute-force candidates: >20 failures from one source.
	for src, stats := range bySrc {
		if stats.count < 20 {
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
		r.BruteForce = append(r.BruteForce, BruteForceCandidate{
			Source:         src,
			Failures:       stats.count,
			UniqueAccounts: len(stats.accounts),
			FirstSeen:      stats.first,
			LastSeen:       stats.last,
			Accounts:       accounts,
		})
		sev := SeverityHigh
		if stats.count >= 200 {
			sev = SeverityCritical
		}
		r.Findings = append(r.Findings, Finding{
			Severity:       sev,
			Title:          fmt.Sprintf("SSH brute force: %d failures from %s", stats.count, src),
			Description:    fmt.Sprintf("%d failed SSH authentication attempts from %s targeting %d account(s).", stats.count, src, len(stats.accounts)),
			MITRETechnique: "T1110.001",
			IOCType:        "ip",
			IOCValue:       src,
			Source:         "auth_log",
			Timestamp:      stats.last,
		})

		// Successful login from same source after the brute force is much worse.
		for _, s := range successPerSrc[src] {
			if !stats.last.IsZero() && (s.when.Equal(stats.last) || s.when.After(stats.last)) {
				r.SuccessAfterBF = append(r.SuccessAfterBF, SSHSuccessAfterBF{
					Source: src,
					User:   s.user,
					When:   s.when,
				})
				r.Findings = append(r.Findings, Finding{
					Severity:       SeverityCritical,
					Title:          fmt.Sprintf("Successful SSH login from brute-force source: %s → %s", src, s.user),
					Description:    fmt.Sprintf("IP %s succeeded as user %s at %s after a brute-force campaign.", src, s.user, s.when.Format(time.RFC3339)),
					MITRETechnique: "T1078",
					IOCType:        "ip",
					IOCValue:       src,
					Source:         "auth_log",
					Timestamp:      s.when,
				})
			}
		}
	}
	sort.Slice(r.BruteForce, func(i, j int) bool {
		return r.BruteForce[i].Failures > r.BruteForce[j].Failures
	})

	// Web users running sudo are nearly always bad.
	for _, webUser := range []string{"www-data", "apache", "nginx", "httpd"} {
		if c := r.SudoByUser[webUser]; c > 0 {
			r.Findings = append(r.Findings, Finding{
				Severity:       SeverityHigh,
				Title:          fmt.Sprintf("Web service user '%s' executing sudo (%d times)", webUser, c),
				Description:    "A web-server account is invoking sudo — a strong sign of post-exploitation activity.",
				MITRETechnique: "T1068",
				Source:         "auth_log",
			})
		}
	}

	return r, nil
}

func findAuthLogFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasPrefix(name, "auth.log") || strings.HasPrefix(name, "secure") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// parseSyslogTimestamp parses the bare "May  1 07:15:00 …" prefix used by
// classic syslog. Year is inferred from the file's modification time when
// missing — for our purposes the current year is good enough.
func parseSyslogTimestamp(line string) time.Time {
	if len(line) < 15 {
		return time.Time{}
	}
	stamp := line[:15]
	year := time.Now().Year()
	t, err := time.Parse("Jan _2 15:04:05 2006", stamp+" "+fmt.Sprintf("%d", year))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

var (
	sshAcceptRE = regexp.MustCompile(`Accepted (?:password|publickey)(?: for)? (?P<user>\S+) from (?P<ip>\S+)`)
	sshFailedRE = regexp.MustCompile(`Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)`)
	sudoUserRE  = regexp.MustCompile(`sudo:\s+(?P<user>\S+)\s*:`)
)

func parseSSHAccept(line string) (ip, user string) {
	m := sshAcceptRE.FindStringSubmatch(line)
	if len(m) == 3 {
		return m[2], m[1]
	}
	return "", ""
}

func parseSSHFailed(line string) (ip, user string) {
	m := sshFailedRE.FindStringSubmatch(line)
	if len(m) == 3 {
		return m[2], m[1]
	}
	return "", ""
}

func parseSudoUser(line string) string {
	m := sudoUserRE.FindStringSubmatch(line)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// FormatAuthLog renders an AuthLogResult.
func FormatAuthLog(r *AuthLogResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Lines:      %s", commaInt(r.TotalLines)),
	}
	if !r.TimeRange[0].IsZero() {
		out = append(out, fmt.Sprintf("Time Range:       %s to %s",
			r.TimeRange[0].Format("2006-01-02 15:04"),
			r.TimeRange[1].Format("2006-01-02 15:04")))
	}
	out = append(out, "",
		fmt.Sprintf("SSH Successful:   %s", commaInt(r.SSHSuccess)),
		fmt.Sprintf("SSH Failed:       %s", commaInt(r.SSHFailed)),
		fmt.Sprintf("Sudo Invocations: %s", commaInt(r.SudoCount)),
		fmt.Sprintf("New Accounts:     %s", commaInt(r.AccountCreates)),
	)
	if len(r.FailedBySource) > 0 {
		out = append(out, "", "Top failed SSH sources:")
		for _, kv := range topN(r.FailedBySource, 5) {
			out = append(out, fmt.Sprintf("  %-22s %s attempts", kv.Key, commaInt(kv.Value)))
		}
	}
	if len(r.BruteForce) > 0 {
		out = append(out, "", "BRUTE FORCE DETECTED:")
		for _, b := range r.BruteForce {
			window := ""
			if !b.LastSeen.IsZero() && !b.FirstSeen.IsZero() {
				window = " over " + b.LastSeen.Sub(b.FirstSeen).Truncate(time.Minute).String()
			}
			out = append(out, fmt.Sprintf("  %s — %d failures across %d account(s)%s",
				b.Source, b.Failures, b.UniqueAccounts, window))
			if len(b.Accounts) > 0 {
				out = append(out, "    Targeted: "+strings.Join(b.Accounts, ", "))
			}
		}
	}
	if len(r.SuccessAfterBF) > 0 {
		out = append(out, "", "CRITICAL — Successful login after brute force:")
		for _, s := range r.SuccessAfterBF {
			out = append(out, fmt.Sprintf("  [CRITICAL] %s → %s @ %s",
				s.Source, s.User, s.When.Format("2006-01-02 15:04:05")))
		}
	}
	if len(r.SudoByUser) > 0 {
		out = append(out, "", "Sudo by user:")
		for _, kv := range topN(r.SudoByUser, 5) {
			out = append(out, fmt.Sprintf("  %-20s %s commands", kv.Key, commaInt(kv.Value)))
		}
	}
	if len(r.AccountChanges) > 0 {
		out = append(out, "", "Account changes:")
		for i, c := range r.AccountChanges {
			if i >= 5 {
				out = append(out, fmt.Sprintf("  ... %d more (see findings)", len(r.AccountChanges)-i))
				break
			}
			out = append(out, "  • "+c)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Syslog analysis
// ---------------------------------------------------------------------------

// SyslogResult summarises generic syslog/messages content.
type SyslogResult struct {
	TotalLines    int
	KernelMsgs    int
	OOMKills      int
	ServiceFails  int
	ModuleLoads   []string
	Errors        []string
	Findings      []Finding
}

// AnalyzeSyslog scans syslog/messages files under root for IoCs.
func AnalyzeSyslog(root string) (*SyslogResult, error) {
	r := &SyslogResult{}

	files := findFilesByPrefix(root, []string{"syslog", "messages", "kern.log", "daemon.log"})
	if len(files) == 0 {
		return r, fmt.Errorf("no syslog/messages/kern.log found under %s", root)
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			r.TotalLines++
			lower := strings.ToLower(line)
			if strings.Contains(lower, "kernel:") {
				r.KernelMsgs++
			}
			if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom-killer") {
				r.OOMKills++
				r.Findings = append(r.Findings, Finding{
					Severity:       SeverityMedium,
					Title:          "OOM-killer invocation",
					Description:    strings.TrimSpace(line),
					Source:         "syslog",
					Timestamp:      parseSyslogTimestamp(line),
				})
			}
			if strings.Contains(lower, "module loaded") || strings.Contains(lower, "loaded module") || strings.Contains(lower, "loading module") {
				r.ModuleLoads = append(r.ModuleLoads, strings.TrimSpace(line))
				r.Findings = append(r.Findings, Finding{
					Severity:       SeverityMedium,
					Title:          "Kernel module loaded",
					Description:    strings.TrimSpace(line),
					MITRETechnique: "T1547.006",
					Source:         "syslog",
					Timestamp:      parseSyslogTimestamp(line),
				})
			}
			if strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
				r.ServiceFails++
				if len(r.Errors) < 50 {
					r.Errors = append(r.Errors, strings.TrimSpace(line))
				}
			}
		}
		f.Close()
	}
	return r, nil
}

func findFilesByPrefix(root string, prefixes []string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		for _, pre := range prefixes {
			if strings.HasPrefix(name, pre) {
				out = append(out, p)
				return nil
			}
		}
		return nil
	})
	return out
}

// FormatSyslog renders a SyslogResult.
func FormatSyslog(r *SyslogResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total lines:        %s", commaInt(r.TotalLines)),
		fmt.Sprintf("Kernel messages:    %s", commaInt(r.KernelMsgs)),
		fmt.Sprintf("OOM-killer events:  %s", commaInt(r.OOMKills)),
		fmt.Sprintf("Service failures:   %s", commaInt(r.ServiceFails)),
		fmt.Sprintf("Module load events: %d", len(r.ModuleLoads)),
	}
	if len(r.ModuleLoads) > 0 {
		out = append(out, "", "Recent module loads:")
		for i, m := range r.ModuleLoads {
			if i >= 5 {
				out = append(out, fmt.Sprintf("  ... %d more", len(r.ModuleLoads)-i))
				break
			}
			out = append(out, "  • "+m)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Web server log analysis
// ---------------------------------------------------------------------------

// WebLogResult summarises Apache/Nginx access-log activity.
type WebLogResult struct {
	TotalRequests int
	UniqueIPs     int
	StatusCounts  map[int]int
	TopIPs        []kv

	SQLi          []WebHit
	XSS           []WebHit
	PathTraversal []WebHit
	WebShells     []WebHit
	CmdInjection  []WebHit
	Scanners      []WebHit
	Findings      []Finding
}

// WebHit is a flagged web-log line.
type WebHit struct {
	Severity string
	IP       string
	Method   string
	Path     string
	Status   int
	Reason   string
}

// AnalyzeWebLogs scans every access log under root and runs detection.
func AnalyzeWebLogs(root string) (*WebLogResult, error) {
	r := &WebLogResult{StatusCounts: map[int]int{}}

	files := findWebLogFiles(root)
	if len(files) == 0 {
		return r, fmt.Errorf("no access logs found under %s", root)
	}

	ipCounts := map[string]int{}
	scannerSrc := map[string]int{}

	sqliPats := []string{"union+select", "union%20select", " or 1=1", "%20or%201=1", "drop+table", "select+from", " ' or '", "waitfor+delay", "sqlmap"}
	xssPats := []string{"<script", "javascript:", "onerror=", "onload=", "alert("}
	traversalPats := []string{"../../", "..%2f", "%2e%2e/", "/etc/passwd", "/etc/shadow"}
	webshellPats := []string{".php?cmd=", ".php?exec=", ".asp?cmd=", ".aspx?cmd=", "shell.php", "/cmd.php", ".jsp?cmd="}
	cmdInjectionPats := []string{";cat ", ";id;", ";whoami", "|whoami", "&&whoami", "%3bwhoami", "%26%26whoami"}
	scannerAgents := []string{"nikto", "sqlmap", "nessus", "nmap", "acunetix", "wpscan", "dirb", "gobuster", "ffuf"}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			r.TotalRequests++
			ip, method, path, status, ua := parseAccessLine(line)
			if ip != "" {
				ipCounts[ip]++
			}
			if status > 0 {
				r.StatusCounts[status]++
			}
			lowerLine := strings.ToLower(path) + " " + strings.ToLower(ua)

			match := func(pats []string) bool {
				for _, p := range pats {
					if strings.Contains(lowerLine, p) {
						return true
					}
				}
				return false
			}

			if match(sqliPats) {
				h := WebHit{Severity: SeverityHigh, IP: ip, Method: method, Path: path, Status: status, Reason: "SQL injection pattern"}
				r.SQLi = append(r.SQLi, h)
				r.Findings = append(r.Findings, webFinding(h, "T1190"))
			}
			if match(xssPats) {
				h := WebHit{Severity: SeverityMedium, IP: ip, Method: method, Path: path, Status: status, Reason: "XSS pattern"}
				r.XSS = append(r.XSS, h)
				r.Findings = append(r.Findings, webFinding(h, "T1190"))
			}
			if match(traversalPats) {
				h := WebHit{Severity: SeverityHigh, IP: ip, Method: method, Path: path, Status: status, Reason: "Path traversal"}
				r.PathTraversal = append(r.PathTraversal, h)
				r.Findings = append(r.Findings, webFinding(h, "T1190"))
			}
			if match(webshellPats) {
				h := WebHit{Severity: SeverityCritical, IP: ip, Method: method, Path: path, Status: status, Reason: "Web shell access"}
				r.WebShells = append(r.WebShells, h)
				r.Findings = append(r.Findings, webFinding(h, "T1505.003"))
			}
			if match(cmdInjectionPats) {
				h := WebHit{Severity: SeverityHigh, IP: ip, Method: method, Path: path, Status: status, Reason: "Command injection pattern"}
				r.CmdInjection = append(r.CmdInjection, h)
				r.Findings = append(r.Findings, webFinding(h, "T1190"))
			}
			lowerUA := strings.ToLower(ua)
			for _, sa := range scannerAgents {
				if strings.Contains(lowerUA, sa) {
					scannerSrc[ip]++
					if scannerSrc[ip] == 1 {
						h := WebHit{Severity: SeverityMedium, IP: ip, Method: method, Path: path, Status: status, Reason: "Known scanner: " + sa}
						r.Scanners = append(r.Scanners, h)
						r.Findings = append(r.Findings, webFinding(h, "T1595"))
					}
					break
				}
			}
		}
		f.Close()
	}

	r.UniqueIPs = len(ipCounts)
	r.TopIPs = topN(ipCounts, 5)
	return r, nil
}

func webFinding(h WebHit, mitre string) Finding {
	return Finding{
		Severity:       h.Severity,
		Title:          h.Reason + " from " + h.IP,
		Description:    fmt.Sprintf("%s %s → %d", h.Method, h.Path, h.Status),
		MITRETechnique: mitre,
		IOCType:        "ip",
		IOCValue:       h.IP,
		Source:         "weblog",
	}
}

func findWebLogFiles(root string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.Contains(name, "access") && (strings.HasSuffix(name, ".log") || strings.Contains(name, "access.log")) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// parseAccessLine parses a "common log format" / "combined log format" line.
// IPs and paths are returned even when other fields are missing.
var accessLogRE = regexp.MustCompile(`^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+)\s+(?P<path>\S+)[^"]*" (?P<status>\d+) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?`)

func parseAccessLine(line string) (ip, method, path string, status int, ua string) {
	m := accessLogRE.FindStringSubmatch(line)
	if len(m) < 5 {
		// Best-effort: pull a leading IP at minimum.
		fields := strings.Fields(line)
		if len(fields) > 0 {
			ip = fields[0]
		}
		return
	}
	ip = m[1]
	method = m[2]
	path = m[3]
	status = atoiSafe(m[4])
	if len(m) >= 6 {
		ua = m[5]
	}
	return
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// FormatWebLogs renders a WebLogResult.
func FormatWebLogs(r *WebLogResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Requests: %s", commaInt(r.TotalRequests)),
		fmt.Sprintf("Unique IPs:     %s", commaInt(r.UniqueIPs)),
	}
	if len(r.StatusCounts) > 0 {
		out = append(out, "", "Response Codes:")
		statuses := make([]int, 0, len(r.StatusCounts))
		for s := range r.StatusCounts {
			statuses = append(statuses, s)
		}
		sort.Ints(statuses)
		for _, s := range statuses {
			out = append(out, fmt.Sprintf("  %d:  %s", s, commaInt(r.StatusCounts[s])))
		}
	}
	if len(r.TopIPs) > 0 {
		out = append(out, "", "Top requesting IPs:")
		for _, kv := range r.TopIPs {
			out = append(out, fmt.Sprintf("  %-22s %s requests", kv.Key, commaInt(kv.Value)))
		}
	}
	out = append(out, "", "Suspicious activity:")
	suspicious := []struct {
		label string
		hits  []WebHit
	}{
		{"SQL injection attempts", r.SQLi},
		{"XSS attempts", r.XSS},
		{"Path traversal attempts", r.PathTraversal},
		{"Web shell access", r.WebShells},
		{"Command injection attempts", r.CmdInjection},
		{"Scanner activity", r.Scanners},
	}
	any := false
	for _, group := range suspicious {
		if len(group.hits) == 0 {
			continue
		}
		any = true
		out = append(out, fmt.Sprintf("  %s: %d", group.label, len(group.hits)))
		for i, h := range group.hits {
			if i >= 3 {
				out = append(out, fmt.Sprintf("    ... %d more (see findings)", len(group.hits)-i))
				break
			}
			truncPath := h.Path
			if len(truncPath) > 80 {
				truncPath = truncPath[:80] + "…"
			}
			out = append(out, fmt.Sprintf("    [%s] %s — %s", strings.ToUpper(h.Severity), h.IP, truncPath))
		}
	}
	if !any {
		out = append(out, "  No web-attack patterns detected.")
	}
	return out
}

// ---------------------------------------------------------------------------
// Journal log analysis
// ---------------------------------------------------------------------------

// JournalResult summarises systemd journal output (collected via journalctl --output=json).
type JournalResult struct {
	TotalEntries int
	ByPriority   map[int]int
	ByUnit       map[string]int
	Errors       int
	Critical     int
	Findings     []Finding
}

// AnalyzeJournal scans journal_*.json files under root.
func AnalyzeJournal(root string) (*JournalResult, error) {
	r := &JournalResult{
		ByPriority: map[int]int{},
		ByUnit:     map[string]int{},
	}

	files := findFilesBySuffix(root, []string{".json"})
	jsonFiles := []string{}
	for _, f := range files {
		base := strings.ToLower(filepath.Base(f))
		if strings.HasPrefix(base, "journal") {
			jsonFiles = append(jsonFiles, f)
		}
	}
	if len(jsonFiles) == 0 {
		return r, fmt.Errorf("no journal_*.json found under %s", root)
	}

	for _, file := range jsonFiles {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var entry map[string]interface{}
			if err := json.Unmarshal(line, &entry); err != nil {
				continue
			}
			r.TotalEntries++
			if pStr, ok := entry["PRIORITY"].(string); ok {
				p := atoiSafe(pStr)
				r.ByPriority[p]++
				if p <= 3 {
					r.Errors++
				}
				if p <= 2 {
					r.Critical++
				}
			}
			if unit, ok := entry["_SYSTEMD_UNIT"].(string); ok {
				r.ByUnit[unit]++
			} else if unit, ok := entry["UNIT"].(string); ok {
				r.ByUnit[unit]++
			}
		}
		f.Close()
	}
	return r, nil
}

func findFilesBySuffix(root string, suffixes []string) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		for _, suf := range suffixes {
			if strings.HasSuffix(name, suf) {
				out = append(out, p)
				return nil
			}
		}
		return nil
	})
	return out
}

// FormatJournal renders a JournalResult.
func FormatJournal(r *JournalResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total entries:   %s", commaInt(r.TotalEntries)),
		fmt.Sprintf("Critical (≤2):  %s", commaInt(r.Critical)),
		fmt.Sprintf("Errors (≤3):    %s", commaInt(r.Errors)),
	}
	if len(r.ByUnit) > 0 {
		out = append(out, "", "Top units (by entry count):")
		for _, kv := range topN(r.ByUnit, 10) {
			out = append(out, fmt.Sprintf("  %-30s %s", truncRemote(kv.Key, 30), commaInt(kv.Value)))
		}
	}
	return out
}

func truncRemote(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
