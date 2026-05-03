package analysis

import (
	"fmt"
	"sort"
	"strings"
	"time"

	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/mitre"
)

// CorrelationResult is the output of grouping case findings into time-bounded
// clusters. Each cluster is a list of findings on the same logical host within
// a 30-minute sliding window.
type CorrelationResult struct {
	Clusters   []FindingCluster
	Techniques []string // distinct MITRE technique IDs across all findings
	Total      int
}

// FindingCluster is a tight group of related findings — typically the
// fingerprint of a single attacker session.
type FindingCluster struct {
	Host     string
	From     time.Time
	To       time.Time
	Findings []casemanager.Finding
	// Techniques observed in this cluster.
	Techniques []string
}

// CorrelateFindings groups the case's findings into clusters by host and time
// window. Empty hosts (findings without a Source/Host hint) are folded under
// "(unknown)". Sliding window: 30 minutes.
func CorrelateFindings(findings []casemanager.Finding) *CorrelationResult {
	res := &CorrelationResult{Total: len(findings)}
	if len(findings) == 0 {
		return res
	}

	// Sort by timestamp ascending for window walking.
	sorted := make([]casemanager.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].DiscoveredAt.Before(sorted[j].DiscoveredAt)
	})

	const window = 30 * time.Minute
	hostBuckets := map[string]*FindingCluster{}

	techSet := map[string]bool{}
	flush := func(host string) {
		c, ok := hostBuckets[host]
		if !ok || c == nil {
			return
		}
		// Distinct techniques inside the cluster.
		seen := map[string]bool{}
		for _, f := range c.Findings {
			if f.MITRETechnique != "" && !seen[f.MITRETechnique] {
				seen[f.MITRETechnique] = true
				c.Techniques = append(c.Techniques, f.MITRETechnique)
			}
		}
		sort.Strings(c.Techniques)
		res.Clusters = append(res.Clusters, *c)
		delete(hostBuckets, host)
	}

	for _, f := range sorted {
		host := hostFromFinding(f)
		if c, ok := hostBuckets[host]; ok {
			if f.DiscoveredAt.Sub(c.To) > window {
				flush(host)
			}
		}
		c, ok := hostBuckets[host]
		if !ok || c == nil {
			c = &FindingCluster{
				Host: host,
				From: f.DiscoveredAt,
			}
			hostBuckets[host] = c
		}
		c.To = f.DiscoveredAt
		c.Findings = append(c.Findings, f)
		if f.MITRETechnique != "" {
			techSet[f.MITRETechnique] = true
		}
	}
	for host := range hostBuckets {
		flush(host)
	}

	// Order clusters chronologically.
	sort.Slice(res.Clusters, func(i, j int) bool {
		return res.Clusters[i].From.Before(res.Clusters[j].From)
	})

	for t := range techSet {
		res.Techniques = append(res.Techniques, t)
	}
	sort.Strings(res.Techniques)
	return res
}

// hostFromFinding extracts a host hint from a finding's description blob.
// Findings emitted by remote_* sources prefix titles with "host:", which is
// what we look for first; otherwise we fall back to "(unknown)".
func hostFromFinding(f casemanager.Finding) string {
	for _, line := range strings.Split(f.Description, "\n") {
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "host:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return "(unknown)"
}

// FormatCorrelation renders a CorrelationResult for the TUI.
func FormatCorrelation(r *CorrelationResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total Findings:  %d", r.Total),
		fmt.Sprintf("Clusters:        %d", len(r.Clusters)),
		"",
		"Automated correlation — verify findings manually before drawing conclusions.",
		"",
	}

	for i, c := range r.Clusters {
		if i >= 10 {
			out = append(out, fmt.Sprintf("  ... %d more clusters", len(r.Clusters)-i))
			break
		}
		out = append(out, fmt.Sprintf("Cluster %d — %s  (%s → %s, %d findings)",
			i+1, c.Host,
			c.From.Format("2006-01-02 15:04"),
			c.To.Format("2006-01-02 15:04"),
			len(c.Findings)))
		for j, f := range c.Findings {
			if j >= 6 {
				out = append(out, fmt.Sprintf("    ... %d more findings", len(c.Findings)-j))
				break
			}
			out = append(out, fmt.Sprintf("  [%s] %s — %s",
				strings.ToUpper(f.Severity),
				f.DiscoveredAt.Format("15:04:05"),
				f.Title))
		}
		if len(c.Techniques) > 0 {
			out = append(out, "    MITRE: "+strings.Join(c.Techniques, ", "))
		}
		out = append(out, "")
	}
	return out
}

// ---------------------------------------------------------------------------
// MITRE mapping
// ---------------------------------------------------------------------------

// MITREMappingResult is grouping of case findings by tactic/technique.
type MITREMappingResult struct {
	ByTactic map[mitre.Tactic][]MITRECount // ordered presentation: iterate mitre.TacticOrder
	Total    int
	Unique   int
}

// MITRECount is the count of findings observed per technique.
type MITRECount struct {
	Technique mitre.Technique
	Count     int
}

// BuildMITREMapping collects every finding's MITRE technique and groups by tactic.
func BuildMITREMapping(findings []casemanager.Finding) *MITREMappingResult {
	res := &MITREMappingResult{
		ByTactic: map[mitre.Tactic][]MITRECount{},
		Total:    len(findings),
	}
	counts := map[string]int{}
	for _, f := range findings {
		if f.MITRETechnique == "" {
			continue
		}
		counts[f.MITRETechnique]++
	}
	res.Unique = len(counts)

	for id, n := range counts {
		t, ok := mitre.Techniques[id]
		if !ok {
			t = mitre.Technique{ID: id, Name: id}
		}
		res.ByTactic[t.Tactic] = append(res.ByTactic[t.Tactic], MITRECount{
			Technique: t,
			Count:     n,
		})
	}
	for k := range res.ByTactic {
		sort.Slice(res.ByTactic[k], func(i, j int) bool {
			return res.ByTactic[k][i].Technique.ID < res.ByTactic[k][j].Technique.ID
		})
	}
	return res
}

// FormatMITREMapping renders a MITREMappingResult for the TUI.
func FormatMITREMapping(r *MITREMappingResult) []string {
	if r == nil {
		return nil
	}
	out := []string{
		fmt.Sprintf("Total findings:   %d", r.Total),
		fmt.Sprintf("Unique techniques: %d", r.Unique),
	}
	if r.Unique == 0 {
		out = append(out, "", "No MITRE-tagged findings yet.",
			"Run threat hunting / log analysis to populate technique attributions.")
		return out
	}
	out = append(out, "")
	for _, tactic := range mitre.TacticOrder {
		entries := r.ByTactic[tactic]
		if len(entries) == 0 {
			continue
		}
		out = append(out, strings.ToUpper(string(tactic)))
		for _, e := range entries {
			out = append(out, fmt.Sprintf("  %-12s %-44s %d findings",
				e.Technique.ID, e.Technique.Name, e.Count))
		}
		out = append(out, "")
	}
	return out
}
