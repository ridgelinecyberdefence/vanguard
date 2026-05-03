package memory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AnalysisStepUpdate is sent during a multi-plugin analysis run.
type AnalysisStepUpdate struct {
	StepIndex int
	Result    *PluginResult // nil = step started, non-nil = step finished
}

// AnalysisRequest configures a multi-plugin analysis run.
type AnalysisRequest struct {
	DumpFile   string
	OutputDir  string
	Plugins    []string
	DetectOS   bool
}

// RunFullAnalysis executes a curated plugin set against dumpFile.
// Per-plugin progress is sent on updates. The channel is closed when done.
func (r *VolatilityRunner) RunFullAnalysis(ctx context.Context, req AnalysisRequest, updates chan<- AnalysisStepUpdate) AnalysisSummary {
	defer func() {
		if updates != nil {
			close(updates)
		}
	}()

	summary := AnalysisSummary{
		DumpFile:  req.DumpFile,
		OutputDir: req.OutputDir,
		StartedAt: time.Now(),
	}

	if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
		summary.Error = fmt.Sprintf("creating output dir: %v", err)
		summary.FinishedAt = time.Now()
		summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
		return summary
	}

	plugins := req.Plugins

	if req.DetectOS && len(plugins) == 0 {
		osFamily, desc, err := r.DetectOS(ctx, req.DumpFile, req.OutputDir)
		if err != nil {
			summary.Error = fmt.Sprintf("OS detection failed: %v", err)
			summary.FinishedAt = time.Now()
			summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
			return summary
		}
		summary.DetectedOS = desc
		switch osFamily {
		case "windows":
			plugins = WindowsFullAnalysisPlugins()
		case "linux":
			plugins = LinuxFullAnalysisPlugins()
		default:
			summary.Error = "unable to determine OS plugin set"
			summary.FinishedAt = time.Now()
			summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
			return summary
		}
	}

	results := make([]PluginResult, 0, len(plugins))
	for i, plugin := range plugins {
		if updates != nil {
			updates <- AnalysisStepUpdate{StepIndex: i, Result: nil}
		}

		stepResult := r.RunPlugin(ctx, req.DumpFile, plugin, req.OutputDir)
		results = append(results, stepResult)

		// Tally rough counts by plugin type.
		switch plugin {
		case "windows.pslist", "linux.pslist":
			summary.Processes = CountTableRows(stepResult.OutFile)
		case "windows.netscan", "windows.netstat", "linux.sockstat":
			if c := CountTableRows(stepResult.OutFile); c > summary.Connections {
				summary.Connections = c
			}
		case "windows.malfind", "linux.malfind":
			findings := ParseMalfindFindings(stepResult.OutFile, plugin)
			summary.Suspicious += len(findings)
			summary.Findings = append(summary.Findings, findings...)
		case "windows.svcscan":
			summary.Services = CountTableRows(stepResult.OutFile)
		case "windows.registry.hivelist":
			summary.RegistryHives = CountTableRows(stepResult.OutFile)
		case "linux.lsmod":
			summary.KernelModules = CountTableRows(stepResult.OutFile)
		}

		if updates != nil {
			r := stepResult
			updates <- AnalysisStepUpdate{StepIndex: i, Result: &r}
		}
	}

	summary.Plugins = results
	summary.FinishedAt = time.Now()
	summary.Duration = summary.FinishedAt.Sub(summary.StartedAt)
	summary.Success = true

	r.writeSummaryFile(req.OutputDir, &summary)
	return summary
}

// writeSummaryFile produces a human-readable summary of the analysis run.
func (r *VolatilityRunner) writeSummaryFile(outDir string, s *AnalysisSummary) {
	path := filepath.Join(outDir, "analysis_summary.txt")

	var b strings.Builder
	b.WriteString("VanGuard Memory Analysis — Summary\n")
	b.WriteString(strings.Repeat("=", 50) + "\n\n")
	fmt.Fprintf(&b, "Dump File:    %s\n", s.DumpFile)
	fmt.Fprintf(&b, "Detected OS:  %s\n", s.DetectedOS)
	fmt.Fprintf(&b, "Output Dir:   %s\n", s.OutputDir)
	fmt.Fprintf(&b, "Started:      %s\n", s.StartedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "Finished:     %s\n", s.FinishedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&b, "Duration:     %s\n", s.Duration.Truncate(time.Second))
	b.WriteString("\nCounts\n")
	b.WriteString(strings.Repeat("-", 50) + "\n")
	fmt.Fprintf(&b, "Processes:           %d\n", s.Processes)
	fmt.Fprintf(&b, "Network Connections: %d\n", s.Connections)
	fmt.Fprintf(&b, "Suspicious (malfind): %d\n", s.Suspicious)
	fmt.Fprintf(&b, "Services:            %d\n", s.Services)
	fmt.Fprintf(&b, "Registry Hives:      %d\n", s.RegistryHives)
	fmt.Fprintf(&b, "Kernel Modules:      %d\n", s.KernelModules)

	b.WriteString("\nPlugin Results\n")
	b.WriteString(strings.Repeat("-", 50) + "\n")
	for _, p := range s.Plugins {
		fmt.Fprintf(&b, "%-32s %-10s %s\n",
			p.Plugin, p.Status.String(), p.Duration.Truncate(time.Second))
		if p.Error != "" {
			fmt.Fprintf(&b, "    error: %s\n", p.Error)
		}
	}

	if len(s.Findings) > 0 {
		b.WriteString("\nFindings\n")
		b.WriteString(strings.Repeat("-", 50) + "\n")
		for _, f := range s.Findings {
			fmt.Fprintf(&b, "[%s] %s\n", strings.ToUpper(f.Severity), f.Title)
			if f.Address != "" {
				fmt.Fprintf(&b, "    address: %s\n", f.Address)
			}
		}
	}

	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

// AnalysisOutputDir computes a timestamped subdir under output/{case}/memory/.
func AnalysisOutputDir(rootDir, caseID string) string {
	ts := time.Now().Format("20060102_150405")
	return filepath.Join(rootDir, "output", caseID, "memory", "analysis_"+ts)
}
