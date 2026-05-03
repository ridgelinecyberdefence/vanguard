// Package usecases drives VanGuard's pre-built investigation workflows: 28
// curated use cases (Windows, Linux, cross-platform) that take an analyst from
// initial triage through phased evidence collection, parsing, and reporting.
//
// Each use case is a YAML-serialisable struct so users can both run the
// built-in catalog and drop their own UC-CUSTOM-* files into usecases/.
package usecases

// Severity is one of "critical" / "high" / "medium" / "low" / "varies".
// Stored as a string (rather than a typed enum) so YAML round-trips cleanly
// without custom marshalling.
type Severity = string

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityVaries   = "varies"
)

// Platform values used by both UseCase.Platform and UseCaseStep.Platform.
const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
	PlatformBoth    = "both"
	PlatformXP      = "cross-platform"
)

// StepType identifies how a UseCaseStep's payload runs.
const (
	StepCommand      = "command"      // shell / PowerShell command line
	StepTool         = "tool"         // tool ID + extra arg template
	StepVelociraptor = "velociraptor" // VQL launched via the local server (placeholder hook)
	StepAnalysis     = "analysis"     // calls into internal/analysis (forward-compat hook)
	StepManual       = "manual"       // shows instructions and waits for analyst ack
)

// UseCase is the top-level definition consumed by the runner.
type UseCase struct {
	Name          string             `yaml:"name"`
	ID            string             `yaml:"id"`
	Description   string             `yaml:"description"`
	Platform      string             `yaml:"platform"`       // windows | linux | cross-platform
	Severity      string             `yaml:"severity"`       // critical | high | medium | low | varies
	EstimatedTime string             `yaml:"estimated_time"` // e.g. "45-60 minutes"
	MITREAttack   []string           `yaml:"mitre_attack"`
	Prerequisites []string           `yaml:"prerequisites"`
	Parameters    []UseCaseParameter `yaml:"parameters,omitempty"`
	Phases        []UseCasePhase     `yaml:"phases"`
	Output        UseCaseOutput      `yaml:"output,omitempty"`
	AnalysisGuide []string           `yaml:"analysis_guidance,omitempty"`
	FollowUp      []string           `yaml:"follow_up,omitempty"`
}

// UseCaseParameter is one user-supplied input to a use case run.
type UseCaseParameter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default,omitempty"`
	Type        string `yaml:"type"` // string | path | datetime | selection
}

// UseCasePhase groups related steps. Phases run sequentially.
type UseCasePhase struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description,omitempty"`
	Steps       []UseCaseStep `yaml:"steps"`
}

// UseCaseStep is a single executable unit inside a phase.
type UseCaseStep struct {
	Name        string            `yaml:"name"`
	Type        string            `yaml:"type"`
	Tool        string            `yaml:"tool,omitempty"`
	Command     string            `yaml:"command,omitempty"`
	Platform    string            `yaml:"platform,omitempty"` // windows | linux | both
	Args        map[string]string `yaml:"args,omitempty"`
	Timeout     int               `yaml:"timeout,omitempty"` // seconds; 0 → 300
	Optional    bool              `yaml:"optional,omitempty"`
	Description string            `yaml:"description,omitempty"`
}

// UseCaseOutput configures post-run reporting.
type UseCaseOutput struct {
	Format          string `yaml:"format,omitempty"`           // html | csv | txt
	Template        string `yaml:"template,omitempty"`
	IncludeTimeline bool   `yaml:"include_timeline,omitempty"`
}

// MatchesPlatform reports whether step (or use case) p is applicable for
// runtime platform host. "both" / "cross-platform" / empty match everything.
func MatchesPlatform(p, host string) bool {
	switch p {
	case "", PlatformBoth, PlatformXP:
		return true
	}
	return p == host
}

// CountSteps returns the total step count across all phases.
func (uc *UseCase) CountSteps() int {
	n := 0
	for _, p := range uc.Phases {
		n += len(p.Steps)
	}
	return n
}
