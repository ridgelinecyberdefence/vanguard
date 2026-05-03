package memory

import "time"

// CaptureTool identifies the memory capture tool used.
type CaptureTool string

const (
	ToolDumpIt       CaptureTool = "dumpit"
	ToolWinPmem      CaptureTool = "winpmem"
	ToolBelkasoft    CaptureTool = "belkasoft"
	ToolMagnetRAM    CaptureTool = "magnet_ram"
	ToolAVML         CaptureTool = "avml"
	ToolLiME         CaptureTool = "lime"
	ToolVelociraptor CaptureTool = "velociraptor"
	ToolRemote       CaptureTool = "remote"
)

// CaptureStatus represents the lifecycle of a capture operation.
type CaptureStatus int

const (
	CaptureIdle CaptureStatus = iota
	CapturePreparing
	CaptureRunning
	CaptureFinalizing
	CaptureSuccess
	CaptureFailed
)

func (s CaptureStatus) String() string {
	switch s {
	case CaptureIdle:
		return "idle"
	case CapturePreparing:
		return "preparing"
	case CaptureRunning:
		return "running"
	case CaptureFinalizing:
		return "finalizing"
	case CaptureSuccess:
		return "success"
	case CaptureFailed:
		return "failed"
	}
	return "unknown"
}

// CaptureProgress is sent periodically while a capture is running.
type CaptureProgress struct {
	Status      CaptureStatus
	BytesWritten int64
	TotalBytes   int64 // 0 if unknown
	Message      string
}

// CaptureResult is the final outcome of a memory capture operation.
type CaptureResult struct {
	Tool       CaptureTool
	Hostname   string
	OutputPath string
	Size       int64
	SHA256     string
	Duration   time.Duration
	Stdout     string
	Stderr     string
	Error      string
	Success    bool
}

// AnalysisStepStatus tracks a single Volatility plugin's progress.
type AnalysisStepStatus int

const (
	StepPending AnalysisStepStatus = iota
	StepRunning
	StepSuccess
	StepFailed
	StepSkipped
)

func (s AnalysisStepStatus) String() string {
	switch s {
	case StepPending:
		return "pending"
	case StepRunning:
		return "running"
	case StepSuccess:
		return "success"
	case StepFailed:
		return "failed"
	case StepSkipped:
		return "skipped"
	}
	return "unknown"
}

// PluginResult captures the outcome of a single Volatility3 plugin invocation.
type PluginResult struct {
	Plugin    string
	Status    AnalysisStepStatus
	Duration  time.Duration
	OutFile   string // text output path
	CSVFile   string // optional CSV path
	Lines     int
	Error     string
	Warnings  []string
}

// AnalysisSummary is the final report for a memory analysis run.
type AnalysisSummary struct {
	DumpFile       string
	OutputDir      string
	DetectedOS     string // e.g. "Windows 10 22H2"
	StartedAt      time.Time
	FinishedAt     time.Time
	Duration       time.Duration
	Plugins        []PluginResult
	Processes      int
	Connections    int
	Suspicious     int // malfind hits
	Services       int
	RegistryHives  int
	KernelModules  int
	Findings       []Finding
	Error          string
	Success        bool
}

// Finding describes something noteworthy discovered during analysis (malfind / yara).
type Finding struct {
	Severity string // "critical", "high", "medium", "low", "info"
	Title    string
	Detail   string
	Source   string // plugin name
	PID      int
	Process  string
	Address  string
}

// DumpInfo describes a memory dump file on disk.
type DumpInfo struct {
	Name     string
	Path     string
	Size     int64
	Modified time.Time
	Format   string // "raw", "lime", "vmem", "dmp"
}
