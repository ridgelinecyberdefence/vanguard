package disk

import (
	"path/filepath"
	"time"
)

// Status tracks a disk collection / parser operation's lifecycle.
type Status int

const (
	StatusPending Status = iota
	StatusRunning
	StatusSuccess
	StatusPartial
	StatusFailed
	StatusSkipped
)

func (s Status) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusRunning:
		return "running"
	case StatusSuccess:
		return "success"
	case StatusPartial:
		return "partial"
	case StatusFailed:
		return "failed"
	case StatusSkipped:
		return "skipped"
	}
	return "unknown"
}

// CollectionResult is the outcome of a single collection or parse step.
type CollectionResult struct {
	Name       string
	Status     Status
	Duration   time.Duration
	OutputDir  string
	OutputFile string // single-file outputs (e.g. EvtxECmd CSV)
	Files      int
	Bytes      int64
	Lines      int
	Stdout     string
	Stderr     string
	Warnings   []string
	Error      string
}

// CollectionTimestamp returns the timestamp suffix used for a collection dir.
func CollectionTimestamp() string {
	return time.Now().Format("20060102_150405")
}

// OutputBase returns output/{case}/disk.
func OutputBase(rootDir, caseID string) string {
	return filepath.Join(rootDir, "output", caseID, "disk")
}

// CollectionDir returns output/{case}/disk/{ts}/{subdir}.
func CollectionDir(rootDir, caseID, ts, subdir string) string {
	return filepath.Join(OutputBase(rootDir, caseID), ts, subdir)
}
