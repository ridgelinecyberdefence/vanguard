package network

import (
	"context"
	"sync"
	"time"
)

// TriageCommand describes one step in a remote triage sequence.
type TriageCommand struct {
	Name    string
	Command string
	Timeout time.Duration
}

// MultiTargetResult captures the outcome of a single fan-out command on one target.
type MultiTargetResult struct {
	Host     string        `json:"Host"`
	Status   string        `json:"Status"` // "success" | "failed" | "skipped"
	Stdout   string        `json:"Stdout"`
	Stderr   string        `json:"Stderr,omitempty"`
	Error    string        `json:"Error,omitempty"`
	Duration time.Duration `json:"Duration"`
}

// MultiTargetJob describes a fan-out single-command job.
type MultiTargetJob struct {
	Targets     []Target
	Command     string
	Timeout     time.Duration
	MaxParallel int
	ProgressFn  func(completed, total int, current *MultiTargetResult)
}

// ExecuteMulti runs Command across all Targets with bounded parallelism.
// Results are returned in the same order as Targets.
func ExecuteMulti(ctx context.Context, job *MultiTargetJob) []MultiTargetResult {
	n := len(job.Targets)
	results := make([]MultiTargetResult, n)
	maxP := job.MaxParallel
	if maxP <= 0 {
		maxP = 5
	}
	sem := make(chan struct{}, maxP)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, t := range job.Targets {
		wg.Add(1)
		go func(idx int, target Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = MultiTargetResult{
					Host:   targetHost(target),
					Status: "skipped",
					Error:  "context cancelled",
				}
				return
			}
			tout := job.Timeout
			if tout <= 0 {
				tout = 60 * time.Second
			}
			start := time.Now()
			res := ExecOnTarget(target, job.Command, tout)
			mtr := MultiTargetResult{
				Host:     targetHost(target),
				Duration: time.Since(start),
				Stdout:   res.Stdout,
				Stderr:   res.Stderr,
			}
			if res.Err != nil {
				mtr.Status = "failed"
				mtr.Error = res.Err.Error()
			} else {
				mtr.Status = "success"
			}
			results[idx] = mtr
			mu.Lock()
			done++
			if job.ProgressFn != nil {
				job.ProgressFn(done, n, &mtr)
			}
			mu.Unlock()
		}(i, t)
	}
	wg.Wait()
	return results
}

// targetHost returns the most useful address string for display.
func targetHost(t Target) string {
	if t.IPAddress != "" {
		return t.IPAddress
	}
	return t.Hostname
}
