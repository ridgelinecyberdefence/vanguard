package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/triage"
)

// triageRunState tracks a single in-flight or most-recent triage run so
// /api/triage/status has something to return without scraping the DB. We
// allow only one active run at a time — the SPA disables the launch
// buttons while running, but the server enforces it too.
type triageRunState struct {
	mu        sync.Mutex
	running   bool
	startedAt time.Time
	type_     string
	outputDir string
	last      *triage.CollectionSummary
}

var triageState triageRunState

// handleTriageRun — POST /api/triage/run.
//
// Body shape:
//
//	{
//	  "type":  "full|process_network|eventlogs|persistence|users|sysinfo|browser|custom",
//	  "steps": ["sysinfo","processes",...]   // only for type="custom"
//	}
//
// Returns 202 + {"status":"started","output_dir":"..."} immediately. All
// progress is streamed via the WebSocket as triage_progress / triage_complete
// events. See broadcastProgress in websocket.go.
func handleTriageRun(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	if ctx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest,
			"no active case — create or select one first")
		return
	}

	var req struct {
		Type  string   `json:"type"`
		Steps []string `json:"steps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}

	triageState.mu.Lock()
	if triageState.running {
		triageState.mu.Unlock()
		writeError(w, http.StatusConflict,
			"a triage run is already in progress — wait for it to finish")
		return
	}
	triageState.running = true
	triageState.startedAt = time.Now()
	triageState.type_ = req.Type
	triageState.last = nil
	triageState.mu.Unlock()

	// Build collector. Prefer the analyst recorded on the case so the audit
	// trail reflects who created the evidence.
	analyst := ctx.ActiveCase.Analyst
	if analyst == "" && ctx.Config != nil {
		analyst = ctx.Config.VanGuard.Analyst
	}
	org := ctx.ActiveCase.Organization
	if org == "" && ctx.Config != nil {
		org = ctx.Config.VanGuard.Organization
	}
	collector := triage.NewCollector(
		ctx.RootDir,
		ctx.ActiveCase.ID,
		ctx.Hostname,
		analyst,
		ctx.Platform,
		ctx.Elevated,
		ctx.Logger,
	)
	collector.CaseName = ctx.ActiveCase.Name
	collector.Organization = org

	allSteps := collector.Steps()
	indices, err := resolveTriageIndices(ctx.Platform, req.Type, req.Steps, allSteps)
	if err != nil {
		triageState.mu.Lock()
		triageState.running = false
		triageState.mu.Unlock()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Pre-compute the output dir so we can return it immediately. The
	// collector regenerates a fresh timestamp on its own Run; we mirror
	// the same format here so paths align.
	ts := time.Now().Format("20060102_150405")
	outputDir := collector.OutputDir(ts)
	triageState.mu.Lock()
	triageState.outputDir = outputDir
	triageState.mu.Unlock()

	// Cancellable task — the SPA's floating cancel bar maps to this ID.
	// taskCtx is threaded into Collector.Run so a Cancel from the UI
	// kills the active step's exec.CommandContext child and prevents
	// every subsequent step from starting.
	taskID, taskCtx, _ := StartTask("Quick Triage: " + req.Type)

	go runTriageInGoroutine(taskCtx, taskID, collector, indices, allSteps)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "started",
		"output_dir": outputDir,
		"steps":      stepNamesAt(allSteps, indices),
		"total":      len(indices),
		"task_id":    taskID,
	})
}

// runTriageInGoroutine is the goroutine that executes the collection and
// fans every step transition out as a triage_progress WebSocket event.
// On completion it emits a single triage_complete event with the summary
// and registers the result as evidence in the case DB.
func runTriageInGoroutine(taskCtx context.Context, taskID string, c *triage.Collector, indices []int, all []triage.StepDef) {
	defer func() {
		triageState.mu.Lock()
		triageState.running = false
		triageState.mu.Unlock()
	}()

	progressCh := make(chan triage.ProgressMsg, 16)
	doneCh := make(chan triage.CollectionSummary, 1)

	// Pump progress events to the websocket.
	go func() {
		for msg := range progressCh {
			if msg.StepIndex < 0 || msg.StepIndex >= len(all) {
				continue
			}
			stepName := all[msg.StepIndex].Name
			if msg.Result == nil {
				broadcastProgress("triage_progress", map[string]interface{}{
					"step_index": msg.StepIndex,
					"step":       stepName,
					"status":     "running",
				})
				continue
			}
			r := msg.Result
			payload := map[string]interface{}{
				"step_index": msg.StepIndex,
				"step":       stepName,
				"status":     r.Status.String(),
				"duration":   int(r.Duration.Seconds()),
				"files":      r.Files,
				"bytes":      r.Bytes,
			}
			if len(r.Warnings) > 0 {
				payload["warnings"] = r.Warnings
				if r.Status == triage.StepFailed {
					payload["error"] = r.Warnings[0]
				}
			}
			broadcastProgress("triage_progress", payload)
		}
	}()

	// Collector.Run is synchronous. It closes progressCh on return.
	go func() {
		summary := c.Run(taskCtx, indices, progressCh)
		doneCh <- summary
	}()

	summary := <-doneCh

	// Emit the final summary event. Build a per-step array the SPA can
	// render directly (avoids a second round-trip).
	stepRows := make([]map[string]interface{}, 0, len(summary.Steps))
	for _, s := range summary.Steps {
		if s.Status == triage.StepSkipped {
			continue
		}
		stepRows = append(stepRows, map[string]interface{}{
			"step":     s.Name,
			"status":   s.Status.String(),
			"duration": int(s.Duration.Seconds()),
			"files":    s.Files,
			"bytes":    s.Bytes,
			"warnings": s.Warnings,
		})
	}

	// Mark the task as cancelled when the analyst clicked Cancel —
	// otherwise it's a normal completion. The SPA reads triage_complete
	// status to decide between the success / cancelled rendering paths.
	triageStatus := "success"
	taskStatus := "completed"
	if taskCtx.Err() != nil {
		triageStatus = "cancelled"
		taskStatus = "cancelled"
	}
	broadcastProgress("triage_complete", map[string]interface{}{
		"output_dir":  summary.OutputDir,
		"total_files": summary.TotalFiles,
		"total_bytes": summary.TotalBytes,
		"duration":    int(summary.Duration.Seconds()),
		"steps":       stepRows,
		"case_id":     summary.CaseID,
		"case_name":   summary.CaseName,
		"status":      triageStatus,
	})
	CompleteTask(taskID, taskStatus)

	triageState.mu.Lock()
	triageState.last = &summary
	triageState.mu.Unlock()

	// Register the triage tree as evidence. Failures here only affect the
	// case DB, not the on-disk artifacts.
	if appCtx := getAppCtx(); appCtx != nil && appCtx.CaseManager != nil && appCtx.ActiveCase != nil {
		_, _ = appCtx.CaseManager.AddEvidence(
			appCtx.ActiveCase.ID, 0, "triage_collection", summary.OutputDir)
	}
}

// resolveTriageIndices maps a "type" string (and optional explicit steps for
// type="custom") to the integer indices the Collector expects. Errors out
// when the type is unknown so the SPA gets a clear 400.
func resolveTriageIndices(platform, typeName string, customSteps []string, all []triage.StepDef) ([]int, error) {
	if typeName == "custom" {
		if len(customSteps) == 0 {
			return nil, badRequest("custom type requires at least one step")
		}
		return resolveCustomSteps(customSteps, all)
	}

	if platform == "windows" {
		switch typeName {
		case "full":
			return triage.WindowsFullTriageIndices(), nil
		case "process_network":
			return triage.WindowsProcessNetworkIndices(), nil
		case "eventlogs":
			return triage.WindowsEventLogIndices(), nil
		case "persistence":
			return triage.WindowsPersistenceIndices(), nil
		case "users":
			return triage.WindowsUserActivityIndices(), nil
		case "sysinfo":
			return triage.WindowsSystemInfoIndices(), nil
		case "browser":
			return triage.WindowsBrowserIndices(), nil
		}
	} else {
		switch typeName {
		case "full":
			return triage.LinuxFullTriageIndices(), nil
		case "process_network":
			return triage.LinuxProcessNetworkIndices(), nil
		case "eventlogs", "logs":
			return triage.LinuxLogIndices(), nil
		case "persistence":
			return triage.LinuxPersistenceIndices(), nil
		case "users":
			return triage.LinuxUserActivityIndices(), nil
		case "sysinfo":
			return triage.LinuxSystemInfoIndices(), nil
		case "browser":
			// Linux doesn't have a browser-specific preset; fall back to
			// user activity which collects shell history.
			return triage.LinuxUserActivityIndices(), nil
		}
	}
	return nil, badRequest("unknown triage type: " + typeName)
}

// resolveCustomSteps maps user-supplied step IDs ("sysinfo", "processes",
// etc.) to indices in the platform's StepDef slice. The SPA's IDs are
// shorter than the human-readable Name field, so we map by SubDir or a
// keyword match against the Name.
//
// Unknown IDs are quietly dropped — better than a hard error during a
// multi-select form where the user accidentally typed a step that doesn't
// apply to the current platform.
func resolveCustomSteps(ids []string, all []triage.StepDef) ([]int, error) {
	idToKeyword := map[string]string{
		"sysinfo":     "system",
		"processes":   "process",
		"network":     "network connection",
		"netconfig":   "network configuration",
		"eventlogs":   "event log",
		"persistence": "persistence",
		"users":       "user",
		"browser":     "browser",
		"software":    "installed software",
		"logs":        "log",
		"cron":        "cron",
	}
	var out []int
	for _, id := range ids {
		keyword, known := idToKeyword[id]
		if !known {
			keyword = id
		}
		for i, s := range all {
			lname := strings.ToLower(s.Name)
			if strings.Contains(lname, keyword) {
				out = append(out, i)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil, badRequest("no matching steps for the supplied step IDs")
	}
	// Dedupe while preserving order.
	seen := make(map[int]bool, len(out))
	dedup := out[:0]
	for _, i := range out {
		if !seen[i] {
			seen[i] = true
			dedup = append(dedup, i)
		}
	}
	return dedup, nil
}

// stepNamesAt returns the Name field for each step at the given indices.
// Used in the response body so the SPA can pre-render placeholder rows.
func stepNamesAt(all []triage.StepDef, indices []int) []string {
	out := make([]string, 0, len(indices))
	for _, i := range indices {
		if i >= 0 && i < len(all) {
			out = append(out, all[i].Name)
		}
	}
	return out
}

// badRequest is a tiny error type that lets the dispatcher map the resolver's
// validation failures back to HTTP 400 without depending on errors.As gymnastics.
type apiBadRequest struct{ msg string }

func (b apiBadRequest) Error() string { return b.msg }
func badRequest(msg string) error     { return apiBadRequest{msg: msg} }

// handleTriageStatus — GET /api/triage/status. Returns either the running
// state (if a triage is in flight) or the last completed summary.
func handleTriageStatus(w http.ResponseWriter, r *http.Request) {
	triageState.mu.Lock()
	defer triageState.mu.Unlock()

	resp := map[string]interface{}{
		"running": triageState.running,
	}
	if triageState.running {
		resp["type"] = triageState.type_
		resp["started_at"] = triageState.startedAt.UTC().Format(time.RFC3339)
		resp["output_dir"] = triageState.outputDir
		resp["elapsed_seconds"] = int(time.Since(triageState.startedAt).Seconds())
	}
	if triageState.last != nil {
		s := triageState.last
		resp["last"] = map[string]interface{}{
			"output_dir":  s.OutputDir,
			"total_files": s.TotalFiles,
			"total_bytes": s.TotalBytes,
			"duration":    int(s.Duration.Seconds()),
			"started_at":  s.StartedAt.UTC().Format(time.RFC3339),
			"finished_at": s.FinishedAt.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
