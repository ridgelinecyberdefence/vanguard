package web

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/ridgelinecyberdefence/vanguard/internal/usecases"
)

// handleUseCases — GET /api/usecases. Returns the catalog summary (no
// phases / steps) for every defined use case, suitable for a list table.
//
// We trim the response to scalar fields the SPA renders directly. The
// detail endpoint returns the full struct.
func handleUseCases(w http.ResponseWriter, r *http.Request) {
	all := usecases.Defaults()
	type summary struct {
		ID            string   `json:"ID"`
		Name          string   `json:"Name"`
		Description   string   `json:"Description"`
		Platform      string   `json:"Platform"`
		Severity      string   `json:"Severity"`
		EstimatedTime string   `json:"EstimatedTime"`
		MITREAttack   []string `json:"MITREAttack"`
	}
	out := make([]summary, 0, len(all))
	for _, uc := range all {
		out = append(out, summary{
			ID:            uc.ID,
			Name:          uc.Name,
			Description:   uc.Description,
			Platform:      uc.Platform,
			Severity:      uc.Severity,
			EstimatedTime: uc.EstimatedTime,
			MITREAttack:   uc.MITREAttack,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleUseCaseDetail — GET /api/usecases/detail?id=UC-WIN-001. Returns
// the full UseCase struct including phases + steps so the SPA can render
// the run-confirmation modal.
func handleUseCaseDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id query parameter required")
		return
	}
	for _, uc := range usecases.Defaults() {
		if uc.ID == id {
			writeJSON(w, http.StatusOK, uc)
			return
		}
	}
	writeError(w, http.StatusNotFound, "use case not found: "+id)
}

// useCaseRunState mirrors the triage / hunt state holders. Only one use
// case runs at a time — the TUI enforces this too via single-Model state.
var useCaseRunState struct {
	mu        sync.Mutex
	running   bool
	useCaseID string
}

// handleUseCaseRun — POST /api/usecases/run. Body: {id, parameters?}.
// Drives usecases.Runner in a goroutine and emits usecase_progress /
// usecase_complete WS events. Phase / step results are surfaced live via
// the events emitted around each phase.
func handleUseCaseRun(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	if ctx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	var req struct {
		ID         string            `json:"id"`
		Parameters map[string]string `json:"parameters"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, "id is required")
		return
	}

	var uc *usecases.UseCase
	for _, candidate := range usecases.Defaults() {
		if candidate.ID == req.ID {
			c := candidate // copy so we don't take the address of the loop variable
			uc = &c
			break
		}
	}
	if uc == nil {
		writeError(w, http.StatusNotFound, "use case not found: "+req.ID)
		return
	}

	useCaseRunState.mu.Lock()
	if useCaseRunState.running {
		useCaseRunState.mu.Unlock()
		writeError(w, http.StatusConflict, "a use case is already running")
		return
	}
	useCaseRunState.running = true
	useCaseRunState.useCaseID = req.ID
	useCaseRunState.mu.Unlock()

	analyst := ctx.ActiveCase.Analyst
	if analyst == "" && ctx.Config != nil {
		analyst = ctx.Config.VanGuard.Analyst
	}
	runner := usecases.New(uc, ctx.ActiveCase.ID, ctx.RootDir, ctx.Platform,
		ctx.Hostname, analyst, ctx.ToolManager, ctx.CaseManager, ctx.Logger)

	go func() {
		defer func() {
			useCaseRunState.mu.Lock()
			useCaseRunState.running = false
			useCaseRunState.mu.Unlock()
		}()

		broadcastProgress("usecase_progress", map[string]interface{}{
			"id":     uc.ID,
			"name":   uc.Name,
			"status": "running",
			"phases": len(uc.Phases),
		})

		summary, err := runner.Run(req.Parameters)
		if err != nil {
			broadcastProgress("usecase_complete", map[string]interface{}{
				"id":     uc.ID,
				"name":   uc.Name,
				"status": "failed",
				"error":  err.Error(),
			})
			return
		}
		// Register the use case output as evidence.
		if ctx.CaseManager != nil {
			_, _ = ctx.CaseManager.AddEvidence(ctx.ActiveCase.ID, 0,
				"usecase:"+uc.ID, summary.OutputDir)
		}
		broadcastProgress("usecase_complete", map[string]interface{}{
			"id":          uc.ID,
			"name":        uc.Name,
			"status":      "complete",
			"output_dir":  summary.OutputDir,
			"duration":    int(summary.Duration.Seconds()),
			"total_files": summary.TotalFiles,
			"phases":      summary.Phases,
		})
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "started",
		"id":         req.ID,
		"name":       uc.Name,
		"phases":     len(uc.Phases),
		"output_dir": runner.OutputDir(),
	})
}
