package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

// handleCases — GET /api/cases. Returns every case in the SQLite store,
// newest first. Pagination is not implemented; the case list is small in
// practice (one investigation per VanGuard root).
func handleCases(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}
	cases, err := ctx.CaseManager.ListCases("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cases)
}

// handleCreateCase — POST /api/cases/create. Accepts {name, classification,
// description}; analyst + organization are pulled from config so the operator
// can't accidentally override them per-case via the API. Sets the new case as
// the active case and returns the full Case row.
func handleCreateCase(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}

	var req struct {
		Name           string `json:"name"`
		Classification string `json:"classification"`
		Description    string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	analyst := ""
	org := ""
	if ctx.Config != nil {
		analyst = ctx.Config.VanGuard.Analyst
		org = ctx.Config.VanGuard.Organization
	}

	newCase, err := ctx.CaseManager.CreateCaseFull(
		req.Name, analyst, org, req.Classification, req.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Provision the case output tree. Failures here are non-fatal — the
	// individual collectors will MkdirAll the subdirs they need anyway.
	caseDir := filepath.Join(ctx.RootDir, "output", newCase.ID)
	for _, sub := range []string{"memory", "disk", "triage", "velociraptor", "reports", "threat_hunting", "analysis"} {
		if err := os.MkdirAll(filepath.Join(caseDir, sub), 0o700); err != nil && ctx.Logger != nil {
			ctx.Logger.Warn("web", "mkdir %s: %v", filepath.Join(caseDir, sub), err)
		}
	}

	ctx.ActiveCase = newCase
	if ctx.Logger != nil {
		ctx.Logger.Info("web", "created case %s: %s", newCase.ID, newCase.Name)
	}
	if ctx.Audit != nil {
		_ = ctx.Audit.Log("create_case", "", newCase.Name, newCase.ID, newCase.ID)
	}

	writeJSON(w, http.StatusOK, newCase)
}

// handleActiveCase — GET returns the active case (or null), POST sets the
// active case by ID. Body for POST: {"case_id": "<id>"}.
func handleActiveCase(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, ctx.ActiveCase)
	case http.MethodPost:
		var req struct {
			CaseID string `json:"case_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		c, err := ctx.CaseManager.GetCase(req.CaseID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		ctx.ActiveCase = c
		if ctx.Logger != nil {
			ctx.Logger.Info("web", "selected active case %s", c.ID)
		}
		writeJSON(w, http.StatusOK, c)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "GET or POST required")
	}
}

// handleCaseDetail — GET /api/cases/detail?id=<case-id>. Returns the full
// case row. Used by the SPA when an analyst clicks through from the case
// list to view metadata.
func handleCaseDetail(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id query parameter required")
		return
	}
	c, err := ctx.CaseManager.GetCase(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// handleUpdateCase — POST /api/cases/update. Rewrites the editable metadata
// for a case (name, classification, description, analyst, organization). The
// case_id field selects the row; if it matches the active case, the in-memory
// pointer is refreshed so subsequent /api/status calls see the new values.
func handleUpdateCase(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}

	var req struct {
		CaseID         string `json:"case_id"`
		Name           string `json:"name"`
		Classification string `json:"classification"`
		Description    string `json:"description"`
		Analyst        string `json:"analyst"`
		Organization   string `json:"organization"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.CaseID == "" {
		writeError(w, http.StatusBadRequest, "case_id is required")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := ctx.CaseManager.UpdateCase(
		req.CaseID, req.Name, req.Classification, req.Description,
		req.Analyst, req.Organization,
	); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Refresh the active case pointer so /api/status reflects the edit
	// without requiring a re-select.
	if ctx.ActiveCase != nil && ctx.ActiveCase.ID == req.CaseID {
		if updated, err := ctx.CaseManager.GetCase(req.CaseID); err == nil {
			ctx.ActiveCase = updated
		}
	}
	if ctx.Logger != nil {
		ctx.Logger.Info("web", "updated case %s", req.CaseID)
	}
	if ctx.Audit != nil {
		_ = ctx.Audit.Log("update_case", req.CaseID, req.Name, "ok", req.CaseID)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "case_id": req.CaseID})
}

// handleCaseEvidence — GET /api/cases/evidence. Returns every evidence
// record for the active case, newest-first. Returns [] when no active case
// or no evidence exists so the dashboard can safely check .length.
func handleCaseEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil || ctx.ActiveCase == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	evidence, err := ctx.CaseManager.ListEvidence(ctx.ActiveCase.ID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	writeJSON(w, http.StatusOK, evidence)
}

// handleCloseCase — POST /api/cases/close. Closes the active case. Body
// optional: {"case_id": "<id>"} to close a specific case rather than active.
func handleCloseCase(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.CaseManager == nil {
		writeError(w, http.StatusInternalServerError, "case manager not initialised")
		return
	}

	var req struct {
		CaseID string `json:"case_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	id := req.CaseID
	if id == "" && ctx.ActiveCase != nil {
		id = ctx.ActiveCase.ID
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "no active case and no case_id supplied")
		return
	}
	if err := ctx.CaseManager.UpdateCaseStatus(id, "closed"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ctx.ActiveCase != nil && ctx.ActiveCase.ID == id {
		ctx.ActiveCase = nil
	}
	if ctx.Logger != nil {
		ctx.Logger.Info("web", "closed case %s", id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"closed": id})
}
