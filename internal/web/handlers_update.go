package web

import (
	"encoding/json"
	"net/http"

	"github.com/ridgelinecyberdefence/vanguard/internal/updates"
)

// updatesManager builds an *updates.Manager bound to the current AppContext.
// Cheap to recreate on each request — the manager itself is stateless apart
// from the tools.ToolManager pointer.
func updatesManager() (*updates.Manager, error) {
	ctx := getAppCtx()
	if ctx == nil {
		return nil, errAppCtxMissing
	}
	if ctx.ToolManager == nil {
		return nil, errAppCtxMissing
	}
	return updates.New(ctx.RootDir, ctx.ToolManager, ctx.Logger), nil
}

var errAppCtxMissing = httpErr{status: http.StatusInternalServerError, msg: "context not initialised"}

// httpErr is a tiny error type that carries a status code so handlers can
// switch on the kind of failure when surfacing.
type httpErr struct {
	status int
	msg    string
}

func (e httpErr) Error() string { return e.msg }

// handleUpdatesCheck — GET /api/updates/check. Wraps updates.Manager.CheckAll.
// Reshapes the report into the same {Name, InstalledVersion, LatestVersion,
// UpdateAvailable} shape the SPA's existing "Check for Updates" view expects.
func handleUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	m, err := updatesManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	report := m.CheckAll()

	type row struct {
		Name             string `json:"Name"`
		ToolID           string `json:"ToolID"`
		Kind             string `json:"Kind"`
		InstalledVersion string `json:"InstalledVersion"`
		LatestVersion    string `json:"LatestVersion"`
		Status           string `json:"Status"`
		UpdateAvailable  bool   `json:"UpdateAvailable"`
		Reason           string `json:"Reason,omitempty"`
	}
	out := make([]row, 0, len(report.Results))
	for _, c := range report.Results {
		out = append(out, row{
			Name:             c.Name,
			ToolID:           c.ToolID,
			Kind:             string(c.Kind),
			InstalledVersion: c.InstalledLabel,
			LatestVersion:    c.LatestLabel,
			Status:           string(c.Status),
			UpdateAvailable:  c.Status == updates.StatusUpdateAvail,
			Reason:           c.Reason,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleUpdatesTool — POST /api/updates/tool. Body: {tool_id}. Drives
// updates.Manager.UpdateTool synchronously; the real download happens via
// tools.ToolManager which streams to disk in one call.
func handleUpdatesTool(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	m, err := updatesManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req struct {
		ToolID string `json:"tool_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.ToolID == "" {
		writeError(w, http.StatusBadRequest, "tool_id is required")
		return
	}

	// Long-running, but the existing SPA "Check for Updates" view treats it
	// as one request. Run inline; broadcast progress as a single event.
	go func() {
		broadcastProgress("update_tool", map[string]interface{}{
			"tool_id": req.ToolID,
			"status":  "running",
		})
		out := m.UpdateTool(req.ToolID)
		payload := map[string]interface{}{
			"tool_id":  req.ToolID,
			"name":     out.Name,
			"from":     out.From,
			"to":       out.To,
			"duration": int(out.Duration.Seconds()),
		}
		if out.Success {
			payload["status"] = "complete"
		} else {
			payload["status"] = "failed"
			payload["error"] = out.Error
		}
		broadcastProgress("update_tool", payload)
	}()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"tool_id": req.ToolID,
	})
}

// handleUpdatesRules — POST /api/updates/rules. Body: {type:
// "sigma|yara|hayabusa|all"}. Rule sets are tools too in the registry — we
// translate the SPA's friendly names to the matching tool IDs.
func handleUpdatesRules(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	m, err := updatesManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req struct {
		Type string `json:"type"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Type == "" {
		req.Type = "all"
	}

	ids := map[string][]string{
		"sigma":    {"sigma-rules"},
		"yara":     {"yara-rules"},
		"hayabusa": {"hayabusa-rules"},
		"all":      {"sigma-rules", "yara-rules", "hayabusa-rules"},
	}[req.Type]
	if ids == nil {
		writeError(w, http.StatusBadRequest, "unknown type: "+req.Type)
		return
	}

	go func() {
		var outcomes []map[string]interface{}
		for _, id := range ids {
			broadcastProgress("update_rules", map[string]interface{}{
				"id":     id,
				"status": "running",
			})
			out := m.UpdateRuleSet(id)
			row := map[string]interface{}{
				"id":       id,
				"name":     out.Name,
				"from":     out.From,
				"to":       out.To,
				"duration": int(out.Duration.Seconds()),
			}
			if out.Success {
				row["status"] = "complete"
				// When YARA rules are refreshed, also update Loki-RS signatures
				// (loki-util fetches its own signature DB, separate from the rules repo).
				if id == "yara-rules" && m.Tools != nil {
					appCtx := getAppCtx()
					platform := ""
					if appCtx != nil {
						platform = appCtx.Platform
					}
					go m.Tools.RunLokiUtil(platform)
				}
			} else {
				row["status"] = "failed"
				row["error"] = out.Error
			}
			broadcastProgress("update_rules", row)
			outcomes = append(outcomes, row)
		}
		broadcastProgress("update_rules", map[string]interface{}{
			"status":   "all_complete",
			"type":     req.Type,
			"outcomes": outcomes,
		})
	}()
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status": "started",
		"type":   req.Type,
		"items":  ids,
	})
}

// handleUpdatesBundleCreate — POST /api/updates/bundle/create. Builds an
// offline update bundle (tools + rules) under output/_updates/bundles/.
func handleUpdatesBundleCreate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	m, err := updatesManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Include every downloadable tool + every rule set the registry knows
	// about. The Manager itself decides what's actually packageable.
	ctx := getAppCtx()
	var toolIDs, ruleIDs []string
	if ctx != nil && ctx.ToolManager != nil {
		for _, t := range ctx.ToolManager.AllTools() {
			switch t.DownloadMethod {
			case "github_release":
				toolIDs = append(toolIDs, t.ID)
			case "repo_archive":
				ruleIDs = append(ruleIDs, t.ID)
			}
		}
	}
	spec := updates.BundleSpec{
		IncludeTools:    toolIDs,
		IncludeRuleSets: ruleIDs,
	}
	res, err := m.CreateBundle(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"path":       res.BundleDir,
		"zip_path":   res.ZipPath,
		"size":       res.Bytes,
		"manifest":   res.ManifestPath,
		"components": res.Components,
	})
}

// handleUpdatesBundleApply — POST /api/updates/bundle/apply. Body: {path}.
func handleUpdatesBundleApply(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	m, err := updatesManager()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	res, err := m.ApplyBundle(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	applied, failed := 0, 0
	for _, o := range res.Outcomes {
		if o.Success {
			applied++
		} else {
			failed++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"applied":  applied,
		"failed":   failed,
		"outcomes": res.Outcomes,
	})
}
