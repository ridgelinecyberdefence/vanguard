package web

import (
	"encoding/json"
	"net/http"

	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// handleTools — GET /api/tools. Returns the tool registry's view of every
// tool, including install state, configured path, category, and whether
// it's required. The SPA groups by category in the rendered table.
func handleTools(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.ToolManager == nil {
		writeError(w, http.StatusInternalServerError, "tool manager not initialised")
		return
	}
	writeJSON(w, http.StatusOK, ctx.ToolManager.GetStatus())
}

// handleToolDownload — POST /api/tools/download. Body:
//
//	{"tool_id": "<id>"}        download a single tool
//	{"all": true}              download every required-but-missing tool
//
// The download runs on a goroutine; the HTTP response returns immediately
// with {"status": "started"}. Progress is streamed to connected WebSocket
// clients via broadcastProgress("tool_download", ...).
func handleToolDownload(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.ToolManager == nil {
		writeError(w, http.StatusInternalServerError, "tool manager not initialised")
		return
	}

	var req struct {
		ToolID          string `json:"tool_id"`
		All             bool   `json:"all"`             // download required-but-missing
		IncludeOptional bool   `json:"include_optional"` // also download non-required tools
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	// /api/tools/download-all routes here too — treat the path as an
	// implicit `all=true` so the SPA can call either endpoint.
	if r.URL.Path == "/api/tools/download-all" {
		req.All = true
		req.IncludeOptional = true
	}
	if !req.All && req.ToolID == "" {
		writeError(w, http.StatusBadRequest, "either tool_id or all=true required")
		return
	}

	tm := ctx.ToolManager
	go func() {
		if req.All {
			runBulkDownload(tm, req.IncludeOptional)
			return
		}
		runSingleDownload(tm, req.ToolID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

// runBulkDownload iterates the tool registry and downloads every required
// tool that isn't installed (or every downloadable tool when
// includeOptional is true). Broadcasts a per-tool "downloading" event
// before each, and "complete"/"failed" after, so the SPA can render
// progress one row at a time.
func runBulkDownload(tm *tools.ToolManager, includeOptional bool) {
	all := tm.AllTools()
	var failures []string
	scope := "required"
	if includeOptional {
		scope = "all"
	}

	// Pre-count how many we'll attempt so the SPA can show "0/N" before
	// the first tool finishes.
	total := 0
	for _, t := range all {
		if t.Installed {
			continue
		}
		if !includeOptional && !t.Required {
			continue
		}
		if t.DownloadMethod == tools.DownloadManual || t.DownloadMethod == "" {
			continue
		}
		total++
	}
	broadcastProgress("tool_download", map[string]interface{}{
		"scope":  scope,
		"status": "starting",
		"total":  total,
	})

	for _, t := range all {
		if t.Installed {
			continue
		}
		if !includeOptional && !t.Required {
			continue
		}
		if t.DownloadMethod == tools.DownloadManual || t.DownloadMethod == "" {
			// No automated path — surface as skipped so the SPA can
			// still render the row instead of silently dropping it.
			broadcastProgress("tool_download", map[string]interface{}{
				"tool_id": t.ID,
				"tool":    t.Name,
				"status":  "skipped",
				"reason":  "manual install required",
			})
			continue
		}

		broadcastProgress("tool_download", map[string]interface{}{
			"tool_id": t.ID,
			"tool":    t.Name,
			"status":  "downloading",
		})

		err := tm.DownloadTool(t.ID)
		payload := map[string]interface{}{
			"tool_id": t.ID,
			"tool":    t.Name,
			"status":  "complete",
		}
		if err != nil {
			payload["status"] = "failed"
			payload["error"] = err.Error()
			failures = append(failures, t.Name+": "+err.Error())
		}
		broadcastProgress("tool_download", payload)
	}

	tm.ScanInstalled()
	broadcastProgress("tool_download", map[string]interface{}{
		"scope":    scope,
		"status":   "all_complete",
		"failures": failures,
	})
}

// runSingleDownload handles the one-off tool case. Same event shape as the
// bulk loop so the SPA can use a single handler.
func runSingleDownload(tm *tools.ToolManager, toolID string) {
	broadcastProgress("tool_download", map[string]interface{}{
		"tool_id": toolID,
		"status":  "downloading",
	})
	err := tm.DownloadTool(toolID)
	tm.ScanInstalled()
	payload := map[string]interface{}{
		"tool_id": toolID,
		"status":  "complete",
	}
	if err != nil {
		payload["status"] = "failed"
		payload["error"] = err.Error()
	}
	broadcastProgress("tool_download", payload)
}

// handleToolScan — POST /api/tools/scan. Re-runs ToolManager.ScanInstalled
// and returns the refreshed status table. Cheap (just stat calls + hashing
// of installed binaries) so synchronous return is fine.
func handleToolScan(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.ToolManager == nil {
		writeError(w, http.StatusInternalServerError, "tool manager not initialised")
		return
	}
	ctx.ToolManager.ScanInstalled()
	writeJSON(w, http.StatusOK, ctx.ToolManager.GetStatus())
}

// handleToolUpdates — GET /api/tools/updates. Hits each downloadable tool's
// GitHub releases endpoint and reports which have a newer build than the
// one on disk. The SPA renders this as a table.
//
// CheckForUpdates only returns tools where an update was discovered; we
// re-shape each entry with an UpdateAvailable=true flag so the SPA can
// uniformly render an "Up to date" row in the same view if we extend later.
func handleToolUpdates(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.ToolManager == nil {
		writeError(w, http.StatusInternalServerError, "tool manager not initialised")
		return
	}
	updates, err := ctx.ToolManager.CheckForUpdates()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	type updateRow struct {
		ID               string `json:"ID"`
		Name             string `json:"Name"`
		InstalledVersion string `json:"InstalledVersion"`
		LatestVersion    string `json:"LatestVersion"`
		UpdateAvailable  bool   `json:"UpdateAvailable"`
		AssetName        string `json:"AssetName"`
		AssetSize        int64  `json:"AssetSize"`
	}
	out := make([]updateRow, 0, len(updates))
	for _, u := range updates {
		out = append(out, updateRow{
			ID:               u.ID,
			Name:             u.Name,
			InstalledVersion: u.CurrentVersion,
			LatestVersion:    u.LatestVersion,
			UpdateAvailable:  u.LatestVersion != "" && u.LatestVersion != u.CurrentVersion,
			AssetName:        u.AssetName,
			AssetSize:        u.AssetSize,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// errsToStrings converts a slice of errors to plain strings for JSON.
// `error` doesn't satisfy MarshalJSON, so without this the SPA would see
// every error as `{}`.
func errsToStrings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		out = append(out, e.Error())
	}
	return out
}
