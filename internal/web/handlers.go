package web

import (
	"encoding/json"
	"net/http"

	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// writeJSON serialises v as JSON to w with the appropriate content-type.
// Errors during marshal produce a 500 with a plain-text body — the SPA
// surfaces these as toast notifications.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Header already flushed; best-effort log via the manager logger.
		if ctx := getAppCtx(); ctx != nil && ctx.Logger != nil {
			ctx.Logger.Warn("web", "encoding response failed: %v", err)
		}
	}
}

// writeError sends a JSON error envelope. Matches the SPA's expectation:
// `{"error": "<message>"}` for any non-2xx response that has a body.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// requireMethod responds 405 if r's method isn't `want`. Returns true when
// the request method matched (caller continues), false when rejected.
func requireMethod(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method == want {
		return true
	}
	w.Header().Set("Allow", want)
	writeError(w, http.StatusMethodNotAllowed, want+" required")
	return false
}

// handleStatus returns the dashboard summary: version, platform, hostname,
// elevation, active case (if any), and a tools-installed/total tally.
//
// The SPA polls this on every page render so it stays cheap — no DB hits,
// just struct reads.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}

	status := map[string]interface{}{
		"version":     ctx.Version,
		"build_date":  ctx.BuildDate,
		"commit":      ctx.Commit,
		"platform":    ctx.Platform,
		"elevated":    ctx.Elevated,
		"hostname":    ctx.Hostname,
		"root_dir":    ctx.RootDir,
		"active_case": nil,
	}

	if ctx.ActiveCase != nil {
		c := ctx.ActiveCase
		status["active_case"] = map[string]interface{}{
			"id":             c.ID,
			"name":           c.Name,
			"status":         c.Status,
			"analyst":        c.Analyst,
			"organization":   c.Organization,
			"classification": c.Classification,
			"description":    c.Description,
			"created_at":     c.CreatedAt,
		}
	}

	if ctx.ToolManager != nil {
		all := ctx.ToolManager.AllTools()
		installed := 0
		for _, t := range all {
			if t.Installed {
				installed++
			}
		}
		status["tools"] = map[string]interface{}{
			"installed": installed,
			"total":     len(all),
		}
	}

	// Surface Python3 detection so the SPA can show the resolved
	// interpreter path (or guidance when nothing usable was found). The
	// detection runs `python -c "..."` on every candidate; cache-busting
	// is intentional — analysts may install Python while VanGuard is up.
	if info, ok := tools.DetectPython(ctx.RootDir); ok {
		py := map[string]interface{}{
			"found":   true,
			"path":    info.Path,
			"version": info.Version,
		}
		if len(info.Args) > 0 {
			py["args"] = info.Args
		}
		status["python3"] = py
	} else {
		status["python3"] = map[string]interface{}{
			"found": false,
		}
	}

	writeJSON(w, http.StatusOK, status)
}
