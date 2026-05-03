package web

import (
	"encoding/json"
	"net/http"
)

// handleConfig — GET /api/config. Returns the user-visible portions of the
// loaded YAML config (analyst, organization, network defaults, velo defaults).
// Avoids returning the full config so we don't leak the GitHub token.
func handleConfig(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil || ctx.Config == nil {
		writeError(w, http.StatusInternalServerError, "config not loaded")
		return
	}
	cfg := ctx.Config
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"analyst":      cfg.VanGuard.Analyst,
		"organization": cfg.VanGuard.Organization,
		"velociraptor": map[string]interface{}{
			"frontend_port": cfg.Velociraptor.Server.FrontendPort,
			"gui_port":      cfg.Velociraptor.Server.GUIPort,
		},
	})
}

// handleConfigUpdate — POST /api/config/update. Accepts {analyst, organization}
// and writes them through the config saver. The full network/velo blocks are
// not editable from the web UI yet — analysts can hand-edit vanguard.yaml.
func handleConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.Config == nil {
		writeError(w, http.StatusInternalServerError, "config not loaded")
		return
	}

	var req struct {
		Analyst      *string `json:"analyst"`
		Organization *string `json:"organization"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Analyst != nil {
		ctx.Config.VanGuard.Analyst = *req.Analyst
	}
	if req.Organization != nil {
		ctx.Config.VanGuard.Organization = *req.Organization
	}

	if ctx.ConfigPath != "" {
		if err := ctx.Config.Save(ctx.ConfigPath); err != nil {
			writeError(w, http.StatusInternalServerError, "saving config: "+err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}
