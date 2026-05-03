package web

import "net/http"

// registerRoutes wires every JSON / WebSocket endpoint into the given mux.
// All handlers live in handlers_*.go files keyed by feature area.
//
// Routing convention:
//   - GET  /api/<resource>           list / read
//   - POST /api/<resource>/<verb>    create / mutate / start
//   - GET  /api/<resource>/<id>      single read (handler decides on method)
//
// Handlers that aren't yet implemented return 501 Not Implemented with a
// JSON body so the SPA can show "Coming soon" without parsing free text.
func registerRoutes(mux *http.ServeMux) {
	// Status / dashboard.
	mux.HandleFunc("/api/status", handleStatus)

	// Cases.
	mux.HandleFunc("/api/cases", handleCases)
	mux.HandleFunc("/api/cases/create", handleCreateCase)
	mux.HandleFunc("/api/cases/active", handleActiveCase)
	mux.HandleFunc("/api/cases/close", handleCloseCase)
	mux.HandleFunc("/api/cases/update", handleUpdateCase)
	mux.HandleFunc("/api/cases/detail", handleCaseDetail)
	mux.HandleFunc("/api/cases/evidence", handleCaseEvidence)

	// Tools.
	mux.HandleFunc("/api/tools", handleTools)
	mux.HandleFunc("/api/tools/download", handleToolDownload)
	mux.HandleFunc("/api/tools/download-all", handleToolDownload) // alias; handler reads URL.Path
	mux.HandleFunc("/api/tools/scan", handleToolScan)
	mux.HandleFunc("/api/tools/updates", handleToolUpdates)

	// Triage / hunting / memory / velo / analysis / usecases / config —
	// minimal implementations now; full handlers added per-feature later.
	mux.HandleFunc("/api/triage/run", handleTriageRun)
	mux.HandleFunc("/api/triage/status", handleTriageStatus)
	mux.HandleFunc("/api/hunt/run", handleHuntRun)
	mux.HandleFunc("/api/hunt/live", handleHuntLive)
	mux.HandleFunc("/api/memory/capture", handleMemoryCapture)
	mux.HandleFunc("/api/memory/analyze", handleMemoryAnalyze)
	mux.HandleFunc("/api/memory/dumps", handleMemoryDumps)
	mux.HandleFunc("/api/memory/plugins", handleMemoryPlugins)
	mux.HandleFunc("/api/velo/status", handleVeloStatus)
	mux.HandleFunc("/api/velo/launch-gui", handleVeloLaunchGUI)
	mux.HandleFunc("/api/velo/launch-server", handleVeloLaunchServer)
	mux.HandleFunc("/api/velo/import", handleVeloImport)
	// Disk collection.
	mux.HandleFunc("/api/disk/collect", handleDiskCollect)
	mux.HandleFunc("/api/disk/acquire", handleDiskAcquire)

	// Remote operations.
	mux.HandleFunc("/api/remote/targets", handleRemoteTargets)
	mux.HandleFunc("/api/remote/targets/add", handleRemoteAdd)
	mux.HandleFunc("/api/remote/targets/remove", handleRemoteRemove)
	mux.HandleFunc("/api/remote/targets/test", handleRemoteTest)
	mux.HandleFunc("/api/remote/targets/test-all", handleRemoteTestAll)
	mux.HandleFunc("/api/remote/collect", handleRemoteCollect)
	mux.HandleFunc("/api/remote/execute", handleRemoteExecute)
	mux.HandleFunc("/api/remote/triage", handleRemoteTriage)
	mux.HandleFunc("/api/remote/file", handleRemoteFileGet)
	mux.HandleFunc("/api/remote/multi-triage", handleRemoteMultiTriage)
	mux.HandleFunc("/api/remote/multi-command", handleRemoteMultiCommand)
	mux.HandleFunc("/api/remote/deploy-tool", handleRemoteToolDeploy)
	mux.HandleFunc("/api/remote/evidence-collect", handleRemoteEvidenceCollect)
	mux.HandleFunc("/api/remote/ioc-sweep", handleRemoteIOCSweep)
	mux.HandleFunc("/api/remote/live-response", handleRemoteLiveResponse)
	mux.HandleFunc("/api/remote/memory-capture", handleRemoteMemoryCapture)

	// Analysis & reporting. Every action verb under /api/analysis/<verb>
	// (except /findings) routes through one handler that switches on the
	// path — keeps routes.go from listing eight near-identical entries.
	mux.HandleFunc("/api/analysis/findings", handleAnalysisFindings)
	mux.HandleFunc("/api/analysis/html_report", handleHTMLReport)
	mux.HandleFunc("/api/analysis/super_timeline", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/correlate", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/mitre_map", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/exec_summary", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/export_findings", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/export_timeline", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/export_iocs", handleAnalysisAction)
	mux.HandleFunc("/api/analysis/parse", handleAnalysisGeneric)
	mux.HandleFunc("/api/analysis/report", handleAnalysisGeneric)

	// Use cases.
	mux.HandleFunc("/api/usecases", handleUseCases)
	mux.HandleFunc("/api/usecases/detail", handleUseCaseDetail)
	mux.HandleFunc("/api/usecases/run", handleUseCaseRun)

	// Update.
	mux.HandleFunc("/api/updates/check", handleUpdatesCheck)
	mux.HandleFunc("/api/updates/tool", handleUpdatesTool)
	mux.HandleFunc("/api/updates/rules", handleUpdatesRules)
	mux.HandleFunc("/api/updates/bundle/create", handleUpdatesBundleCreate)
	mux.HandleFunc("/api/updates/bundle/apply", handleUpdatesBundleApply)
	// Legacy aliases the SPA still uses.
	mux.HandleFunc("/api/update/rules", handleUpdatesRules)
	mux.HandleFunc("/api/update/bundle", handleUpdatesBundleCreate)

	// File browser — lets the SPA offer a local filesystem picker modal.
	mux.HandleFunc("/api/files/browse", handleFileBrowse)

	// Config.
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/config/update", handleConfigUpdate)

	// Cancellable task tracking — single source of truth for "what's
	// running right now" so the SPA's floating cancel bar can drive Stop
	// across every long-running endpoint.
	mux.HandleFunc("/api/tasks", handleTasksList)
	mux.HandleFunc("/api/tasks/cancel", handleTaskCancel)

	// WebSocket — broadcast channel for progress updates.
	mux.HandleFunc("/ws", handleWebSocket)
}

// notImplemented returns a handler that responds with 501 + JSON body. Used
// as a placeholder for endpoints that the SPA already calls but whose
// backend wiring isn't built yet.
func notImplemented(feature string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"error":"not implemented","feature":"` + feature + `"}`))
	}
}
