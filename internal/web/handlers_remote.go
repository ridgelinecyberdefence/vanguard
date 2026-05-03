package web

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/network"
	"github.com/ridgelinecyberdefence/vanguard/internal/remote"
)

// ensureRemoteStore lazy-initialises the *remote.Store on the shared
// AppContext. Mirrors the TUI's ensureRemoteState — the Store loads
// targets.yaml from config/, creating an empty file when missing.
func ensureRemoteStore() (*remote.Store, error) {
	ctx := getAppCtx()
	if ctx == nil {
		return nil, fmt.Errorf("context not initialised")
	}
	if ctx.RemoteCreds == nil {
		ctx.RemoteCreds = remote.NewCredentialCache()
	}
	if ctx.RemoteStore == nil {
		path := filepath.Join(ctx.RootDir, "config", "targets.yaml")
		store, err := remote.NewStore(path)
		if err != nil {
			return nil, err
		}
		ctx.RemoteStore = store
	}
	return ctx.RemoteStore, nil
}

// handleRemoteTargets — GET /api/remote/targets. Lists every target known
// to the persistent store. Targets are scoped per-case in the TUI; we
// return the unscoped All() list so the SPA can show targets created
// outside the current active case (useful when switching investigations).
//
// Reshaped into the SPA's lower-cased field names ({hostname, ip, os,
// protocol, port, username, status, notes}) so the table renderer doesn't
// have to remember which fields the Go struct uses.
func handleRemoteTargets(w http.ResponseWriter, r *http.Request) {
	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()
	out := make([]map[string]interface{}, 0, len(all))
	for _, t := range all {
		out = append(out, map[string]interface{}{
			"id":        t.ID,
			"hostname":  t.Hostname,
			"ip":        t.IPAddress,
			"os":        t.OSType,
			"protocol":  t.Protocol,
			"port":      t.Port,
			"username":  t.Username,
			"status":    string(t.Status),
			"notes":     t.Notes,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// targetByIndex returns the target at array position i in the store's All()
// listing. The SPA addresses targets by array index because that's what the
// table renderer uses; the underlying store assigns numeric IDs but those
// are gappy after removals. Returns (nil, msg) when index is out of range.
func targetByIndex(i int) (*remote.RemoteTarget, string) {
	store, err := ensureRemoteStore()
	if err != nil {
		return nil, err.Error()
	}
	all := store.All()
	if i < 0 || i >= len(all) {
		return nil, fmt.Sprintf("target index %d out of range (have %d)", i, len(all))
	}
	return all[i], ""
}

// handleRemoteAdd — POST /api/remote/targets/add. Body is a partial
// RemoteTarget (the store assigns ID and validates). Responds with the
// stored target (including its assigned ID).
func handleRemoteAdd(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ctx := getAppCtx()

	// Accept the SPA's lower-cased fields explicitly, then map onto
	// remote.RemoteTarget. Doing this in two steps lets us populate
	// CaseID + sensible defaults rather than trusting client JSON.
	var req struct {
		Hostname  string `json:"hostname"`
		IP        string `json:"ip"`
		OS        string `json:"os"`
		Protocol  string `json:"protocol"`
		Port      int    `json:"port"`
		Username  string `json:"username"`
		KeyPath   string `json:"key_path"`
		Notes     string `json:"notes"`
		AuthMethod string `json:"auth_method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	auth := req.AuthMethod
	if auth == "" {
		auth = "password"
	}
	t := &remote.RemoteTarget{
		Hostname:   req.Hostname,
		IPAddress:  req.IP,
		OSType:     req.OS,
		Port:       req.Port,
		Protocol:   req.Protocol,
		Username:   req.Username,
		AuthMethod: auth,
		KeyPath:    req.KeyPath,
		Notes:      req.Notes,
	}
	if ctx != nil && ctx.ActiveCase != nil {
		t.CaseID = ctx.ActiveCase.ID
	}
	stored, err := store.Add(t)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stored)
}

// handleRemoteRemove — POST /api/remote/targets/remove. Body: {index}.
// Index addresses array position in the All() listing; we resolve to the
// stored numeric ID before calling Store.Remove.
func handleRemoteRemove(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Index int  `json:"index"`
		ID    *int `json:"id,omitempty"` // legacy fallback
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	id := 0
	if req.ID != nil {
		id = *req.ID
	} else {
		t, msg := targetByIndex(req.Index)
		if t == nil {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		id = t.ID
	}
	if err := store.Remove(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "removed",
		"id":      id,
		"message": "Target removed",
	})
}

// handleRemoteTest — POST /api/remote/targets/test.
//
// Always performs a layer-4 TCP reachability check. When an optional
// "password" field is included and the TCP probe succeeds, also attempts a
// full authenticated command ("hostname") so the analyst can confirm
// credentials before kicking off a collection job.
func handleRemoteTest(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Index    int    `json:"index"`
		ID       *int   `json:"id,omitempty"`
		Password string `json:"password,omitempty"` // optional; triggers auth test when present
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var t *remote.RemoteTarget
	if req.ID != nil {
		t = store.Get(*req.ID)
		if t == nil {
			writeError(w, http.StatusNotFound, "target not found")
			return
		}
	} else {
		var msg string
		t, msg = targetByIndex(req.Index)
		if t == nil {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
	}

	resp := probeTarget(store, t)

	// Optional auth test — only attempted when a password was supplied and
	// the TCP probe already confirmed the port is open.
	if req.Password != "" && resp["status"] == "online" {
		nt := t.AsNetworkTarget(req.Password)
		authRes := network.ExecOnTarget(nt, "hostname", 15*time.Second)
		if authRes.Err != nil {
			resp["auth_status"] = "failed"
			resp["auth_error"] = authRes.Err.Error()
			if hint := connErrorHint(authRes.Err, string(t.Protocol)); hint != "" {
				resp["auth_hint"] = hint
			}
		} else if authRes.ExitCode != 0 {
			resp["auth_status"] = "failed"
			resp["auth_error"] = fmt.Sprintf("exit %d: %s", authRes.ExitCode, strings.TrimSpace(authRes.Stderr))
		} else {
			resp["auth_status"] = "ok"
			resp["auth_hostname"] = strings.TrimSpace(authRes.Stdout)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// connErrorHint maps a connection/auth error to a human-readable diagnostic hint.
func connErrorHint(err error, protocol string) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "authentication") ||
		strings.Contains(msg, "password") ||
		strings.Contains(msg, "credentials") ||
		strings.Contains(msg, "access denied"):
		return "Authentication failed — verify username and password."
	case strings.Contains(msg, "connection refused"):
		return strings.ToUpper(protocol) + " service not accepting connections; check the service is running."
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out"):
		return "Connection timed out — check firewall rules allow port " + strings.ToUpper(protocol) + "."
	case strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable"):
		return "Host unreachable — verify the IP address and network routing."
	}
	return ""
}

// handleRemoteTestAll — POST /api/remote/targets/test-all. Probes every
// configured target in parallel (bounded). Returns one row per target with
// the same shape as /test.
func handleRemoteTestAll(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	results := make([]map[string]interface{}, len(all))
	// Concurrency: a single missing host shouldn't make the analyst wait
	// 5s × N targets. Cap parallelism so we don't open hundreds of sockets
	// on a sweep across a full asset list.
	const concurrency = 8
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, t := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, t *remote.RemoteTarget) {
			defer func() { <-sem; wg.Done() }()
			results[i] = probeTarget(store, t)
		}(i, t)
	}
	wg.Wait()

	online, offline := 0, 0
	for _, r := range results {
		if r["status"] == "online" {
			online++
		} else {
			offline++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": fmt.Sprintf("Tested %d targets — %d online, %d offline", len(all), online, offline),
		"results": results,
	})
}

// probeTarget performs the layer-4 dial test against a single target,
// updates its store status, and returns the one-row result map. Shared
// between /test and /test-all so they emit identical shapes.
func probeTarget(store *remote.Store, t *remote.RemoteTarget) map[string]interface{} {
	host := t.IPAddress
	if host == "" {
		host = t.Hostname
	}
	addr := fmt.Sprintf("%s:%d", host, t.Port)
	started := time.Now()
	conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
	elapsed := time.Since(started)

	resp := map[string]interface{}{
		"id":               t.ID,
		"hostname":         t.Hostname,
		"address":          addr,
		"response_time_ms": elapsed.Milliseconds(),
	}
	if dialErr != nil {
		_ = store.SetStatus(t.ID, remote.StatusOffline)
		resp["status"] = "offline"
		resp["error"] = dialErr.Error()
		resp["message"] = t.Hostname + " offline (" + dialErr.Error() + ")"
	} else {
		_ = conn.Close()
		_ = store.SetStatus(t.ID, remote.StatusOnline)
		resp["status"] = "online"
		resp["message"] = fmt.Sprintf("%s online (%dms)", t.Hostname, elapsed.Milliseconds())
	}
	return resp
}

// handleRemoteCollect — POST /api/remote/collect. All collection ops
// (triage, eventlogs, registry, file, memory, ioc, batch_*) deferred to
// the TUI for now — these need credential prompts + progress streaming
// the web shell hasn't ported.
func handleRemoteCollect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Op     string `json:"op"`
		Target int    `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "deferred",
		"op":      req.Op,
		"message": "Remote collection (" + req.Op + ") is currently TUI-only. Run vanguard.exe --tui and select Remote Operations.",
	})
}

// resolveNetworkTarget looks up a stored RemoteTarget by ID and builds a
// network.Target with the supplied password. Returns an error ready to write
// to the response on failure.
func resolveNetworkTarget(targetID int, password string) (network.Target, *remote.RemoteTarget, error) {
	store, err := ensureRemoteStore()
	if err != nil {
		return network.Target{}, nil, fmt.Errorf("store: %w", err)
	}
	rt := store.Get(targetID)
	if rt == nil {
		return network.Target{}, nil, fmt.Errorf("target %d not found", targetID)
	}
	return rt.AsNetworkTarget(password), rt, nil
}

// remoteOutDir builds the output path for a remote operation.
// Pattern: output/{caseID}/remote/{hostname}/{ts}
func remoteOutDir(rootDir, caseID, hostname, subdir string) string {
	ts := time.Now().Format("20060102_150405")
	if subdir != "" {
		return filepath.Join(rootDir, "output", caseID, "remote", hostname, subdir, ts)
	}
	return filepath.Join(rootDir, "output", caseID, "remote", hostname, ts)
}

// handleRemoteExecute — POST /api/remote/execute. Runs a single command on a
// target and returns the output synchronously.
// Body: {target_id, password, command, timeout_sec}.
func handleRemoteExecute(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetID   int    `json:"target_id"`
		Password   string `json:"password"`
		Command    string `json:"command"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	nt, _, err := resolveNetworkTarget(req.TargetID, req.Password)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	res := network.ExecOnTarget(nt, req.Command, timeout)
	status := "ok"
	errMsg := ""
	if res.Err != nil {
		status = "error"
		errMsg = res.Err.Error()
	} else if res.ExitCode != 0 {
		status = "exit_error"
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    status,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
		"exit_code": res.ExitCode,
		"duration":  int(res.Duration.Seconds()),
		"error":     errMsg,
	})
}

// handleRemoteTriage — POST /api/remote/triage. Runs the full quick-triage
// command set on a target, saving each output file under
// output/{case}/remote/{host}/{ts}/. Progress is streamed via WebSocket.
// Body: {target_id, password}.
func handleRemoteTriage(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetID int    `json:"target_id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	nt, rt, err := resolveNetworkTarget(req.TargetID, req.Password)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}

	var cmdSet remote.CommandSet
	if rt.OSType == "windows" {
		cmdSet = remote.WindowsTriageCommands()
	} else {
		cmdSet = remote.LinuxTriageCommands()
	}

	hostname := rt.Hostname
	if hostname == "" {
		hostname = rt.IPAddress
	}
	caseID := ""
	if ctx.ActiveCase != nil {
		caseID = ctx.ActiveCase.ID
	}
	outDir := remoteOutDir(ctx.RootDir, caseID, hostname, "")

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "started",
		"target":     rt.DisplayName(),
		"output_dir": outDir,
		"steps":      len(cmdSet.Commands),
	})

	go func() {
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			broadcastProgress("remote_progress", map[string]interface{}{
				"target": rt.DisplayName(),
				"status": "error",
				"error":  "mkdir: " + err.Error(),
			})
			return
		}
		client, err := network.NewClient(nt)
		if err != nil {
			broadcastProgress("remote_progress", map[string]interface{}{
				"target": rt.DisplayName(),
				"status": "error",
				"error":  "client: " + err.Error(),
			})
			return
		}
		if err := client.Connect(); err != nil {
			broadcastProgress("remote_progress", map[string]interface{}{
				"target": rt.DisplayName(),
				"status": "error",
				"error":  "connect: " + err.Error(),
			})
			return
		}
		defer client.Close()

		broadcastProgress("remote_progress", map[string]interface{}{
			"target": rt.DisplayName(),
			"status": "connected",
			"total":  len(cmdSet.Commands),
		})

		succeeded := 0
		for i, spec := range cmdSet.Commands {
			broadcastProgress("remote_progress", map[string]interface{}{
				"target": rt.DisplayName(),
				"status": "running",
				"step":   i + 1,
				"total":  len(cmdSet.Commands),
				"name":   spec.Name,
			})
			res := client.Execute(spec.Command, 2*time.Minute)
			content := res.Stdout
			if content == "" {
				content = res.Stderr
			}
			_ = os.WriteFile(filepath.Join(outDir, spec.OutFile), []byte(content), 0o644)
			if res.Err != nil {
				broadcastProgress("remote_progress", map[string]interface{}{
					"target": rt.DisplayName(),
					"status": "step_error",
					"step":   i + 1,
					"total":  len(cmdSet.Commands),
					"name":   spec.Name,
					"error":  res.Err.Error(),
				})
			} else {
				succeeded++
				broadcastProgress("remote_progress", map[string]interface{}{
					"target": rt.DisplayName(),
					"status": "step_done",
					"step":   i + 1,
					"total":  len(cmdSet.Commands),
					"name":   spec.Name,
					"file":   spec.OutFile,
					"bytes":  len(content),
				})
			}
		}

		broadcastProgress("remote_complete", map[string]interface{}{
			"target":     rt.DisplayName(),
			"status":     "complete",
			"succeeded":  succeeded,
			"total":      len(cmdSet.Commands),
			"output_dir": outDir,
		})
	}()
}

// handleRemoteFileGet — POST /api/remote/file. Copies a single file from the
// remote target to output/{case}/remote/{host}/files/{ts}/. Synchronous.
// Body: {target_id, password, remote_path}.
func handleRemoteFileGet(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetID   int    `json:"target_id"`
		Password   string `json:"password"`
		RemotePath string `json:"remote_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.RemotePath == "" {
		writeError(w, http.StatusBadRequest, "remote_path is required")
		return
	}
	nt, rt, err := resolveNetworkTarget(req.TargetID, req.Password)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}

	hostname := rt.Hostname
	if hostname == "" {
		hostname = rt.IPAddress
	}
	caseID := ""
	if ctx.ActiveCase != nil {
		caseID = ctx.ActiveCase.ID
	}
	outDir := remoteOutDir(ctx.RootDir, caseID, hostname, "files")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	localFile := filepath.Join(outDir, filepath.Base(req.RemotePath))
	if err := network.CopyFromTarget(nt, req.RemotePath, localFile); err != nil {
		writeError(w, http.StatusInternalServerError, "copy failed: "+err.Error())
		return
	}

	info, _ := os.Stat(localFile)
	var size int64
	if info != nil {
		size = info.Size()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"remote_path": req.RemotePath,
		"local_path":  localFile,
		"size":        size,
		"size_fmt":    formatVeloSize(size),
	})
}

// handleRemoteMultiTriage — POST /api/remote/multi-triage.
// Body: {target_ids, triage_type, max_parallel, password}.
// Runs a full triage across multiple targets in parallel, saving per-host
// output under output/{case}/remote/multi_{ts}/{host}/.
func handleRemoteMultiTriage(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetIDs   []int  `json:"target_ids"`
		TriageType  string `json:"triage_type"`
		MaxParallel int    `json:"max_parallel"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.TargetIDs) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids is required")
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	var selected []*remote.RemoteTarget
	for _, idx := range req.TargetIDs {
		if idx >= 0 && idx < len(all) {
			selected = append(selected, all[idx])
		}
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "no valid targets at given indices")
		return
	}

	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	maxP := req.MaxParallel
	if maxP <= 0 {
		maxP = 5
	}

	outputDir := filepath.Join(appCtx.RootDir, "output", appCtx.ActiveCase.ID, "remote",
		"multi_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"targets": len(selected),
	})

	go func() {
		broadcastProgress("multi_triage_started", map[string]interface{}{
			"targets": len(selected),
			"type":    req.TriageType,
		})

		type hostResult struct {
			Host     string `json:"Host"`
			OS       string `json:"OS"`
			Success  int    `json:"Success"`
			Failed   int    `json:"Failed"`
			Total    int    `json:"Total"`
			Duration int    `json:"Duration"`
		}

		var mu sync.Mutex
		var hostResults []hostResult
		sem := make(chan struct{}, maxP)
		var wg sync.WaitGroup

		for _, rt := range selected {
			wg.Add(1)
			go func(t *remote.RemoteTarget) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				host := t.IPAddress
				if host == "" {
					host = t.Hostname
				}

				nt := t.AsNetworkTarget(req.Password)
				hostDir := filepath.Join(outputDir, host)
				_ = os.MkdirAll(hostDir, 0o700)

				var cmdSet remote.CommandSet
				if strings.EqualFold(t.OSType, "linux") {
					cmdSet = remote.LinuxTriageCommands()
				} else {
					cmdSet = remote.WindowsTriageCommands()
				}

				start := time.Now()
				successCount, failCount := 0, 0

				client, clientErr := network.NewClient(nt)
				if clientErr != nil {
					broadcastProgress("multi_triage_step", map[string]interface{}{
						"host": host, "step": "connect", "current": 0,
						"total": len(cmdSet.Commands), "error": clientErr.Error(),
						"targets_total": len(selected),
					})
					mu.Lock()
					hostResults = append(hostResults, hostResult{
						Host: host, OS: t.OSType,
						Failed: len(cmdSet.Commands), Total: len(cmdSet.Commands),
						Duration: int(time.Since(start).Seconds()),
					})
					mu.Unlock()
					return
				}
				if connErr := client.Connect(); connErr != nil {
					broadcastProgress("multi_triage_step", map[string]interface{}{
						"host": host, "step": "connect", "current": 0,
						"total": len(cmdSet.Commands), "error": connErr.Error(),
						"targets_total": len(selected),
					})
					mu.Lock()
					hostResults = append(hostResults, hostResult{
						Host: host, OS: t.OSType,
						Failed: len(cmdSet.Commands), Total: len(cmdSet.Commands),
						Duration: int(time.Since(start).Seconds()),
					})
					mu.Unlock()
					return
				}
				defer client.Close()

				for i, spec := range cmdSet.Commands {
					mu.Lock()
					totalDone := len(hostResults)
					mu.Unlock()
					broadcastProgress("multi_triage_step", map[string]interface{}{
						"host": host, "step": spec.Name,
						"current": i + 1, "total": len(cmdSet.Commands),
						"targets_completed": totalDone, "targets_total": len(selected),
					})
					res := client.Execute(spec.Command, 2*time.Minute)
					content := res.Stdout
					if content == "" {
						content = res.Stderr
					}
					_ = os.WriteFile(filepath.Join(hostDir, spec.OutFile), []byte(content), 0o644)
					if res.Err != nil {
						failCount++
					} else {
						successCount++
					}
				}

				mu.Lock()
				hostResults = append(hostResults, hostResult{
					Host: host, OS: t.OSType,
					Success: successCount, Failed: failCount, Total: len(cmdSet.Commands),
					Duration: int(time.Since(start).Seconds()),
				})
				mu.Unlock()
			}(rt)
		}

		wg.Wait()

		totalSuccess, totalFail := 0, 0
		for _, hr := range hostResults {
			totalSuccess += hr.Success
			totalFail += hr.Failed
		}
		broadcastProgress("multi_triage_complete", map[string]interface{}{
			"status":        "complete",
			"targets":       len(selected),
			"total_success": totalSuccess,
			"total_failed":  totalFail,
			"output_dir":    outputDir,
			"host_results":  hostResults,
		})
	}()
}

// handleRemoteMultiCommand — POST /api/remote/multi-command.
// Body: {target_ids, command, timeout, max_parallel, password}.
// Fans the command out across selected targets and returns all results via WS.
func handleRemoteMultiCommand(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetIDs   []int  `json:"target_ids"`
		Command     string `json:"command"`
		TimeoutSec  int    `json:"timeout"`
		MaxParallel int    `json:"max_parallel"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Command == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}
	if len(req.TargetIDs) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids is required")
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	var targets []network.Target
	for _, idx := range req.TargetIDs {
		if idx >= 0 && idx < len(all) {
			targets = append(targets, all[idx].AsNetworkTarget(req.Password))
		}
	}
	if len(targets) == 0 {
		writeError(w, http.StatusBadRequest, "no valid targets at given indices")
		return
	}

	tout := time.Duration(req.TimeoutSec) * time.Second
	if tout <= 0 {
		tout = 60 * time.Second
	}
	maxP := req.MaxParallel
	if maxP <= 0 {
		maxP = 5
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"targets": len(targets),
	})

	go func() {
		job := &network.MultiTargetJob{
			Targets:     targets,
			Command:     req.Command,
			Timeout:     tout,
			MaxParallel: maxP,
			ProgressFn: func(completed, total int, cur *network.MultiTargetResult) {
				broadcastProgress("multi_cmd_progress", map[string]interface{}{
					"host":      cur.Host,
					"status":    cur.Status,
					"completed": completed,
					"total":     total,
				})
			},
		}
		results := network.ExecuteMulti(context.Background(), job)
		broadcastProgress("multi_cmd_complete", map[string]interface{}{
			"results": results,
		})
	}()
}

// handleRemoteToolDeploy — POST /api/remote/tool-deploy.
// Body: {target_ids, tool, scan_type, max_parallel, password}.
// Uploads hayabusa or loki to each selected target, executes a scan, pulls
// results back to output/{case}/remote/deploy_{tool}_{ts}/{host}/
func handleRemoteToolDeploy(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetIDs   []int  `json:"target_ids"`
		Tool        string `json:"tool"`        // "hayabusa" | "loki"
		ScanType    string `json:"scan_type"`   // "full" | "critical"
		MaxParallel int    `json:"max_parallel"`
		Password    string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.TargetIDs) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids is required")
		return
	}
	switch req.Tool {
	case "hayabusa", "loki":
	default:
		writeError(w, http.StatusBadRequest, "unsupported tool: "+req.Tool+"; must be hayabusa or loki")
		return
	}

	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	var selected []*remote.RemoteTarget
	for _, idx := range req.TargetIDs {
		if idx >= 0 && idx < len(all) {
			selected = append(selected, all[idx])
		}
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "no valid targets at given indices")
		return
	}

	maxP := req.MaxParallel
	if maxP <= 0 {
		maxP = 3
	}

	outputDir := filepath.Join(appCtx.RootDir, "output", appCtx.ActiveCase.ID, "remote",
		"deploy_"+req.Tool+"_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"targets": len(selected),
	})

	go func() {
		broadcastProgress("tool_deploy_started", map[string]interface{}{
			"tool":    req.Tool,
			"targets": len(selected),
		})

		type deployResult struct {
			Host       string `json:"host"`
			Status     string `json:"status"`
			OutputFile string `json:"output_file,omitempty"`
			Lines      int    `json:"lines,omitempty"`
			Error      string `json:"error,omitempty"`
			Duration   int    `json:"duration"`
		}

		var mu sync.Mutex
		var results []deployResult
		sem := make(chan struct{}, maxP)
		var wg sync.WaitGroup

		for _, rt := range selected {
			wg.Add(1)
			go func(t *remote.RemoteTarget) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				host := t.IPAddress
				if host == "" {
					host = t.Hostname
				}
				hostDir := filepath.Join(outputDir, host)
				_ = os.MkdirAll(hostDir, 0o700)
				start := time.Now()

				result := deployResult{Host: host, Status: "failed"}
				defer func() {
					result.Duration = int(time.Since(start).Seconds())
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}()

				broadcastStep := func(step string) {
					mu.Lock()
					done := len(results)
					total := len(selected)
					mu.Unlock()
					broadcastProgress("tool_deploy_step", map[string]interface{}{
						"host":              host,
						"step":              step,
						"targets_completed": done,
						"targets_total":     total,
					})
				}

				isLinux := strings.EqualFold(t.OSType, "linux")

				// Resolve the local binary for the target's OS.
				toolSuffix := "-win"
				if isLinux {
					toolSuffix = "-lnx"
				}
				toolPath := appCtx.ToolManager.GetInstalledPath(req.Tool + toolSuffix)
				if toolPath == "" {
					toolPath = appCtx.ToolManager.GetInstalledPath(req.Tool)
				}
				if toolPath == "" {
					result.Error = req.Tool + " binary not installed locally (need " + req.Tool + toolSuffix + ")"
					return
				}

				// Remote temp paths.
				var remoteTempDir, remoteToolBin, remoteOutputFile string
				if isLinux {
					remoteTempDir = "/tmp/vg_" + req.Tool
					remoteToolBin = remoteTempDir + "/" + filepath.Base(toolPath)
					remoteOutputFile = remoteTempDir + "/output.csv"
				} else {
					remoteTempDir = `C:\Windows\Temp\vg_` + req.Tool
					remoteToolBin = remoteTempDir + `\` + filepath.Base(toolPath)
					remoteOutputFile = remoteTempDir + `\output.csv`
				}

				// Establish a single connection; reuse for upload/execute/download.
				nt := t.AsNetworkTarget(req.Password)
				client, clientErr := network.NewClient(nt)
				if clientErr != nil {
					result.Error = "init client: " + clientErr.Error()
					return
				}
				if connErr := client.Connect(); connErr != nil {
					result.Error = "connect: " + connErr.Error()
					return
				}
				defer client.Close()

				// Create the remote working directory.
				if isLinux {
					client.Execute("mkdir -p '"+remoteTempDir+"'", 30*time.Second)
				} else {
					client.Execute(`New-Item -ItemType Directory -Force -Path '`+remoteTempDir+`'`, 30*time.Second)
				}

				// Upload: for hayabusa try to bundle binary + rules + config as a ZIP
				// so the scan has signatures available (critical for air-gapped targets).
				if req.Tool == "hayabusa" {
					toolDir := filepath.Dir(toolPath)
					rulesDir := filepath.Join(toolDir, "rules")
					configDir := filepath.Join(toolDir, "config")

					rulesInfo, rulesErr := os.Stat(rulesDir)
					hasRules := rulesErr == nil && rulesInfo.IsDir()

					configInfo, configErr := os.Stat(configDir)
					hasConfig := configErr == nil && configInfo.IsDir()

					if hasRules || hasConfig {
						broadcastStep("archiving hayabusa + rules")
						extras := map[string]string{}
						if hasRules {
							extras["rules"] = rulesDir
						}
						if hasConfig {
							extras["config"] = configDir
						}
						archivePath, archErr := createDeployArchive(req.Tool, toolPath, extras)
						if archErr == nil {
							defer os.Remove(archivePath)
							var remoteZip string
							if isLinux {
								remoteZip = remoteTempDir + "/deploy.zip"
							} else {
								remoteZip = remoteTempDir + `\deploy.zip`
							}
							broadcastStep("uploading hayabusa archive (" + filepath.Base(archivePath) + ")")
							if uploadErr := client.CopyTo(archivePath, remoteZip); uploadErr != nil {
								result.Error = "upload archive: " + uploadErr.Error()
								return
							}
							broadcastStep("extracting archive on remote")
							if isLinux {
								client.Execute("unzip -o '"+remoteZip+"' -d '"+remoteTempDir+"'", 3*time.Minute)
							} else {
								client.Execute(`Expand-Archive -LiteralPath '`+remoteZip+`' -DestinationPath '`+remoteTempDir+`' -Force`, 3*time.Minute)
							}
						} else {
							// Archive failed; fall back to binary-only upload.
							broadcastStep("uploading hayabusa (binary only)")
							if uploadErr := client.CopyTo(toolPath, remoteToolBin); uploadErr != nil {
								result.Error = "upload: " + uploadErr.Error()
								return
							}
						}
					} else {
						broadcastStep("uploading hayabusa")
						if uploadErr := client.CopyTo(toolPath, remoteToolBin); uploadErr != nil {
							result.Error = "upload: " + uploadErr.Error()
							return
						}
					}
				} else {
					// loki: upload binary only (signatures are bundled in the binary).
					broadcastStep("uploading loki")
					if uploadErr := client.CopyTo(toolPath, remoteToolBin); uploadErr != nil {
						result.Error = "upload: " + uploadErr.Error()
						return
					}
					if isLinux {
						client.Execute("chmod +x '"+remoteToolBin+"'", 15*time.Second)
					}
				}

				// Build and run the scan command.
				broadcastStep("running " + req.Tool + " scan")
				var scanCmd string
				var scanTimeout time.Duration

				switch req.Tool {
				case "hayabusa":
					scanTimeout = 30 * time.Minute
					levelFilter := ""
					if req.ScanType == "critical" {
						levelFilter = " -m critical"
					}
					if isLinux {
						evtxDir := "/var/log"
						scanCmd = fmt.Sprintf(
							"chmod +x '%s' && '%s' csv-timeline -d '%s' -o '%s' -n -U --no-wizard%s",
							remoteToolBin, remoteToolBin, evtxDir, remoteOutputFile, levelFilter)
					} else {
						evtxDir := `C:\Windows\System32\winevt\Logs`
						scanCmd = fmt.Sprintf(
							`& '%s' csv-timeline -d '%s' -o '%s' -n -U --no-wizard%s`,
							remoteToolBin, evtxDir, remoteOutputFile, levelFilter)
					}

				case "loki":
					scanTimeout = 30 * time.Minute
					if isLinux {
						scanCmd = fmt.Sprintf(
							"chmod +x '%s' && '%s' --folder / --no-tui --nolog 2>&1 | tee '%s'",
							remoteToolBin, remoteToolBin, remoteOutputFile)
					} else {
						// --folder scans the specified path; capture output to file via PowerShell.
						scanCmd = fmt.Sprintf(
							`& '%s' --folder 'C:\' --no-tui --nolog 2>&1 | Out-File -FilePath '%s' -Encoding UTF8`,
							remoteToolBin, remoteOutputFile)
					}
				}

				scanRes := client.Execute(scanCmd, scanTimeout)

				// Pull results back.
				broadcastStep("downloading results")
				ext := ".csv"
				if req.Tool == "loki" {
					ext = ".txt"
				}
				localOutput := filepath.Join(hostDir, host+"_"+req.Tool+"_output"+ext)

				if copyErr := client.CopyFrom(remoteOutputFile, localOutput); copyErr != nil {
					// Fallback: write whatever was captured on stdout/stderr.
					captured := scanRes.Stdout
					if captured == "" {
						captured = scanRes.Stderr
					}
					if captured != "" {
						_ = os.WriteFile(localOutput, []byte(captured), 0o644)
					} else {
						result.Error = "pull results: " + copyErr.Error()
						return
					}
				}

				// Count output lines for the summary.
				if data, readErr := os.ReadFile(localOutput); readErr == nil {
					result.Lines = strings.Count(string(data), "\n")
				}

				// Remove remote working directory.
				if isLinux {
					client.Execute("rm -rf '"+remoteTempDir+"'", 30*time.Second)
				} else {
					client.Execute(`Remove-Item -Recurse -Force '`+remoteTempDir+`'`, 30*time.Second)
				}

				result.Status = "success"
				result.OutputFile = localOutput
			}(rt)
		}

		wg.Wait()

		succeeded := 0
		for _, dr := range results {
			if dr.Status == "success" {
				succeeded++
			}
		}
		broadcastProgress("tool_deploy_complete", map[string]interface{}{
			"tool":       req.Tool,
			"targets":    len(selected),
			"succeeded":  succeeded,
			"failed":     len(selected) - succeeded,
			"output_dir": outputDir,
			"results":    results,
		})
	}()
}

// createDeployArchive builds a ZIP containing toolBinPath at the archive root
// plus any directories listed in extraDirs (key = name in archive, value = local path).
// Missing or empty extra dirs are silently skipped.
func createDeployArchive(toolName, toolBinPath string, extraDirs map[string]string) (string, error) {
	tmp, err := os.CreateTemp("", "vg-deploy-"+toolName+"-*.zip")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	zw := zip.NewWriter(tmp)

	if err := addFileToZip(zw, toolBinPath, filepath.Base(toolBinPath)); err != nil {
		zw.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("zip binary: %w", err)
	}

	for dirName, dirPath := range extraDirs {
		if dirPath == "" {
			continue
		}
		if info, statErr := os.Stat(dirPath); statErr != nil || !info.IsDir() {
			continue
		}
		walkErr := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			relInDir, relErr := filepath.Rel(dirPath, path)
			if relErr != nil {
				return relErr
			}
			return addFileToZip(zw, path, dirName+"/"+filepath.ToSlash(relInDir))
		})
		if walkErr != nil {
			zw.Close()
			os.Remove(tmp.Name())
			return "", fmt.Errorf("zip %s: %w", dirName, walkErr)
		}
	}

	if err := zw.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// addFileToZip adds the file at localPath to the zip archive under archiveName.
func addFileToZip(zw *zip.Writer, localPath, archiveName string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	hdr.Name = archiveName
	hdr.Method = zip.Deflate
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

// ---------------------------------------------------------------------------
// Remote evidence collection
// ---------------------------------------------------------------------------

// EvidenceTemplate is a named set of remote file paths to collect.
// Files == nil means the paths are discovered dynamically at collection time.
type EvidenceTemplate struct {
	Name  string
	Files []string
}

var windowsEvidenceTemplates = map[string]EvidenceTemplate{
	"event_logs": {
		Name: "Event Logs",
		Files: []string{
			`C:\Windows\System32\winevt\Logs\Security.evtx`,
			`C:\Windows\System32\winevt\Logs\System.evtx`,
			`C:\Windows\System32\winevt\Logs\Application.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx`,
		},
	},
	"registry": {
		Name: "Registry Hives",
		Files: []string{
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\config\SYSTEM`,
			`C:\Windows\System32\config\SOFTWARE`,
			`C:\Windows\System32\config\SECURITY`,
		},
	},
	"amcache": {
		Name:  "Amcache",
		Files: []string{`C:\Windows\AppCompat\Programs\Amcache.hve`},
	},
	// Dynamic templates — Files is nil; paths discovered at runtime.
	"ntuser":         {Name: "User Profiles (NTUSER.DAT)"},
	"prefetch":       {Name: "Prefetch Files"},
	"browser_history": {Name: "Browser History"},
}

var linuxEvidenceTemplates = map[string]EvidenceTemplate{
	"auth_logs": {
		Name: "Authentication Logs",
		Files: []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/faillog",
			"/var/log/lastlog",
			"/var/log/wtmp",
			"/var/log/btmp",
		},
	},
	"system_logs": {
		Name: "System Logs",
		Files: []string{
			"/var/log/syslog",
			"/var/log/messages",
			"/var/log/kern.log",
			"/var/log/dmesg",
			"/var/log/cron",
		},
	},
	"config": {
		Name: "System Configuration",
		Files: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/group",
			"/etc/hosts",
			"/etc/crontab",
			"/etc/sudoers",
			"/etc/ssh/sshd_config",
		},
	},
	// Dynamic.
	"bash_history": {Name: "Shell History"},
	"ssh_keys":     {Name: "SSH Keys"},
}

// handleRemoteEvidenceCollect — POST /api/remote/evidence-collect.
// Body: {target_ids, templates, custom_paths, max_parallel, password}.
// Pulls forensic artifacts from each selected target, SHA256-hashes them,
// and writes a per-host evidence_manifest.json for chain of custody.
func handleRemoteEvidenceCollect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetIDs   []int    `json:"target_ids"`
		Templates   []string `json:"templates"`
		CustomPaths []string `json:"custom_paths"`
		MaxParallel int      `json:"max_parallel"`
		Password    string   `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.TargetIDs) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids is required")
		return
	}
	if len(req.Templates) == 0 && len(req.CustomPaths) == 0 {
		writeError(w, http.StatusBadRequest, "templates or custom_paths is required")
		return
	}

	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	var selected []*remote.RemoteTarget
	for _, idx := range req.TargetIDs {
		if idx >= 0 && idx < len(all) {
			selected = append(selected, all[idx])
		}
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "no valid targets at given indices")
		return
	}

	maxP := req.MaxParallel
	if maxP <= 0 {
		maxP = 3
	}

	outputDir := filepath.Join(appCtx.RootDir, "output", appCtx.ActiveCase.ID, "remote",
		"evidence_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"targets": len(selected),
	})

	go func() {
		broadcastProgress("evidence_collect_started", map[string]interface{}{
			"targets":   len(selected),
			"templates": req.Templates,
		})

		type hostSummary struct {
			Host      string `json:"host"`
			Collected int    `json:"collected"`
			Failed    int    `json:"failed"`
			Total     int    `json:"total"`
		}

		var mu sync.Mutex
		var allResults []hostSummary
		sem := make(chan struct{}, maxP)
		var wg sync.WaitGroup

		for _, rt := range selected {
			wg.Add(1)
			go func(t *remote.RemoteTarget) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				host := t.IPAddress
				if host == "" {
					host = t.Hostname
				}
				hostDir := filepath.Join(outputDir, host)
				_ = os.MkdirAll(hostDir, 0o700)

				isLinux := strings.EqualFold(t.OSType, "linux")

				// Connect once; reuse for discovery and file transfer.
				nt := t.AsNetworkTarget(req.Password)
				client, clientErr := network.NewClient(nt)
				if clientErr != nil {
					mu.Lock()
					allResults = append(allResults, hostSummary{Host: host})
					mu.Unlock()
					return
				}
				if connErr := client.Connect(); connErr != nil {
					mu.Lock()
					allResults = append(allResults, hostSummary{Host: host})
					mu.Unlock()
					return
				}
				defer client.Close()

				// Phase 1: build the file list from templates + custom paths.
				var filesToCollect []string

				for _, tmplName := range req.Templates {
					var tmplMap map[string]EvidenceTemplate
					if isLinux {
						tmplMap = linuxEvidenceTemplates
					} else {
						tmplMap = windowsEvidenceTemplates
					}

					et, ok := tmplMap[tmplName]
					if !ok {
						continue
					}
					if len(et.Files) > 0 {
						filesToCollect = append(filesToCollect, et.Files...)
						continue
					}

					// Dynamic discovery via Execute.
					var discoverCmd string
					switch tmplName {
					case "ntuser":
						discoverCmd = `Get-ChildItem 'C:\Users\*\NTUSER.DAT' -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName`
					case "prefetch":
						discoverCmd = `Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName`
					case "browser_history":
						discoverCmd = `Get-ChildItem ` +
							`'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History',` +
							`'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History',` +
							`'C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite' ` +
							`-ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName`
					case "bash_history":
						discoverCmd = `find /root /home -maxdepth 3 \( -name '.bash_history' -o -name '.zsh_history' \) 2>/dev/null`
					case "ssh_keys":
						discoverCmd = `find /root /home -maxdepth 4 \( -name 'authorized_keys' -o -name 'known_hosts' -o -name 'id_rsa' -o -name 'id_ed25519' \) 2>/dev/null`
					}
					if discoverCmd == "" {
						continue
					}
					res := client.Execute(discoverCmd, 30*time.Second)
					for _, line := range strings.Split(res.Stdout, "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							filesToCollect = append(filesToCollect, line)
						}
					}
				}

				filesToCollect = append(filesToCollect, req.CustomPaths...)

				// Phase 2: collect files with progress + SHA256 hashing.
				type collectedFile struct {
					RemotePath string `json:"remote_path"`
					LocalPath  string `json:"local_path"`
					Size       int64  `json:"size,omitempty"`
					SHA256     string `json:"sha256,omitempty"`
					Status     string `json:"status"`
					Error      string `json:"error,omitempty"`
				}
				var manifest []collectedFile
				collectedCount, failedCount := 0, 0
				total := len(filesToCollect)

				for i, remotePath := range filesToCollect {
					broadcastProgress("evidence_collect_step", map[string]interface{}{
						"host":    host,
						"file":    filepath.Base(remotePath),
						"current": i + 1,
						"total":   total,
					})

					// Build a safe local filename from the remote path.
					safeName := strings.NewReplacer(":", "_", `\`, "_", "/", "_").Replace(remotePath)
					safeName = strings.TrimLeft(safeName, "_")
					localPath := filepath.Join(hostDir, safeName)

					entry := collectedFile{RemotePath: remotePath, LocalPath: localPath}

					if copyErr := client.CopyFrom(remotePath, localPath); copyErr != nil {
						entry.Status = "failed"
						entry.Error = copyErr.Error()
						failedCount++
					} else {
						if fi, statErr := os.Stat(localPath); statErr == nil {
							entry.Size = fi.Size()
						}
						if h, hashErr := hashFileSHA256(localPath); hashErr == nil {
							entry.SHA256 = h
						}
						entry.Status = "collected"
						collectedCount++
					}
					manifest = append(manifest, entry)
				}

				// Write chain-of-custody manifest.
				if data, err := json.MarshalIndent(manifest, "", "  "); err == nil {
					_ = os.WriteFile(filepath.Join(hostDir, "evidence_manifest.json"), data, 0o644)
				}

				mu.Lock()
				allResults = append(allResults, hostSummary{
					Host:      host,
					Collected: collectedCount,
					Failed:    failedCount,
					Total:     total,
				})
				mu.Unlock()
			}(rt)
		}

		wg.Wait()

		broadcastProgress("evidence_collect_complete", map[string]interface{}{
			"output_dir": outputDir,
			"results":    allResults,
		})
	}()
}

// ---------------------------------------------------------------------------
// Remote live response
// ---------------------------------------------------------------------------

// handleRemoteLiveResponse — POST /api/remote/live-response.
// Body: {target_id, module, command, password}.
// Synchronous: executes one forensic module on the target and returns the
// output immediately so the SPA can render tabbed live-response views.
func handleRemoteLiveResponse(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetID int    `json:"target_id"`
		Module   string `json:"module"`  // see switch below
		Command  string `json:"command"` // only for "command" module
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	nt, rt, err := resolveNetworkTarget(req.TargetID, req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	isWindows := !strings.EqualFold(rt.OSType, "linux")
	var cmd string
	timeout := 60 * time.Second

	if isWindows {
		switch req.Module {
		case "processes":
			timeout = 90 * time.Second
			cmd = `Get-Process | Select-Object Id,ProcessName,CPU,` +
				`@{N='MemMB';E={[math]::Round($_.WorkingSet64/1MB,1)}},Path,StartTime | ` +
				`Sort-Object CPU -Descending | ConvertTo-Json -Depth 2`
		case "network":
			timeout = 90 * time.Second
			cmd = `Get-NetTCPConnection | Select-Object ` +
				`@{N='PID';E={$_.OwningProcess}},` +
				`@{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},` +
				`LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ` +
				`Where-Object {$_.State -eq 'Established' -or $_.State -eq 'Listen'} | ` +
				`Sort-Object State,RemoteAddress | ConvertTo-Json -Depth 2`
		case "services":
			cmd = `Get-Service | Select-Object Name,DisplayName,Status,StartType | ` +
				`Sort-Object Status,Name | ConvertTo-Json -Depth 2`
		case "users":
			cmd = `@{` +
				`LocalUsers=(Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet);` +
				`LoggedOn=(query user 2>$null);` +
				`AdminGroup=(Get-LocalGroupMember Administrators -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass)` +
				`} | ConvertTo-Json -Depth 3`
		case "autoruns":
			cmd = `@{` +
				`Startup=(Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User);` +
				`RunKeys=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',` +
				`'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue)` +
				`} | ConvertTo-Json -Depth 3`
		case "tasks":
			cmd = `Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | ` +
				`Select-Object TaskName,TaskPath,State,` +
				`@{N='Actions';E={($_.Actions | ForEach-Object {"$($_.Execute) $($_.Arguments)"}) -join '; '}} | ` +
				`Sort-Object TaskPath,TaskName | ConvertTo-Json -Depth 2`
		case "logons":
			timeout = 120 * time.Second
			cmd = `Get-WinEvent -LogName Security ` +
				`-FilterXPath "*[System[(EventID=4624 or EventID=4625)]]" ` +
				`-MaxEvents 100 -ErrorAction SilentlyContinue | ` +
				`Select-Object TimeCreated,Id,` +
				`@{N='Message';E={$_.Message.Substring(0,[Math]::Min(200,$_.Message.Length))}} | ` +
				`ConvertTo-Json -Depth 2`
		case "command":
			if req.Command == "" {
				writeError(w, http.StatusBadRequest, "command is required for command module")
				return
			}
			cmd = req.Command
		default:
			writeError(w, http.StatusBadRequest, "unknown module: "+req.Module)
			return
		}
	} else {
		switch req.Module {
		case "processes":
			cmd = `ps auxww --sort=-%cpu | head -100`
		case "network":
			cmd = `ss -tulpn; echo '--- ESTABLISHED ---'; ss -tn state established`
		case "services":
			cmd = `systemctl list-units --type=service --state=running --no-pager --no-legend`
		case "users":
			cmd = `echo '=== LOGGED IN ==='; w; ` +
				`echo '=== LOCAL USERS ==='; grep -v nologin /etc/passwd | grep -v '/bin/false'; ` +
				`echo '=== SUDO GROUP ==='; getent group sudo wheel 2>/dev/null; ` +
				`echo '=== LAST LOGINS ==='; last -n 20`
		case "autoruns":
			cmd = `echo '=== CRONTAB ROOT ==='; crontab -l 2>/dev/null; ` +
				`echo '=== SYSTEM CRON ==='; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null; ` +
				`echo '=== SYSTEMD ENABLED ==='; systemctl list-unit-files --state=enabled --no-pager 2>/dev/null`
		case "tasks":
			cmd = `echo '=== AT JOBS ==='; atq 2>/dev/null; ` +
				`echo '=== TIMER UNITS ==='; systemctl list-timers --no-pager 2>/dev/null; ` +
				`echo '=== USER CRONTABS ==='; ` +
				`for u in $(cut -f1 -d: /etc/passwd); do ` +
				`c=$(crontab -l -u "$u" 2>/dev/null); ` +
				`[ -n "$c" ] && echo "=== $u ===" && echo "$c"; done`
		case "logons":
			cmd = `echo '=== AUTH LOG (last 100) ==='; ` +
				`tail -100 /var/log/auth.log 2>/dev/null || tail -100 /var/log/secure 2>/dev/null; ` +
				`echo '=== FAILED LOGINS ==='; ` +
				`grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 || ` +
				`grep 'Failed password' /var/log/secure 2>/dev/null | tail -20`
		case "command":
			if req.Command == "" {
				writeError(w, http.StatusBadRequest, "command is required for command module")
				return
			}
			cmd = req.Command
		default:
			writeError(w, http.StatusBadRequest, "unknown module: "+req.Module)
			return
		}
	}

	client, clientErr := network.NewClient(nt)
	if clientErr != nil {
		writeError(w, http.StatusInternalServerError, "init client: "+clientErr.Error())
		return
	}
	if connErr := client.Connect(); connErr != nil {
		writeError(w, http.StatusBadRequest, "connect: "+connErr.Error())
		return
	}
	defer client.Close()

	res := client.Execute(cmd, timeout)

	errStr := ""
	if res.Err != nil {
		errStr = res.Err.Error()
	}
	format := "text"
	if req.Module != "command" && isWindows {
		format = "json"
	}
	status := "ok"
	if res.Err != nil {
		status = "error"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    status,
		"module":    req.Module,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
		"exit_code": res.ExitCode,
		"duration":  res.Duration.Seconds(),
		"error":     errStr,
		"format":    format,
	})
}

// ---------------------------------------------------------------------------
// Remote memory capture
// ---------------------------------------------------------------------------

// handleRemoteMemoryCapture — POST /api/remote/memory-capture.
// Body: {target_id, tool, password}.
// Uploads DumpIt or WinPmem to a Windows target, captures RAM, pulls the dump
// back via client.CopyFrom (which handles large files via SMB automatically),
// and SHA256-hashes the result for chain of custody.
func handleRemoteMemoryCapture(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetID int    `json:"target_id"`
		Tool     string `json:"tool"`     // "dumpit" | "winpmem"
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	switch req.Tool {
	case "dumpit", "winpmem", "":
	default:
		writeError(w, http.StatusBadRequest, "unsupported tool: "+req.Tool+"; must be dumpit or winpmem")
		return
	}
	if req.Tool == "" {
		req.Tool = "dumpit"
	}

	nt, rt, err := resolveNetworkTarget(req.TargetID, req.Password)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	hostname := rt.Hostname
	if hostname == "" {
		hostname = rt.IPAddress
	}
	outDir := remoteOutDir(appCtx.RootDir, appCtx.ActiveCase.ID, hostname, "memory")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status": "started",
		"target": rt.DisplayName(),
		"tool":   req.Tool,
	})

	go func() {
		broadcast := func(step string) {
			broadcastProgress("remote_mem_step", map[string]interface{}{
				"target": rt.DisplayName(),
				"step":   step,
			})
		}
		fail := func(msg string) {
			broadcastProgress("remote_mem_complete", map[string]interface{}{
				"target": rt.DisplayName(),
				"status": "failed",
				"error":  msg,
			})
		}

		// Locate the local binary (try OS-specific suffix first).
		toolPath := appCtx.ToolManager.GetInstalledPath(req.Tool + "-win")
		if toolPath == "" {
			toolPath = appCtx.ToolManager.GetInstalledPath(req.Tool)
		}
		if toolPath == "" {
			fail(req.Tool + " binary not installed locally (run Tools → Download to install it)")
			return
		}

		ts := time.Now().Format("20060102_150405")
		remoteTempDir := `C:\Windows\Temp\vanguard_memdump`
		remoteToolBin := remoteTempDir + `\` + filepath.Base(toolPath)
		remoteDumpFile := remoteTempDir + `\` + hostname + `_` + ts + `.raw`
		localDumpFile := filepath.Join(outDir, hostname+"_"+ts+".raw")

		broadcast("connecting to " + rt.DisplayName())
		client, clientErr := network.NewClient(nt)
		if clientErr != nil {
			fail("init client: " + clientErr.Error())
			return
		}
		if connErr := client.Connect(); connErr != nil {
			fail("connect: " + connErr.Error())
			return
		}
		defer client.Close()

		broadcast("creating remote working directory")
		client.Execute(`New-Item -ItemType Directory -Force -Path '`+remoteTempDir+`'`, 30*time.Second)

		broadcast("uploading " + req.Tool + " (" + filepath.Base(toolPath) + ")")
		if uploadErr := client.CopyTo(toolPath, remoteToolBin); uploadErr != nil {
			fail("upload tool: " + uploadErr.Error())
			return
		}

		var captureCmd string
		switch req.Tool {
		case "winpmem":
			captureCmd = fmt.Sprintf(`& '%s' '%s'`, remoteToolBin, remoteDumpFile)
		default: // dumpit
			captureCmd = fmt.Sprintf(`& '%s' /OUTPUT '%s' /Q /T RAW`, remoteToolBin, remoteDumpFile)
		}

		broadcast("capturing memory on " + rt.DisplayName() + " (this may take several minutes)")
		captureRes := client.Execute(captureCmd, 30*time.Minute)
		if captureRes.Err != nil {
			fail("capture failed: " + captureRes.Err.Error())
			return
		}

		// Get remote dump size for the report before we pull it.
		sizeRes := client.Execute(
			fmt.Sprintf(`(Get-Item '%s' -ErrorAction SilentlyContinue).Length`, remoteDumpFile),
			30*time.Second)
		remoteSize := strings.TrimSpace(sizeRes.Stdout)

		broadcast("downloading memory dump to analyst workstation")
		if copyErr := client.CopyFrom(remoteDumpFile, localDumpFile); copyErr != nil {
			fail("download dump: " + copyErr.Error())
			return
		}

		var dumpSize int64
		if fi, statErr := os.Stat(localDumpFile); statErr == nil {
			dumpSize = fi.Size()
		}
		broadcast("computing SHA256 hash")
		var hashStr string
		if h, hashErr := hashFileSHA256(localDumpFile); hashErr == nil {
			hashStr = h
		}

		// Chain-of-custody JSON report.
		report := map[string]interface{}{
			"host":                  rt.DisplayName(),
			"tool":                  req.Tool,
			"remote_dump":           remoteDumpFile,
			"local_dump":            localDumpFile,
			"size":                  dumpSize,
			"size_fmt":              formatMemSize(dumpSize),
			"remote_size_reported":  remoteSize,
			"sha256":                hashStr,
			"captured_at":           time.Now().UTC().Format(time.RFC3339),
			"capture_stdout":        captureRes.Stdout,
		}
		if data, merr := json.MarshalIndent(report, "", "  "); merr == nil {
			_ = os.WriteFile(filepath.Join(outDir, "memory_capture_report.json"), data, 0o644)
		}

		broadcast("cleaning up remote temp files")
		client.Execute(`Remove-Item -Recurse -Force '`+remoteTempDir+`'`, 30*time.Second)

		broadcastProgress("remote_mem_complete", map[string]interface{}{
			"target":     rt.DisplayName(),
			"status":     "success",
			"local_dump": localDumpFile,
			"size":       dumpSize,
			"size_fmt":   formatMemSize(dumpSize),
			"sha256":     hashStr,
			"output_dir": outDir,
		})
	}()
}

// hashFileSHA256 computes the SHA256 hex digest of the file at path.
func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// Remote IOC sweep
// ---------------------------------------------------------------------------

// handleRemoteIOCSweep — POST /api/remote/ioc-sweep.
// Body: {target_ids, ioc_type, indicators, max_parallel, password}.
// Searches each selected target for the supplied indicators across running
// processes, network connections, DNS cache, file system, and registry.
func handleRemoteIOCSweep(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		TargetIDs   []int    `json:"target_ids"`
		IOCType     string   `json:"ioc_type"`   // "hash"|"filename"|"ip"|"domain"|"registry"|"all"
		Indicators  []string `json:"indicators"`
		MaxParallel int      `json:"max_parallel"`
		Password    string   `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.TargetIDs) == 0 {
		writeError(w, http.StatusBadRequest, "target_ids is required")
		return
	}
	if len(req.Indicators) == 0 {
		writeError(w, http.StatusBadRequest, "indicators is required")
		return
	}

	appCtx := getAppCtx()
	if appCtx == nil || appCtx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}

	store, err := ensureRemoteStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := store.All()

	var selected []*remote.RemoteTarget
	for _, idx := range req.TargetIDs {
		if idx >= 0 && idx < len(all) {
			selected = append(selected, all[idx])
		}
	}
	if len(selected) == 0 {
		writeError(w, http.StatusBadRequest, "no valid targets at given indices")
		return
	}

	if req.IOCType == "" {
		req.IOCType = "all"
	}
	maxP := req.MaxParallel
	if maxP <= 0 {
		maxP = 5
	}

	outputDir := filepath.Join(appCtx.RootDir, "output", appCtx.ActiveCase.ID, "remote",
		"ioc_sweep_"+time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "mkdir: "+err.Error())
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":  "started",
		"targets": len(selected),
	})

	go func() {
		broadcastProgress("ioc_sweep_started", map[string]interface{}{
			"targets":    len(selected),
			"indicators": len(req.Indicators),
			"type":       req.IOCType,
		})

		type iocHit struct {
			Host     string `json:"host"`
			IOC      string `json:"ioc"`
			IOCType  string `json:"ioc_type"`
			Location string `json:"location"`
			Details  string `json:"details"`
		}
		type hostResult struct {
			Host string `json:"host"`
			Hits int    `json:"hits"`
		}

		var mu sync.Mutex
		var allHits []iocHit
		var hostResults []hostResult
		sem := make(chan struct{}, maxP)
		var wg sync.WaitGroup

		for _, rt := range selected {
			wg.Add(1)
			go func(t *remote.RemoteTarget) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				host := t.IPAddress
				if host == "" {
					host = t.Hostname
				}
				hostDir := filepath.Join(outputDir, host)
				_ = os.MkdirAll(hostDir, 0o700)
				isLinux := strings.EqualFold(t.OSType, "linux")

				// Single connection reused for all commands on this target.
				nt := t.AsNetworkTarget(req.Password)
				client, clientErr := network.NewClient(nt)
				if clientErr != nil {
					mu.Lock()
					hostResults = append(hostResults, hostResult{Host: host})
					mu.Unlock()
					return
				}
				if connErr := client.Connect(); connErr != nil {
					mu.Lock()
					hostResults = append(hostResults, hostResult{Host: host})
					mu.Unlock()
					return
				}
				defer client.Close()

				var hits []iocHit

				for _, ioc := range req.Indicators {
					ioc = strings.TrimSpace(ioc)
					if ioc == "" {
						continue
					}

					broadcastProgress("ioc_sweep_step", map[string]interface{}{
						"host": host,
						"ioc":  ioc,
					})

					// Collect (iocType, command) pairs to run for this IOC.
					type cmdSpec struct{ iocType, cmd string }
					var cmds []cmdSpec

					if !isLinux {
						// ── Windows commands ──────────────────────────────
						if req.IOCType == "hash" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"hash", fmt.Sprintf(
								`Get-Process | Where-Object {$_.Path} | ForEach-Object {`+
									`$h=(Get-FileHash $_.Path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash;`+
									`if($h -eq '%s'){"$($_.Id) $($_.ProcessName) $($_.Path)"}}`,
								ioc)})
						}
						if req.IOCType == "filename" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"filename", fmt.Sprintf(
								`Get-ChildItem -Path 'C:\Users','C:\Windows\Temp','C:\ProgramData','C:\Windows\System32'`+
									` -Recurse -ErrorAction SilentlyContinue -Filter '%s'`+
									` | Select-Object FullName,Length,LastWriteTime | ConvertTo-Csv -NoTypeInformation`,
								ioc)})
						}
						if req.IOCType == "ip" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"ip", fmt.Sprintf(
								`Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq '%s'}`+
									` | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess`+
									` | ConvertTo-Csv -NoTypeInformation`,
								ioc)})
							cmds = append(cmds, cmdSpec{"ip", fmt.Sprintf(
								`Get-DnsClientCache | Where-Object {$_.Data -eq '%s'}`+
									` | Select-Object Entry,RecordName,Data | ConvertTo-Csv -NoTypeInformation`,
								ioc)})
						}
						if req.IOCType == "domain" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"domain", fmt.Sprintf(
								`Get-DnsClientCache | Where-Object {$_.Entry -like '*%s*'}`+
									` | Select-Object Entry,RecordName,RecordType,Data | ConvertTo-Csv -NoTypeInformation`,
								ioc)})
							cmds = append(cmds, cmdSpec{"domain", fmt.Sprintf(
								`Select-String -Path 'C:\Windows\System32\drivers\etc\hosts'`+
									` -Pattern '%s' -ErrorAction SilentlyContinue`,
								ioc)})
						}
						if req.IOCType == "registry" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"registry", fmt.Sprintf(
								`Get-ChildItem -Path HKLM:\SOFTWARE,HKLM:\SYSTEM,HKCU:\SOFTWARE`+
									` -Recurse -ErrorAction SilentlyContinue`+
									` | Get-ItemProperty -ErrorAction SilentlyContinue`+
									` | Where-Object {$_ -match '%s'}`+
									` | Select-Object PSPath | Select-Object -First 20 | ConvertTo-Csv -NoTypeInformation`,
								ioc)})
						}
					} else {
						// ── Linux commands ────────────────────────────────
						if req.IOCType == "hash" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"hash", fmt.Sprintf(
								`find /usr/bin /usr/sbin /usr/local/bin /tmp /var/tmp -type f`+
									` -exec sha256sum {} \; 2>/dev/null | grep -i '%s'`,
								ioc)})
						}
						if req.IOCType == "filename" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"filename", fmt.Sprintf(
								`find / -name '%s' -not -path '/proc/*' -not -path '/sys/*' -type f 2>/dev/null | head -50`,
								ioc)})
						}
						if req.IOCType == "ip" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"ip", fmt.Sprintf(
								`ss -tn 2>/dev/null | grep '%s'; netstat -tn 2>/dev/null | grep '%s'`,
								ioc, ioc)})
						}
						if req.IOCType == "domain" || req.IOCType == "all" {
							cmds = append(cmds, cmdSpec{"domain", fmt.Sprintf(
								`grep -r '%s' /etc/hosts /var/log/ 2>/dev/null | head -50`,
								ioc)})
						}
					}

					for _, c := range cmds {
						res := client.Execute(c.cmd, 2*time.Minute)
						out := strings.TrimSpace(res.Stdout)
						if out == "" || res.Err != nil {
							continue
						}
						details := out
						if len(details) > 500 {
							details = details[:500] + "…"
						}
						hits = append(hits, iocHit{
							Host:     host,
							IOC:      ioc,
							IOCType:  c.iocType,
							Location: c.iocType,
							Details:  details,
						})
					}
				}

				// Save per-host hits file.
				if len(hits) > 0 {
					if data, merr := json.MarshalIndent(hits, "", "  "); merr == nil {
						_ = os.WriteFile(filepath.Join(hostDir, "ioc_hits.json"), data, 0o644)
					}
				}

				mu.Lock()
				allHits = append(allHits, hits...)
				hostResults = append(hostResults, hostResult{Host: host, Hits: len(hits)})
				mu.Unlock()
			}(rt)
		}

		wg.Wait()

		// Save consolidated hits across all targets.
		if len(allHits) > 0 {
			if data, merr := json.MarshalIndent(allHits, "", "  "); merr == nil {
				_ = os.WriteFile(filepath.Join(outputDir, "all_ioc_hits.json"), data, 0o644)
			}
		}

		broadcastProgress("ioc_sweep_complete", map[string]interface{}{
			"total_hits":   len(allHits),
			"output_dir":   outputDir,
			"host_results": hostResults,
			"hits":         allHits,
		})
	}()
}
