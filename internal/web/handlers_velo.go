package web

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// fileExists reports whether path points at a regular (non-directory) file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// formatVeloSize formats a byte count as a human-readable string.
func formatVeloSize(bytes int64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%d B", bytes)
	case bytes < 1048576:
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(bytes)/1048576)
	}
}

// handleVeloStatus — GET /api/velo/status.
func handleVeloStatus(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx()
	if ctx == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}

	binaryInstalled := false
	binaryPath := ""
	version := ""

	if ctx.VRManager != nil {
		if p, err := ctx.VRManager.BinaryPath(); err == nil && p != "" {
			binaryInstalled = true
			binaryPath = p
			// Best-effort version fetch — 3-second cap so the status page
			// never hangs waiting for a slow disk.
			vCtx, vCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer vCancel()
			if out, vErr := exec.CommandContext(vCtx, p, "version").Output(); vErr == nil {
				version = strings.TrimSpace(string(out))
			}
		}
	}

	// Probe common Velociraptor GUI ports for a running server. We don't
	// manage the server lifecycle; we just report what we observe.
	serverRunning := false
	guiURL := ""
	for _, port := range []int{8889, 8443} {
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			serverRunning = true
			guiURL = fmt.Sprintf("https://127.0.0.1:%d", port)
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"binary_installed": binaryInstalled,
		"binary_path":      binaryPath,
		"version":          version,
		"server_running":   serverRunning,
		"gui_url":          guiURL,
	})
}

// handleVeloLaunchGUI — POST /api/velo/launch-gui.
//
// Starts `velociraptor gui` in a new visible window. This runs Velociraptor
// in "instant" mode — a self-contained local server + client + web UI in one
// command, no prior configuration needed. Best for single-machine triage.
func handleVeloLaunchGUI(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.VRManager == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	veloPath, err := ctx.VRManager.BinaryPath()
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"Velociraptor binary not found — download it via Configuration > Tool Management")
		return
	}

	// Generate a one-time random password so the GUI does not use the
	// Velociraptor built-in default (admin / password).
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		// Crypto/rand failure is extremely rare; fall back to a fixed
		// non-default value so the handler still works but warn clearly.
		writeError(w, http.StatusInternalServerError,
			"Failed to generate GUI password: "+err.Error())
		return
	}
	guiPassword := base64.RawURLEncoding.EncodeToString(pwBytes)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// /c start "<title>" <binary> gui --password <pw> — opens a new
		// cmd.exe window and returns immediately.
		cmd = exec.Command("cmd", "/c", "start", "Velociraptor", veloPath,
			"gui", "--password", guiPassword)
	} else {
		cmd = exec.Command(veloPath, "gui", "--password", guiPassword)
	}
	cmd.Dir = ctx.RootDir

	if startErr := cmd.Start(); startErr != nil {
		writeError(w, http.StatusInternalServerError,
			"Failed to launch Velociraptor: "+startErr.Error())
		return
	}

	// Return the one-time password in the response. It is NOT logged.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"message":  fmt.Sprintf("Velociraptor GUI launched — username: admin, password: %s (one-time, not logged)", guiPassword),
		"url":      "https://127.0.0.1:8889",
		"username": "admin",
		"password": guiPassword,
	})
}

// handleVeloLaunchServer — POST /api/velo/launch-server.
//
// Opens a terminal window with either the interactive config wizard (first
// run, no server.config.yaml present) or a direct server start (subsequent
// runs). The wizard handles config generation, certs, and admin user creation
// interactively — VanGuard does not attempt to automate these steps.
func handleVeloLaunchServer(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.VRManager == nil {
		writeError(w, http.StatusInternalServerError, "context not initialised")
		return
	}
	veloPath, err := ctx.VRManager.BinaryPath()
	if err != nil {
		writeError(w, http.StatusBadRequest,
			"Velociraptor binary not found — download it via Configuration > Tool Management")
		return
	}

	configDir := filepath.Join(ctx.RootDir, "config", "velociraptor")
	if mkErr := os.MkdirAll(configDir, 0o755); mkErr != nil {
		writeError(w, http.StatusInternalServerError, "creating config dir: "+mkErr.Error())
		return
	}
	serverConfig := filepath.Join(configDir, "server.config.yaml")

	if runtime.GOOS == "windows" {
		var batchContent string
		if fileExists(serverConfig) {
			// Config already exists — start the server directly.
			batchContent = "@echo off\r\n" +
				"echo Starting Velociraptor server...\r\n" +
				"echo.\r\n" +
				"\"" + veloPath + "\" --config \"" + serverConfig + "\" frontend -v\r\n" +
				"pause\r\n"
		} else {
			// First run — open the interactive wizard.
			batchContent = "@echo off\r\n" +
				"echo ================================================\r\n" +
				"echo   VanGuard - Velociraptor Server Setup\r\n" +
				"echo ================================================\r\n" +
				"echo.\r\n" +
				"echo Follow the wizard steps:\r\n" +
				"echo   1. Choose Self Signed SSL\r\n" +
				"echo   2. Accept defaults for most options\r\n" +
				"echo   3. Create an admin user when prompted\r\n" +
				"echo   4. Save config as: server.config.yaml\r\n" +
				"echo.\r\n" +
				"cd /d \"" + configDir + "\"\r\n" +
				"\"" + veloPath + "\" config generate -i\r\n" +
				"echo.\r\n" +
				"if exist server.config.yaml (\r\n" +
				"    echo Generating client config...\r\n" +
				"    \"" + veloPath + "\" --config server.config.yaml config client > client.config.yaml\r\n" +
				"    echo Starting server...\r\n" +
				"    \"" + veloPath + "\" --config server.config.yaml frontend -v\r\n" +
				") else (\r\n" +
				"    echo Config not found. Re-run the wizard.\r\n" +
				")\r\n" +
				"pause\r\n"
		}
		batchFile := filepath.Join(configDir, "launch_server.bat")
		if writeErr := os.WriteFile(batchFile, []byte(batchContent), 0o755); writeErr != nil {
			writeError(w, http.StatusInternalServerError, "writing launch script: "+writeErr.Error())
			return
		}
		if startErr := exec.Command("cmd", "/c", "start", "Velociraptor Server", batchFile).Start(); startErr != nil {
			writeError(w, http.StatusInternalServerError, "opening terminal: "+startErr.Error())
			return
		}
	} else {
		if fileExists(serverConfig) {
			cmd := exec.Command(veloPath, "--config", serverConfig, "frontend", "-v")
			cmd.Dir = ctx.RootDir
			_ = cmd.Start()
		} else {
			script := "#!/bin/bash\ncd " + configDir + "\n" +
				veloPath + " config generate -i\n" +
				"if [ -f server.config.yaml ]; then\n" +
				"  " + veloPath + " --config server.config.yaml config client > client.config.yaml\n" +
				"  " + veloPath + " --config server.config.yaml frontend -v\n" +
				"fi\n"
			scriptFile := filepath.Join(configDir, "launch_server.sh")
			_ = os.WriteFile(scriptFile, []byte(script), 0o755)
			_ = exec.Command("x-terminal-emulator", "-e", scriptFile).Start()
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"message": "Velociraptor server window opened",
	})
}

// handleVeloImport — POST /api/velo/import. Body: {path}.
//
// Extracts an offline collection ZIP into the active case's evidence tree
// and registers the output directory as evidence.
func handleVeloImport(w http.ResponseWriter, r *http.Request) {
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

	absPath, err := filepath.Abs(req.Path)
	if err != nil {
		absPath = req.Path
	}
	if !fileExists(absPath) {
		writeError(w, http.StatusBadRequest, "file not found: "+absPath)
		return
	}

	outputDir := filepath.Join(ctx.RootDir, "output", ctx.ActiveCase.ID,
		"velociraptor", "import_"+time.Now().Format("20060102_150405"))
	if mkErr := os.MkdirAll(outputDir, 0o700); mkErr != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+mkErr.Error())
		return
	}

	fileCount, totalSize, extractErr := extractZIP(absPath, outputDir)
	if extractErr != nil {
		writeError(w, http.StatusInternalServerError, "extract failed: "+extractErr.Error())
		return
	}

	if ctx.CaseManager != nil {
		_, _ = ctx.CaseManager.AddEvidence(ctx.ActiveCase.ID, 0, "velociraptor_import", outputDir)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"message":     fmt.Sprintf("Imported %d files (%s)", fileCount, formatVeloSize(totalSize)),
		"output_path": outputDir,
	})
}

// extractZIP extracts a ZIP archive to destDir, guarding against zip-slip.
// Returns the count and total bytes of extracted files.
func extractZIP(zipPath, destDir string) (int, int64, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, 0, err
	}
	defer zr.Close()

	destDir = filepath.Clean(destDir)
	sep := string(os.PathSeparator)
	fileCount := 0
	var totalSize int64

	for _, f := range zr.File {
		targetPath := filepath.Join(destDir, filepath.FromSlash(f.Name))
		// Zip-slip guard: reject any path that escapes the destination tree.
		if !strings.HasPrefix(filepath.Clean(targetPath)+sep, destDir+sep) {
			continue
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(targetPath, 0o755)
			continue
		}
		if mkErr := os.MkdirAll(filepath.Dir(targetPath), 0o755); mkErr != nil {
			continue
		}
		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}
		out, createErr := os.Create(targetPath)
		if createErr != nil {
			rc.Close()
			continue
		}
		written, _ := io.Copy(out, rc)
		out.Close()
		rc.Close()
		fileCount++
		totalSize += written
	}
	return fileCount, totalSize, nil
}
