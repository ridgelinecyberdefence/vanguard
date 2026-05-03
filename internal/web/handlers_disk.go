package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/disk"
)

// handleDiskCollect — POST /api/disk/collect.
//
// Body: {type: "kape_<preset>" | "ez_<parser>" | "uac_<profile>" | "logs_*" | "user_*" | "sys_*"}.
//
// The TUI implements each of these via interactive flows in disk_panel.go;
// the web equivalent runs them synchronously through the shared
// internal/disk managers and reports the result in one HTTP response. For
// long-running parsers we still respond inline because the analyst clicks
// one button and waits — no need for the full WebSocket-progress dance.
func handleDiskCollect(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}
	var req struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "type is required")
		return
	}

	// Per-call timeout. KAPE on a system drive can be slow; UAC + EZ Tools
	// usually finish quickly. 30 minutes is enough for the slow path
	// without being abusive.
	runCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	switch {
	case strings.HasPrefix(req.Type, "kape_"):
		runKapeCollection(w, runCtx, ctx, req.Type)
	case strings.HasPrefix(req.Type, "ez_"):
		runEZParser(w, runCtx, ctx, req.Type)
	case strings.HasPrefix(req.Type, "uac_"):
		runUACCollection(w, runCtx, ctx, req.Type)
	case strings.HasPrefix(req.Type, "logs_"):
		runLogCollection(w, runCtx, ctx, req.Type)
	case strings.HasPrefix(req.Type, "user_") || strings.HasPrefix(req.Type, "sys_"):
		runDirCopyCollection(w, runCtx, ctx, req.Type)
	default:
		writeError(w, http.StatusBadRequest, "unknown collection type: "+req.Type)
	}
}

// runKapeCollection dispatches the kape_<preset> family to KAPE's preset
// runner. The preset string after the underscore matches KapeManager's
// switch (sans / full / evtx / registry / browser).
func runKapeCollection(w http.ResponseWriter, ctx context.Context, app interface{}, t string) {
	appCtx := getAppCtx()
	preset := strings.TrimPrefix(t, "kape_")

	km := disk.NewKapeManager(appCtx.RootDir, appCtx.Logger)
	if !km.Installed() {
		writeError(w, http.StatusBadRequest,
			"KAPE not installed. Download from https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape and place kape.exe in bin/windows/kape/")
		return
	}
	outDir := caseDiskOutDir(appCtx, "kape", time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}
	result := km.CollectPreset(ctx, preset, outDir)
	registerDiskEvidence(appCtx, "disk_kape", outDir, result)
	writeCollectionResult(w, result, outDir)
}

// findEZTool returns the absolute path to an EZ Tools binary.
// Probes flat layout first (current shipping layout: all .exe files at the
// ez-tools root), then per-tool subdirectory, so it works across every
// known release shape.
func findEZTool(rootDir, toolName string) string {
	ezBase := filepath.Join(rootDir, "bin", "windows", "ez-tools")

	// 1. Exact flat match: ez-tools/EvtxECmd.exe
	flat := filepath.Join(ezBase, toolName+".exe")
	if fileExists(flat) {
		return flat
	}
	// 2. Case-insensitive flat scan (handles EVTXECMD.EXE casing variants).
	entries, err := os.ReadDir(ezBase)
	if err != nil {
		return ""
	}
	target := strings.ToLower(toolName + ".exe")
	for _, e := range entries {
		if !e.IsDir() && strings.ToLower(e.Name()) == target {
			return filepath.Join(ezBase, e.Name())
		}
	}
	// 3. Per-tool subdirectory: ez-tools/EvtxECmd/EvtxECmd.exe
	subdir := filepath.Join(ezBase, toolName, toolName+".exe")
	if fileExists(subdir) {
		return subdir
	}
	return ""
}

// runEZToolDirect runs a single EZ Tools binary with custom args.
// It is a low-level escape hatch for callers that need to pass flags that
// disk.EZToolsManager does not expose, or to invoke a newly-added tool before
// the manager gains a typed wrapper for it.
func runEZToolDirect(ctx context.Context, rootDir, toolName string, args []string) (string, error) {
	bin := findEZTool(rootDir, toolName)
	if bin == "" {
		return "", fmt.Errorf("%s not found in bin/windows/ez-tools/", toolName)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(bin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// findLatestArtifacts returns the most-recent collection root for caseID.
// It searches in priority order: KAPE output → triage output → any other
// timestamped disk directory → any directory in the case tree containing
// .evtx files. Returns "" when nothing is found.
func findLatestArtifacts(rootDir, caseID string) string {
	// Priority 1: KAPE (richest EZ-Tools-compatible artifact tree).
	if p := disk.LatestKapeCollection(rootDir, caseID); p != "" {
		return p
	}
	// Priority 2: Quick Triage output.
	if p := disk.LatestTriageCollection(rootDir, caseID); p != "" {
		return p
	}
	// Priority 3: Any other timestamped directory under disk/<kind>/.
	diskBase := filepath.Join(rootDir, "output", caseID, "disk")
	if entries, err := os.ReadDir(diskBase); err == nil {
		var latest, latestName string
		for _, kind := range entries {
			if !kind.IsDir() {
				continue
			}
			tsEntries, err := os.ReadDir(filepath.Join(diskBase, kind.Name()))
			if err != nil {
				continue
			}
			for _, ts := range tsEntries {
				if ts.IsDir() && ts.Name() > latestName {
					latestName = ts.Name()
					latest = filepath.Join(diskBase, kind.Name(), ts.Name())
				}
			}
		}
		if latest != "" {
			return latest
		}
	}
	// Priority 4: Anywhere in the case tree that has .evtx files.
	caseDir := filepath.Join(rootDir, "output", caseID)
	var evtxRoot string
	_ = filepath.Walk(caseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(info.Name()), ".evtx") {
			evtxRoot = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})
	return evtxRoot
}

// findFilesWithExtension searches rootDir recursively for files with the given
// extension (e.g. ".evtx"). Returns the parent directory of the first match,
// or "" when none is found.
func findFilesWithExtension(rootDir, ext string) string {
	ext = strings.ToLower(ext)
	var result string
	_ = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(info.Name())) == ext {
			result = filepath.Dir(path)
			return filepath.SkipAll
		}
		return nil
	})
	return result
}

// findFileRecursive searches rootDir recursively for a file with the given
// name (case-insensitive). Returns the full path to the first match, or "".
func findFileRecursive(rootDir, fileName string) string {
	target := strings.ToLower(fileName)
	var result string
	_ = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(info.Name()) == target {
			result = path
			return filepath.SkipAll
		}
		return nil
	})
	return result
}

// runEZParser dispatches the ez_<parser> family. Each parser searches the
// KAPE/triage artifact tree recursively for its required input files — KAPE
// mirrors the source drive (e.g. kape/{ts}/C/Windows/…) so tools must not
// assume a flat layout.
func runEZParser(w http.ResponseWriter, ctx context.Context, _ interface{}, t string) {
	appCtx := getAppCtx()
	parser := strings.TrimPrefix(t, "ez_")

	// Verify EZ Tools directory is present.
	ezBase := filepath.Join(appCtx.RootDir, "bin", "windows", "ez-tools")
	if info, err := os.Stat(ezBase); err != nil || !info.IsDir() {
		writeError(w, http.StatusBadRequest,
			"EZ Tools not found at bin/windows/ez-tools/ — install MFTECmd, EvtxECmd, etc. into that directory")
		return
	}

	// Pre-check: probe .NET runtime availability before attempting any parse.
	// EZ Tools are .NET applications; they exit 150 with a descriptive error
	// when the required runtime is absent. A quick --version probe catches this
	// up front so every subsequent error message is actionable.
	{
		testBin := findEZTool(appCtx.RootDir, "EvtxECmd")
		if testBin == "" {
			testBin = findEZTool(appCtx.RootDir, "PECmd")
		}
		if testBin != "" {
			testCmd := exec.Command(testBin, "--version")
			testOut, testErr := testCmd.CombinedOutput()
			testStr := string(testOut)
			if testErr != nil && (strings.Contains(testStr, "You must install or update .NET") ||
				strings.Contains(testStr, "install missing framework")) {
				writeError(w, http.StatusBadRequest,
					"EZ Tools require .NET 9.0 Runtime which is not installed. "+
						"Download from: https://dotnet.microsoft.com/download/dotnet/9")
				return
			}
		}
	}

	// Find latest artifact collection for the active case.
	if appCtx.Logger != nil {
		appCtx.Logger.Info("disk", "EZ Tools: findLatestArtifacts searching in output/%s", appCtx.ActiveCase.ID)
	}
	source := findLatestArtifacts(appCtx.RootDir, appCtx.ActiveCase.ID)
	if appCtx.Logger != nil {
		appCtx.Logger.Info("disk", "EZ Tools: findLatestArtifacts result = %q", source)
	}
	if source == "" {
		writeError(w, http.StatusBadRequest,
			"No collected artifacts found — run KAPE or Quick Triage first. "+
				"Searched: output/"+appCtx.ActiveCase.ID+"/disk/kape/, output/"+appCtx.ActiveCase.ID+"/triage/")
		return
	}

	outDir := caseDiskOutDir(appCtx, "ez_"+parser, time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}

	type toolRun struct {
		Name    string `json:"name"`
		Status  string `json:"status"`  // ok | skipped | failed
		Message string `json:"message"`
	}

	// dotnetMissing is set by runTool when the .NET runtime error is detected.
	// case "all" checks it after each tool to break early.
	dotnetMissing := false

	// runTool executes one EZ Tools binary. %OUT% in args is replaced with a
	// per-tool subdirectory. Success is measured by output-file count, not
	// exit code — EZ Tools often exit non-zero on warnings but still produce
	// valid CSV output.
	runTool := func(toolName string, args []string) toolRun {
		toolPath := findEZTool(appCtx.RootDir, toolName)
		if toolPath == "" {
			return toolRun{Name: toolName, Status: "skipped", Message: "binary not found in bin/windows/ez-tools/"}
		}
		toolOut := filepath.Join(outDir, strings.ToLower(toolName))
		if err := os.MkdirAll(toolOut, 0o700); err != nil {
			return toolRun{Name: toolName, Status: "failed", Message: "mkdir: " + err.Error()}
		}
		finalArgs := make([]string, len(args))
		for i, a := range args {
			finalArgs[i] = strings.ReplaceAll(a, "%OUT%", toolOut)
		}
		if appCtx.Logger != nil {
			appCtx.Logger.Info("disk", "EZ Tools: %s %s", filepath.Base(toolPath), strings.Join(finalArgs, " "))
		}
		cmd := exec.CommandContext(ctx, toolPath, finalArgs...)
		cmd.Dir = filepath.Dir(toolPath)
		output, err := cmd.CombinedOutput()
		if appCtx.Logger != nil {
			appCtx.Logger.Info("disk", "EZ Tools %s exit: err=%v output_len=%d", toolName, err, len(output))
			if len(output) > 0 {
				appCtx.Logger.Info("disk", "EZ Tools %s output: %s", toolName, truncate(string(output), 500))
			}
		}

		// Detect missing .NET runtime (exit 150, message in stdout/stderr).
		outputStr := string(output)
		if strings.Contains(outputStr, "You must install or update .NET") ||
			strings.Contains(outputStr, "install missing framework") {
			dotnetVer := "9.0"
			if idx := strings.Index(outputStr, "version '"); idx >= 0 {
				rest := outputStr[idx+9:]
				if end := strings.Index(rest, "'"); end > 0 {
					dotnetVer = rest[:end]
				}
			}
			majorVer := strings.SplitN(dotnetVer, ".", 2)[0]
			dotnetMissing = true
			return toolRun{
				Name:   toolName,
				Status: "failed",
				Message: fmt.Sprintf(".NET %s Runtime required. Install from: https://dotnet.microsoft.com/download/dotnet/%s",
					dotnetVer, majorVer),
			}
		}

		fileCount := 0
		_ = filepath.Walk(toolOut, func(p string, fi os.FileInfo, e error) error {
			if e == nil && !fi.IsDir() && fi.Size() > 0 {
				fileCount++
			}
			return nil
		})
		if err != nil && fileCount == 0 {
			return toolRun{Name: toolName, Status: "failed", Message: err.Error() + ": " + truncate(outputStr, 200)}
		}
		return toolRun{Name: toolName, Status: "ok", Message: fmt.Sprintf("%d output files", fileCount)}
	}

	// perFile resolves a named file recursively then runs toolName with the
	// found path substituted for the __FILE__ sentinel in args.
	perFile := func(toolName, fileName string, args []string) toolRun {
		path := findFileRecursive(source, fileName)
		if path == "" {
			if appCtx.Logger != nil {
				appCtx.Logger.Info("disk", "EZ Tools %s: %s not found under %s", toolName, fileName, source)
			}
			return toolRun{Name: toolName, Status: "skipped", Message: fileName + " not found in " + source}
		}
		if appCtx.Logger != nil {
			appCtx.Logger.Info("disk", "EZ Tools %s: input = %s", toolName, path)
		}
		finalArgs := make([]string, len(args))
		for i, a := range args {
			if a == "__FILE__" {
				finalArgs[i] = path
			} else {
				finalArgs[i] = a
			}
		}
		return runTool(toolName, finalArgs)
	}

	// perDir locates the first directory containing a file with ext, then
	// runs toolName with that directory substituted for the __DIR__ sentinel.
	perDir := func(toolName, ext string, args []string) toolRun {
		dir := findFilesWithExtension(source, ext)
		if dir == "" {
			if appCtx.Logger != nil {
				appCtx.Logger.Info("disk", "EZ Tools %s: no *%s files found under %s", toolName, ext, source)
			}
			return toolRun{Name: toolName, Status: "skipped", Message: "no " + ext + " files found in " + source}
		}
		if appCtx.Logger != nil {
			appCtx.Logger.Info("disk", "EZ Tools %s: input dir = %s", toolName, dir)
		}
		finalArgs := make([]string, len(args))
		for i, a := range args {
			if a == "__DIR__" {
				finalArgs[i] = dir
			} else {
				finalArgs[i] = a
			}
		}
		return runTool(toolName, finalArgs)
	}

	// findRecycleBin locates the $Recycle.Bin directory anywhere in the tree.
	findRecycleBin := func() string {
		var found string
		_ = filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return nil
			}
			if strings.EqualFold(info.Name(), "$Recycle.Bin") {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		return found
	}

	// findHiveDir locates the directory that holds common Windows registry hives.
	findHiveDir := func() string {
		for _, hive := range []string{"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER.DAT"} {
			if p := findFileRecursive(source, hive); p != "" {
				return filepath.Dir(p)
			}
		}
		return ""
	}

	var results []toolRun

	switch parser {
	case "evtx":
		results = append(results, perDir("EvtxECmd", ".evtx",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "EvtxECmd_Output.csv"}))

	case "mft":
		results = append(results, perFile("MFTECmd", "$MFT",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "MFT_Output.csv"}))

	case "registry":
		if hiveDir := findHiveDir(); hiveDir != "" {
			if appCtx.Logger != nil {
				appCtx.Logger.Info("disk", "EZ Tools RECmd: hive dir = %s", hiveDir)
			}
			results = append(results, runTool("RECmd",
				[]string{"-d", hiveDir, "--csv", "%OUT%", "--csvf", "Registry_Output.csv"}))
		} else {
			results = append(results, toolRun{Name: "RECmd", Status: "skipped", Message: "no registry hives found in " + source})
		}

	case "prefetch":
		results = append(results, perDir("PECmd", ".pf",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "Prefetch_Output.csv", "-q"}))

	case "amcache":
		results = append(results, perFile("AmcacheParser", "Amcache.hve",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "Amcache_Output.csv", "-i"}))

	case "shimcache":
		results = append(results, perFile("AppCompatCacheParser", "SYSTEM",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "Shimcache_Output.csv"}))

	case "jumplists":
		results = append(results, perDir("JLECmd", ".automaticDestinations-ms",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "JumpLists_Output.csv", "-q"}))

	case "lnk":
		results = append(results, perDir("LECmd", ".lnk",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "LNK_Output.csv", "-q"}))

	case "srum":
		results = append(results, perFile("SrumECmd", "SRUDB.dat",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "SRUM_Output.csv"}))

	case "recyclebin":
		if rbDir := findRecycleBin(); rbDir != "" {
			if appCtx.Logger != nil {
				appCtx.Logger.Info("disk", "EZ Tools RBCmd: dir = %s", rbDir)
			}
			results = append(results, runTool("RBCmd",
				[]string{"-d", rbDir, "--csv", "%OUT%", "--csvf", "RecycleBin_Output.csv"}))
		} else {
			results = append(results, toolRun{Name: "RBCmd", Status: "skipped", Message: "$Recycle.Bin not found in " + source})
		}

	case "all":
		results = append(results, perDir("EvtxECmd", ".evtx",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "EvtxECmd_Output.csv"}))
		if dotnetMissing {
			break
		}
		results = append(results, perDir("PECmd", ".pf",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "Prefetch_Output.csv", "-q"}))
		if dotnetMissing {
			break
		}
		results = append(results, perFile("AmcacheParser", "Amcache.hve",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "Amcache_Output.csv", "-i"}))
		if dotnetMissing {
			break
		}
		results = append(results, perFile("AppCompatCacheParser", "SYSTEM",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "Shimcache_Output.csv"}))
		if dotnetMissing {
			break
		}
		results = append(results, perDir("JLECmd", ".automaticDestinations-ms",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "JumpLists_Output.csv", "-q"}))
		if dotnetMissing {
			break
		}
		results = append(results, perDir("LECmd", ".lnk",
			[]string{"-d", "__DIR__", "--csv", "%OUT%", "--csvf", "LNK_Output.csv", "-q"}))
		if dotnetMissing {
			break
		}
		results = append(results, perFile("SrumECmd", "SRUDB.dat",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "SRUM_Output.csv"}))
		if dotnetMissing {
			break
		}
		results = append(results, perFile("MFTECmd", "$MFT",
			[]string{"-f", "__FILE__", "--csv", "%OUT%", "--csvf", "MFT_Output.csv"}))
		if dotnetMissing {
			break
		}
		if rbDir := findRecycleBin(); rbDir != "" {
			results = append(results, runTool("RBCmd",
				[]string{"-d", rbDir, "--csv", "%OUT%", "--csvf", "RecycleBin_Output.csv"}))
		} else {
			results = append(results, toolRun{Name: "RBCmd", Status: "skipped", Message: "$Recycle.Bin not found"})
		}
		if dotnetMissing {
			break
		}
		if hiveDir := findHiveDir(); hiveDir != "" {
			results = append(results, runTool("RECmd",
				[]string{"-d", hiveDir, "--csv", "%OUT%", "--csvf", "Registry_Output.csv"}))
		} else {
			results = append(results, toolRun{Name: "RECmd", Status: "skipped", Message: "no registry hives found"})
		}

	default:
		writeError(w, http.StatusBadRequest, "unknown EZ Tools parser: "+parser)
		return
	}

	// Aggregate status.
	okCount, failCount, skipCount := 0, 0, 0
	for _, res := range results {
		switch res.Status {
		case "ok":
			okCount++
		case "failed":
			failCount++
		case "skipped":
			skipCount++
		}
	}
	status := "ok"
	var msg string
	switch {
	case okCount == 0 && failCount > 0:
		status = "failed"
		msg = fmt.Sprintf("all %d parsers failed", failCount)
	case okCount == 0:
		status = "failed"
		msg = fmt.Sprintf("all parsers skipped (%d) — no matching artifacts found in %s", skipCount, source)
	case failCount > 0 || skipCount > 0:
		status = "partial"
		msg = fmt.Sprintf("%d succeeded, %d failed, %d skipped", okCount, failCount, skipCount)
	default:
		msg = fmt.Sprintf("%d parsers completed successfully", okCount)
	}

	if okCount > 0 && appCtx.CaseManager != nil && appCtx.ActiveCase != nil {
		_, _ = appCtx.CaseManager.AddEvidence(appCtx.ActiveCase.ID, 0, "disk_ez_"+parser, outDir)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      status,
		"message":     msg,
		"output_path": outDir,
		"input_dir":   source,
		"results":     results,
	})
}

// runUACCollection runs UAC against the host with the requested profile
// (full / ir_triage / custom). "custom" runs ir_triage too — without a
// profile picker in the web UI we'd just be guessing.
func runUACCollection(w http.ResponseWriter, ctx context.Context, _ interface{}, t string) {
	appCtx := getAppCtx()
	profile := strings.TrimPrefix(t, "uac_")
	if profile == "ir" || profile == "custom" {
		profile = "ir_triage"
	}
	if profile == "" {
		profile = "full"
	}

	um := disk.NewUACManager(appCtx.RootDir, appCtx.Logger)
	if !um.Installed() {
		writeError(w, http.StatusBadRequest,
			"UAC binary not found at bin/linux/uac/uac — install from github.com/tclahr/uac")
		return
	}
	outDir := caseDiskOutDir(appCtx, "uac", time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}
	result := um.Run(ctx, profile, outDir)
	registerDiskEvidence(appCtx, "disk_uac_"+profile, outDir, result)
	writeCollectionResult(w, result, outDir)
}

// runLogCollection copies common log directories. Each subtype maps to one
// or more roots; the helper walks them and tars them up under
// output/<case>/disk/logs_<kind>/.
func runLogCollection(w http.ResponseWriter, _ context.Context, _ interface{}, t string) {
	appCtx := getAppCtx()
	kind := strings.TrimPrefix(t, "logs_")

	roots := map[string][]string{
		"system":  {"/var/log/syslog", "/var/log/messages", "/var/log/kern.log"},
		"auth":    {"/var/log/auth.log", "/var/log/secure", "/var/log/wtmp", "/var/log/btmp"},
		"web":     {"/var/log/nginx", "/var/log/apache2", "/var/log/httpd"},
		"journal": {"/var/log/journal", "/run/log/journal"},
	}[kind]
	if roots == nil {
		writeError(w, http.StatusBadRequest, "unknown log kind: "+kind)
		return
	}

	outDir := caseDiskOutDir(appCtx, "logs_"+kind, time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}
	copied, skipped := 0, 0
	for _, src := range roots {
		if _, err := os.Stat(src); err != nil {
			skipped++
			continue
		}
		dst := filepath.Join(outDir, filepath.Base(src))
		if err := copyTree(src, dst); err != nil {
			skipped++
			if appCtx.Logger != nil {
				appCtx.Logger.Warn("web", "log copy %s: %v", src, err)
			}
			continue
		}
		copied++
	}
	status := "ok"
	msg := fmt.Sprintf("Copied %d / %d log paths", copied, copied+skipped)
	if copied == 0 {
		status = "failed"
		msg = "No log paths were readable; collection failed"
	}
	if appCtx.CaseManager != nil && copied > 0 {
		_, _ = appCtx.CaseManager.AddEvidence(appCtx.ActiveCase.ID, 0,
			"disk_logs_"+kind, outDir)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      status,
		"message":     msg,
		"output_path": outDir,
		"copied":      copied,
		"skipped":     skipped,
	})
}

// runDirCopyCollection covers the user_* and sys_* tile family — each maps
// to one or more well-known directories that get tar-walked into the case
// output tree.
func runDirCopyCollection(w http.ResponseWriter, _ context.Context, _ interface{}, t string) {
	appCtx := getAppCtx()

	roots := map[string][]string{
		"user_homes":   {"/home", "/root"},
		"user_history": {"/home", "/root"}, // .bash_history etc. live under each user
		"user_ssh":     {"/etc/ssh", "/home", "/root"},
		"sys_packages": {"/var/lib/dpkg", "/var/lib/rpm"},
		"sys_systemd":  {"/etc/systemd", "/lib/systemd"},
		"sys_docker":   {"/var/lib/docker"},
	}[t]
	if roots == nil {
		writeError(w, http.StatusBadRequest, "unknown collection: "+t)
		return
	}

	outDir := caseDiskOutDir(appCtx, t, time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating output dir: "+err.Error())
		return
	}
	copied, skipped := 0, 0
	for _, src := range roots {
		info, err := os.Stat(src)
		if err != nil {
			skipped++
			continue
		}
		var dst string
		if info.IsDir() {
			dst = filepath.Join(outDir, filepath.Base(src))
		} else {
			dst = filepath.Join(outDir, filepath.Base(src))
		}
		if err := copyTree(src, dst); err != nil {
			skipped++
			continue
		}
		copied++
	}
	status, msg := "ok", fmt.Sprintf("Collected %d / %d sources", copied, copied+skipped)
	if copied == 0 {
		status = "failed"
		msg = "No source paths were readable"
	}
	if appCtx.CaseManager != nil && copied > 0 {
		_, _ = appCtx.CaseManager.AddEvidence(appCtx.ActiveCase.ID, 0,
			"disk_"+t, outDir)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      status,
		"message":     msg,
		"output_path": outDir,
		"copied":      copied,
		"skipped":     skipped,
	})
}

// caseDiskOutDir returns output/<case>/disk/<kind>/<ts>, creating the parent
// chain on demand. Kept here rather than at the call site because every
// dispatcher needs the same shape.
func caseDiskOutDir(appCtx interface{}, kind, ts string) string {
	c := getAppCtx()
	return filepath.Join(c.RootDir, "output", c.ActiveCase.ID, "disk", kind, ts)
}

// registerDiskEvidence wraps CaseManager.AddEvidence with a guard for
// missing components. Called after every disk operation that produced an
// output directory.
func registerDiskEvidence(appCtx interface{}, kind, outDir string, result disk.CollectionResult) {
	c := getAppCtx()
	if c == nil || c.CaseManager == nil || c.ActiveCase == nil {
		return
	}
	if result.Status == disk.StatusFailed {
		return
	}
	_, _ = c.CaseManager.AddEvidence(c.ActiveCase.ID, 0, kind, outDir)
}

// writeCollectionResult shapes a disk.CollectionResult into the SPA's
// expected JSON shape. Always returns 200 — failure is conveyed via the
// status field rather than HTTP code so the SPA's progress card can render
// the message inline.
func writeCollectionResult(w http.ResponseWriter, r disk.CollectionResult, outDir string) {
	payload := map[string]interface{}{
		"status":      r.Status.String(),
		"message":     r.Name,
		"output_path": outDir,
		"files":       r.Files,
		"bytes":       r.Bytes,
		"duration":    int(r.Duration.Seconds()),
	}
	if r.Error != "" {
		payload["error"] = r.Error
		payload["status"] = "failed"
		writeJSON(w, http.StatusOK, payload)
		return
	}
	if r.Status == disk.StatusSuccess {
		payload["message"] = r.Name + " — complete"
	} else if r.Status == disk.StatusPartial {
		payload["message"] = r.Name + " — partial (some steps failed)"
	}
	writeJSON(w, http.StatusOK, payload)
}

// copyTree recursively copies src to dst. Symlinks are skipped to avoid
// infinite loops on /home → /var-style mounts. Errors on individual files
// short-circuit only that file — the walk continues.
func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return copyFile(src, dst)
	}
	return filepath.Walk(src, func(path string, f os.FileInfo, walkErr error) error {
		if walkErr != nil || f == nil {
			return nil
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		out := filepath.Join(dst, rel)
		if f.IsDir() {
			return os.MkdirAll(out, 0o700)
		}
		_ = copyFile(path, out)
		return nil
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// handleDiskAcquire — POST /api/disk/acquire. Body: {path, description}.
//
// Synchronous: copies the source file into output/<case>/disk/manual/, hashes
// it with SHA-256, registers the copy as evidence, returns destination path
// + hash. Memory usage is constant via streaming MultiWriter.
func handleDiskAcquire(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ctx := getAppCtx()
	if ctx == nil || ctx.ActiveCase == nil {
		writeError(w, http.StatusBadRequest, "no active case — create or select one first")
		return
	}
	var req struct {
		Path        string `json:"path"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}
	srcInfo, err := os.Stat(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "source file not found: "+err.Error())
		return
	}
	if srcInfo.IsDir() {
		writeError(w, http.StatusBadRequest, "path is a directory; only file copy is supported")
		return
	}

	destDir := filepath.Join(ctx.RootDir, "output", ctx.ActiveCase.ID, "disk", "acquired")
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "creating destination dir: "+err.Error())
		return
	}
	destPath := filepath.Join(destDir,
		time.Now().Format("20060102_150405_")+filepath.Base(req.Path))

	hash, size, err := copyAndHash(req.Path, destPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "copy: "+err.Error())
		return
	}
	if ctx.CaseManager != nil {
		_, _ = ctx.CaseManager.AddEvidence(
			ctx.ActiveCase.ID, 0, "disk_manual", destPath)
	}
	if ctx.Logger != nil {
		ctx.Logger.Info("web", "disk acquire %s -> %s (%d bytes, sha256=%s)",
			req.Path, destPath, size, hash)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"source":      req.Path,
		"output_path": destPath,
		"sha256":      hash,
		"size":        size,
		"description": req.Description,
	})
}

// truncate returns s truncated to maxLen runes with "..." appended if clipped.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// copyAndHash streams src into dst and returns sha256+size. Constant memory.
func copyAndHash(src, dst string) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return "", 0, err
	}
	defer out.Close()
	h := sha256.New()
	mw := io.MultiWriter(out, h)
	n, err := io.Copy(mw, in)
	if err != nil {
		return "", n, err
	}
	if err := out.Close(); err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
