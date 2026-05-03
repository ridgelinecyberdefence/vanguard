package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/app"
	"github.com/ridgelinecyberdefence/vanguard/internal/audit"
	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/config"
	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
	"github.com/ridgelinecyberdefence/vanguard/internal/tui"
	"github.com/ridgelinecyberdefence/vanguard/internal/velociraptor"
	"github.com/ridgelinecyberdefence/vanguard/internal/web"
)

// TODO: Consider running the TUI unprivileged and using runas/sudo for
// individual elevated operations (memory capture, registry export, etc.).
// Today VanGuard expects to be launched once with whatever privilege the
// operator has and lives within those bounds — see Help > Privilege
// Requirements for the per-op breakdown.

// Build-time injection.
//
// Set these via ldflags so prebuilt binaries identify themselves correctly:
//
//   go build -ldflags "-X main.version=1.0.0 \
//                      -X main.buildDate=2026-05-01 \
//                      -X main.commit=abc1234" \
//            -o vanguard.exe ./cmd/vanguard/
//
// The CI workflow does this automatically; for a local dev build the defaults
// below render as "v dev (built unknown, commit unknown)".
var (
	version   = "dev"
	buildDate = "unknown"
	commit    = "unknown"
)

func main() {
	// 0. Parse flags. Web UI is the default; --tui falls back to the bubbletea
	//    terminal interface for headless / SSH / air-gapped scenarios.
	var (
		tuiMode = flag.Bool("tui", false, "Launch the terminal UI instead of the web UI")
		webPort = flag.Int("port", 8080, "Port for the web UI (only used in web mode)")
	)
	flag.Parse()

	// 1. Detect platform.
	platform := runtime.GOOS

	// 2. Detect privilege level.
	elevated := checkElevated()

	// 3. Resolve hostname.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// 4. Resolve VanGuard root from executable location.
	root, err := resolveRoot()
	if err != nil {
		fatal("resolving VanGuard root: %v", err)
	}

	// 4. Load config — create default if missing.
	configPath := filepath.Join(root, "config", "vanguard.yaml")
	if err := ensureDefaultConfig(configPath); err != nil {
		fatal("creating default config: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fatal("loading config: %v", err)
	}

	// 5. Initialise logger.
	logDir := filepath.Join(root, "logs")
	logger, err := logging.NewLogger(logDir, logging.ParseLevel(cfg.VanGuard.LogLevel))
	if err != nil {
		fatal("initialising logger: %v", err)
	}
	defer logger.Close()

	logger.Info("main", "VanGuard %s (built %s, commit %s) starting on %s, elevated=%v",
		version, buildDate, commit, platform, elevated)
	logger.Info("main", "root directory: %s", root)
	if cfg.VanGuard.Analyst == "" || cfg.VanGuard.Analyst == "Analyst" {
		logger.Warn("main", "vanguard.analyst is not configured — update in Configuration > Settings before generating reports")
	}

	// Pre-create directories that downstream code expects to exist. These are
	// cheap (no-op if they already exist) and avoid "directory does not exist"
	// false negatives in detection paths.
	for _, dir := range []string{
		filepath.Join(root, "lib", "volatility3"),
		filepath.Join(root, "lib", "python-embedded"),
		filepath.Join(root, "bin", "windows"),
		filepath.Join(root, "bin", "linux"),
		filepath.Join(root, "rules", "yara"),
		filepath.Join(root, "rules", "sigma"),
		filepath.Join(root, "rules", "hayabusa"),
		filepath.Join(root, "logs"),
		filepath.Join(root, "output"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			logger.Warn("main", "creating %s: %v", dir, err)
		}
	}

	// Diagnostic: list lib/volatility3/ contents at startup so we can confirm
	// the install layout matches what the tool scanner expects to find.
	logVolatility3Layout(logger, root)

	// 5a. Clean up orphaned temp files / directories from previous runs that
	// crashed before their deferred cleanup could fire. Conservative window:
	// only delete VanGuard-prefixed entries older than an hour to avoid
	// stomping on a concurrent VanGuard process's in-flight downloads.
	if removed := cleanupOrphanedTempFiles(); removed > 0 {
		logger.Info("main", "cleaned up %d orphaned temp entries", removed)
	}

	// 6. Initialise case manager.
	dbPath := filepath.Join(root, "output", "vanguard.db")
	cm, err := casemanager.NewCaseManager(dbPath)
	if err != nil {
		logger.Error("main", "initialising case manager: %v", err)
		fatal("initialising case manager: %v", err)
	}
	defer cm.Close()

	logger.Info("main", "case database ready at %s", dbPath)

	// 6a. Initialise audit logger. Tamper-evident JSONL stream of operator
	// actions (logs/audit.jsonl) signed with HMAC-SHA256 using a key under
	// logs/.audit_key. Failure is non-fatal — the rest of VanGuard works,
	// but every Audit.Log call becomes a no-op.
	al, err := audit.NewLogger(logDir, cfg.VanGuard.Analyst)
	if err != nil {
		logger.Warn("main", "audit logger unavailable: %v", err)
		al = nil
	} else {
		_ = al.Log("startup", hostname, fmt.Sprintf("v=%s commit=%s elevated=%v", version, commit, elevated), "ok", "")
		defer al.Close()
		// Plumb the audit logger through the case manager so AddEvidence /
		// AddFinding emit chain-of-custody entries automatically.
		cm.SetAuditHook(al)
		logger.Info("main", "audit log ready at %s", filepath.Join(logDir, "audit.jsonl"))
	}

	// 7. Initialise tool manager and scan for installed tools.
	tm := tools.NewToolManager(root, platform, logger)
	tm.SetVersion(version)
	// GitHub token resolution: env var wins over config so operators can
	// override per-shell without editing yaml. Token is held in memory only.
	if token := os.Getenv("VANGUARD_GITHUB_TOKEN"); token != "" {
		tm.SetGitHubToken(token)
	} else if cfg.GitHub.Token != "" {
		tm.SetGitHubToken(cfg.GitHub.Token)
	}
	installed := tm.ScanInstalled()
	installedCount := 0
	for _, t := range installed {
		if t.Installed {
			installedCount++
		}
	}
	logger.Info("main", "tool scan: %d of %d tools found", installedCount, len(installed))

	// 8. Initialise Velociraptor manager.
	vrm := velociraptor.NewManager(root, platform, logger, tm)

	// Load GUI/Frontend ports and bind address from config.
	if cfg.Velociraptor.Server.GUIPort > 0 {
		vrm.State.GUIPort = cfg.Velociraptor.Server.GUIPort
	}
	if cfg.Velociraptor.Server.FrontendPort > 0 {
		vrm.State.FrontendPort = cfg.Velociraptor.Server.FrontendPort
	}
	if cfg.Velociraptor.Server.BindAddress != "" {
		vrm.State.GUIBindAddress = cfg.Velociraptor.Server.BindAddress
	}

	logger.Info("main", "velociraptor manager ready (binary installed: %v)", vrm.BinaryInstalled())

	// 9. Build shared application context. Both frontends consume the same
	//    struct, so swapping UIs requires no re-initialisation of managers.
	ctx := &app.Context{
		Version:     version,
		BuildDate:   buildDate,
		Commit:      commit,
		Platform:    platform,
		Hostname:    hostname,
		Elevated:    elevated,
		RootDir:     root,
		ConfigPath:  configPath,
		Config:      cfg,
		CaseManager: cm,
		Logger:      logger,
		Audit:       al,
		ToolManager: tm,
		VRManager:   vrm,
	}

	// 10. Launch the chosen frontend.
	if *tuiMode {
		logger.Info("main", "launching TUI")
		if err := tui.Run(ctx); err != nil {
			logger.Error("main", "TUI error: %v", err)
			fatal("TUI error: %v", err)
		}
	} else {
		logger.Info("main", "launching web UI on port %d", *webPort)
		if err := web.Run(ctx, *webPort); err != nil {
			logger.Error("main", "web UI error: %v", err)
			fatal("web UI error: %v", err)
		}
	}

	// 11. Cleanup: stop Velociraptor server if it was started during this session.
	if vrm.State.Running {
		logger.Info("main", "stopping Velociraptor server on exit")
		vrm.Stop()
	}

	logger.Info("main", "VanGuard exiting normally")
}

// cleanupOrphanedTempFiles removes VanGuard-prefixed entries from the system
// temp directory that are older than one hour. This recovers space when
// VanGuard crashes before its deferred cleanup runs.
//
// Patterns matched (these are the prefixes used by os.MkdirTemp / CreateTemp
// across the codebase): "vanguard-*", "vg-bundle-*", "vg-download-*",
// "vg-repo-*", "vg-symbols-*", "vg-yara-custom-*", "vg-pw-*".
//
// One-hour threshold is conservative: it ensures a concurrent VanGuard
// process actively downloading a tool isn't disrupted by another instance
// that just started.
func cleanupOrphanedTempFiles() int {
	tmp := os.TempDir()
	patterns := []string{
		"vanguard-*",
		"vg-bundle-*",
		"vg-download-*",
		"vg-repo-*",
		"vg-symbols-*",
		"vg-yara-custom-*",
		"vg-pw-*",
	}
	cutoff := time.Now().Add(-time.Hour)
	removed := 0
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(tmp, pat))
		if err != nil {
			continue
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				continue
			}
			if info.ModTime().After(cutoff) {
				continue
			}
			// RemoveAll handles both files and directories.
			if err := os.RemoveAll(m); err == nil {
				removed++
			}
		}
	}
	return removed
}

// logVolatility3Layout writes the contents of lib/volatility3/ to the log so we
// can diagnose detection failures. Walks one level deep so we can see whether
// vol.py lives at the top or inside a nested {repo}-{branch}/ directory.
func logVolatility3Layout(logger *logging.Logger, root string) {
	base := filepath.Join(root, "lib", "volatility3")
	info, err := os.Stat(base)
	if err != nil {
		logger.Info("main", "volatility3 layout: %s does not exist (%v)", base, err)
		return
	}
	if !info.IsDir() {
		logger.Info("main", "volatility3 layout: %s exists but is not a directory", base)
		return
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		logger.Info("main", "volatility3 layout: cannot read %s: %v", base, err)
		return
	}

	if len(entries) == 0 {
		logger.Info("main", "volatility3 layout: %s is empty", base)
		return
	}

	for _, e := range entries {
		path := filepath.Join(base, e.Name())
		if e.IsDir() {
			sub, err := os.ReadDir(path)
			if err != nil {
				logger.Info("main", "volatility3 layout: %s/ (cannot read: %v)", path, err)
				continue
			}
			names := make([]string, 0, len(sub))
			for _, s := range sub {
				names = append(names, s.Name())
			}
			logger.Info("main", "volatility3 layout: %s/ contains: %s",
				path, strings.Join(names, ", "))
		} else {
			logger.Info("main", "volatility3 layout: %s (file)", path)
		}
	}

	// Resolve where vol.py lives so we can confirm the analysis runner will
	// find it.
	candidates := []string{filepath.Join(base, "vol.py")}
	for _, e := range entries {
		if e.IsDir() {
			candidates = append(candidates, filepath.Join(base, e.Name(), "vol.py"))
		}
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			logger.Info("main", "volatility3 layout: vol.py found at %s", c)
			return
		}
	}
	logger.Info("main", "volatility3 layout: vol.py NOT found at any candidate path")
}

// resolveRoot returns the directory containing the VanGuard executable.
func resolveRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("getting executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving symlinks: %w", err)
	}
	// Executable lives in cmd/vanguard/ or root — walk up to find config/.
	dir := filepath.Dir(exe)
	// If launched from cmd/vanguard, go up two levels.
	// Otherwise check current dir for config/.
	for i := 0; i < 3; i++ {
		if _, err := os.Stat(filepath.Join(dir, "config")); err == nil {
			return dir, nil
		}
		dir = filepath.Dir(dir)
	}
	// Fall back to executable's directory.
	return filepath.Dir(exe), nil
}

// checkElevated detects whether the process is running with elevated privileges.
func checkElevated() bool {
	switch runtime.GOOS {
	case "windows":
		return checkElevatedWindows()
	default:
		return os.Getuid() == 0
	}
}

// checkElevatedWindows attempts to open \\.\PHYSICALDRIVE0 which requires admin.
func checkElevatedWindows() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// ensureDefaultConfig writes the default vanguard.yaml if it does not exist.
func ensureDefaultConfig(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	return os.WriteFile(path, []byte(defaultConfigYAML), 0o600)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[FATAL] "+format+"\n", args...)
	os.Exit(1)
}

const defaultConfigYAML = `# VanGuard DFIR Toolkit — Master Configuration
# https://github.com/ridgelinecyberdefence/vanguard

vanguard:
  version: "1.0.0"
  analyst: "Analyst"
  organization: ""
  log_level: "info"  # debug | info | warn | error

paths:
  output: "./output"
  cases: "./cases"
  logs: "./logs"
  tools:
    windows: "./bin/windows"
    linux: "./bin/linux"
  rules:
    sigma: "./rules/sigma"
    yara: "./rules/yara"
    hayabusa: "./rules/hayabusa/rules"

network:
  default_mode: "local"
  ssh:
    port: 22
    key_path: ""
    timeout: 30
  winrm:
    port: 5985
    ssl_port: 5986
    use_ssl: false
    timeout: 30
  psexec:
    copy_binary: true
    cleanup: true

velociraptor:
  auto_download: false
  server:
    bind_address: "0.0.0.0"
    frontend_port: 8000
    gui_port: 8889
    datastore: "file"
    datastore_path: "./velociraptor/datastore"
  client:
    poll_interval: 10

memory:
  capture_tool_windows: "winpmem"
  capture_tool_linux: "avml"
  volatility:
    symbols_path: "./lib/volatility3/symbols"
    auto_detect_profile: true
    default_plugins:
      - "windows.pslist.PsList"
      - "windows.netscan.NetScan"
      - "windows.malfind.Malfind"

disk:
  kape:
    default_targets:
      - "EventLogs"
      - "Registry"
      - "FileSystem"
    default_modules:
      - "!EZParser"
  uac:
    profile: "full"

triage:
  hayabusa:
    min_level: "medium"
    output_format: "csv"
  loki:
    intense_mode: false
    scan_processes: true
    scan_files: true

updates:
  auto_check: false
  check_interval_hours: 24
  auto_apply: false

output:
  default_format: "auto"
  include_timestamps: true
  compress_large_files: false
  large_file_threshold_mb: 100

github:
  # token: ""  # WARNING: GitHub PAT — this file is written with 0600 permissions.
  #             # Do not share or commit this file if a token is configured.
  #             # Raises API rate limit from 60 req/hr to 5,000 req/hr.
  #             # No special scopes required (public repo access only).
  #             # Can also be set via VANGUARD_GITHUB_TOKEN env var (takes precedence).
  token: ""
`
