package velociraptor

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

// ServerState tracks the runtime state of the Velociraptor server process.
type ServerState struct {
	Running          bool
	PID              int
	StartedAt        time.Time
	ServerConfigPath string
	ClientConfigPath string
	GUIPort          int
	FrontendPort     int
	GUIBindAddress   string // 127.0.0.1 by default; 0.0.0.0 for remote GUI access
	ServerURL        string
	LogPath          string

	mu      sync.Mutex
	process *os.Process
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

// Manager coordinates all Velociraptor operations: init, server lifecycle,
// client packaging, offline collectors, and imports.
type Manager struct {
	rootDir  string
	platform string
	logger   *logging.Logger
	tm       *tools.ToolManager
	State    ServerState
}

// NewManager creates a Velociraptor manager.
func NewManager(rootDir, platform string, logger *logging.Logger, tm *tools.ToolManager) *Manager {
	return &Manager{
		rootDir:  rootDir,
		platform: platform,
		logger:   logger,
		tm:       tm,
		State: ServerState{
			GUIPort:        8889,
			FrontendPort:   8000,
			GUIBindAddress: "127.0.0.1", // SECURITY: localhost-only by default
		},
	}
}

// ---------------------------------------------------------------------------
// Binary resolution
// ---------------------------------------------------------------------------

// BinaryPath returns the absolute path to the velociraptor binary, or an error
// if it is not installed.
func (m *Manager) BinaryPath() (string, error) {
	id := "velociraptor-win"
	if m.platform == "linux" {
		id = "velociraptor-lnx"
	}
	t := m.tm.GetTool(id)
	if t == nil {
		return "", fmt.Errorf("velociraptor tool not registered for platform %s", m.platform)
	}
	abs := filepath.Join(m.rootDir, filepath.FromSlash(t.LocalPath))
	if !fileExists(abs) {
		return "", fmt.Errorf("velociraptor binary not found at %s", abs)
	}
	return abs, nil
}

// BinaryInstalled returns true if the velociraptor binary is present.
func (m *Manager) BinaryInstalled() bool {
	_, err := m.BinaryPath()
	return err == nil
}

// ---------------------------------------------------------------------------
// Config paths
// ---------------------------------------------------------------------------

func (m *Manager) serverConfigPath() string {
	return filepath.Join(m.rootDir, "config", "velociraptor", "server.config.yaml")
}

func (m *Manager) clientConfigPath() string {
	return filepath.Join(m.rootDir, "config", "velociraptor", "client.config.yaml")
}

// ServerInitialized returns true if the server config file exists.
func (m *Manager) ServerInitialized() bool {
	return fileExists(m.serverConfigPath())
}

// ---------------------------------------------------------------------------
// Command helpers
// ---------------------------------------------------------------------------

// CmdResult captures the output of an exec.Command invocation.
type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// runCmd executes a velociraptor command synchronously and captures output.
func (m *Manager) runCmd(args ...string) CmdResult {
	bin, err := m.BinaryPath()
	if err != nil {
		return CmdResult{Err: err, ExitCode: -1}
	}
	return m.runExe(bin, args...)
}

// runExe executes an arbitrary binary with args and captures output.
//
// The exec line is logged at INFO. The logging package's redaction filter
// scrubs known credential patterns (-p / --password / etc.), but callers that
// pass a secret on argv MUST also use runExeSecret so the secret never appears
// in the log line at all — defence-in-depth, not a single point of failure.
func (m *Manager) runExe(bin string, args ...string) CmdResult {
	return m.runExeWithStdin(bin, args, nil, true)
}

// runExeSecret runs bin with args but writes the supplied stdinData to the
// process's stdin and logs a redacted form of the args. Use for any command
// that handles passwords / tokens — even though the logger redacts known
// patterns, this avoids the secret reaching the log writer in the first place.
func (m *Manager) runExeSecret(bin string, args []string, stdinData []byte) CmdResult {
	return m.runExeWithStdin(bin, args, stdinData, false)
}

// runExeWithStdin is the shared implementation. logArgs=false suppresses the
// argv from the log line.
func (m *Manager) runExeWithStdin(bin string, args []string, stdinData []byte, logArgs bool) CmdResult {
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = m.rootDir
	if stdinData != nil {
		cmd.Stdin = bytes.NewReader(stdinData)
	}

	if m.logger != nil {
		if logArgs {
			m.logger.Info("velociraptor", "exec: %s %s", bin, strings.Join(args, " "))
		} else {
			m.logger.Info("velociraptor", "exec: %s [args redacted; secret on stdin]", bin)
		}
	}

	err := cmd.Run()
	result := CmdResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err != nil {
		result.Err = err
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	if result.Err != nil && m.logger != nil {
		m.logger.Error("velociraptor", "command failed: %v\nstderr: %s", result.Err, result.Stderr)
	}

	return result
}

// ---------------------------------------------------------------------------
// [1] Initialize Server
// ---------------------------------------------------------------------------

// InitResult carries the outcome of an initialization.
type InitResult struct {
	Success          bool
	ServerConfigPath string
	ClientConfigPath string
	GUIPort          int
	FrontendPort     int
	GUIBindAddress   string
	AdminUser        string
	DataStorePath    string
	Error            string
	Steps            []string // step-by-step progress messages
}

// Initialize generates server and client configuration files and creates
// the admin user. If adminPassword is empty, the user-add step is skipped.
func (m *Manager) Initialize(adminPassword string) InitResult {
	result := InitResult{
		ServerConfigPath: m.serverConfigPath(),
		ClientConfigPath: m.clientConfigPath(),
		GUIPort:          m.State.GUIPort,
		FrontendPort:     m.State.FrontendPort,
		AdminUser:        "admin",
		DataStorePath:    filepath.Join(m.rootDir, "velociraptor_data"),
	}

	// Ensure config directory.
	configDir := filepath.Dir(result.ServerConfigPath)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		result.Error = fmt.Sprintf("creating config directory: %v", err)
		return result
	}

	// Ensure datastore directory.
	if err := os.MkdirAll(result.DataStorePath, 0o755); err != nil {
		result.Error = fmt.Sprintf("creating datastore directory: %v", err)
		return result
	}

	// Step 1: Generate server configuration.
	//
	// SECURITY: bind the GUI to GUIBindAddress (127.0.0.1 by default) — without
	// this Velociraptor would expose the admin GUI on every interface. The
	// frontend stays on 0.0.0.0 because clients legitimately need to reach
	// it. Operators who want a remote GUI should set State.GUIBindAddress to
	// 0.0.0.0 explicitly before calling Initialize and put a firewall in
	// front of the GUI port.
	//
	// Velociraptor's `config generate --merge` accepts a JSON snippet that
	// gets layered on top of the default-generated config. We pass datastore
	// paths, both bind ports, and the GUI bind address. Self-signed
	// certificates are generated by Velociraptor as part of this step;
	// rotate them by calling Initialize again (see RegenerateCertificates).
	bindAddr := m.State.GUIBindAddress
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	result.GUIBindAddress = bindAddr
	result.Steps = append(result.Steps, "Generating Velociraptor server configuration...")
	mergePayload, mergeErr := json.Marshal(map[string]interface{}{
		"datastore": map[string]string{
			"location":            result.DataStorePath,
			"filestore_directory": filepath.Join(result.DataStorePath, "filestore"),
		},
		"GUI": map[string]interface{}{
			"bind_address": bindAddr,
			"bind_port":    m.State.GUIPort,
		},
		"Frontend": map[string]interface{}{
			"bind_port": m.State.FrontendPort,
		},
	})
	if mergeErr != nil {
		result.Error = fmt.Sprintf("building --merge payload: %v", mergeErr)
		return result
	}
	r := m.runCmd("config", "generate", "--merge", string(mergePayload))
	if r.Err != nil {
		result.Error = fmt.Sprintf("generating server config: %v\n%s", r.Err, r.Stderr)
		return result
	}
	// Write stdout (the generated config) to file.
	if err := os.WriteFile(result.ServerConfigPath, []byte(r.Stdout), 0o600); err != nil {
		result.Error = fmt.Sprintf("writing server config: %v", err)
		return result
	}
	// Self-heal: strip any legacy `role` keys from GUI.initial_users that an
	// older VanGuard build might have left lying around. No-op on a freshly
	// generated config.
	if err := repairServerConfig(result.ServerConfigPath); err != nil && m.logger != nil {
		m.logger.Warn("velociraptor", "config repair: %v", err)
	}
	result.Steps = append(result.Steps, "Server configuration written.")

	// Step 2: Extract client configuration.
	result.Steps = append(result.Steps, "Generating client configuration...")
	r = m.runCmd("--config", result.ServerConfigPath, "config", "client")
	if r.Err != nil {
		result.Error = fmt.Sprintf("generating client config: %v\n%s", r.Err, r.Stderr)
		return result
	}
	if err := os.WriteFile(result.ClientConfigPath, []byte(r.Stdout), 0o600); err != nil {
		result.Error = fmt.Sprintf("writing client config: %v", err)
		return result
	}
	result.Steps = append(result.Steps, "Client configuration written.")

	// User creation deliberately moved out of Initialize. We tried four
	// approaches to seed initial_users in the config (raw bcrypt, hex-
	// encoded bcrypt, hex-encoded SHA256+salt, and `user add --password`)
	// and every one of them fell over against some build of Velociraptor
	// because the on-disk hash format isn't part of the published API.
	// Instead, the orchestrating layer (web/handlers_velo.go) starts the
	// server and pipes the password into `velociraptor user add` over
	// stdin — see Manager.AddUserViaStdin. Velociraptor's own CLI is the
	// authoritative writer for its user database.
	_ = adminPassword

	// Update internal state.
	m.State.ServerConfigPath = result.ServerConfigPath
	m.State.ClientConfigPath = result.ClientConfigPath
	result.Success = true
	result.Steps = append(result.Steps, "Server initialized successfully.")
	result.Steps = append(result.Steps,
		"Self-signed certificates generated. Recommended: regenerate annually via [R] Regenerate Certificates.")
	if bindAddr == "0.0.0.0" {
		result.Steps = append(result.Steps,
			"WARNING: GUI is bound to 0.0.0.0 — accessible from all network "+
				"interfaces. Restrict access to port "+fmt.Sprintf("%d", m.State.GUIPort)+
				" via firewall.")
	}

	if m.logger != nil {
		m.logger.Info("velociraptor", "server initialized: config=%s gui=%s:%d frontend=%d",
			result.ServerConfigPath, bindAddr, result.GUIPort, result.FrontendPort)
	}

	return result
}

// RegenerateCertificates produces a fresh server config (and therefore new
// self-signed TLS certs) by re-running Initialize. Existing client configs
// embed the old cert and will stop trusting the server until they are
// re-deployed; the caller must warn the operator before invoking this.
//
// adminPassword is required because Velociraptor's config-generation flow
// recreates the admin user as part of the same invocation.
func (m *Manager) RegenerateCertificates(adminPassword string) InitResult {
	if m.logger != nil {
		m.logger.Info("velociraptor", "regenerating certificates — old certs will be invalidated")
	}
	return m.Initialize(adminPassword)
}

// ---------------------------------------------------------------------------
// [2] Start Server
// ---------------------------------------------------------------------------

// StartResult carries the outcome of a server start attempt.
type StartResult struct {
	Success   bool
	PID       int
	GUIURL    string
	LogPath   string
	Healthy   bool
	Error     string
	AlreadyOn bool
}

// Start launches the Velociraptor frontend as a background process.
func (m *Manager) Start(logDir string) StartResult {
	m.State.mu.Lock()
	defer m.State.mu.Unlock()

	if m.State.Running {
		return StartResult{
			AlreadyOn: true,
			PID:       m.State.PID,
			GUIURL:    m.State.ServerURL,
		}
	}

	bin, err := m.BinaryPath()
	if err != nil {
		return StartResult{Error: fmt.Sprintf("binary not found: %v", err)}
	}

	cfgPath := m.serverConfigPath()
	if !fileExists(cfgPath) {
		return StartResult{Error: "server not initialized — run Initialize first"}
	}
	// Self-heal legacy configs before launching: Velociraptor 0.76+ refuses
	// to start when GUI.initial_users entries contain a `role` key (older
	// VanGuard builds wrote one). repairServerConfig is a no-op on clean
	// configs, so the cost on every start is one parse + write-skip.
	if err := repairServerConfig(cfgPath); err != nil && m.logger != nil {
		m.logger.Warn("velociraptor", "config repair before start: %v", err)
	}
	// Reload the GUI port from the config file so subsequent status checks
	// look at the port the analyst actually configured (not the default).
	if port := readGUIPort(cfgPath); port > 0 {
		m.State.GUIPort = port
	}

	// Ensure log directory.
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return StartResult{Error: fmt.Sprintf("creating log directory: %v", err)}
	}

	logPath := filepath.Join(logDir, "velociraptor_server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return StartResult{Error: fmt.Sprintf("opening log file: %v", err)}
	}

	cmd := exec.Command(bin, "--config", cfgPath, "frontend", "-v")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = m.rootDir

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return StartResult{Error: fmt.Sprintf("starting server: %v", err)}
	}

	// Don't leak the log file handle — but we can't close it while the process
	// is writing to it. We'll let it be inherited and cleaned up on stop.
	// Store a reference to close later.

	guiURL := fmt.Sprintf("https://localhost:%d", m.State.GUIPort)

	m.State.Running = true
	m.State.PID = cmd.Process.Pid
	m.State.StartedAt = time.Now()
	m.State.process = cmd.Process
	m.State.ServerURL = guiURL
	m.State.LogPath = logPath
	m.State.ServerConfigPath = cfgPath
	m.State.ClientConfigPath = m.clientConfigPath()

	if m.logger != nil {
		m.logger.Info("velociraptor", "server started: pid=%d gui=%s log=%s",
			m.State.PID, guiURL, logPath)
	}

	// Wait for the process in a goroutine so we can detect unexpected exit.
	go func() {
		_ = cmd.Wait()
		logFile.Close()
		m.State.mu.Lock()
		m.State.Running = false
		m.State.PID = 0
		m.State.process = nil
		m.State.mu.Unlock()
		if m.logger != nil {
			m.logger.Warn("velociraptor", "server process exited")
		}
	}()

	// Health check after a brief pause.
	healthy := false
	time.Sleep(3 * time.Second)
	if m.healthCheck() {
		healthy = true
	}

	return StartResult{
		Success: true,
		PID:     m.State.PID,
		GUIURL:  guiURL,
		LogPath: logPath,
		Healthy: healthy,
	}
}

// healthCheck attempts an HTTPS GET to the GUI port with TLS verification
// disabled.
//
// SECURITY: InsecureSkipVerify is intentional here. Velociraptor's GUI uses a
// self-signed certificate generated by VanGuard at server-init time, with no
// CA chain to validate against. The connection target is always the loopback
// interface (127.0.0.1) of the analyst's own machine, so a TLS MITM would
// require code execution on the analyst host — at which point cert pinning
// adds nothing. For a hardened production deployment this should pin the
// cert fingerprint we captured during Initialize() and reject mismatches.
func (m *Manager) healthCheck() bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // self-signed cert + loopback target — see comment above
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	host := m.State.GUIBindAddress
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	url := fmt.Sprintf("https://%s:%d", host, m.State.GUIPort)
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode > 0
}

// ---------------------------------------------------------------------------
// [3] Stop Server
// ---------------------------------------------------------------------------

// StopResult carries the outcome of a server stop attempt.
type StopResult struct {
	Success    bool
	WasRunning bool
	Error      string
}

// Stop terminates the Velociraptor server process.
func (m *Manager) Stop() StopResult {
	m.State.mu.Lock()
	defer m.State.mu.Unlock()

	if !m.State.Running || m.State.process == nil {
		return StopResult{WasRunning: false}
	}

	pid := m.State.PID

	if m.logger != nil {
		m.logger.Info("velociraptor", "stopping server pid=%d", pid)
	}

	// Send signal based on platform.
	var err error
	if runtime.GOOS == "windows" {
		err = m.State.process.Kill()
	} else {
		err = m.State.process.Signal(os.Interrupt)
	}
	if err != nil {
		// Try force kill as fallback.
		_ = m.State.process.Kill()
	}

	// Wait up to 10 seconds for the process to exit.
	done := make(chan struct{})
	go func() {
		m.State.process.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Clean exit.
	case <-time.After(10 * time.Second):
		// Force kill if still running.
		_ = m.State.process.Kill()
		<-done
	}

	m.State.Running = false
	m.State.PID = 0
	m.State.process = nil

	if m.logger != nil {
		m.logger.Info("velociraptor", "server stopped")
	}

	return StopResult{Success: true, WasRunning: true}
}

// ---------------------------------------------------------------------------
// [4] Server Status
// ---------------------------------------------------------------------------

// StatusInfo represents a snapshot of the server state for display.
type StatusInfo struct {
	Running          bool
	Healthy          bool
	PID              int
	GUIURL           string
	FrontendAddr     string
	ConfigPath       string
	DataStorePath    string
	Uptime           time.Duration
	LogPath          string
	ServerConfigPath string
	ClientConfigPath string
}

// Status returns the current server state. The Running flag is sourced from
// in-memory state when this VanGuard process owns the server; when the
// server was started by a previous VanGuard run (PID lost), we still detect
// it via a TCP probe of the GUI port plus a process-name lookup so the
// dashboard reports RUNNING after a VanGuard restart.
func (m *Manager) Status() StatusInfo {
	m.State.mu.Lock()
	defer m.State.mu.Unlock()

	cfgPath := m.serverConfigPath()
	guiPort := m.State.GUIPort
	if fileExists(cfgPath) {
		if p := readGUIPort(cfgPath); p > 0 {
			guiPort = p
			m.State.GUIPort = p
		}
	}

	info := StatusInfo{
		Running:          m.State.Running,
		PID:              m.State.PID,
		GUIURL:           fmt.Sprintf("https://localhost:%d", guiPort),
		FrontendAddr:     fmt.Sprintf("https://0.0.0.0:%d", m.State.FrontendPort),
		ConfigPath:       cfgPath,
		DataStorePath:    filepath.Join(m.rootDir, "velociraptor_data"),
		LogPath:          m.State.LogPath,
		ServerConfigPath: cfgPath,
		ClientConfigPath: m.clientConfigPath(),
	}

	if !info.Running && fileExists(cfgPath) {
		// Externally-started server (or this VanGuard restarted while the
		// server kept running): port probe is the authoritative signal.
		if isPortListening(guiPort) || isVelociraptorProcessRunning() {
			info.Running = true
		}
	}

	if info.Running {
		if !m.State.StartedAt.IsZero() {
			info.Uptime = time.Since(m.State.StartedAt)
		}
		info.Healthy = m.healthCheck()
	}

	return info
}

// isPortListening attempts a short TCP connect to 127.0.0.1:port. Returns
// true if anything answered. The 1.5s timeout matches what the SPA waits on
// the dashboard render call.
func isPortListening(port int) bool {
	if port <= 0 {
		return false
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port),
		1500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isVelociraptorProcessRunning shells out to the platform process lister and
// looks for a velociraptor binary. Used as a secondary signal — the port
// probe is preferred (cheap, no exec) but a server still spinning up may not
// yet have bound the port. Failures bubble up as `false`; the dashboard
// already shows status based on the port probe.
func isVelociraptorProcessRunning() bool {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist",
			"/fi", "imagename eq velociraptor.exe",
			"/fo", "csv", "/nh").Output()
		if err != nil {
			return false
		}
		return strings.Contains(strings.ToLower(string(out)), "velociraptor")
	}
	if out, err := exec.Command("pgrep", "-f", "velociraptor").Output(); err == nil {
		return len(strings.TrimSpace(string(out))) > 0
	}
	if out, err := exec.Command("ps", "-eo", "comm").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(strings.ToLower(line), "velociraptor") {
				return true
			}
		}
	}
	return false
}

// readGUIPort parses configPath as YAML and returns the port from
// GUI.bind_port (or the GUI.bind_address suffix if present). Returns 0 if
// nothing parseable is found — callers fall back to the configured default.
func readGUIPort(configPath string) int {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return 0
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return 0
	}
	gui := findMap(root.Content[0], "GUI")
	if gui == nil {
		return 0
	}
	// bind_port (preferred — what `velociraptor config generate --merge` writes).
	for i := 0; i < len(gui.Content); i += 2 {
		if gui.Content[i].Value == "bind_port" {
			if p, err := strconv.Atoi(strings.TrimSpace(gui.Content[i+1].Value)); err == nil && p > 0 {
				return p
			}
		}
	}
	// Fallback: bind_address may carry "host:port".
	for i := 0; i < len(gui.Content); i += 2 {
		if gui.Content[i].Value == "bind_address" {
			addr := gui.Content[i+1].Value
			if idx := strings.LastIndex(addr, ":"); idx >= 0 {
				if p, err := strconv.Atoi(addr[idx+1:]); err == nil && p > 0 {
					return p
				}
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// [5] Open Web UI
// ---------------------------------------------------------------------------

// OpenWebUI opens the Velociraptor GUI in the default browser.
func (m *Manager) OpenWebUI() (string, error) {
	if !m.State.Running {
		return "", fmt.Errorf("server is not running — start it first with [2]")
	}

	url := m.State.ServerURL
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return url, fmt.Errorf("opening browser: %w", err)
	}

	return url, nil
}

// IsRemoteSession returns true if running over SSH.
func IsRemoteSession() bool {
	return os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != ""
}

// ---------------------------------------------------------------------------
// [6] Generate Client Package
// ---------------------------------------------------------------------------

// ClientPackageResult carries the outcome of client package generation.
type ClientPackageResult struct {
	Success    bool
	OutputPath string
	Size       int64
	SHA256     string
	Error      string
}

// GenerateClientPackage creates a repacked client binary for the given target platform.
func (m *Manager) GenerateClientPackage(targetPlatform, caseID string) ClientPackageResult {
	clientCfg := m.clientConfigPath()
	if !fileExists(clientCfg) {
		return ClientPackageResult{Error: "client config not found — initialize server first"}
	}

	// Determine the velociraptor binary for the target platform.
	var targetBinID string
	var outputName string
	switch targetPlatform {
	case "windows-amd64":
		targetBinID = "velociraptor-win"
		outputName = "vanguard_client_windows.exe"
	case "linux-amd64":
		targetBinID = "velociraptor-lnx"
		outputName = "vanguard_client_linux_amd64"
	case "linux-arm64":
		// Velociraptor arm64 would need a separate tool entry; for now use amd64.
		targetBinID = "velociraptor-lnx"
		outputName = "vanguard_client_linux_arm64"
	default:
		return ClientPackageResult{Error: fmt.Sprintf("unsupported target platform: %s", targetPlatform)}
	}

	targetTool := m.tm.GetTool(targetBinID)
	if targetTool == nil || !targetTool.Installed {
		platLabel := strings.Split(targetPlatform, "-")[0]
		return ClientPackageResult{
			Error: fmt.Sprintf("%s Velociraptor binary not found at %s. Download it first via Configuration > Tool Management.",
				platLabel, targetTool.LocalPath),
		}
	}

	targetBin := filepath.Join(m.rootDir, filepath.FromSlash(targetTool.LocalPath))

	// Output directory.
	outDir := filepath.Join(m.rootDir, "output", caseID, "velociraptor", "clients")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ClientPackageResult{Error: fmt.Sprintf("creating output directory: %v", err)}
	}
	outputPath := filepath.Join(outDir, outputName)

	// Run repack.
	r := m.runCmd("--config", clientCfg, "config", "repack",
		"--exe", targetBin, outputPath)
	if r.Err != nil {
		return ClientPackageResult{Error: fmt.Sprintf("repacking client: %v\n%s", r.Err, r.Stderr)}
	}

	// Stat and hash output.
	info, err := os.Stat(outputPath)
	if err != nil {
		return ClientPackageResult{Error: fmt.Sprintf("stat output: %v", err)}
	}

	hash, err := computeSHA256(outputPath)
	if err != nil {
		hash = "error"
	}

	if m.logger != nil {
		m.logger.Info("velociraptor", "client package: %s (%d bytes) sha256=%s",
			outputPath, info.Size(), hash)
	}

	return ClientPackageResult{
		Success:    true,
		OutputPath: outputPath,
		Size:       info.Size(),
		SHA256:     hash,
	}
}

// ---------------------------------------------------------------------------
// [8] Create Offline Collector
// ---------------------------------------------------------------------------

// CollectorProfile defines a named set of artifacts to collect.
type CollectorProfile struct {
	Name      string
	Artifacts []string
}

// WindowsCollectorProfiles defines the available offline collection profiles.
var WindowsCollectorProfiles = []CollectorProfile{
	{
		Name: "Full Triage",
		Artifacts: []string{
			"Windows.KapeFiles.Targets",
			"Windows.System.Pslist",
			"Windows.Network.Netstat",
			"Windows.Sys.StartupItems",
			"Windows.System.TaskScheduler",
			"Windows.EventLogs.Evtx",
		},
	},
	{
		Name: "Quick Triage",
		Artifacts: []string{
			"Windows.System.Pslist",
			"Windows.Network.Netstat",
			"Windows.System.TaskScheduler",
		},
	},
	{
		Name: "Memory + Triage",
		Artifacts: []string{
			"Windows.KapeFiles.Targets",
			"Windows.System.Pslist",
			"Windows.Network.Netstat",
			"Windows.Sys.StartupItems",
			"Windows.System.TaskScheduler",
			"Windows.EventLogs.Evtx",
			"Windows.Memory.Acquisition",
		},
	},
}

// LinuxCollectorProfiles defines the available offline collection profiles.
var LinuxCollectorProfiles = []CollectorProfile{
	{
		Name: "Full Triage",
		Artifacts: []string{
			"Linux.Sys.Pslist",
			"Linux.Network.Netstat",
			"Linux.Sys.Crontab",
			"Linux.Sys.LastUserLogin",
			"Linux.Syslog.SSHLogin",
		},
	},
	{
		Name: "Quick Triage",
		Artifacts: []string{
			"Linux.Sys.Pslist",
			"Linux.Network.Netstat",
		},
	},
	{
		Name: "Memory + Triage",
		Artifacts: []string{
			"Linux.Sys.Pslist",
			"Linux.Network.Netstat",
			"Linux.Sys.Crontab",
			"Linux.Sys.LastUserLogin",
			"Linux.Syslog.SSHLogin",
			"Linux.Memory.Acquisition",
		},
	},
}

// CollectorResult carries the outcome of offline collector creation.
type CollectorResult struct {
	Success    bool
	OutputPath string
	Size       int64
	SHA256     string
	Profile    string
	Platform   string
	Error      string
}

// CreateOfflineCollector builds a self-contained offline collector executable.
func (m *Manager) CreateOfflineCollector(profileIdx int, targetPlatform, caseID string) CollectorResult {
	serverCfg := m.serverConfigPath()
	if !fileExists(serverCfg) {
		return CollectorResult{Error: "server not initialized — run Initialize first"}
	}

	// Select profile.
	var profiles []CollectorProfile
	var outputName string
	switch targetPlatform {
	case "windows":
		profiles = WindowsCollectorProfiles
		outputName = "collector_windows.exe"
	case "linux":
		profiles = LinuxCollectorProfiles
		outputName = "collector_linux"
	default:
		return CollectorResult{Error: fmt.Sprintf("unsupported platform: %s", targetPlatform)}
	}

	if profileIdx < 0 || profileIdx >= len(profiles) {
		return CollectorResult{Error: "invalid profile index"}
	}
	profile := profiles[profileIdx]

	outDir := filepath.Join(m.rootDir, "output", caseID, "velociraptor", "collectors")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectorResult{Error: fmt.Sprintf("creating output directory: %v", err)}
	}
	outputPath := filepath.Join(outDir, outputName)

	// Build args.
	args := []string{"--config", serverCfg, "collector", "create", "--output", outputPath}
	for _, a := range profile.Artifacts {
		args = append(args, "--target", a)
	}

	r := m.runCmd(args...)
	if r.Err != nil {
		return CollectorResult{Error: fmt.Sprintf("creating collector: %v\n%s", r.Err, r.Stderr)}
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		return CollectorResult{Error: fmt.Sprintf("stat output: %v", err)}
	}

	hash, err := computeSHA256(outputPath)
	if err != nil {
		hash = "error"
	}

	if m.logger != nil {
		m.logger.Info("velociraptor", "offline collector: %s profile=%s (%d bytes)",
			outputPath, profile.Name, info.Size())
	}

	return CollectorResult{
		Success:    true,
		OutputPath: outputPath,
		Size:       info.Size(),
		SHA256:     hash,
		Profile:    profile.Name,
		Platform:   targetPlatform,
	}
}

// ---------------------------------------------------------------------------
// [A] Import Offline Collection
// ---------------------------------------------------------------------------

// ImportResult carries the outcome of a collection import.
type ImportResult struct {
	Success    bool
	ImportPath string
	Error      string
}

// ImportCollection imports a collected ZIP into the Velociraptor datastore.
func (m *Manager) ImportCollection(zipPath, caseID string) ImportResult {
	if !fileExists(zipPath) {
		return ImportResult{Error: fmt.Sprintf("file not found: %s", zipPath)}
	}

	serverCfg := m.serverConfigPath()

	// If server is running and initialized, import into the datastore.
	if m.State.Running && fileExists(serverCfg) {
		r := m.runCmd("--config", serverCfg, "import", "collection", zipPath)
		if r.Err != nil {
			return ImportResult{Error: fmt.Sprintf("importing collection: %v\n%s", r.Err, r.Stderr)}
		}
		if m.logger != nil {
			m.logger.Info("velociraptor", "collection imported into datastore: %s", zipPath)
		}
		return ImportResult{Success: true, ImportPath: "Velociraptor datastore"}
	}

	// Server not running — extract to output directory.
	importDir := filepath.Join(m.rootDir, "output", caseID, "velociraptor", "imports",
		time.Now().Format("20060102_150405"))
	if err := os.MkdirAll(importDir, 0o700); err != nil {
		return ImportResult{Error: fmt.Sprintf("creating import directory: %v", err)}
	}

	// Copy the ZIP to the import directory.
	data, err := os.ReadFile(zipPath)
	if err != nil {
		return ImportResult{Error: fmt.Sprintf("reading file: %v", err)}
	}
	destPath := filepath.Join(importDir, filepath.Base(zipPath))
	if err := os.WriteFile(destPath, data, 0o644); err != nil {
		return ImportResult{Error: fmt.Sprintf("writing file: %v", err)}
	}

	if m.logger != nil {
		m.logger.Info("velociraptor", "collection copied to: %s (server not running)", destPath)
	}

	return ImportResult{Success: true, ImportPath: importDir}
}

// ---------------------------------------------------------------------------
// Deploy helpers (for [7])
// ---------------------------------------------------------------------------

// DeployMethod enumerates deployment methods.
type DeployMethod int

const (
	DeployWinRM DeployMethod = iota
	DeploySSH
	DeployPSExec
	DeployManual
)

// DeployTarget holds the parameters for a remote deployment.
type DeployTarget struct {
	Method   DeployMethod
	Hostname string
	Username string
	Password string
	KeyPath  string
	Port     int
}

// ManualDeployInstructions returns formatted manual deployment instructions.
func (m *Manager) ManualDeployInstructions(caseID string, guiPort int) []string {
	clientDir := filepath.Join("output", caseID, "velociraptor", "clients")
	return []string{
		"",
		"  1. Copy the client binary to the target:",
		fmt.Sprintf("     Windows: %s/vanguard_client_windows.exe", clientDir),
		fmt.Sprintf("     Linux:   %s/vanguard_client_linux_amd64", clientDir),
		"",
		"  2. On the target, run as Administrator/root:",
		"     Windows: vanguard_client_windows.exe service install",
		"     Linux:   chmod +x vanguard_client_linux_amd64 && sudo ./vanguard_client_linux_amd64 service install",
		"",
		"  3. Verify connection in the Velociraptor GUI:",
		fmt.Sprintf("     https://localhost:%d", guiPort),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// createAdminUser writes a bootstrap "admin" entry into GUI.initial_users
// in the server config. This is the only provisioning surface that works
// non-interactively against Velociraptor 0.76.x:
//
//   - `velociraptor user add` exists but its --password / --name flags are
//     not present on this release; the binary insists on prompting the
//     controlling terminal, which the web UI doesn't own.
//   - Velociraptor consumes initial_users on first server start and grants
//     the very first user full administrator rights — no separate role/ACL
//     step required.
//
// AddUserViaStdin creates (or rewrites) a user in Velociraptor's user
// store by spawning `velociraptor user add <name> --role <role>` and
// piping the password through stdin. The server must be running for this
// to take effect — Velociraptor's user database is held inside the
// datastore the running server owns; offline editing of YAML doesn't
// reach it.
//
// We pipe the password TWICE because Velociraptor's CLI prompts for a
// confirmation. The 500 ms sleeps give the child time to print each
// prompt before we feed it the next line — without them on Windows the
// pipe writes occasionally land before the prompt is ready and the
// child reads them as a single concatenated string.
//
// stdinTimeout caps the whole interaction so a hang in the child can't
// stall init forever; we kill it and return the captured output for
// diagnostics. Returns nil on success, an error wrapping the captured
// stderr on failure.
func (m *Manager) AddUserViaStdin(username, password, role string) (string, error) {
	bin, err := m.BinaryPath()
	if err != nil {
		return "", err
	}
	cfg := m.serverConfigPath()
	if !fileExists(cfg) {
		return "", fmt.Errorf("server config not found at %s", cfg)
	}

	args := []string{"--config", cfg, "user", "add", username}
	if role != "" {
		args = append(args, "--role", role)
	}

	if m.logger != nil {
		m.logger.Info("velociraptor",
			"user add: %s %s [password on stdin]", bin, strings.Join(args, " "))
	}

	cmd := exec.Command(bin, args...)
	cmd.Dir = m.rootDir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("creating stdin pipe: %w", err)
	}
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting user add: %w", err)
	}

	// Feed password + confirmation. Sleep before the first write so the
	// CLI has time to print its first prompt.
	go func() {
		defer stdin.Close()
		time.Sleep(500 * time.Millisecond)
		_, _ = stdin.Write([]byte(password + "\n"))
		time.Sleep(500 * time.Millisecond)
		_, _ = stdin.Write([]byte(password + "\n"))
	}()

	// Bound the wait — kill if the CLI hangs (e.g. on a TTY-only build
	// where stdin pipes don't satisfy the terminal-read).
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case waitErr := <-done:
		out := strings.TrimSpace(combined.String())
		if waitErr != nil {
			return out, fmt.Errorf("user add exited %w: %s", waitErr, out)
		}
		return out, nil
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return strings.TrimSpace(combined.String()),
			fmt.Errorf("user add timed out after 15s — Velociraptor build may not accept stdin pipe")
	}
}

// repairServerConfig removes the entire GUI.initial_users sequence when
// any entry is corrupt. Three corruption modes are recognised, all from
// older VanGuard builds:
//
//   - `role:` key on the user entry. Velociraptor rejects unknown fields
//     with `field role not found in type proto.GUIUser`.
//   - Raw `$2a$…` / `$2b$…` / `$2y$…` bcrypt blob in password_hash —
//     Velociraptor crashes with `encoding/hex: invalid byte: U+0024 '$'`.
//   - Hex-encoded bcrypt blob (the previous attempted fix). It hex-decodes
//     fine, but Velociraptor doesn't actually do bcrypt — it does
//     SHA256(salt || password) — so login always fails. We detect this
//     by the missing `password_salt` companion: a correctly-shaped entry
//     always carries both fields.
//
// In every case wiping the whole block is the only safe move; the
// operator re-runs Initialize, which writes a fresh SHA256+salt entry.
// Idempotent: nil if nothing's corrupt.
func repairServerConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	gui := findMap(doc, "GUI")
	if gui == nil {
		return nil
	}
	users := findSequence(gui, "initial_users")
	if users == nil {
		return nil
	}
	corrupt := false
	for _, child := range users.Content {
		if child.Kind != yaml.MappingNode {
			continue
		}
		var hasHash, hasSalt, hasRole, hasRawBcrypt bool
		for i := 0; i < len(child.Content); i += 2 {
			key := child.Content[i].Value
			val := child.Content[i+1].Value
			switch key {
			case "role":
				hasRole = true
			case "password_hash":
				hasHash = true
				// Raw bcrypt blobs always start with $2{a,b,y}.
				if strings.HasPrefix(val, "$2") {
					hasRawBcrypt = true
				}
			case "password_salt":
				hasSalt = true
			}
		}
		if hasRole || hasRawBcrypt || (hasHash && !hasSalt) {
			corrupt = true
			break
		}
	}
	if !corrupt {
		return nil
	}
	if !deleteMapKey(gui, "initial_users") {
		return nil
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return fmt.Errorf("serializing config: %w", err)
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := os.Rename(tmp, configPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing config: %w", err)
	}
	return nil
}

// findMap returns the value node for key under parent (mapping) only when it
// already exists and is itself a mapping. Returns nil otherwise — used by
// read-only walkers that shouldn't synthesise empty branches.
func findMap(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			node := parent.Content[i+1]
			if node.Kind == yaml.MappingNode {
				return node
			}
			return nil
		}
	}
	return nil
}

// findSequence is the read-only counterpart to findOrCreateSequence.
func findSequence(parent *yaml.Node, key string) *yaml.Node {
	if parent == nil || parent.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			node := parent.Content[i+1]
			if node.Kind == yaml.SequenceNode {
				return node
			}
			return nil
		}
	}
	return nil
}

// deleteMapKey removes (key, value) pair from a mapping node. Returns true
// when something was deleted, false when key was absent.
func deleteMapKey(node *yaml.Node, key string) bool {
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			return true
		}
	}
	return false
}

func computeSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
