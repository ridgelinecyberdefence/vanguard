package remote

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/network"
)

// randomSuffix returns an 8-character hex string for unique temp file naming.
func randomSuffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Engine orchestrates remote operations against targets, threading the
// credential cache and a logger through every call.
type Engine struct {
	RootDir     string
	CaseID      string
	Logger      *logging.Logger
	Creds       *CredentialCache
	SkipCleanup bool // set to true when config.Network.PSExec.Cleanup == false
}

// NewEngine constructs a remote-operations engine.
func NewEngine(rootDir, caseID string, logger *logging.Logger, creds *CredentialCache) *Engine {
	return &Engine{
		RootDir: rootDir,
		CaseID:  caseID,
		Logger:  logger,
		Creds:   creds,
	}
}

// outputDir returns output/{case}/remote/{subdir}/{hostname}_{timestamp}/.
func (e *Engine) outputDir(target *RemoteTarget, subdir string) string {
	ts := time.Now().Format("20060102_150405")
	hostName := target.Hostname
	if hostName == "" {
		hostName = target.IPAddress
	}
	return filepath.Join(e.RootDir, "output", e.CaseID, "remote", subdir,
		fmt.Sprintf("%s_%s", hostName, ts))
}

// connect resolves credentials for the target and returns a live network.Client.
// Caller is responsible for client.Close().
func (e *Engine) connect(target *RemoteTarget) (network.Client, Credentials, error) {
	creds, ok := e.Creds.Get(target)
	if !ok {
		// Fill from the target's static fields where possible.
		creds = Credentials{
			Username: target.Username,
			KeyPath:  target.KeyPath,
		}
		if target.AuthMethod == "key" {
			// Key auth needs no additional secret unless the key is encrypted;
			// in that case the underlying ssh tooling will prompt itself.
			e.Creds.Put(target, creds)
		} else {
			return nil, creds, fmt.Errorf("no cached credentials for %s — prompt the user first",
				target.DisplayName())
		}
	}

	netTarget := target.AsNetworkTarget(string(creds.Password))
	if creds.KeyPath != "" {
		netTarget.KeyPath = creds.KeyPath
	}

	client, err := network.NewClient(netTarget)
	if err != nil {
		return nil, creds, err
	}
	if err := client.Connect(); err != nil {
		client.Close()
		return nil, creds, fmt.Errorf("connect failed: %w", err)
	}
	return client, creds, nil
}

// ---------------------------------------------------------------------------
// Connectivity test
// ---------------------------------------------------------------------------

// ConnectivityResult is the result of a single connectivity probe.
type ConnectivityResult struct {
	Target   *RemoteTarget
	Status   Status
	Output   string
	Duration time.Duration
	Error    string
}

// TestConnectivity probes one target. Updates Status field on the target.
func (e *Engine) TestConnectivity(target *RemoteTarget) ConnectivityResult {
	r := ConnectivityResult{Target: target}
	started := time.Now()

	client, _, err := e.connect(target)
	if err != nil {
		r.Status = StatusError
		r.Error = err.Error()
		r.Duration = time.Since(started)
		target.Status = StatusError
		return r
	}
	defer client.Close()

	cmd := "hostname"
	if target.OSType == "linux" {
		cmd = "uname -n"
	}
	res := client.Execute(cmd, 30*time.Second)
	r.Duration = time.Since(started)
	r.Output = strings.TrimSpace(res.Stdout)
	if res.Failed() {
		r.Status = StatusError
		r.Error = strings.TrimSpace(res.Stderr)
		if r.Error == "" && res.Err != nil {
			r.Error = res.Err.Error()
		}
		target.Status = StatusOffline
		return r
	}
	r.Status = StatusOnline
	target.Status = StatusOnline
	target.LastContact = time.Now()
	return r
}

// ---------------------------------------------------------------------------
// Step-by-step command runner used by triage / hunting
// ---------------------------------------------------------------------------

// StepResult is the outcome of one CommandSpec execution.
type StepResult struct {
	Name     string
	OutFile  string
	Status   string // "success" | "failed" | "partial"
	Duration time.Duration
	Bytes    int64
	Error    string
}

// RunCommandSet executes set on target, writing each command's stdout to
// outputDir/{OutFile}. Per-command failures are captured but don't abort the
// run — callers see one StepResult per command.
func (e *Engine) RunCommandSet(target *RemoteTarget, set CommandSet, outputDir string, perStepTimeout time.Duration) ([]StepResult, error) {
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating output dir: %w", err)
	}
	client, _, err := e.connect(target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if perStepTimeout <= 0 {
		perStepTimeout = 5 * time.Minute
	}
	results := make([]StepResult, 0, len(set.Commands))
	for _, c := range set.Commands {
		r := StepResult{Name: c.Name, OutFile: c.OutFile}
		started := time.Now()
		execRes := client.Execute(c.Command, perStepTimeout)
		r.Duration = time.Since(started)

		outPath := filepath.Join(outputDir, c.OutFile)
		_ = os.MkdirAll(filepath.Dir(outPath), 0o700)
		if writeErr := os.WriteFile(outPath, []byte(execRes.Stdout), 0o644); writeErr != nil && e.Logger != nil {
			e.Logger.Warn("remote", "writing %s: %v", outPath, writeErr)
		}
		if info, statErr := os.Stat(outPath); statErr == nil {
			r.Bytes = info.Size()
		}

		if execRes.Failed() {
			r.Status = "failed"
			if execRes.Stderr != "" {
				r.Error = strings.TrimSpace(execRes.Stderr)
			} else if execRes.Err != nil {
				r.Error = execRes.Err.Error()
			} else {
				r.Error = fmt.Sprintf("exit code %d", execRes.ExitCode)
			}
		} else if r.Bytes == 0 {
			r.Status = "partial"
			r.Error = "empty output"
		} else {
			r.Status = "success"
		}
		results = append(results, r)
	}
	return results, nil
}

// TriageTarget runs the OS-appropriate Quick Triage command set.
func (e *Engine) TriageTarget(target *RemoteTarget) (string, []StepResult, error) {
	outDir := e.outputDir(target, "triage")
	var set CommandSet
	switch target.OSType {
	case "windows":
		set = WindowsTriageCommands()
	case "linux":
		set = LinuxTriageCommands()
	default:
		return outDir, nil, fmt.Errorf("unsupported OS: %s", target.OSType)
	}
	results, err := e.RunCommandSet(target, set, outDir, 5*time.Minute)
	return outDir, results, err
}

// ---------------------------------------------------------------------------
// Event log + registry collection (Windows only)
// ---------------------------------------------------------------------------

// EventLogResult summarises one remote event log collection.
type EventLogResult struct {
	OutputDir string
	Files     []string
	Failed    map[string]string // filename → error
	Duration  time.Duration
}

// CollectEventLogs exports each well-known event log on the remote host with
// wevtutil, copies it back, and removes the temp file.
func (e *Engine) CollectEventLogs(target *RemoteTarget) (EventLogResult, error) {
	res := EventLogResult{Failed: map[string]string{}}
	started := time.Now()
	if target.OSType != "windows" {
		return res, fmt.Errorf("event log collection requires Windows target")
	}

	res.OutputDir = e.outputDir(target, "eventlogs")
	if err := os.MkdirAll(res.OutputDir, 0o700); err != nil {
		return res, fmt.Errorf("creating output dir: %w", err)
	}

	client, _, err := e.connect(target)
	if err != nil {
		return res, err
	}
	defer client.Close()

	for _, ch := range WindowsEventLogChannels() {
		remoteTmp := `C:\Windows\Temp\` + ch.FileName
		exportCmd := fmt.Sprintf(`wevtutil epl '%s' '%s' /ow:true 2>$null; if (Test-Path '%s') { 'OK' } else { 'MISSING' }`,
			escapeForPS(ch.Channel), escapeForPS(remoteTmp), escapeForPS(remoteTmp))
		exec := client.Execute(exportCmd, 5*time.Minute)
		if exec.Failed() || !strings.Contains(exec.Stdout, "OK") {
			res.Failed[ch.FileName] = strings.TrimSpace(exec.Stderr)
			continue
		}

		localPath := filepath.Join(res.OutputDir, ch.FileName)
		if cpErr := client.CopyFrom(remoteTmp, localPath); cpErr != nil {
			res.Failed[ch.FileName] = cpErr.Error()
		} else {
			res.Files = append(res.Files, localPath)
		}
		// Best-effort cleanup; no error propagation.
		_ = client.Execute(fmt.Sprintf(`Remove-Item -Force '%s' -ErrorAction SilentlyContinue`,
			escapeForPS(remoteTmp)), 30*time.Second)
	}
	res.Duration = time.Since(started)
	return res, nil
}

// CollectRegistry exports the SYSTEM-wide hives and copies them back.
func (e *Engine) CollectRegistry(target *RemoteTarget) (EventLogResult, error) {
	res := EventLogResult{Failed: map[string]string{}}
	started := time.Now()
	if target.OSType != "windows" {
		return res, fmt.Errorf("registry collection requires Windows target")
	}

	res.OutputDir = e.outputDir(target, "registry")
	if err := os.MkdirAll(res.OutputDir, 0o700); err != nil {
		return res, fmt.Errorf("creating output dir: %w", err)
	}

	client, _, err := e.connect(target)
	if err != nil {
		return res, err
	}
	defer client.Close()

	for _, h := range WindowsRegistryHives() {
		remoteTmp := `C:\Windows\Temp\` + h.FileName
		// reg.exe under PowerShell needs explicit invocation via cmd /c.
		exportCmd := fmt.Sprintf(`cmd /c reg save %s "%s" /y`,
			h.KeyPath, remoteTmp)
		exec := client.Execute(exportCmd, 5*time.Minute)
		if exec.Failed() {
			res.Failed[h.FileName] = strings.TrimSpace(exec.Stderr)
			continue
		}

		localPath := filepath.Join(res.OutputDir, h.FileName)
		if cpErr := client.CopyFrom(remoteTmp, localPath); cpErr != nil {
			res.Failed[h.FileName] = cpErr.Error()
		} else {
			res.Files = append(res.Files, localPath)
		}
		_ = client.Execute(fmt.Sprintf(`Remove-Item -Force '%s' -ErrorAction SilentlyContinue`,
			escapeForPS(remoteTmp)), 30*time.Second)
	}
	res.Duration = time.Since(started)
	return res, nil
}

// ---------------------------------------------------------------------------
// File acquisition
// ---------------------------------------------------------------------------

// AcquisitionResult describes the outcome of a remote file pull.
type AcquisitionResult struct {
	Source      string
	Destination string
	SHA256      string
	Bytes       int64
	Description string
	Duration    time.Duration
}

// AcquireFile copies remotePath from target to a local file under the case's
// remote acquisitions directory, then computes SHA256.
func (e *Engine) AcquireFile(target *RemoteTarget, remotePath, description string) (AcquisitionResult, error) {
	res := AcquisitionResult{Source: remotePath, Description: description}
	started := time.Now()

	outDir := e.outputDir(target, "acquired")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return res, fmt.Errorf("creating output dir: %w", err)
	}
	res.Destination = filepath.Join(outDir, filepath.Base(remotePath))

	client, _, err := e.connect(target)
	if err != nil {
		return res, err
	}
	defer client.Close()

	if err := client.CopyFrom(remotePath, res.Destination); err != nil {
		return res, err
	}

	if info, statErr := os.Stat(res.Destination); statErr == nil {
		res.Bytes = info.Size()
	}
	if hash, hashErr := sha256File(res.Destination); hashErr == nil {
		res.SHA256 = hash
	}
	res.Duration = time.Since(started)
	return res, nil
}

// ---------------------------------------------------------------------------
// Memory capture
// ---------------------------------------------------------------------------

// MemoryCaptureResult mirrors AcquisitionResult for the memory case so the
// caller can register evidence + report file size and hash.
type MemoryCaptureResult AcquisitionResult

// CaptureMemory uploads the appropriate capture tool to the target, runs it,
// and downloads the resulting dump. WinPmem on Windows / AVML on Linux.
func (e *Engine) CaptureMemory(target *RemoteTarget) (MemoryCaptureResult, error) {
	var (
		toolLocal, toolRemote, dumpRemote, runCmd, dumpExt string
	)
	suffix := randomSuffix()
	switch target.OSType {
	case "windows":
		toolLocal = filepath.Join(e.RootDir, "bin", "windows", "winpmem.exe")
		toolRemote = fmt.Sprintf(`C:\Windows\Temp\winpmem_%s.exe`, suffix)
		dumpRemote = fmt.Sprintf(`C:\Windows\Temp\memory_%s.raw`, suffix)
		runCmd = fmt.Sprintf(`& '%s' --format raw --output '%s' 2>&1`,
			escapeForPS(toolRemote), escapeForPS(dumpRemote))
		dumpExt = "raw"
	case "linux":
		toolLocal = filepath.Join(e.RootDir, "bin", "linux", "avml")
		toolRemote = fmt.Sprintf("/tmp/avml_%s", suffix)
		dumpRemote = fmt.Sprintf("/tmp/memory_%s.lime", suffix)
		runCmd = fmt.Sprintf(`chmod +x %s && %s %s`,
			toolRemote, toolRemote, dumpRemote)
		dumpExt = "lime"
	default:
		return MemoryCaptureResult{}, fmt.Errorf("unsupported OS: %s", target.OSType)
	}

	if _, err := os.Stat(toolLocal); err != nil {
		return MemoryCaptureResult{}, fmt.Errorf(
			"local capture tool missing at %s — install via Configuration > Tool Management", toolLocal)
	}

	outDir := e.outputDir(target, "memory")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return MemoryCaptureResult{}, err
	}
	hostName := target.Hostname
	if hostName == "" {
		hostName = target.IPAddress
	}
	localPath := filepath.Join(outDir,
		fmt.Sprintf("%s_%s.%s", hostName, time.Now().Format("20060102_150405"), dumpExt))
	res := MemoryCaptureResult{Source: dumpRemote, Destination: localPath}
	started := time.Now()

	client, _, err := e.connect(target)
	if err != nil {
		return res, err
	}
	defer client.Close()

	if err := client.CopyTo(toolLocal, toolRemote); err != nil {
		return res, fmt.Errorf("uploading capture tool: %w", err)
	}

	exec := client.Execute(runCmd, 30*time.Minute)
	if exec.Failed() {
		if !e.SkipCleanup {
			cleanup(client, target.OSType, toolRemote, dumpRemote)
		}
		return res, fmt.Errorf("remote capture failed: %s", strings.TrimSpace(exec.Stderr))
	}

	if err := client.CopyFrom(dumpRemote, localPath); err != nil {
		if !e.SkipCleanup {
			cleanup(client, target.OSType, toolRemote, dumpRemote)
		}
		return res, fmt.Errorf("downloading dump: %w", err)
	}

	if !e.SkipCleanup {
		cleanup(client, target.OSType, toolRemote, dumpRemote)
	}

	if info, statErr := os.Stat(localPath); statErr == nil {
		res.Bytes = info.Size()
	}
	if hash, hashErr := sha256File(localPath); hashErr == nil {
		res.SHA256 = hash
	}
	res.Duration = time.Since(started)
	return res, nil
}

// cleanup is a best-effort delete of remote temp files. Errors are swallowed.
func cleanup(client network.Client, osType string, files ...string) {
	for _, f := range files {
		var cmd string
		if osType == "windows" {
			cmd = fmt.Sprintf(`Remove-Item -Force '%s' -ErrorAction SilentlyContinue`, escapeForPS(f))
		} else {
			cmd = "rm -f " + f
		}
		_ = client.Execute(cmd, 30*time.Second)
	}
	// Best-effort PSEXESVC cleanup — the service lingers if PSExec crashed
	// mid-execution. sc delete is silent if the service doesn't exist.
	if osType == "windows" {
		_ = client.Execute(`sc delete PSEXESVC`, 30*time.Second)
	}
}

// ---------------------------------------------------------------------------
// Hunting snapshots + IOC sweep
// ---------------------------------------------------------------------------

// HuntResult summarises a remote hunting snapshot.
type HuntResult struct {
	OutputDir string
	Findings  []Finding
	Steps     []StepResult
	Duration  time.Duration
}

// HuntSnapshot runs the named hunt set ("processes" / "network" / "persistence")
// against target, then runs the matching analysis function over the captured
// output.
func (e *Engine) HuntSnapshot(target *RemoteTarget, kind string) (HuntResult, error) {
	res := HuntResult{}
	started := time.Now()

	var sets map[string]CommandSet
	switch target.OSType {
	case "windows":
		sets = WindowsHuntCommands
	case "linux":
		sets = LinuxHuntCommands
	default:
		return res, fmt.Errorf("unsupported OS: %s", target.OSType)
	}
	set, ok := sets[kind]
	if !ok {
		return res, fmt.Errorf("unknown hunt kind: %s", kind)
	}

	res.OutputDir = e.outputDir(target, "hunt_"+kind)
	steps, err := e.RunCommandSet(target, set, res.OutputDir, 5*time.Minute)
	if err != nil {
		return res, err
	}
	res.Steps = steps

	hostLabel := target.DisplayName()
	for _, step := range steps {
		if step.Status == "failed" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(res.OutputDir, step.OutFile))
		if readErr != nil {
			continue
		}
		switch kind {
		case "processes":
			res.Findings = append(res.Findings, AnalyzeProcessOutput(hostLabel, string(data))...)
		case "network":
			res.Findings = append(res.Findings, AnalyzeNetworkOutput(hostLabel, string(data))...)
		case "persistence":
			res.Findings = append(res.Findings, AnalyzePersistenceOutput(hostLabel, string(data))...)
		}
	}
	res.Duration = time.Since(started)
	return res, nil
}

// IOCSweepResult summarises one IOC sweep against one target.
type IOCSweepResult struct {
	Target    *RemoteTarget
	IOC       IOC
	OutputDir string
	Output    string
	Findings  []Finding
	Duration  time.Duration
	Error     string
}

// SweepIOC runs an IOC search on target. The match-extraction logic is a
// simple "non-empty stdout means at least one hit" heuristic — for high-fidelity
// hits, AnalyzeProcessOutput-style parsers can be added per IOC type.
func (e *Engine) SweepIOC(target *RemoteTarget, ioc IOC) IOCSweepResult {
	res := IOCSweepResult{Target: target, IOC: ioc}
	started := time.Now()

	label, command := BuildIOCCommand(target.OSType, ioc)
	if command == "" {
		res.Error = "unsupported IOC type for OS"
		res.Duration = time.Since(started)
		return res
	}

	client, _, err := e.connect(target)
	if err != nil {
		res.Error = err.Error()
		res.Duration = time.Since(started)
		return res
	}
	defer client.Close()

	result := client.Execute(command, 10*time.Minute)
	res.Output = result.Stdout
	res.OutputDir = e.outputDir(target, "ioc_sweep")
	_ = os.MkdirAll(res.OutputDir, 0o700)
	outFile := filepath.Join(res.OutputDir,
		fmt.Sprintf("%s_%s.txt", string(ioc.Type), time.Now().Format("150405")))
	_ = os.WriteFile(outFile, []byte(result.Stdout), 0o644)

	if result.Failed() {
		res.Error = strings.TrimSpace(result.Stderr)
		if res.Error == "" && result.Err != nil {
			res.Error = result.Err.Error()
		}
		res.Duration = time.Since(started)
		return res
	}

	// Treat any non-empty, non-header line as a hit.
	hostLabel := target.DisplayName()
	for _, line := range strings.Split(result.Stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Hash,Path") || strings.HasPrefix(trimmed, "FullName,") {
			continue
		}
		res.Findings = append(res.Findings, Finding{
			Severity: SeverityHigh,
			Title:    fmt.Sprintf("IOC %s hit: %s", ioc.Type, ioc.Value),
			Detail:   trimmed,
			Source:   "ioc_sweep:" + label,
			Host:     hostLabel,
		})
	}
	res.Duration = time.Since(started)
	return res
}

// ---------------------------------------------------------------------------
// Multi-target / batch operations
// ---------------------------------------------------------------------------

// BatchTriageResult collects per-target triage outcomes.
type BatchTriageResult struct {
	Target    *RemoteTarget
	OutputDir string
	Steps     []StepResult
	Duration  time.Duration
	Error     string
}

// BatchTriage runs Quick Triage against each target sequentially. Failures are
// recorded and the loop continues to the next target.
//
// progress fires once per target (post-completion) so the TUI can re-render.
// A nil progress callback is fine.
func (e *Engine) BatchTriage(targets []*RemoteTarget, progress func(int, BatchTriageResult)) []BatchTriageResult {
	results := make([]BatchTriageResult, len(targets))
	for i, t := range targets {
		started := time.Now()
		outDir, steps, err := e.TriageTarget(t)
		r := BatchTriageResult{
			Target: t, OutputDir: outDir, Steps: steps,
			Duration: time.Since(started),
		}
		if err != nil {
			r.Error = err.Error()
		}
		results[i] = r
		if progress != nil {
			progress(i, r)
		}
	}
	return results
}

// BatchIOCSweep runs the same IOC against each target in turn.
func (e *Engine) BatchIOCSweep(targets []*RemoteTarget, ioc IOC, progress func(int, IOCSweepResult)) []IOCSweepResult {
	results := make([]IOCSweepResult, len(targets))
	for i, t := range targets {
		results[i] = e.SweepIOC(t, ioc)
		if progress != nil {
			progress(i, results[i])
		}
	}
	return results
}

// ---------------------------------------------------------------------------
// Tool deployment
// ---------------------------------------------------------------------------

// DeployResult describes one tool-push outcome.
type DeployResult struct {
	Target     *RemoteTarget
	LocalPath  string
	RemotePath string
	Bytes      int64
	Duration   time.Duration
	Error      string
}

// DeployTool uploads a single binary to each target. localPathFor resolves the
// correct local binary based on the target's OS — typical use is one of the
// helpers below (DeployHayabusaPath, DeployVelociraptorPath…).
func (e *Engine) DeployTool(targets []*RemoteTarget, localPathFor func(*RemoteTarget) (string, string), progress func(int, DeployResult)) []DeployResult {
	results := make([]DeployResult, len(targets))
	for i, t := range targets {
		r := DeployResult{Target: t}
		started := time.Now()

		localPath, remotePath := localPathFor(t)
		r.LocalPath = localPath
		r.RemotePath = remotePath

		if localPath == "" {
			r.Error = "no local binary available for this target's OS"
			r.Duration = time.Since(started)
			results[i] = r
			if progress != nil {
				progress(i, r)
			}
			continue
		}
		if _, err := os.Stat(localPath); err != nil {
			r.Error = "local binary missing: " + err.Error()
			r.Duration = time.Since(started)
			results[i] = r
			if progress != nil {
				progress(i, r)
			}
			continue
		}

		client, _, err := e.connect(t)
		if err != nil {
			r.Error = err.Error()
			r.Duration = time.Since(started)
			results[i] = r
			if progress != nil {
				progress(i, r)
			}
			continue
		}

		if cpErr := client.CopyTo(localPath, remotePath); cpErr != nil {
			r.Error = cpErr.Error()
		} else {
			if info, statErr := os.Stat(localPath); statErr == nil {
				r.Bytes = info.Size()
			}
			// chmod +x on Linux targets so the binary is immediately runnable.
			if t.OSType == "linux" {
				_ = client.Execute("chmod +x "+remotePath, 30*time.Second)
			}
		}
		client.Close()
		r.Duration = time.Since(started)
		results[i] = r
		if progress != nil {
			progress(i, r)
		}
	}
	return results
}

// DeployBinaryPaths is a convenience helper returning (localPath, remotePath)
// for one of the bundled tools.
func DeployBinaryPaths(rootDir, toolID string, target *RemoteTarget) (local, remote string) {
	switch toolID {
	case "velociraptor":
		if target.OSType == "windows" {
			return filepath.Join(rootDir, "bin", "windows", "velociraptor.exe"), `C:\Windows\Temp\velociraptor.exe`
		}
		return filepath.Join(rootDir, "bin", "linux", "velociraptor"), "/tmp/velociraptor"
	case "hayabusa":
		if target.OSType == "windows" {
			return filepath.Join(rootDir, "bin", "windows", "hayabusa.exe"), `C:\Windows\Temp\hayabusa.exe`
		}
		return filepath.Join(rootDir, "bin", "linux", "hayabusa"), "/tmp/hayabusa"
	case "loki":
		if target.OSType == "windows" {
			return filepath.Join(rootDir, "bin", "windows", "loki", "loki.exe"), `C:\Windows\Temp\loki.exe`
		}
		return filepath.Join(rootDir, "bin", "linux", "loki", "loki"), "/tmp/loki"
	case "yara":
		// YARA isn't bundled by VanGuard yet — caller can supply its own binary.
		return "", ""
	}
	return "", ""
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// sha256File returns the hex SHA256 of path, streamed via io.Copy.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
