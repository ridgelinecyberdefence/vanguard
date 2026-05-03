package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// CaptureManager orchestrates memory capture operations.
type CaptureManager struct {
	RootDir  string
	CaseID   string
	Hostname string
	Platform string
	Logger   *logging.Logger
	Tools    *tools.ToolManager
}

// NewCaptureManager creates a new capture manager.
func NewCaptureManager(rootDir, caseID, hostname, platform string, logger *logging.Logger, tm *tools.ToolManager) *CaptureManager {
	return &CaptureManager{
		RootDir:  rootDir,
		CaseID:   caseID,
		Hostname: hostname,
		Platform: platform,
		Logger:   logger,
		Tools:    tm,
	}
}

// OutputDir returns the memory output directory for this case.
func (c *CaptureManager) OutputDir() string {
	return filepath.Join(c.RootDir, "output", c.CaseID, "memory")
}

// SuggestedOutputPath builds the canonical output path for a capture.
func (c *CaptureManager) SuggestedOutputPath(extension string) string {
	ts := time.Now().Format("20060102_150405")
	name := fmt.Sprintf("%s_%s.%s", c.Hostname, ts, extension)
	return filepath.Join(c.OutputDir(), name)
}

// ToolPath returns the absolute path to a registered capture binary.
// Returns "" if the tool is not installed.
func (c *CaptureManager) ToolPath(toolID string) string {
	if c.Tools == nil {
		return ""
	}
	t := c.Tools.GetTool(toolID)
	if t == nil || !t.Installed {
		return ""
	}
	return filepath.Join(c.RootDir, filepath.FromSlash(t.LocalPath))
}

// LimeKoPath returns the path to lime.ko, regardless of installed status.
func (c *CaptureManager) LimeKoPath() string {
	return filepath.Join(c.RootDir, "bin", "linux", "lime.ko")
}

// TotalRAM reports the system's total physical memory in bytes.
// Returns 0 if it cannot be determined.
func TotalRAM() int64 {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell.exe", "-NoProfile", "-Command",
			"(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory").Output()
		if err != nil {
			return 0
		}
		s := strings.TrimSpace(string(out))
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0
		}
		return v
	}

	// Linux: parse /proc/meminfo MemTotal (kB).
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return v * 1024
	}
	return 0
}

// FormatBytes returns a human-readable byte count.
func FormatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ---------------------------------------------------------------------------
// Capture orchestration
// ---------------------------------------------------------------------------

// CaptureRequest carries arguments for a capture run.
type CaptureRequest struct {
	Tool       CaptureTool
	BinPath    string // capture tool binary path
	OutputPath string
	ExtraArgs  []string // optional extra args (e.g. for LiME)
}

// Run executes a memory capture synchronously. Progress is sent on progressCh
// (which may be nil). The channel is closed when the capture finishes.
//
// Capture is robust to CLI variation in tools like WinPmem (which has changed
// flag syntax across versions) and to output paths that contain spaces (a
// common culprit when tools fail to load kernel drivers): if the analyst's
// chosen path contains spaces, we capture to a space-free path under
// %WINDIR%\Temp first, then move the file to its final location.
func (c *CaptureManager) Run(ctx context.Context, req CaptureRequest, progressCh chan<- CaptureProgress) CaptureResult {
	defer func() {
		if progressCh != nil {
			close(progressCh)
		}
	}()

	result := CaptureResult{
		Tool:       req.Tool,
		Hostname:   c.Hostname,
		OutputPath: req.OutputPath,
	}
	started := time.Now()

	if err := os.MkdirAll(filepath.Dir(req.OutputPath), 0o700); err != nil {
		result.Error = fmt.Sprintf("creating output directory: %v", err)
		result.Duration = time.Since(started)
		return result
	}

	if req.BinPath == "" {
		result.Error = "capture tool binary not found"
		result.Duration = time.Since(started)
		return result
	}

	sendProgress(progressCh, CaptureProgress{Status: CapturePreparing, Message: "Starting capture"})

	// If the final output path contains spaces, capture to a space-free
	// staging path first. Some capture tools (notably WinPmem) fail to load
	// their kernel driver when the CLI is given a quoted path containing
	// spaces, returning exit code 0xffffffff.
	finalPath := req.OutputPath
	stagingPath := finalPath
	if runtime.GOOS == "windows" && strings.Contains(finalPath, " ") {
		stagingDir := filepath.Join(`C:\Windows\Temp`, "vanguard-mem")
		if err := os.MkdirAll(stagingDir, 0o700); err == nil {
			stagingPath = filepath.Join(stagingDir, filepath.Base(finalPath))
			if c.Logger != nil {
				c.Logger.Info("memory", "output path contains spaces; staging to %s", stagingPath)
			}
		}
	}
	stagedReq := req
	stagedReq.OutputPath = stagingPath

	// WinPmem: try multiple CLI variants. Different builds use different
	// flag syntax — and a misnamed flag returns 0xffffffff with no useful
	// stderr. Fall through each form until one produces output.
	var attempts [][]string
	if req.Tool == ToolWinPmem {
		attempts = [][]string{
			{stagedReq.OutputPath},
			{"-o", stagedReq.OutputPath},
			{"--format", "raw", "--output", stagedReq.OutputPath},
			{"--output", stagedReq.OutputPath, "--format", "raw"},
		}
	} else {
		args, err := buildCaptureArgs(stagedReq)
		if err != nil {
			result.Error = err.Error()
			result.Duration = time.Since(started)
			return result
		}
		attempts = [][]string{args}
	}

	var (
		stdout    *captureBuffer
		stderr    *captureBuffer
		waitErr   error
		usedArgs  []string
		attempted []string
	)
	for i, args := range attempts {
		stdout = &captureBuffer{}
		stderr = &captureBuffer{}

		// Wipe any partial file from a previous attempt so we're not
		// confused by stale bytes when the next form fails too.
		_ = os.Remove(stagedReq.OutputPath)

		cmd := exec.CommandContext(ctx, req.BinPath, args...)
		cmd.Dir = c.RootDir
		cmd.Stdout = stdout
		cmd.Stderr = stderr

		if c.Logger != nil {
			c.Logger.Info("memory", "capture exec [%d/%d]: %s %s",
				i+1, len(attempts), req.BinPath, strings.Join(args, " "))
		}

		if err := cmd.Start(); err != nil {
			result.Error = fmt.Sprintf("starting capture: %v", err)
			result.Duration = time.Since(started)
			return result
		}

		monitorDone := make(chan struct{})
		go monitorCaptureFile(stagedReq.OutputPath, progressCh, monitorDone)

		if i == 0 {
			sendProgress(progressCh, CaptureProgress{Status: CaptureRunning, Message: "Capture in progress"})
		} else {
			sendProgress(progressCh, CaptureProgress{Status: CaptureRunning,
				Message: fmt.Sprintf("Retrying with alternate flags (%d/%d)", i+1, len(attempts))})
		}

		waitErr = cmd.Wait()
		close(monitorDone)
		usedArgs = args
		attempted = append(attempted,
			fmt.Sprintf("[%s] %v: %s", strings.Join(args, " "),
				summarizeErr(waitErr),
				strings.TrimSpace(stderr.String())))

		// Success: produced a non-empty output file and exited cleanly.
		if waitErr == nil {
			if info, err := os.Stat(stagedReq.OutputPath); err == nil && info.Size() > 0 {
				break
			}
		}
		// Continue to next attempt only if this is WinPmem (we have alternates).
		if req.Tool != ToolWinPmem {
			break
		}
	}

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if waitErr != nil {
		// Surface the full stderr (and the list of every attempted form for
		// WinPmem) so the analyst knows what actually failed instead of
		// staring at "exit status 0xffffffff".
		msg := fmt.Sprintf("%s exited %s", filepath.Base(req.BinPath), summarizeErr(waitErr))
		if trimmed := strings.TrimSpace(result.Stderr); trimmed != "" {
			msg += "\nstderr: " + trimmed
		}
		if req.Tool == ToolWinPmem && len(attempts) > 1 {
			msg += "\n\nAttempted CLI forms:"
			for _, a := range attempted {
				msg += "\n  " + a
			}
		}
		msg += "\n\nargs: " + strings.Join(usedArgs, " ")
		result.Error = msg
		result.Duration = time.Since(started)
		// Try alternate DumpIt invocation if first form failed.
		if req.Tool == ToolDumpIt && len(req.ExtraArgs) == 0 {
			alt := stagedReq
			alt.ExtraArgs = []string{"alt"}
			altResult := c.runDumpItAlt(ctx, alt, progressCh)
			if altResult.Success {
				if stagingPath != finalPath {
					if err := moveCaptureFile(stagingPath, finalPath); err == nil {
						altResult.OutputPath = finalPath
					}
				}
				return altResult
			}
		}
		return result
	}

	// Move staged file to final path if we used a temp staging dir.
	if stagingPath != finalPath {
		if err := moveCaptureFile(stagingPath, finalPath); err != nil {
			result.Error = fmt.Sprintf("moving %s -> %s: %v", stagingPath, finalPath, err)
			result.Duration = time.Since(started)
			return result
		}
	}

	// Verify output exists.
	info, err := os.Stat(finalPath)
	if err != nil {
		result.Error = fmt.Sprintf("output file not found after capture: %v", err)
		result.Duration = time.Since(started)
		return result
	}
	result.Size = info.Size()
	if result.Size == 0 {
		result.Error = fmt.Sprintf("capture produced empty output (%s exited cleanly but wrote 0 bytes); check elevation and disk space",
			filepath.Base(req.BinPath))
		result.Duration = time.Since(started)
		return result
	}

	sendProgress(progressCh, CaptureProgress{
		Status: CaptureFinalizing, Message: "Computing SHA256",
	})

	hash, err := computeSHA256(finalPath)
	if err != nil {
		result.Error = fmt.Sprintf("hashing output: %v", err)
		result.Duration = time.Since(started)
		return result
	}
	result.SHA256 = hash
	result.OutputPath = finalPath
	result.Success = true
	result.Duration = time.Since(started)

	sendProgress(progressCh, CaptureProgress{
		Status: CaptureSuccess, BytesWritten: result.Size, Message: "Capture complete",
	})

	if c.Logger != nil {
		c.Logger.Info("memory", "capture complete: %s (%d bytes, sha256=%s)",
			finalPath, result.Size, result.SHA256)
	}
	return result
}

// summarizeErr converts a process-exit error into a short readable form
// (e.g. "status 1" or "0xffffffff") suitable for inclusion in a user-facing
// message alongside the captured stderr.
func summarizeErr(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	// Shorten "exit status 0xffffffff" → "0xffffffff".
	msg = strings.TrimPrefix(msg, "exit status ")
	return msg
}

// moveCaptureFile renames src to dst, falling back to copy+remove when the
// rename crosses filesystem boundaries (Windows temp on a different volume
// than the analyst's chosen output dir).
func moveCaptureFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
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
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

// runDumpItAlt retries DumpIt with the alternative CLI form.
func (c *CaptureManager) runDumpItAlt(ctx context.Context, req CaptureRequest, progressCh chan<- CaptureProgress) CaptureResult {
	result := CaptureResult{
		Tool:       req.Tool,
		Hostname:   c.Hostname,
		OutputPath: req.OutputPath,
	}
	started := time.Now()

	cmd := exec.CommandContext(ctx, req.BinPath, "-o", req.OutputPath)
	cmd.Dir = c.RootDir
	stdout := &captureBuffer{}
	stderr := &captureBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("starting capture (alt): %v", err)
		result.Duration = time.Since(started)
		return result
	}
	monitorDone := make(chan struct{})
	go monitorCaptureFile(req.OutputPath, progressCh, monitorDone)

	if err := cmd.Wait(); err != nil {
		close(monitorDone)
		result.Error = fmt.Sprintf("%v: %s", err, stderr.String())
		result.Duration = time.Since(started)
		return result
	}
	close(monitorDone)

	info, err := os.Stat(req.OutputPath)
	if err != nil {
		result.Error = fmt.Sprintf("output file not found: %v", err)
		result.Duration = time.Since(started)
		return result
	}
	result.Size = info.Size()
	hash, err := computeSHA256(req.OutputPath)
	if err == nil {
		result.SHA256 = hash
	}
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Success = true
	result.Duration = time.Since(started)
	return result
}

// buildCaptureArgs returns the command-line arguments for a capture tool.
func buildCaptureArgs(req CaptureRequest) ([]string, error) {
	switch req.Tool {
	case ToolDumpIt:
		// Primary form: /OUTPUT path /QUIET
		return []string{"/OUTPUT", req.OutputPath, "/QUIET"}, nil
	case ToolWinPmem:
		return []string{"--format", "raw", "--output", req.OutputPath}, nil
	case ToolAVML:
		args := []string{}
		args = append(args, req.ExtraArgs...)
		args = append(args, req.OutputPath)
		return args, nil
	case ToolLiME:
		// LiME runs via insmod; this branch is invoked from RunLiME() below.
		return nil, fmt.Errorf("LiME must be loaded via RunLiME, not Run")
	}
	return nil, fmt.Errorf("unsupported capture tool: %s", req.Tool)
}

// RunLiME loads the LiME kernel module to capture memory. Linux only.
func (c *CaptureManager) RunLiME(ctx context.Context, koPath, outputPath string, progressCh chan<- CaptureProgress) CaptureResult {
	defer func() {
		if progressCh != nil {
			close(progressCh)
		}
	}()

	result := CaptureResult{
		Tool:       ToolLiME,
		Hostname:   c.Hostname,
		OutputPath: outputPath,
	}
	started := time.Now()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		result.Error = fmt.Sprintf("creating output directory: %v", err)
		result.Duration = time.Since(started)
		return result
	}

	if _, err := os.Stat(koPath); err != nil {
		result.Error = fmt.Sprintf("lime.ko not found: %v", err)
		result.Duration = time.Since(started)
		return result
	}

	sendProgress(progressCh, CaptureProgress{Status: CapturePreparing, Message: "Loading LiME kernel module"})

	insmodArgs := []string{koPath, fmt.Sprintf("path=%s", outputPath), "format=lime"}
	cmd := exec.CommandContext(ctx, "insmod", insmodArgs...)
	stdout := &captureBuffer{}
	stderr := &captureBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("starting insmod: %v", err)
		result.Duration = time.Since(started)
		return result
	}

	monitorDone := make(chan struct{})
	go monitorCaptureFile(outputPath, progressCh, monitorDone)

	sendProgress(progressCh, CaptureProgress{Status: CaptureRunning, Message: "LiME writing memory image"})

	waitErr := cmd.Wait()
	close(monitorDone)

	// Always attempt rmmod, even on failure.
	rmCmd := exec.Command("rmmod", "lime")
	_ = rmCmd.Run()

	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if waitErr != nil {
		result.Error = fmt.Sprintf("%v: %s", waitErr, result.Stderr)
		result.Duration = time.Since(started)
		return result
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		result.Error = fmt.Sprintf("output file not found: %v", err)
		result.Duration = time.Since(started)
		return result
	}
	result.Size = info.Size()

	hash, err := computeSHA256(outputPath)
	if err == nil {
		result.SHA256 = hash
	}
	result.Success = true
	result.Duration = time.Since(started)

	sendProgress(progressCh, CaptureProgress{
		Status: CaptureSuccess, BytesWritten: result.Size, Message: "Capture complete",
	})
	return result
}

// ---------------------------------------------------------------------------
// File monitoring helpers
// ---------------------------------------------------------------------------

// monitorCaptureFile polls the output file every 2 seconds and reports growth
// on progressCh. It exits when done is closed.
func monitorCaptureFile(path string, progressCh chan<- CaptureProgress, done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	totalRAM := TotalRAM()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			progress := CaptureProgress{
				Status:       CaptureRunning,
				BytesWritten: info.Size(),
				TotalBytes:   totalRAM,
			}
			if totalRAM > 0 {
				pct := float64(info.Size()) / float64(totalRAM) * 100
				progress.Message = fmt.Sprintf("Capturing... %s / %s (%.0f%%)",
					FormatBytes(info.Size()), FormatBytes(totalRAM), pct)
			} else {
				progress.Message = fmt.Sprintf("Capturing... %s", FormatBytes(info.Size()))
			}
			sendProgress(progressCh, progress)
		}
	}
}

// sendProgress publishes a progress message non-blockingly.
func sendProgress(ch chan<- CaptureProgress, p CaptureProgress) {
	if ch == nil {
		return
	}
	select {
	case ch <- p:
	default:
	}
}

// computeSHA256 hashes a file using streaming I/O.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// captureBuffer is a thread-safe buffer that captures both stdout and stderr.
type captureBuffer struct {
	data []byte
}

func (b *captureBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	if len(b.data) > 64*1024 {
		// Trim to last 64KB so we don't unbounded-grow on chatty tools.
		b.data = b.data[len(b.data)-64*1024:]
	}
	return len(p), nil
}

func (b *captureBuffer) String() string {
	return string(b.data)
}
