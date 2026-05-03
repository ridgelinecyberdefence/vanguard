package disk

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// KapeManager wraps KAPE invocation.
type KapeManager struct {
	RootDir string
	Logger  *logging.Logger
}

// NewKapeManager creates a KAPE manager.
func NewKapeManager(rootDir string, logger *logging.Logger) *KapeManager {
	return &KapeManager{RootDir: rootDir, Logger: logger}
}

// BinaryPath returns the absolute path to kape.exe (or "" if missing).
func (k *KapeManager) BinaryPath() string {
	p := filepath.Join(k.RootDir, "bin", "windows", "kape", "kape.exe")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// Installed reports whether KAPE is available locally.
func (k *KapeManager) Installed() bool {
	return k.BinaryPath() != ""
}

// TargetsDir returns the KAPE Targets directory.
func (k *KapeManager) TargetsDir() string {
	return filepath.Join(k.RootDir, "bin", "windows", "kape", "Targets")
}

// SystemDrive returns the source drive — typically C:\.
func SystemDrive() string {
	if d := os.Getenv("SystemDrive"); d != "" {
		return d + "\\"
	}
	return "C:\\"
}

// ListTargets enumerates compound and individual KAPE targets.
// Compound targets start with "!" and live at the Targets/ root.
// Individual targets are .tkape files anywhere under Targets/.
func (k *KapeManager) ListTargets() (compound, individual []string, err error) {
	dir := k.TargetsDir()
	if _, err := os.Stat(dir); err != nil {
		return nil, nil, fmt.Errorf("targets directory not found at %s", dir)
	}
	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".tkape") {
			return nil
		}
		name := strings.TrimSuffix(d.Name(), ".tkape")
		if strings.HasPrefix(name, "!") {
			compound = append(compound, name)
		} else {
			individual = append(individual, name)
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}
	sort.Strings(compound)
	sort.Strings(individual)
	return compound, individual, nil
}

// CollectRequest configures a KAPE run.
type CollectRequest struct {
	Targets   []string // KAPE targets, e.g. []string{"!SANS_Triage"}
	Source    string   // source drive, e.g. "C:\\"
	OutputDir string   // tdest
}

// Collect runs KAPE against the configured targets.
func (k *KapeManager) Collect(ctx context.Context, req CollectRequest) CollectionResult {
	result := CollectionResult{Name: "KAPE: " + strings.Join(req.Targets, ","), OutputDir: req.OutputDir}
	started := time.Now()

	bin := k.BinaryPath()
	if bin == "" {
		result.Status = StatusFailed
		result.Error = "kape.exe not found"
		result.Duration = time.Since(started)
		return result
	}
	if len(req.Targets) == 0 {
		result.Status = StatusFailed
		result.Error = "no KAPE targets specified"
		result.Duration = time.Since(started)
		return result
	}
	if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
		result.Status = StatusFailed
		result.Error = "creating output dir: " + err.Error()
		result.Duration = time.Since(started)
		return result
	}

	source := req.Source
	if source == "" {
		source = SystemDrive()
	}

	args := []string{
		"--tsource", source,
		"--tdest", req.OutputDir,
		"--target", strings.Join(req.Targets, ","),
		"--tflush",
	}

	if k.Logger != nil {
		k.Logger.Info("disk", "kape exec: %s %s", bin, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Dir(bin) // KAPE expects to run from its install directory
	out, err := cmd.CombinedOutput()
	result.Stdout = string(out)
	result.Duration = time.Since(started)

	// Count output files BEFORE checking the exit code. KAPE frequently exits
	// non-zero even when it collected artifacts successfully (e.g. locked files
	// encountered mid-walk, or a target had no matching items on one drive).
	// Treating a non-zero exit as an immediate failure causes every real KAPE
	// run to be reported as FAILED even when the output directory is full.
	files, totalBytes := countDirContents(req.OutputDir)
	result.Files = files
	result.Bytes = totalBytes

	switch {
	case files > 0 && err == nil:
		result.Status = StatusSuccess
	case files > 0 && err != nil:
		// Collected something despite a non-zero exit — partial success.
		result.Status = StatusPartial
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("KAPE exited non-zero (%v) but collected %d files — some targets may have been skipped", err, files))
	case files == 0 && err != nil:
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("KAPE exited with error and collected no files: %v", err)
	default: // files == 0, err == nil
		result.Status = StatusPartial
		result.Warnings = append(result.Warnings,
			"KAPE completed but collected no files — target may not have matching artifacts on this system")
	}
	return result
}

// CollectPreset runs KAPE with one of the named preset targets.
func (k *KapeManager) CollectPreset(ctx context.Context, preset, outputDir string) CollectionResult {
	var targets []string
	switch preset {
	case "sans":
		targets = []string{"!SANS_Triage"}
	case "basic":
		targets = []string{"!BasicCollection"}
	case "full":
		// KapeTriage is a broad individual target covering common IR artefacts.
		// !BasicCollection is the compound version; use that as fallback if
		// KapeTriage isn't present in this KAPE installation.
		targets = []string{"KapeTriage"}
	case "evtx":
		targets = []string{"EventLogs"}
	case "registry":
		targets = []string{"RegistryHives"}
	case "browser":
		// WebBrowsers covers Chrome, Edge, Firefox, IE.
		targets = []string{"WebBrowsers"}
	default:
		return CollectionResult{
			Name:   "KAPE preset " + preset,
			Status: StatusFailed,
			Error:  "unknown preset: " + preset,
		}
	}
	return k.Collect(ctx, CollectRequest{
		Targets:   targets,
		Source:    SystemDrive(),
		OutputDir: outputDir,
	})
}
