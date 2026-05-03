package disk

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// UACManager wraps the Unix-like Artifacts Collector.
type UACManager struct {
	RootDir string
	Logger  *logging.Logger
}

// NewUACManager creates a UAC manager.
func NewUACManager(rootDir string, logger *logging.Logger) *UACManager {
	return &UACManager{RootDir: rootDir, Logger: logger}
}

// Dir returns the UAC install directory.
func (u *UACManager) Dir() string {
	return filepath.Join(u.RootDir, "bin", "linux", "uac")
}

// BinaryPath returns the absolute path to the uac launcher script.
func (u *UACManager) BinaryPath() string {
	p := filepath.Join(u.Dir(), "uac")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// Installed reports whether UAC is available locally.
func (u *UACManager) Installed() bool {
	return u.BinaryPath() != ""
}

// ListProfiles enumerates UAC profiles from profiles/.
func (u *UACManager) ListProfiles() ([]string, error) {
	dir := filepath.Join(u.Dir(), "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading UAC profiles dir: %w", err)
	}
	var profiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// UAC profiles are .yaml files.
		if strings.HasSuffix(name, ".yaml") {
			profiles = append(profiles, strings.TrimSuffix(name, ".yaml"))
		}
	}
	sort.Strings(profiles)
	return profiles, nil
}

// Run executes UAC with the given profile, writing artifacts under outDir.
func (u *UACManager) Run(ctx context.Context, profile, outDir string) CollectionResult {
	result := CollectionResult{Name: "UAC: " + profile, OutputDir: outDir}
	started := time.Now()

	bin := u.BinaryPath()
	if bin == "" {
		result.Status = StatusFailed
		result.Error = "UAC binary not found"
		result.Duration = time.Since(started)
		return result
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		result.Status = StatusFailed
		result.Error = "creating output dir: " + err.Error()
		result.Duration = time.Since(started)
		return result
	}

	args := []string{"-p", profile, outDir}
	if u.Logger != nil {
		u.Logger.Info("disk", "uac exec: %s %s", bin, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = u.Dir()
	out, err := cmd.CombinedOutput()
	result.Stdout = string(out)
	result.Duration = time.Since(started)

	if err != nil {
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("uac failed: %v", err)
		return result
	}

	files, bytes := countDirContents(outDir)
	result.Files = files
	result.Bytes = bytes
	if files == 0 {
		result.Status = StatusPartial
		result.Warnings = append(result.Warnings, "UAC completed but no artifacts collected")
	} else {
		result.Status = StatusSuccess
	}
	return result
}
