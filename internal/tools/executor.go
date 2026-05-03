package tools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToolExecResult captures the full outcome of a single tool invocation.
type ToolExecResult struct {
	ToolName   string
	Command    string
	Args       []string
	WorkingDir string
	Combined   string
	ExitCode   int
	Duration   time.Duration
	Error      error
}

// Success reports whether the tool exited cleanly (exit 0, no error).
func (r *ToolExecResult) Success() bool { return r.Error == nil && r.ExitCode == 0 }

// GetInstalledPath resolves the absolute binary path for toolID. It tries the
// exact ID first, then platform-qualified suffixes (-win / -lnx) so callers
// can pass the bare base name ("hayabusa") without caring about the platform.
// Returns "" when no installed binary can be found.
func (m *ToolManager) GetInstalledPath(toolID string) string {
	if p := m.resolvedPath(toolID); p != "" {
		return p
	}
	for _, suffix := range []string{"-" + m.platform, "-win", "-lnx"} {
		if p := m.resolvedPath(toolID + suffix); p != "" {
			return p
		}
	}
	return ""
}

func (m *ToolManager) resolvedPath(id string) string {
	t := m.GetTool(id)
	if t == nil || !t.Installed {
		return ""
	}
	p := filepath.Join(m.rootDir, t.LocalPath)
	if fileExists(p) {
		return p
	}
	return ""
}

// VerifyTool confirms that a tool's registered binary exists on disk.
func (m *ToolManager) VerifyTool(toolID string) error {
	if m.GetInstalledPath(toolID) != "" {
		return nil
	}
	t := m.GetTool(toolID)
	if t == nil {
		return fmt.Errorf("tool %q not registered", toolID)
	}
	return fmt.Errorf("%s: binary not found at %s",
		t.Name, filepath.Join(m.rootDir, t.LocalPath))
}

// FindBinaryFlexible searches dir for a file whose name matches expectedName
// case-insensitively. It checks the exact path first, then scans the directory
// for a case-insensitive match, then recurses one level into sub-directories.
// Returns "" when nothing is found.
func FindBinaryFlexible(dir, expectedName string) string {
	exact := filepath.Join(dir, expectedName)
	if fileExists(exact) {
		return exact
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	lower := strings.ToLower(expectedName)
	for _, e := range entries {
		if !e.IsDir() && strings.ToLower(e.Name()) == lower {
			return filepath.Join(dir, e.Name())
		}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		subEntries, err2 := os.ReadDir(sub)
		if err2 != nil {
			continue
		}
		for _, se := range subEntries {
			if !se.IsDir() && strings.ToLower(se.Name()) == lower {
				return filepath.Join(sub, se.Name())
			}
		}
	}
	return ""
}

// ExecuteToolContext runs the tool identified by toolID with the given args.
//
// workDir sets cmd.Dir. Passing "" defaults to the binary's own directory —
// the right default for tools (like Hayabusa) that resolve bundled resources
// relative to their own location.
//
// The caller is responsible for applying a context deadline; this function
// forwards the context unchanged to exec.CommandContext.
func (m *ToolManager) ExecuteToolContext(ctx context.Context, toolID string, args []string, workDir string) *ToolExecResult {
	res := &ToolExecResult{ToolName: toolID, Args: args}

	bin := m.GetInstalledPath(toolID)
	if bin == "" {
		res.Error = fmt.Errorf("%s not installed — download via Configuration > Download Required Tools", toolID)
		return res
	}
	res.Command = bin

	if workDir == "" {
		workDir = filepath.Dir(bin)
	}
	res.WorkingDir = workDir

	start := time.Now()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = workDir
	combined, err := cmd.CombinedOutput()
	res.Duration = time.Since(start)
	res.Combined = string(combined)

	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exit.ExitCode()
		}
		res.Error = err
		m.logger.Warn("tools", "%s: exit: %v", toolID, err)
	}
	return res
}

// ExecuteTool is a convenience wrapper around ExecuteToolContext that uses
// context.Background(). Prefer ExecuteToolContext when you need cancellation.
func (m *ToolManager) ExecuteTool(toolID string, args []string, workDir string) *ToolExecResult {
	return m.ExecuteToolContext(context.Background(), toolID, args, workDir)
}
