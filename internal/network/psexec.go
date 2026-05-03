package network

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PSExecClient drives Sysinternals psexec.exe. Windows-only. The binary must
// be placed at bin/windows/sysinternals/psexec.exe (or in PATH).
//
// File copy is implemented via SMB UNC paths (\\host\C$\…) — psexec itself
// doesn't transfer files, so callers reach the admin share with cmd /c copy.
type PSExecClient struct {
	target  Target
	binPath string // resolved psexec path; populated by Connect
}

// NewPSExecClient returns a PSExec client.
func NewPSExecClient(target Target) *PSExecClient {
	return &PSExecClient{target: target}
}

// PSExecBinary returns the resolved psexec path (used by tests).
func (c *PSExecClient) PSExecBinary() string { return c.binPath }

// Connect resolves the psexec binary and runs a hostname probe.
func (c *PSExecClient) Connect() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("PSExec is Windows-only; analyst host is %s", runtime.GOOS)
	}
	bin, err := resolvePSExec()
	if err != nil {
		return err
	}
	c.binPath = bin

	r := c.Execute("hostname", 30*time.Second)
	if r.Err != nil {
		return r.Err
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("psexec connect: exit %d: %s", r.ExitCode, r.Stderr)
	}
	return nil
}

// Close zeroes the in-memory password and releases any resources.
func (c *PSExecClient) Close() error {
	for i := range c.target.Password {
		c.target.Password[i] = 0
	}
	return nil
}

// Execute runs cmd on the target via psexec.
//
// SECURITY LIMITATION: PSExec (Sysinternals) does NOT support reading the
// password from stdin or a credential file. It only accepts -p PASSWORD on
// the command line. This means the password IS visible in the local process
// listing for the duration of the call. There is no way around this without
// changing transport.
//
// Mitigations applied:
//   - runProcess() does NOT log the argv anywhere (psexec callers in
//     internal/remote/ also avoid logging the constructed command).
//   - The logging package's redaction filter scrubs `-p VALUE` from any line
//     that does end up logged (see internal/logging/logger.go).
//
// Operators who cannot tolerate transient process-listing exposure of the
// password should use WinRM or SSH instead, both of which keep the secret
// off argv.
func (c *PSExecClient) Execute(cmd string, timeout time.Duration) CommandResult {
	if c.binPath == "" {
		bin, err := resolvePSExec()
		if err != nil {
			return CommandResult{Err: err, ExitCode: -1}
		}
		c.binPath = bin
	}
	if c.target.AuthMethod != AuthPassword {
		return CommandResult{
			Err:      fmt.Errorf("psexec requires password authentication"),
			ExitCode: -1,
		}
	}
	if len(c.target.Password) == 0 {
		return CommandResult{Err: fmt.Errorf("psexec: password is empty"), ExitCode: -1}
	}

	addr := c.target.Address()
	if addr == "" {
		return CommandResult{Err: fmt.Errorf("psexec: target host empty"), ExitCode: -1}
	}

	// Detect PowerShell-style commands (cmdlets, pipeline, variables) and
	// wrap them accordingly; everything else goes through cmd.exe /c.
	var execArgs []string
	if isPSCommand(cmd) {
		execArgs = []string{"powershell.exe", "-NonInteractive", "-NoProfile", "-Command", cmd}
	} else {
		execArgs = []string{"cmd.exe", "/c", cmd}
	}

	fmt.Fprintf(os.Stderr, "[WARN-PSEXEC] password will be visible in the analyst host's process list for the duration of this call — consider WinRM or SSH for sensitive credentials\n")
	args := append([]string{
		`\\` + addr,
		"-accepteula",
		"-nobanner",
		"-u", c.target.Username,
		"-p", string(c.target.Password), // see SECURITY LIMITATION above
	}, execArgs...)

	debugArgs := make([]string, len(args))
	copy(debugArgs, args)
	for i := range debugArgs {
		if i > 0 && debugArgs[i-1] == "-p" {
			debugArgs[i] = "***"
		}
	}
	log.Printf("[DEBUG-PSEXEC] binary=%s args=%v", c.binPath, debugArgs)

	r := runProcess(c.binPath, args, os.Environ(), timeout)

	// Annotate well-known PSExec exit codes with actionable hints.
	if r.Err == nil && r.ExitCode != 0 {
		switch r.ExitCode {
		case 1:
			r.Err = fmt.Errorf("psexec exit 1: check credentials or target availability (stderr: %s)", strings.TrimSpace(r.Stderr))
		case 2, 5:
			r.Err = fmt.Errorf("psexec access denied (exit %d): verify the account has remote execution rights", r.ExitCode)
		case 6:
			r.Err = fmt.Errorf("psexec argument error (exit 6): command quoting or flag may be malformed")
		}
	}
	return r
}

// isPSCommand returns true when cmd looks like a PowerShell expression rather
// than a plain cmd.exe command line.
func isPSCommand(cmd string) bool {
	psMarkers := []string{"Get-", "Set-", "New-", "Remove-", "Invoke-", "Out-",
		"Select-", "Where-", "ForEach-", "ConvertTo-", "Export-", "Import-"}
	for _, m := range psMarkers {
		if strings.Contains(cmd, m) {
			return true
		}
	}
	// Pipeline or variable references are also PS-specific.
	return strings.ContainsAny(cmd, "|$")
}

// CopyTo uploads localPath to remotePath via SMB. remotePath should be a
// drive-rooted path like "C:\\Windows\\Temp\\foo.exe"; this is converted to
// "\\\\host\\C$\\Windows\\Temp\\foo.exe".
func (c *PSExecClient) CopyTo(localPath, remotePath string) error {
	uncPath, err := toAdminUNC(c.target.Address(), remotePath)
	if err != nil {
		return err
	}
	return smbCopy(localPath, uncPath, c.target.Username, string(c.target.Password))
}

// CopyFrom downloads remotePath to localPath via SMB.
func (c *PSExecClient) CopyFrom(remotePath, localPath string) error {
	uncPath, err := toAdminUNC(c.target.Address(), remotePath)
	if err != nil {
		return err
	}
	return smbCopy(uncPath, localPath, c.target.Username, string(c.target.Password))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolvePSExec returns the path to psexec.exe.
func resolvePSExec() (string, error) {
	candidates := []string{
		filepath.Join("bin", "windows", "sysinternals", "PsExec64.exe"),
		filepath.Join("bin", "windows", "sysinternals", "psexec.exe"),
		"PsExec64.exe",
		"psexec.exe",
		"PsExec.exe",
	}
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		// Relative path under current working dir.
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs, nil
		}
	}
	return "", fmt.Errorf(
		"PSExec not available. Install Sysinternals to bin/windows/sysinternals/ or use WinRM/SSH instead.")
}

// toAdminUNC converts a drive-rooted path like C:\Windows\Temp\foo.exe into
// \\host\C$\Windows\Temp\foo.exe.
func toAdminUNC(host, remotePath string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("psexec: target host empty")
	}
	if len(remotePath) < 3 || remotePath[1] != ':' {
		return "", fmt.Errorf("psexec: remote path must be drive-rooted (e.g. C:\\Windows\\Temp\\foo): %q", remotePath)
	}
	drive := remotePath[:1]
	rest := remotePath[3:] // skip "C:\"
	return `\\` + host + `\` + drive + `$\` + rest, nil
}

// smbCopy mounts the share with `net use` (so credentials are presented),
// performs the copy, then disconnects.
//
// SECURITY: `net use \\host\share /user:NAME PASSWORD` puts the password on
// argv. To avoid this, we invoke `net use \\host\share /user:NAME *` which
// causes net.exe to prompt on stdin, and we feed the password to that prompt.
// The password never appears in argv this way.
func smbCopy(src, dst, user, password string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("SMB copy requires Windows analyst host")
	}

	// Determine the UNC root (\\host\C$) for net use.
	uncRoot := uncShareRoot(src)
	if uncRoot == "" {
		uncRoot = uncShareRoot(dst)
	}
	if uncRoot == "" {
		return fmt.Errorf("smb copy: neither source nor destination is a UNC path")
	}

	// Authenticate against the share — feed the password via stdin (`*`
	// makes net.exe prompt, and stdin satisfies that prompt).
	netUse := exec.Command("net", "use", uncRoot, "/user:"+user, "*")
	netUse.Stdin = strings.NewReader(password + "\n")
	// Discard CombinedOutput — it may contain the password prompt echo on
	// some Windows versions, and we don't want it in error/log surfaces.
	if _, err := netUse.CombinedOutput(); err != nil {
		return fmt.Errorf("net use %s: %v", uncRoot, err)
	}
	defer func() {
		_ = exec.Command("net", "use", uncRoot, "/delete", "/y").Run()
	}()

	cp := exec.Command("cmd", "/c", "copy", "/Y", src, dst)
	if out, err := cp.CombinedOutput(); err != nil {
		return fmt.Errorf("copy %s -> %s: %v: %s", src, dst, err, string(out))
	}
	return nil
}

// runProcess spawns bin with args, captures stdout/stderr, and returns a
// CommandResult. It is used by PSExecClient and other callers that shell out to
// local binaries rather than using a remote protocol library.
func runProcess(bin string, args []string, env []string, timeout time.Duration) CommandResult {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := time.Now()
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(env) > 0 {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	r := CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: time.Since(started),
	}
	if runErr != nil {
		if ctx.Err() != nil {
			r.Err = fmt.Errorf("command timed out after %v", timeout)
			r.ExitCode = -1
		} else if exitErr, ok := runErr.(*exec.ExitError); ok {
			r.ExitCode = exitErr.ExitCode()
		} else {
			r.Err = runErr
			r.ExitCode = -1
		}
	}
	return r
}

// uncShareRoot returns "\\host\share" portion of p, or "" if p isn't a UNC.
func uncShareRoot(p string) string {
	if len(p) < 4 || p[0] != '\\' || p[1] != '\\' {
		return ""
	}
	// Find third backslash.
	count := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' {
			count++
			if count == 4 {
				return p[:i]
			}
		}
	}
	return p
}
