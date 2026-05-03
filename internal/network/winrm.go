package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/masterzen/winrm"
)

// maxInlineTransferSize caps the size of files transferred via inline base64
// over WinRM. Above this threshold CopyFrom routes through an SMB temporary share.
const maxInlineTransferSize int64 = 10 * 1024 * 1024 // 10 MB

// largeTransferWarningSize triggers a strong "consider another transport" warning.
const largeTransferWarningSize int64 = 100 * 1024 * 1024 // 100 MB

// WinRMClient drives Windows Remote Management via the masterzen/winrm library.
// No PowerShell on the analyst host is required — all negotiation is in-process
// over HTTP/HTTPS using NTLM authentication.
type WinRMClient struct {
	target Target
}

// NewWinRMClient returns a client for the given WinRM target.
func NewWinRMClient(target Target) *WinRMClient {
	return &WinRMClient{target: target}
}

// newWinRMClient builds an authenticated winrm.Client for this target.
// A fresh client is created per call so Execute/CopyTo/CopyFrom are stateless.
func (c *WinRMClient) newWinRMClient(timeout time.Duration) (*winrm.Client, error) {
	host := c.target.Address()
	if host == "" {
		return nil, fmt.Errorf("winrm: target host is empty")
	}
	if c.target.AuthMethod != AuthPassword {
		return nil, fmt.Errorf("winrm: only password auth is supported")
	}
	if c.target.Username == "" {
		return nil, fmt.Errorf("winrm: username is empty")
	}
	if len(c.target.Password) == 0 {
		return nil, fmt.Errorf("winrm: password is empty")
	}

	port := c.target.Port
	if port == 0 {
		port = 5985
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	useHTTPS := port == 5986
	log.Printf("[DEBUG-WINRM] host=%s port=%d user=%s useHTTPS=%v", host, port, c.target.Username, useHTTPS)
	if !useHTTPS {
		log.Printf("[WARN] WinRM connecting to %s:%d over HTTP — NTLM credentials transmitted unencrypted; use port 5986 (HTTPS) for production", host, port)
	}
	// insecure=true skips TLS certificate verification. This is deliberate:
	// IR targets rarely have valid CA-signed certificates. Future: add optional
	// CAPath to target config for environments requiring certificate pinning.
	endpoint := winrm.NewEndpoint(host, port, useHTTPS, true, nil, nil, nil, timeout)
	params := winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter {
		return &winrm.ClientNTLM{}
	}
	return winrm.NewClientWithParameters(endpoint, c.target.Username, string(c.target.Password), params)
}

// Connect verifies the host is reachable and credentials are valid by running
// a hostname probe.
func (c *WinRMClient) Connect() error {
	r := c.Execute("hostname", 30*time.Second)
	if r.Err != nil {
		return r.Err
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("winrm connect: exit %d: %s", r.ExitCode, r.Stderr)
	}
	return nil
}

// Close zeroes the in-memory password and releases any resources.
func (c *WinRMClient) Close() error {
	for i := range c.target.Password {
		c.target.Password[i] = 0
	}
	return nil
}

// Execute runs cmd as a PowerShell expression on the target. A fresh WinRM
// client and shell are created per call.
//
// Non-zero exit codes are reflected in CommandResult.ExitCode but do NOT set
// CommandResult.Err — the command ran successfully from a transport perspective.
// Err is only set for connection / session errors.
func (c *WinRMClient) Execute(cmd string, timeout time.Duration) CommandResult {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	started := time.Now()

	client, err := c.newWinRMClient(timeout)
	if err != nil {
		return CommandResult{Err: err, ExitCode: -1, Duration: time.Since(started)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var outBuf, errBuf bytes.Buffer
	var exitCode int
	var runErr error

	if isPSCommand(cmd) {
		var so, se string
		so, se, exitCode, runErr = client.RunPSWithContext(ctx, cmd)
		outBuf.WriteString(so)
		errBuf.WriteString(se)
	} else {
		exitCode, runErr = client.RunWithContext(ctx, cmd, &outBuf, &errBuf)
	}

	r := CommandResult{
		Stdout:   outBuf.String(),
		Stderr:   errBuf.String(),
		ExitCode: exitCode,
		Duration: time.Since(started),
	}
	if runErr != nil {
		r.Err = runErr
		if r.ExitCode == 0 {
			r.ExitCode = -1
		}
		errMsg := runErr.Error()
		if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "nauthorized") {
			r.Err = fmt.Errorf("%w\nhint: ensure WinRM is enabled on the target and the account has remote access:\n  winrm quickconfig\n  Enable-PSRemoting -Force", runErr)
		}
	}
	return r
}

// CopyTo uploads localPath to remotePath by base64-streaming the contents into
// a remote file via PowerShell. Suitable for files up to maxInlineTransferSize.
func (c *WinRMClient) CopyTo(localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("reading local file: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	// base64 chars are URL-safe; only remotePath needs PS quoting.
	cmd := fmt.Sprintf(
		`$bytes = [System.Convert]::FromBase64String('%s'); `+
			`[System.IO.File]::WriteAllBytes('%s', $bytes)`,
		encoded, escapePSString(remotePath))

	r := c.Execute(cmd, 30*time.Minute)
	if r.Err != nil {
		return fmt.Errorf("winrm upload: %w (stderr: %s)", r.Err, r.Stderr)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("winrm upload exit %d: %s", r.ExitCode, r.Stderr)
	}
	return nil
}

// CopyFrom downloads remotePath to localPath, routing large files through an
// SMB temporary share (Windows analyst only) to avoid WinRM message-size limits.
func (c *WinRMClient) CopyFrom(remotePath, localPath string) error {
	size, err := c.remoteFileSize(remotePath)
	if err != nil {
		return c.copyFromInline(remotePath, localPath)
	}

	if size > largeTransferWarningSize {
		fmt.Fprintf(os.Stderr,
			"warning: transferring %s via WinRM. For files over 100MB consider "+
				"SMB file share or physical USB transfer for better performance "+
				"and security.\n", formatBytes(size))
	}

	if size > maxInlineTransferSize {
		return c.copyFromViaSMB(remotePath, localPath)
	}
	return c.copyFromInline(remotePath, localPath)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (c *WinRMClient) remoteFileSize(remotePath string) (int64, error) {
	cmd := fmt.Sprintf(`(Get-Item '%s' -ErrorAction Stop).Length`, escapePSString(remotePath))
	r := c.Execute(cmd, 30*time.Second)
	if r.Err != nil {
		return 0, r.Err
	}
	if r.ExitCode != 0 {
		return 0, fmt.Errorf("get-item exit %d: %s", r.ExitCode, r.Stderr)
	}
	return strconv.ParseInt(strings.TrimSpace(r.Stdout), 10, 64)
}

func (c *WinRMClient) copyFromInline(remotePath, localPath string) error {
	cmd := fmt.Sprintf(
		`[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes('%s'))`,
		escapePSString(remotePath))

	r := c.Execute(cmd, 30*time.Minute)
	if r.Err != nil {
		return fmt.Errorf("winrm download: %w (stderr: %s)", r.Err, r.Stderr)
	}
	if r.ExitCode != 0 {
		return fmt.Errorf("winrm download exit %d: %s", r.ExitCode, r.Stderr)
	}

	clean := stripWhitespace(r.Stdout)
	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return fmt.Errorf("decoding remote payload: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("creating local dir: %w", err)
	}
	return os.WriteFile(localPath, decoded, 0o644)
}

// copyFromViaSMB stands up a one-shot read-only SMB share on the target,
// pulls the file by UNC path, then tears the share down.
func (c *WinRMClient) copyFromViaSMB(remotePath, localPath string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf(
			"WinRM SMB-fallback transfer requires a Windows analyst host. " +
				"For large files from a Linux analyst, use SSH (Linux target) " +
				"or pull the dump physically.")
	}
	host := c.target.Address()
	if host == "" {
		return fmt.Errorf("winrm SMB transfer: target host empty")
	}

	shareName := "VG_TEMP_" + randomHex(4)
	shareDir := filepath.Dir(remotePath)
	fileName := filepath.Base(remotePath)

	createCmd := fmt.Sprintf(
		`net share %s='%s' /grant:everyone,read | Out-Null`,
		shareName, escapePSString(shareDir))
	if r := c.Execute(createCmd, 30*time.Second); r.Err != nil || r.ExitCode != 0 {
		return fmt.Errorf("creating temp share %s: %v %s", shareName, r.Err, r.Stderr)
	}
	defer func() {
		deleteCmd := fmt.Sprintf(`net share %s /delete /y | Out-Null`, shareName)
		_ = c.Execute(deleteCmd, 30*time.Second)
	}()

	uncPath := fmt.Sprintf(`\\%s\%s\%s`, host, shareName, fileName)
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("creating local dir: %w", err)
	}
	cp := exec.Command("cmd", "/c", "copy", "/Y", uncPath, localPath)
	if out, err := cp.CombinedOutput(); err != nil {
		return fmt.Errorf("copy %s -> %s: %v: %s", uncPath, localPath, err, string(out))
	}
	return nil
}

// randomHex returns 2*n hex characters from crypto/rand.
func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// formatBytes renders a byte count in human-friendly units.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// escapePSString escapes a value for embedding inside a single-quoted
// PowerShell string. Only ' needs doubling in PS single-quoting.
func escapePSString(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func stripWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
