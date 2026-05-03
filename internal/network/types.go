// Package network provides protocol-agnostic remote-host clients for SSH,
// WinRM, and PSExec.
//
// All clients implement the Client interface so callers (the remote
// orchestration layer) can stay protocol-neutral. The implementations shell
// out to platform tools that ship with the supported OSes:
//
//   - SSH:    OpenSSH client (ssh / scp). Bundled with Windows 10+ and most
//             Linux distros.
//   - WinRM:  PowerShell 5.1+ Invoke-Command. Bundled with Windows.
//   - PSExec: Sysinternals psexec.exe placed at bin/windows/sysinternals/.
//
// This avoids pulling in unverified third-party libraries while still working
// out of the box on every platform VanGuard targets.
package network

import (
	"fmt"
	"strings"
	"time"
)

// Protocol identifies a remote-execution transport.
type Protocol string

const (
	ProtocolSSH    Protocol = "ssh"
	ProtocolWinRM  Protocol = "winrm"
	ProtocolPSExec Protocol = "psexec"
)

// AuthMethod identifies how a client authenticates.
type AuthMethod string

const (
	AuthPassword AuthMethod = "password"
	AuthKey      AuthMethod = "key"
)

// Target carries everything a Client needs to connect to a remote host.
type Target struct {
	Hostname   string
	IPAddress  string
	Protocol   Protocol
	Port       int
	OSType     string // "windows" or "linux"
	Username   string
	AuthMethod AuthMethod
	Password   []byte // empty when AuthMethod == AuthKey; zeroed in Close()
	KeyPath    string // empty when AuthMethod == AuthPassword
}

// Address returns the host portion clients should connect to.
func (t Target) Address() string {
	if t.IPAddress != "" {
		return t.IPAddress
	}
	return t.Hostname
}

// DisplayName returns "{hostname} ({ip})" or just one of them.
func (t Target) DisplayName() string {
	switch {
	case t.Hostname != "" && t.IPAddress != "":
		return fmt.Sprintf("%s (%s)", t.Hostname, t.IPAddress)
	case t.Hostname != "":
		return t.Hostname
	case t.IPAddress != "":
		return t.IPAddress
	}
	return "(unknown)"
}

// CommandResult captures the structured output of a remote execution.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	Err      error
}

// Failed reports whether the command did not succeed.
func (r CommandResult) Failed() bool {
	return r.Err != nil || r.ExitCode != 0
}

// Client is the protocol-agnostic remote-host interface.
//
// Each implementation is single-shot — Connect must be called before Execute /
// CopyTo / CopyFrom, and Close releases any resources. Concrete implementations
// may be entirely stateless (shelling out per call) but they should still
// behave as if connect/close were meaningful, so callers don't leak handles.
type Client interface {
	// Connect performs an authentication probe. Implementations should fail
	// fast on bad credentials so callers can prompt the user.
	Connect() error

	// Execute runs cmd on the remote host. timeout caps the entire run.
	Execute(cmd string, timeout time.Duration) CommandResult

	// CopyTo uploads localPath to remotePath on the target.
	CopyTo(localPath, remotePath string) error

	// CopyFrom downloads remotePath from the target to localPath.
	CopyFrom(remotePath, localPath string) error

	// Close releases resources. Safe to call multiple times.
	Close() error
}

// NewClient returns a Client for the target's protocol.
func NewClient(target Target) (Client, error) {
	switch target.Protocol {
	case ProtocolSSH:
		return NewSSHClient(target), nil
	case ProtocolWinRM:
		return NewWinRMClient(target), nil
	case ProtocolPSExec:
		return NewPSExecClient(target), nil
	}
	return nil, fmt.Errorf("unsupported protocol: %s", target.Protocol)
}

// DefaultPort returns the conventional port for a protocol.
func DefaultPort(p Protocol) int {
	switch p {
	case ProtocolSSH:
		return 22
	case ProtocolWinRM:
		return 5985
	case ProtocolPSExec:
		return 445
	}
	return 0
}

// quoteShell trivially shell-quotes s so it survives a single-quoted argv.
// Only needed where the implementation embeds a value into a shell template;
// most code passes args directly.
func quoteShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
