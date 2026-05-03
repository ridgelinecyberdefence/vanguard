package network

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient connects to a remote host using the Go crypto/ssh library.
// No external binaries (ssh, scp, sshpass) are required — authentication
// is handled entirely in-process.
type SSHClient struct {
	target Target
}

// NewSSHClient returns a client for the given SSH target.
func NewSSHClient(target Target) *SSHClient {
	return &SSHClient{target: target}
}

// dial creates an authenticated SSH connection. Every Execute / Copy call
// opens a fresh connection so callers don't have to manage session state.
func (c *SSHClient) dial() (*ssh.Client, error) {
	host := c.target.Address()
	if host == "" {
		return nil, fmt.Errorf("ssh: target host is empty")
	}
	port := c.target.Port
	if port == 0 {
		port = 22
	}

	var authMethods []ssh.AuthMethod
	switch c.target.AuthMethod {
	case AuthKey:
		if c.target.KeyPath == "" {
			return nil, fmt.Errorf("ssh: key auth selected but key path is empty")
		}
		keyInfo, err := os.Stat(c.target.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("ssh: stat key %s: %w", c.target.KeyPath, err)
		}
		if runtime.GOOS != "windows" {
			if perm := keyInfo.Mode().Perm(); perm&0o077 != 0 {
				return nil, fmt.Errorf("SSH key %s has insecure permissions %04o — must be 0600 (owner-only); run: chmod 600 %s",
					c.target.KeyPath, perm, c.target.KeyPath)
			}
		}
		key, err := os.ReadFile(c.target.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("ssh: reading key %s: %w", c.target.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			if strings.Contains(err.Error(), "passphrase") {
				return nil, fmt.Errorf("SSH key %s is passphrase-protected — VanGuard does not currently support passphrase-protected keys; use an unencrypted key or ssh-agent", c.target.KeyPath)
			}
			return nil, fmt.Errorf("ssh: parsing key %s: %w", c.target.KeyPath, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	case AuthPassword:
		if len(c.target.Password) == 0 {
			return nil, fmt.Errorf("ssh: password auth selected but password is empty")
		}
		authMethods = append(authMethods, ssh.Password(string(c.target.Password)))
	default:
		return nil, fmt.Errorf("ssh: unknown auth method %q", c.target.AuthMethod)
	}

	// Host key verification is disabled for IR flexibility — targets are
	// rarely configured with known_hosts entries. Warn so analysts are
	// aware of the MITM exposure on untrusted networks.
	fmt.Fprintf(os.Stderr, "[WARN-SSH] host key verification disabled for %s — vulnerable to MITM on untrusted networks\n", host)
	cfg := &ssh.ClientConfig{
		User:            c.target.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — IR tool on trusted analyst LAN
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect to %s: %w", addr, err)
	}
	return conn, nil
}

// Connect verifies the host is reachable and credentials work.
func (c *SSHClient) Connect() error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	var stdout bytes.Buffer
	session.Stdout = &stdout
	if err := session.Run("echo vg-connect-ok"); err != nil {
		return fmt.Errorf("ssh connect probe: %w", err)
	}
	if !strings.Contains(stdout.String(), "vg-connect-ok") {
		return fmt.Errorf("ssh connect: unexpected output: %q", stdout.String())
	}
	return nil
}

// Close is a no-op for the stateless implementation.
func (c *SSHClient) Close() error {
	for i := range c.target.Password {
		c.target.Password[i] = 0
	}
	return nil
}

// Execute runs cmd on the remote host via a fresh SSH session.
//
// Non-zero exit codes are reflected in CommandResult.ExitCode but do NOT
// set CommandResult.Err — the command ran successfully from a transport
// perspective. Err is only set for connection / session errors.
func (c *SSHClient) Execute(cmd string, timeout time.Duration) CommandResult {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	started := time.Now()

	conn, err := c.dial()
	if err != nil {
		return CommandResult{Err: err, ExitCode: -1, Duration: time.Since(started)}
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return CommandResult{
			Err:      fmt.Errorf("ssh session: %w", err),
			ExitCode: -1,
			Duration: time.Since(started),
		}
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- session.Run(cmd) }()

	r := CommandResult{}
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		r.Err = fmt.Errorf("ssh command timed out after %v", timeout)
		r.ExitCode = -1
	case runErr := <-done:
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			r.ExitCode = exitErr.ExitStatus()
			// Non-zero exit: command ran, exit code reflects remote result.
		} else if runErr != nil {
			r.Err = runErr
			r.ExitCode = -1
		}
	}
	r.Stdout = stdout.String()
	r.Stderr = stderr.String()
	r.Duration = time.Since(started)
	return r
}

// CopyTo uploads localPath to remotePath on the target by piping the file
// contents through SSH stdin into `cat`. Binary-safe; no scp required.
func (c *SSHClient) CopyTo(localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("reading local file: %w", err)
	}

	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	session.Stderr = &stderr

	// Create parent directory then write stdin to the remote file.
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s",
		quoteShell(filepath.Dir(remotePath)), quoteShell(remotePath))
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("ssh upload to %s: %w (stderr: %s)", remotePath, err, stderr.String())
	}
	return nil
}

// CopyFrom downloads remotePath from the target to localPath by reading
// remote stdout with `cat`. Binary-safe; no scp required.
func (c *SSHClient) CopyFrom(remotePath, localPath string) error {
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run("cat " + quoteShell(remotePath)); err != nil {
		return fmt.Errorf("ssh download %s: %w (stderr: %s)", remotePath, err, stderr.String())
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("creating local dir: %w", err)
	}
	return os.WriteFile(localPath, stdout.Bytes(), 0o644)
}
