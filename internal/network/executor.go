package network

import "time"

// ExecOnTarget opens a one-shot client connection to t, runs command with the
// given timeout, and closes. Callers running multiple commands should use
// NewClient + Connect directly to avoid reconnect overhead on every call.
func ExecOnTarget(t Target, command string, timeout time.Duration) CommandResult {
	c, err := NewClient(t)
	if err != nil {
		return CommandResult{Err: err}
	}
	if err := c.Connect(); err != nil {
		return CommandResult{Err: err}
	}
	defer c.Close()
	return c.Execute(command, timeout)
}

// TestTarget verifies credentials against t by running a trivial command.
// The CommandResult Stdout contains the remote hostname on success.
func TestTarget(t Target) CommandResult {
	return ExecOnTarget(t, "hostname", 15*time.Second)
}

// CopyFromTarget downloads remotePath from t to localPath.
func CopyFromTarget(t Target, remotePath, localPath string) error {
	c, err := NewClient(t)
	if err != nil {
		return err
	}
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()
	return c.CopyFrom(remotePath, localPath)
}

// CopyToTarget uploads localPath to remotePath on t.
func CopyToTarget(t Target, localPath, remotePath string) error {
	c, err := NewClient(t)
	if err != nil {
		return err
	}
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()
	return c.CopyTo(localPath, remotePath)
}
