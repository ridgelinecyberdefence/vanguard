package logging

import (
	"strings"
	"testing"
)

// TestSanitizeLogMessage verifies that the prefix-preserving redaction
// reads naturally — the prefix stays so debug-by-grep still works, only
// the secret value gets masked.
func TestSanitizeLogMessage(t *testing.T) {
	cases := []struct {
		in           string
		mustNotHave  string // substring that should be redacted
		mustContain  string // substring that should survive
	}{
		// argv-style flags
		{"psexec \\\\host -u admin -p hunter2 cmd /c whoami", "hunter2", "[REDACTED]"},
		{"plink -pw S3cret host", "S3cret", "[REDACTED]"},
		{"sshpass --password mypass ssh", "mypass", "[REDACTED]"},
		// key=value
		{"connecting with password=hunter2", "hunter2", "password="},
		{"token=abc123def", "abc123def", "token="},
		{"secret=topsecret", "topsecret", "secret="},
		{"api_key=1234567890", "1234567890", "api_key="},
		{"Authorization=BearerToken123", "BearerToken123", "Authorization="},
		// HTTP header — the JWT must not leak; "Authorization" prefix
		// stays so log readers can still see the line is auth-related.
		{"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload", "eyJhbGciOiJIUzI1NiJ9.payload", "Authorization"},
		// Env var
		{"SSHPASS=verysecret ssh user@host", "verysecret", "SSHPASS="},
		// Net use
		{"net use \\\\host\\C$ /user:admin hunter2", "hunter2", "/user:admin"},
		// PowerShell inline
		{"$pw = ConvertTo-SecureString 'plaintext' -AsPlainText", "plaintext", "ConvertTo-SecureString"},
	}
	for i, c := range cases {
		got := sanitizeLogMessage(c.in)
		if c.mustNotHave != "" && strings.Contains(got, c.mustNotHave) {
			t.Errorf("case %d: secret %q leaked through redaction: %q",
				i, c.mustNotHave, got)
		}
		if c.mustContain != "" && !strings.Contains(got, c.mustContain) {
			t.Errorf("case %d: expected prefix %q preserved, got: %q",
				i, c.mustContain, got)
		}
	}
}

// TestSanitizeRemoteOpLog confirms the helper produces a deterministic
// short string with no command details.
func TestSanitizeRemoteOpLog(t *testing.T) {
	got := SanitizeRemoteOpLog("dc01.example.com", "WinRM")
	want := "Executing remote command on dc01.example.com via WinRM"
	if got != want {
		t.Errorf("SanitizeRemoteOpLog = %q, want %q", got, want)
	}
	// No command leaks through even with empty args.
	got2 := SanitizeRemoteOpLog("", "")
	if !strings.Contains(got2, "Executing remote command") {
		t.Errorf("missing prefix: %q", got2)
	}
}
