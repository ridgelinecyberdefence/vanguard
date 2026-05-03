// Package audit provides a tamper-evident operator action log for VanGuard.
//
// The log file (logs/audit.jsonl) records every analyst-initiated action
// with a timestamp, parameters, result, and an HMAC-SHA256 signature over
// the entry's content. The HMAC key is generated on first run and stored
// at logs/.audit_key with mode 0600 — anyone able to read the key file can
// forge entries, so the file system permissions on logs/ are the trust
// boundary.
//
// This is intentionally a separate stream from the structured log
// (logs/vanguard.log). The structured log is for debugging; audit.jsonl is
// a chain-of-custody artifact suitable for legal proceedings.
//
// Each entry can be verified independently with VerifyAuditIntegrity(), so
// a tampered or removed line is detectable as long as the operator still
// has the original .audit_key.
package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/security"
)

// AuditEntry is one record in the audit log.
//
// Fields stay flat (no nesting) so each line is a self-contained, grep-able
// JSON object. HMAC is computed over the same field set EXCLUDING HMAC
// itself — see signEntry.
type AuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Analyst    string    `json:"analyst"`
	Action     string    `json:"action"`
	Target     string    `json:"target,omitempty"`
	Parameters string    `json:"parameters,omitempty"`
	Result     string    `json:"result"`
	CaseID     string    `json:"case_id,omitempty"`
	HMAC       string    `json:"hmac"`
}

// Logger writes audit entries to a JSONL file with HMAC signatures.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	hmacKey []byte
	analyst string
	path    string
}

// NewLogger opens (or creates) logs/audit.jsonl in append mode and either
// loads or generates the HMAC key at logs/.audit_key.
//
// The key is 32 bytes from crypto/rand. Both files are written with mode
// 0600 — anyone with read access to logs/.audit_key can forge entries.
func NewLogger(logDir, analyst string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating log dir: %w", err)
	}

	path := filepath.Join(logDir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	keyPath := filepath.Join(logDir, ".audit_key")
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit key: %w", err)
	}

	return &Logger{
		file:    f,
		hmacKey: key,
		analyst: analyst,
		path:    path,
	}, nil
}

// loadOrCreateKey reads an existing 32-byte HMAC key from path, or
// generates one if path doesn't exist. The file is written 0600.
func loadOrCreateKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) < 32 {
			return nil, fmt.Errorf("audit key at %s is too short (%d bytes)", path, len(data))
		}
		return data, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating audit key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("writing audit key: %w", err)
	}
	return key, nil
}

// SetAnalyst updates the recorded analyst name. Useful when the operator
// edits Configuration > Edit Analyst Name mid-session.
func (l *Logger) SetAnalyst(analyst string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.analyst = analyst
}

// Log records one audit entry and flushes it to disk.
//
// Parameters are passed through security.SanitizeShellArg before storage —
// the audit log is read by humans and external tools, and we don't want a
// raw IOC value with shell metacharacters to break terminal display when
// someone `cat`s the file.
//
// Returns an error if the write fails so callers can decide whether the
// failure is fatal to their op.
func (l *Logger) Log(action, target, parameters, result, caseID string) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := AuditEntry{
		Timestamp:  time.Now().UTC(),
		Analyst:    l.analyst,
		Action:     action,
		Target:     target,
		Parameters: security.SanitizeShellArg(parameters),
		Result:     result,
		CaseID:     caseID,
	}
	mac, err := signEntry(entry, l.hmacKey)
	if err != nil {
		return err
	}
	entry.HMAC = mac

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshalling audit entry: %w", err)
	}
	if _, err := l.file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

// signEntry computes HMAC-SHA256 over the canonical-JSON form of e with the
// HMAC field zeroed. Encoding through json.Marshal twice (once to compute,
// once to write) keeps the canonical form deterministic.
func signEntry(e AuditEntry, key []byte) (string, error) {
	e.HMAC = ""
	data, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("marshalling for HMAC: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Close flushes and closes the underlying file. After Close, Log calls fail.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// VerifyResult is the outcome of VerifyAuditIntegrity.
type VerifyResult struct {
	Valid    int // entries whose HMAC matched
	Tampered int // entries whose HMAC didn't match
	Malformed int // lines that wouldn't parse as JSON or were missing fields
}

// VerifyAuditIntegrity walks logPath line-by-line, recomputes the HMAC of
// each entry, and reports the counts. Tampered or malformed entries do NOT
// abort the walk — the goal is to surface every bad line so an analyst can
// investigate.
//
// Returns an error only for I/O failures (key file missing, log file
// unreadable). Tampered lines are reported via VerifyResult, not error.
func VerifyAuditIntegrity(logPath, keyPath string) (VerifyResult, error) {
	var res VerifyResult

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return res, fmt.Errorf("reading audit key %s: %w", keyPath, err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		return res, fmt.Errorf("opening audit log %s: %w", logPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Audit lines can hold long parameter strings — bump scanner buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(line, &e); err != nil {
			res.Malformed++
			continue
		}
		stored := e.HMAC
		recomputed, err := signEntry(e, key)
		if err != nil {
			res.Malformed++
			continue
		}
		if hmac.Equal([]byte(stored), []byte(recomputed)) {
			res.Valid++
		} else {
			res.Tampered++
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return res, fmt.Errorf("scanning audit log: %w", err)
	}
	return res, nil
}
