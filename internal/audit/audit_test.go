package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestLogAndVerify confirms that an entry written by Log produces a record
// VerifyAuditIntegrity validates as good. The HMAC ties the line to the key.
func TestLogAndVerify(t *testing.T) {
	dir := t.TempDir()
	al, err := NewLogger(dir, "alice")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}

	if err := al.Log("create_case", "", "Acme breach", "VG-TEST-001", "VG-TEST-001"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := al.Log("add_evidence", "/tmp/dump.raw", "memory_dump", "deadbeef", "VG-TEST-001"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if err := al.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	res, err := VerifyAuditIntegrity(
		filepath.Join(dir, "audit.jsonl"),
		filepath.Join(dir, ".audit_key"),
	)
	if err != nil {
		t.Fatalf("VerifyAuditIntegrity: %v", err)
	}
	if res.Valid != 2 || res.Tampered != 0 || res.Malformed != 0 {
		t.Errorf("expected 2 valid / 0 tampered / 0 malformed, got %+v", res)
	}
}

// TestVerifyDetectsTampering modifies a single field in a written entry and
// confirms the verifier flags it. This is the chain-of-custody guarantee:
// even one altered byte is caught.
func TestVerifyDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	al, err := NewLogger(dir, "bob")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := al.Log("finding", "Suspicious process", "high", "T1059.001", "VG-TAMPER-001"); err != nil {
		t.Fatalf("Log: %v", err)
	}
	al.Close()

	logPath := filepath.Join(dir, "audit.jsonl")
	keyPath := filepath.Join(dir, ".audit_key")

	// Tamper: change "high" to "low" while leaving HMAC unchanged.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	entry.Parameters = "low" // tamper
	tampered, _ := json.Marshal(entry)
	if err := os.WriteFile(logPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := VerifyAuditIntegrity(logPath, keyPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Tampered != 1 {
		t.Errorf("expected tampered=1, got %+v", res)
	}
}

// TestKeyReuse confirms that closing + reopening reads the existing key
// rather than generating a new one — otherwise every restart would
// invalidate prior entries.
func TestKeyReuse(t *testing.T) {
	dir := t.TempDir()
	first, err := NewLogger(dir, "carol")
	if err != nil {
		t.Fatalf("NewLogger first: %v", err)
	}
	keyPath := filepath.Join(dir, ".audit_key")
	key1, _ := os.ReadFile(keyPath)
	first.Close()

	second, err := NewLogger(dir, "carol")
	if err != nil {
		t.Fatalf("NewLogger second: %v", err)
	}
	key2, _ := os.ReadFile(keyPath)
	second.Close()

	if string(key1) != string(key2) {
		t.Errorf("key changed across restart: %x != %x", key1, key2)
	}
}
