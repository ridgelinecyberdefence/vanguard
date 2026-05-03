// Package casemanager persists case state, evidence chain-of-custody, and
// findings to a local SQLite database.
//
// SECURITY NOTE: The on-disk database (output/vanguard.db) is unencrypted.
// Operators handling sensitive investigations should rely on full-disk
// encryption (BitLocker on Windows, LUKS on Linux) for the VanGuard drive
// itself — see SecurityWarning() for the user-facing message rendered the
// first time a case is created.
//
// TODO: Replace github.com/mattn/go-sqlite3 with
// github.com/mutecomm/go-sqlcipher/v4 to encrypt the database at rest. That
// would require a database password prompt at startup and a key-derivation
// routine; the current go-sqlite3 driver was chosen to keep VanGuard
// self-contained without prompting for a key on every launch.
package casemanager

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// FirstRunWarningPath is the marker file VanGuard touches the first time a
// case is created on this drive. While absent, callers should display the
// SecurityWarning copy as a one-time notice.
func FirstRunWarningPath(rootDir string) string {
	return filepath.Join(rootDir, "output", ".vanguard_db_warning_shown")
}

// FirstRunWarningSeen reports whether the marker file exists.
func FirstRunWarningSeen(rootDir string) bool {
	_, err := os.Stat(FirstRunWarningPath(rootDir))
	return err == nil
}

// MarkFirstRunWarningSeen creates the marker file so the warning isn't
// repeated on subsequent case creations.
func MarkFirstRunWarningSeen(rootDir string) error {
	p := FirstRunWarningPath(rootDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// SecurityWarning returns the canonical one-time warning text shown after the
// first case is created on a fresh drive. Kept as a function so the TUI and
// the help system render an identical message.
func SecurityWarning() []string {
	return []string{
		"SECURITY NOTE: Case data is stored in an unencrypted SQLite database.",
		"For sensitive investigations, ensure the VanGuard drive is encrypted:",
		"  • Windows: Enable BitLocker on the USB drive",
		"  • Linux:   Use LUKS encryption",
		"Case database location: output/vanguard.db",
	}
}

type Case struct {
	ID             string
	Name           string
	Description    string
	Status         string
	Analyst        string
	Organization   string
	Classification string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ClosedAt       *time.Time
}

type Target struct {
	ID               int
	CaseID           string
	Hostname         string
	IPAddress        string
	OSType           string
	OSVersion        string
	CollectionStatus string
	LastContact      *time.Time
}

type Evidence struct {
	ID             int
	CaseID         string
	TargetID       int
	EvidenceType   string
	FilePath       string
	FileHashMD5    string
	FileHashSHA256 string
	CollectedAt    time.Time
	CollectedBy    string
	ChainOfCustody string
}

type Finding struct {
	ID              int
	CaseID          string
	EvidenceID      int
	Severity        string
	Title           string
	Description     string
	MITRETechnique  string
	IOCType         string
	IOCValue        string
	DiscoveredAt    time.Time
}

type TimelineEvent struct {
	ID          int
	CaseID      string
	TargetID    int
	Timestamp   time.Time
	Source      string
	EventType   string
	Description string
	RawData     string
}

type CaseManager struct {
	db    *sql.DB
	audit auditHook // optional — set via SetAuditHook
}

// auditHook is the minimal interface CaseManager needs from the audit logger.
// Defined here so internal/case doesn't depend on internal/audit (avoids
// circular import surface and keeps the case manager testable in isolation).
type auditHook interface {
	Log(action, target, parameters, result, caseID string) error
}

// SetAuditHook registers an audit logger that will be called for evidence
// and finding registration. nil hook disables audit (no-op). Idempotent.
func (cm *CaseManager) SetAuditHook(h auditHook) {
	cm.audit = h
}

const schema = `
CREATE TABLE IF NOT EXISTS cases (
	id              TEXT PRIMARY KEY,
	name            TEXT NOT NULL,
	description     TEXT,
	status          TEXT NOT NULL DEFAULT 'active',
	analyst         TEXT,
	organization    TEXT,
	classification  TEXT,
	created_at      DATETIME NOT NULL,
	updated_at      DATETIME NOT NULL,
	closed_at       DATETIME
);

CREATE TABLE IF NOT EXISTS targets (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id           TEXT NOT NULL,
	hostname          TEXT NOT NULL,
	ip_address        TEXT,
	os_type           TEXT,
	os_version        TEXT,
	collection_status TEXT DEFAULT 'pending',
	last_contact      DATETIME,
	FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE TABLE IF NOT EXISTS evidence (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id          TEXT NOT NULL,
	target_id        INTEGER,
	evidence_type    TEXT NOT NULL,
	file_path        TEXT NOT NULL,
	file_hash_md5    TEXT,
	file_hash_sha256 TEXT,
	collected_at     DATETIME NOT NULL,
	collected_by     TEXT,
	chain_of_custody TEXT DEFAULT '[]',
	FOREIGN KEY (case_id) REFERENCES cases(id),
	FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS findings (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id          TEXT NOT NULL,
	evidence_id      INTEGER,
	severity         TEXT NOT NULL,
	title            TEXT NOT NULL,
	description      TEXT,
	mitre_technique  TEXT,
	ioc_type         TEXT,
	ioc_value        TEXT,
	discovered_at    DATETIME NOT NULL,
	FOREIGN KEY (case_id) REFERENCES cases(id),
	FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS timeline_events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id     TEXT NOT NULL,
	target_id   INTEGER,
	timestamp   DATETIME NOT NULL,
	source      TEXT,
	event_type  TEXT,
	description TEXT,
	raw_data    TEXT,
	FOREIGN KEY (case_id) REFERENCES cases(id),
	FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE INDEX IF NOT EXISTS idx_targets_case_id ON targets(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_case_id ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);
`

// NewCaseManager opens (or creates) the SQLite database and ensures all tables exist.
func NewCaseManager(dbPath string) (*CaseManager, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", dbPath, err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	// Best-effort: tighten permissions so other users on the same workstation
	// can't read case data. Silently ignored on Windows (NTFS controls access
	// there; mode bits are advisory only).
	_ = os.Chmod(dbPath, 0o600)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialising schema: %w", err)
	}

	return &CaseManager{db: db}, nil
}

// Close closes the underlying database connection.
func (cm *CaseManager) Close() error {
	return cm.db.Close()
}

// generateCaseID produces an ID in the format VG-YYYYMMDD-XXXX where XXXX is random hex.
func generateCaseID() (string, error) {
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	date := time.Now().Format("20060102")
	return fmt.Sprintf("VG-%s-%s", date, hex.EncodeToString(b)), nil
}

// CreateCase generates a new case ID and inserts a case record.
func (cm *CaseManager) CreateCase(name, analyst, org string) (*Case, error) {
	return cm.CreateCaseFull(name, analyst, org, "", "")
}

// CreateCaseFull generates a new case with classification and description.
func (cm *CaseManager) CreateCaseFull(name, analyst, org, classification, description string) (*Case, error) {
	id, err := generateCaseID()
	if err != nil {
		return nil, fmt.Errorf("generating case ID: %w", err)
	}

	now := time.Now().UTC()
	c := &Case{
		ID:             id,
		Name:           name,
		Description:    description,
		Status:         "active",
		Analyst:        analyst,
		Organization:   org,
		Classification: classification,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	_, err = cm.db.Exec(
		`INSERT INTO cases (id, name, description, status, analyst, organization, classification, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, c.Status, c.Analyst, c.Organization, c.Classification, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting case: %w", err)
	}

	return c, nil
}

// GetCase retrieves a single case by ID.
func (cm *CaseManager) GetCase(id string) (*Case, error) {
	row := cm.db.QueryRow(
		`SELECT id, name, description, status, analyst, organization, classification,
		        created_at, updated_at, closed_at
		 FROM cases WHERE id = ?`, id,
	)

	c := &Case{}
	var closedAt sql.NullTime
	err := row.Scan(
		&c.ID, &c.Name, &c.Description, &c.Status, &c.Analyst,
		&c.Organization, &c.Classification, &c.CreatedAt, &c.UpdatedAt, &closedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying case %s: %w", id, err)
	}
	if closedAt.Valid {
		c.ClosedAt = &closedAt.Time
	}

	return c, nil
}

// ListCases returns all cases, optionally filtered by status. Pass "" for all cases.
func (cm *CaseManager) ListCases(status string) ([]Case, error) {
	var rows *sql.Rows
	var err error

	if status == "" {
		rows, err = cm.db.Query(
			`SELECT id, name, description, status, analyst, organization, classification,
			        created_at, updated_at, closed_at
			 FROM cases ORDER BY created_at DESC`,
		)
	} else {
		rows, err = cm.db.Query(
			`SELECT id, name, description, status, analyst, organization, classification,
			        created_at, updated_at, closed_at
			 FROM cases WHERE status = ? ORDER BY created_at DESC`, status,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("listing cases: %w", err)
	}
	defer rows.Close()

	var cases []Case
	for rows.Next() {
		var c Case
		var closedAt sql.NullTime
		if err := rows.Scan(
			&c.ID, &c.Name, &c.Description, &c.Status, &c.Analyst,
			&c.Organization, &c.Classification, &c.CreatedAt, &c.UpdatedAt, &closedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning case row: %w", err)
		}
		if closedAt.Valid {
			c.ClosedAt = &closedAt.Time
		}
		cases = append(cases, c)
	}

	return cases, rows.Err()
}

// UpdateCase rewrites the editable metadata fields on a case row. Status,
// timestamps, and case_id are not touched here — UpdateCaseStatus owns those.
func (cm *CaseManager) UpdateCase(id, name, classification, description, analyst, organization string) error {
	now := time.Now().UTC()
	_, err := cm.db.Exec(
		`UPDATE cases
		    SET name = ?, classification = ?, description = ?,
		        analyst = ?, organization = ?, updated_at = ?
		  WHERE id = ?`,
		name, classification, description, analyst, organization, now, id,
	)
	if err != nil {
		return fmt.Errorf("updating case %s: %w", id, err)
	}
	return nil
}

// UpdateCaseStatus sets the status of a case. If the new status is "closed", closed_at is set.
func (cm *CaseManager) UpdateCaseStatus(id, status string) error {
	now := time.Now().UTC()

	var err error
	if status == "closed" {
		_, err = cm.db.Exec(
			`UPDATE cases SET status = ?, updated_at = ?, closed_at = ? WHERE id = ?`,
			status, now, now, id,
		)
	} else {
		_, err = cm.db.Exec(
			`UPDATE cases SET status = ?, updated_at = ? WHERE id = ?`,
			status, now, id,
		)
	}
	if err != nil {
		return fmt.Errorf("updating case %s status: %w", id, err)
	}

	return nil
}

// AddTarget registers a new target host within a case.
func (cm *CaseManager) AddTarget(caseID, hostname, ip, osType string) (*Target, error) {
	result, err := cm.db.Exec(
		`INSERT INTO targets (case_id, hostname, ip_address, os_type, collection_status)
		 VALUES (?, ?, ?, ?, 'pending')`,
		caseID, hostname, ip, osType,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting target: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("getting target ID: %w", err)
	}

	return &Target{
		ID:               int(id),
		CaseID:           caseID,
		Hostname:         hostname,
		IPAddress:        ip,
		OSType:           osType,
		CollectionStatus: "pending",
	}, nil
}

// AddEvidence records a piece of evidence, automatically computing MD5 and SHA256 hashes
// of the file at filePath.
func (cm *CaseManager) AddEvidence(caseID string, targetID int, evidenceType, filePath string) (*Evidence, error) {
	md5Hash, sha256Hash, err := hashFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("hashing evidence file %s: %w", filePath, err)
	}

	now := time.Now().UTC()
	result, err := cm.db.Exec(
		`INSERT INTO evidence (case_id, target_id, evidence_type, file_path,
		                       file_hash_md5, file_hash_sha256, collected_at, chain_of_custody)
		 VALUES (?, ?, ?, ?, ?, ?, ?, '[]')`,
		caseID, targetID, evidenceType, filePath, md5Hash, sha256Hash, now,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting evidence: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("getting evidence ID: %w", err)
	}

	// Seed the chain of custody with a "registered" event. Errors here are
	// non-fatal — the evidence record itself was written successfully.
	_ = cm.AppendCustodyEvent(id, CustodyEvent{
		Analyst: "system",
		Action:  "registered",
		Note:    fmt.Sprintf("Evidence collected: %s", evidenceType),
	})

	if cm.audit != nil {
		_ = cm.audit.Log("add_evidence", filePath, evidenceType, sha256Hash, caseID)
	}

	return &Evidence{
		ID:             int(id),
		CaseID:         caseID,
		TargetID:       targetID,
		EvidenceType:   evidenceType,
		FilePath:       filePath,
		FileHashMD5:    md5Hash,
		FileHashSHA256: sha256Hash,
		CollectedAt:    now,
		ChainOfCustody: "[]",
	}, nil
}

// CustodyEvent records a single chain-of-custody action on an evidence item.
type CustodyEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Analyst   string    `json:"analyst"`
	Action    string    `json:"action"` // registered, transferred, exported, verified
	Note      string    `json:"note,omitempty"`
}

// AppendCustodyEvent adds a custody event to the evidence record's chain.
// The chain is append-only — existing events are never modified or removed.
func (cm *CaseManager) AppendCustodyEvent(evidenceID int64, event CustodyEvent) error {
	var raw string
	err := cm.db.QueryRow(
		`SELECT chain_of_custody FROM evidence WHERE id = ?`, evidenceID,
	).Scan(&raw)
	if err != nil {
		return fmt.Errorf("read custody chain for evidence %d: %w", evidenceID, err)
	}

	var chain []CustodyEvent
	if raw != "" && raw != "[]" {
		if err := json.Unmarshal([]byte(raw), &chain); err != nil {
			return fmt.Errorf("parse existing custody chain: %w", err)
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	chain = append(chain, event)

	data, err := json.Marshal(chain)
	if err != nil {
		return fmt.Errorf("marshal custody chain: %w", err)
	}

	_, err = cm.db.Exec(
		`UPDATE evidence SET chain_of_custody = ? WHERE id = ?`,
		string(data), evidenceID,
	)
	if err != nil {
		return fmt.Errorf("update custody chain for evidence %d: %w", evidenceID, err)
	}
	return nil
}

// AddFinding records an investigative finding linked to a case and evidence item.
//
// evidenceID == 0 is treated as "no linked evidence" and stored as NULL so the
// foreign-key constraint is satisfied. Many detection paths (live hunting,
// log analysis) emit findings before any concrete evidence record exists.
func (cm *CaseManager) AddFinding(caseID string, evidenceID int, severity, title, description, mitreTechnique string) error {
	now := time.Now().UTC()
	var evID interface{}
	if evidenceID > 0 {
		evID = evidenceID
	}
	_, err := cm.db.Exec(
		`INSERT INTO findings (case_id, evidence_id, severity, title, description, mitre_technique, discovered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		caseID, evID, severity, title, description, mitreTechnique, now,
	)
	if err != nil {
		return fmt.Errorf("inserting finding: %w", err)
	}
	if cm.audit != nil {
		_ = cm.audit.Log("finding", title, severity, mitreTechnique, caseID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Read-side queries — used by the analysis & reporting pipeline.
// ---------------------------------------------------------------------------

// ListFindings returns every finding recorded for the case, newest-first.
func (cm *CaseManager) ListFindings(caseID string) ([]Finding, error) {
	rows, err := cm.db.Query(
		`SELECT id, case_id, COALESCE(evidence_id, 0), severity, title, description,
		        COALESCE(mitre_technique, ''), COALESCE(ioc_type, ''), COALESCE(ioc_value, ''),
		        discovered_at
		 FROM findings WHERE case_id = ? ORDER BY discovered_at DESC, id DESC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.ID, &f.CaseID, &f.EvidenceID, &f.Severity,
			&f.Title, &f.Description, &f.MITRETechnique, &f.IOCType, &f.IOCValue,
			&f.DiscoveredAt); err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListEvidence returns every evidence record for the case, newest-first.
func (cm *CaseManager) ListEvidence(caseID string) ([]Evidence, error) {
	rows, err := cm.db.Query(
		`SELECT id, case_id, COALESCE(target_id, 0), evidence_type, file_path,
		        COALESCE(file_hash_md5, ''), COALESCE(file_hash_sha256, ''),
		        collected_at, COALESCE(collected_by, ''), COALESCE(chain_of_custody, '[]')
		 FROM evidence WHERE case_id = ? ORDER BY collected_at DESC, id DESC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("listing evidence: %w", err)
	}
	defer rows.Close()

	var out []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.CaseID, &e.TargetID, &e.EvidenceType, &e.FilePath,
			&e.FileHashMD5, &e.FileHashSHA256, &e.CollectedAt, &e.CollectedBy,
			&e.ChainOfCustody); err != nil {
			return nil, fmt.Errorf("scanning evidence: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListTargets returns every target registered for the case.
func (cm *CaseManager) ListTargets(caseID string) ([]Target, error) {
	rows, err := cm.db.Query(
		`SELECT id, case_id, hostname, COALESCE(ip_address, ''), COALESCE(os_type, ''),
		        COALESCE(os_version, ''), collection_status, last_contact
		 FROM targets WHERE case_id = ? ORDER BY hostname`, caseID)
	if err != nil {
		return nil, fmt.Errorf("listing targets: %w", err)
	}
	defer rows.Close()

	var out []Target
	for rows.Next() {
		var t Target
		var lastContact sql.NullTime
		if err := rows.Scan(&t.ID, &t.CaseID, &t.Hostname, &t.IPAddress, &t.OSType,
			&t.OSVersion, &t.CollectionStatus, &lastContact); err != nil {
			return nil, fmt.Errorf("scanning target: %w", err)
		}
		if lastContact.Valid {
			t.LastContact = &lastContact.Time
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddFindingFull records a finding with full IOC fields populated. AddFinding
// remains for callers that don't have IOC data. evidenceID == 0 → NULL.
func (cm *CaseManager) AddFindingFull(caseID string, evidenceID int, severity, title, description, mitre, iocType, iocValue string) error {
	now := time.Now().UTC()
	var evID interface{}
	if evidenceID > 0 {
		evID = evidenceID
	}
	_, err := cm.db.Exec(
		`INSERT INTO findings (case_id, evidence_id, severity, title, description,
		                       mitre_technique, ioc_type, ioc_value, discovered_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		caseID, evID, severity, title, description, mitre, iocType, iocValue, now,
	)
	if err != nil {
		return fmt.Errorf("inserting finding (full): %w", err)
	}
	return nil
}

// ListTimelineEvents returns timeline events for the case in chronological order.
func (cm *CaseManager) ListTimelineEvents(caseID string) ([]TimelineEvent, error) {
	rows, err := cm.db.Query(
		`SELECT id, case_id, COALESCE(target_id, 0), timestamp, source, event_type,
		        description, COALESCE(raw_data, '')
		 FROM timeline_events WHERE case_id = ? ORDER BY timestamp ASC, id ASC`, caseID)
	if err != nil {
		return nil, fmt.Errorf("listing timeline events: %w", err)
	}
	defer rows.Close()
	var out []TimelineEvent
	for rows.Next() {
		var e TimelineEvent
		if err := rows.Scan(&e.ID, &e.CaseID, &e.TargetID, &e.Timestamp,
			&e.Source, &e.EventType, &e.Description, &e.RawData); err != nil {
			return nil, fmt.Errorf("scanning timeline event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddTimelineEvent appends an event to the case timeline.
func (cm *CaseManager) AddTimelineEvent(caseID string, targetID int, timestamp time.Time, source, eventType, description string) error {
	_, err := cm.db.Exec(
		`INSERT INTO timeline_events (case_id, target_id, timestamp, source, event_type, description)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		caseID, targetID, timestamp, source, eventType, description,
	)
	if err != nil {
		return fmt.Errorf("inserting timeline event: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Evidence integrity verification
// ---------------------------------------------------------------------------

// IntegrityStatus is the per-evidence outcome of VerifyEvidenceIntegrity.
type IntegrityStatus string

const (
	IntegrityVerified IntegrityStatus = "verified" // hashes match (or directory present + populated)
	IntegrityModified IntegrityStatus = "modified" // hash changed since collection — CRITICAL
	IntegrityMissing  IntegrityStatus = "missing"  // file/directory no longer present
	IntegrityError    IntegrityStatus = "error"    // could not check (permission denied, hash error)
	IntegrityInfo     IntegrityStatus = "info"     // present but no stored hash to compare (e.g. directory)
)

// IntegrityResult captures the integrity verdict for one evidence record.
type IntegrityResult struct {
	EvidenceID    int
	EvidenceType  string
	FilePath      string
	StoredMD5     string
	StoredSHA256  string
	CurrentMD5    string
	CurrentSHA256 string
	Status        IntegrityStatus
	Details       string

	// Populated for directory-based evidence: how many files we walked,
	// total bytes. Lets the TUI report "23 files / 1.2 GB verified" without
	// re-walking the dir.
	FileCount int
	ByteCount int64
}

// IntegritySummary aggregates IntegrityResult counts for quick TUI display.
type IntegritySummary struct {
	Verified int
	Modified int
	Missing  int
	Errors   int
	Info     int
	Total    int
}

// IsClean reports whether NO modified or missing entries were found —
// safe for "OK to ship a report" gating.
func (s IntegritySummary) IsClean() bool {
	return s.Modified == 0 && s.Missing == 0
}

// VerifyEvidenceIntegrity walks every evidence record for caseID and
// re-verifies that each file is still present and unchanged since collection.
//
// Behaviour per record:
//   - File is regular: re-hash and compare against StoredSHA256 (and StoredMD5
//     when present). Match → "verified", differ → "modified" (CRITICAL),
//     hash error → "error".
//   - Path is a directory: confirm it exists and contains files. We don't have
//     per-tree hashes, so the strongest claim we can make is "still present
//     and populated" — status "verified" with a FileCount, or "missing".
//   - Path doesn't exist: "missing".
//   - Stored SHA256 is empty (collection failed to hash): "info" with a
//     details message so the analyst knows it can't be cryptographically
//     verified, even if the file is on disk.
//
// Results are returned in the same order as ListEvidence (newest-first), with
// a summary the caller can use to decide whether to flag a tampering alert.
func (cm *CaseManager) VerifyEvidenceIntegrity(caseID string) ([]IntegrityResult, IntegritySummary, error) {
	evs, err := cm.ListEvidence(caseID)
	if err != nil {
		return nil, IntegritySummary{}, err
	}

	results := make([]IntegrityResult, 0, len(evs))
	var sum IntegritySummary
	for _, e := range evs {
		r := verifyOne(e)
		results = append(results, r)
		sum.Total++
		switch r.Status {
		case IntegrityVerified:
			sum.Verified++
		case IntegrityModified:
			sum.Modified++
		case IntegrityMissing:
			sum.Missing++
		case IntegrityError:
			sum.Errors++
		case IntegrityInfo:
			sum.Info++
		}
	}
	return results, sum, nil
}

// verifyOne runs the integrity check for a single evidence record.
func verifyOne(e Evidence) IntegrityResult {
	r := IntegrityResult{
		EvidenceID:   e.ID,
		EvidenceType: e.EvidenceType,
		FilePath:     e.FilePath,
		StoredMD5:    e.FileHashMD5,
		StoredSHA256: e.FileHashSHA256,
	}

	info, err := os.Stat(e.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			r.Status = IntegrityMissing
			r.Details = "Path no longer exists at recorded location"
			return r
		}
		r.Status = IntegrityError
		r.Details = "stat failed: " + err.Error()
		return r
	}

	if info.IsDir() {
		count, bytes := walkDir(e.FilePath)
		r.FileCount = count
		r.ByteCount = bytes
		if count == 0 {
			r.Status = IntegrityMissing
			r.Details = "Directory present but empty"
			return r
		}
		r.Status = IntegrityVerified
		r.Details = fmt.Sprintf("%d files present (no per-tree hash to verify)", count)
		return r
	}

	// Regular file path. If we have no stored SHA256, we can confirm presence
	// but not authenticity — surface that explicitly.
	if e.FileHashSHA256 == "" {
		r.Status = IntegrityInfo
		r.Details = "File present but no SHA256 was recorded at collection time"
		return r
	}

	md5Hex, sha256Hex, hashErr := hashFile(e.FilePath)
	if hashErr != nil {
		r.Status = IntegrityError
		r.Details = "rehash failed: " + hashErr.Error()
		return r
	}
	r.CurrentMD5 = md5Hex
	r.CurrentSHA256 = sha256Hex

	if !equalHash(sha256Hex, e.FileHashSHA256) {
		r.Status = IntegrityModified
		r.Details = "SHA256 mismatch — evidence has been altered since collection"
		return r
	}
	if e.FileHashMD5 != "" && !equalHash(md5Hex, e.FileHashMD5) {
		r.Status = IntegrityModified
		r.Details = "MD5 mismatch (SHA256 matches — possible hash collision worth review)"
		return r
	}
	r.Status = IntegrityVerified
	return r
}

// walkDir returns (file count, total bytes) under dir. Errors silently skip —
// integrity walks should never abort a verification run for a single I/O fail.
func walkDir(dir string) (int, int64) {
	count := 0
	var bytes int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		count++
		bytes += info.Size()
		return nil
	})
	return count, bytes
}

// equalHash performs a case-insensitive comparison of two hex digests.
func equalHash(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// hashFile computes the MD5 and SHA256 hex digests of the file at path.
func hashFile(path string) (md5Hex, sha256Hex string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	md5h := md5.New()
	sha256h := sha256.New()
	w := io.MultiWriter(md5h, sha256h)

	if _, err := io.Copy(w, f); err != nil {
		return "", "", fmt.Errorf("reading file: %w", err)
	}

	return hex.EncodeToString(md5h.Sum(nil)), hex.EncodeToString(sha256h.Sum(nil)), nil
}
