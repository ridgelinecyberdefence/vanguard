// Package remote orchestrates DFIR operations against remote endpoints.
//
// It composes:
//   - the protocol-agnostic clients in internal/network (SSH/WinRM/PSExec),
//   - the same command catalogs and detection patterns used by local triage
//     and threat hunting,
//   - per-case target persistence (config/targets.yaml),
//   - an in-memory credential cache.
//
// Credentials are NEVER persisted to disk; targets.yaml only stores hostname,
// IP, OS, protocol, port, username, auth method, and (for key auth) the key
// path on the analyst host.
package remote

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ridgelinecyberdefence/vanguard/internal/network"
)

// hostnameRe matches valid hostname / FQDN strings: alphanumerics, dots,
// hyphens, underscores. Compiled once.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9\.\-_]+$`)

// usernameRe matches valid usernames including Windows DOMAIN\user and
// user@DOMAIN forms. Allows letters, digits, dot, hyphen, underscore,
// backslash, and @.
var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9\.\-_\\@]+$`)

// Status represents the last-known reachability of a target.
type Status string

const (
	StatusUntested Status = "untested"
	StatusOnline   Status = "online"
	StatusOffline  Status = "offline"
	StatusError    Status = "error"
)

// RemoteTarget describes a single endpoint VanGuard can operate against.
//
// Passwords are NEVER stored. They live in the in-memory CredentialCache for
// the duration of the session.
type RemoteTarget struct {
	ID          int       `yaml:"id,omitempty"`
	CaseID      string    `yaml:"case_id,omitempty"`
	Hostname    string    `yaml:"hostname"`
	IPAddress   string    `yaml:"ip"`
	OSType      string    `yaml:"os"` // "windows" or "linux"
	Port        int       `yaml:"port"`
	Protocol    string    `yaml:"protocol"`    // "ssh", "winrm", "psexec"
	Username    string    `yaml:"username"`
	AuthMethod  string    `yaml:"auth_method"` // "password" or "key"
	KeyPath     string    `yaml:"key_path,omitempty"`
	Status      Status    `yaml:"status,omitempty"`
	LastContact time.Time `yaml:"last_contact,omitempty"`
	Notes       string    `yaml:"notes,omitempty"`
}

// AsNetworkTarget converts a RemoteTarget into a network.Target ready for a
// Client. password is supplied per-call from the credential cache.
func (t *RemoteTarget) AsNetworkTarget(password string) network.Target {
	return network.Target{
		Hostname:   t.Hostname,
		IPAddress:  t.IPAddress,
		Protocol:   network.Protocol(t.Protocol),
		Port:       t.Port,
		OSType:     t.OSType,
		Username:   t.Username,
		AuthMethod: network.AuthMethod(t.AuthMethod),
		Password:   []byte(password),
		KeyPath:    t.KeyPath,
	}
}

// DisplayName returns "{hostname} ({ip})".
func (t *RemoteTarget) DisplayName() string {
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

// Validate reports any data-quality issues with the target. IP need not be
// set when hostname resolves; we don't perform DNS here, but require at
// least one of {hostname, ip}.
//
// Strict character checks defend the downstream command builders against
// shell-metachar injection: a hostname like "host;rm -rf /" or a username
// like "admin'`id`" gets rejected here, before it can flow into PowerShell
// or sh. The transports also escape values, but rejecting at the boundary
// is the cleaner invariant.
func (t *RemoteTarget) Validate() error {
	if t.Hostname == "" && t.IPAddress == "" {
		return fmt.Errorf("hostname or IP is required")
	}

	if t.Hostname != "" && !hostnameRe.MatchString(t.Hostname) {
		return fmt.Errorf("invalid hostname (alphanumerics, dot, hyphen, underscore only): %s", t.Hostname)
	}
	if t.IPAddress != "" {
		if net.ParseIP(t.IPAddress) == nil {
			return fmt.Errorf("invalid IP address: %s", t.IPAddress)
		}
	}
	switch t.OSType {
	case "windows", "linux":
	default:
		return fmt.Errorf("os must be windows or linux (got %q)", t.OSType)
	}
	switch t.Protocol {
	case "ssh", "winrm", "psexec":
	default:
		return fmt.Errorf("protocol must be ssh, winrm, or psexec (got %q)", t.Protocol)
	}
	if t.Port <= 0 || t.Port > 65535 {
		return fmt.Errorf("port out of range: %d", t.Port)
	}
	if t.Username == "" {
		return fmt.Errorf("username is required")
	}
	if !usernameRe.MatchString(t.Username) {
		return fmt.Errorf("invalid username (allowed: letters, digits, .-_\\@): %s", t.Username)
	}
	switch t.AuthMethod {
	case "password", "key":
	default:
		return fmt.Errorf("auth_method must be password or key (got %q)", t.AuthMethod)
	}
	if t.AuthMethod == "key" {
		if t.KeyPath == "" {
			return fmt.Errorf("key auth selected but key_path is empty")
		}
		// Verify the key actually exists — a missing key path means every
		// remote operation will fail later with a less useful error.
		if _, err := os.Stat(t.KeyPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("SSH key not found: %s", t.KeyPath)
			}
			return fmt.Errorf("stat SSH key %s: %w", t.KeyPath, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// Store manages target persistence in config/targets.yaml plus an in-memory
// list for fast lookup. Concurrent-safe.
type Store struct {
	path    string
	mu      sync.RWMutex
	targets []*RemoteTarget
}

// targetsFile is the on-disk YAML schema.
type targetsFile struct {
	Targets []*RemoteTarget `yaml:"targets"`
}

// NewStore loads (or creates) a target store rooted at configPath
// (typically <vanguard root>/config/targets.yaml).
func NewStore(configPath string) (*Store, error) {
	s := &Store{path: configPath}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load reads config/targets.yaml. A missing file is not an error — it just
// yields an empty target list.
//
// Targets that fail validation (bad hostname chars, port out of range,
// missing key file, etc.) are SKIPPED with a warning to stderr rather than
// aborting the whole load. A single typo'd entry shouldn't lock the
// operator out of all their other targets, but we surface every failure so
// it can be fixed.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.targets = nil
			return nil
		}
		return fmt.Errorf("reading %s: %w", s.path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var f targetsFile
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("parsing %s: %w", s.path, err)
	}
	kept := make([]*RemoteTarget, 0, len(f.Targets))
	for _, t := range f.Targets {
		if t.Status == "" {
			t.Status = StatusUntested
		}
		if err := t.Validate(); err != nil {
			fmt.Fprintf(os.Stderr,
				"warning: skipping invalid target %q in %s: %v\n",
				t.DisplayName(), s.path, err)
			continue
		}
		kept = append(kept, t)
	}
	s.targets = kept
	return nil
}

// Save writes the current target set back to config/targets.yaml.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

// saveLocked writes the current state assuming the caller already holds the lock.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := yaml.Marshal(targetsFile{Targets: s.targets})
	if err != nil {
		return fmt.Errorf("marshalling targets: %w", err)
	}
	return os.WriteFile(s.path, data, 0o644)
}

// All returns all targets (defensive copy).
func (s *Store) All() []*RemoteTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RemoteTarget, len(s.targets))
	copy(out, s.targets)
	return out
}

// ForCase returns targets associated with caseID, plus any with empty CaseID
// (which are global and visible to all cases).
func (s *Store) ForCase(caseID string) []*RemoteTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*RemoteTarget
	for _, t := range s.targets {
		if t.CaseID == "" || t.CaseID == caseID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Hostname) < strings.ToLower(out[j].Hostname)
	})
	return out
}

// Get returns the target with the given ID, or nil.
func (s *Store) Get(id int) *RemoteTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.targets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// Add appends a new target, assigning the next available ID. Returns the
// stored pointer.
func (s *Store) Add(t *RemoteTarget) (*RemoteTarget, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	maxID := 0
	for _, existing := range s.targets {
		if existing.ID > maxID {
			maxID = existing.ID
		}
	}
	t.ID = maxID + 1
	if t.Status == "" {
		t.Status = StatusUntested
	}
	s.targets = append(s.targets, t)
	if err := s.saveLocked(); err != nil {
		// Roll back the in-memory add to keep state consistent.
		s.targets = s.targets[:len(s.targets)-1]
		return nil, err
	}
	return t, nil
}

// Update replaces the target with id with the supplied data (preserving id).
func (s *Store) Update(id int, replacement *RemoteTarget) error {
	if err := replacement.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, existing := range s.targets {
		if existing.ID != id {
			continue
		}
		replacement.ID = id
		s.targets[i] = replacement
		return s.saveLocked()
	}
	return fmt.Errorf("target id %d not found", id)
}

// Remove deletes the target with id.
func (s *Store) Remove(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, existing := range s.targets {
		if existing.ID != id {
			continue
		}
		s.targets = append(s.targets[:i], s.targets[i+1:]...)
		return s.saveLocked()
	}
	return fmt.Errorf("target id %d not found", id)
}

// SetStatus updates the live status + LastContact of a target.
func (s *Store) SetStatus(id int, status Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.targets {
		if t.ID == id {
			t.Status = status
			t.LastContact = time.Now()
			return s.saveLocked()
		}
	}
	return fmt.Errorf("target id %d not found", id)
}
