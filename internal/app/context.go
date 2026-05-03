// Package app holds shared application-level state used across the TUI and
// web frontends. Both frontends are thin views over this Context — every
// long-running manager (case DB, tool registry, Velociraptor lifecycle,
// remote ops) lives here so swapping UIs doesn't require re-initialising
// anything.
package app

import (
	"github.com/ridgelinecyberdefence/vanguard/internal/audit"
	casemanager "github.com/ridgelinecyberdefence/vanguard/internal/case"
	"github.com/ridgelinecyberdefence/vanguard/internal/config"
	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/remote"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
	"github.com/ridgelinecyberdefence/vanguard/internal/velociraptor"
)

// Context carries shared application state for whichever frontend is active.
type Context struct {
	Version    string
	BuildDate  string // set via ldflags by main; "unknown" by default
	Commit     string // set via ldflags by main; "unknown" by default
	Platform   string
	Hostname   string
	Elevated   bool
	RootDir    string
	ConfigPath string

	Config      *config.Config
	CaseManager *casemanager.CaseManager
	Logger      *logging.Logger
	Audit       *audit.Logger
	ToolManager *tools.ToolManager
	VRManager   *velociraptor.Manager

	// ActiveCase is mutated as the operator selects/creates/closes cases.
	// Frontends read this on every render; writes happen on the same
	// goroutine that processes user input, so we don't synchronize here.
	ActiveCase *casemanager.Case

	// Remote operations state (populated lazily on first use).
	RemoteStore *remote.Store
	RemoteCreds *remote.CredentialCache
}
