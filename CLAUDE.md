# VanGuard DFIR Toolkit

## Project Overview

Cross-platform (Windows/Linux) enterprise DFIR toolkit for connected, isolated, and air-gapped environments. Go core with bubbletea TUI, PowerShell/Bash modules, Python3 analysis engine. Velociraptor is the primary IR capability. Open-sourced under RidgeLine Cyber.

## Language Stack

- Core Launcher: Go (bubbletea TUI, single binary)
- Windows Modules: PowerShell 5.1+
- Linux Modules: Bash + Python3
- Analysis Engine: Python3 (Volatility3)

## Repository Structure

    cmd/vanguard/
        main.go                         Entry point, platform detection, privilege check
    internal/
        config/
            config.go                   YAML config loading, validation, defaults
        logging/
            logger.go                   Structured file+stderr logger with rotation
        tui/
            menu.go                     Bubbletea TUI engine, sidebar+content layout
            styles.go                   Color schemes, lipgloss styles, dark blue theme
        velociraptor/
            manager.go                  Binary download, SHA256 verify, init, server lifecycle
            deploy.go                   Client deployment (WinRM/SSH/PSExec/USB)
            artifacts.go                Artifact collection engine
            usecases.go                 Use case runner
        tools/
            manager.go                  Tool registry, download, verification, status
        case/
            manager.go                  SQLite case management, evidence chain
        modules/
            executor.go                 Module orchestrator, ToolResult struct
        network/
            ssh.go                      SSH client
            winrm.go                    WinRM client
            psexec.go                   PSExec wrapper
        updater/
            updater.go                  Auto-update from GitHub releases + git
        output/
            engine.go                   CSV/HTML/TXT output generation
            templates.go                Jinja2-style HTML report rendering
    modules/
        windows/                        PowerShell IR modules (Verb-Noun.ps1)
        linux/                          Bash IR modules (snake_case.sh)
    config/
        vanguard.yaml                   Master configuration
        targets.yaml                    Remote target definitions
        velociraptor/                   Auto-generated Velociraptor configs
    usecases/                           YAML use case definitions (UC-WIN/LNX/XP-xxx)
    velociraptor/artifacts/             Custom VQL artifacts (VG.Windows.*, VG.Linux.*)
    rules/                              Sigma/YARA/Hayabusa detection rules
    templates/                          HTML report templates (.j2)
    output/                             Runtime: output/{case_id}/{memory,disk,triage,velociraptor,reports}
    logs/                               Runtime logs
    docs/                               Documentation
    tests/                              Test files

## Code Conventions

### Go
- Standard library preferred. Minimal external dependencies.
- internal/ for all private packages. No exported packages outside cmd/.
- All errors wrapped with context: fmt.Errorf("operation: %w", err)
- Structured error handling: ToolResult struct for all external tool calls.
- No global state. Pass config/context explicitly.
- ALL exec.Command calls must run in tea.Cmd goroutines — never block the TUI.
- View() must be a pure render function — no I/O, no filesystem access, no computation.
- Use strings.Builder for string assembly in View().

### PowerShell
- Verb-Noun function naming (Invoke-MemoryCapture, Export-Results).
- [CmdletBinding()] on all functions.
- Error handling via try/catch with structured output objects.

### Bash
- snake_case function and file naming.
- set -euo pipefail in all scripts.
- Structured logging to stderr, data to stdout.

### Python
- Type hints on all functions.
- Dataclasses for structured data.
- pathlib.Path for all file paths.

### General
- All paths relative to VanGuard root. Never hardcode absolute paths.
- All tools/data must reside within VanGuard directory structure.
- Output always to output/{case_id}/ subdirectories.
- Brand name: RidgeLine Cyber (not RidgeLine).

## Key Dependencies
- github.com/charmbracelet/bubbletea — TUI framework
- github.com/charmbracelet/lipgloss — TUI styling
- github.com/charmbracelet/bubbles — TUI components (textinput, table, spinner)
- gopkg.in/yaml.v3 — YAML config
- github.com/mattn/go-sqlite3 — SQLite case DB (CGO required, build with CGO_ENABLED=1)
- golang.org/x/crypto/ssh — SSH remote ops
- github.com/masterzen/winrm — WinRM remote ops

## Build Commands

    # Windows (PowerShell) — CGO required for SQLite
    $env:CGO_ENABLED=1; go build -o vanguard.exe ./cmd/vanguard/

    # Linux
    CGO_ENABLED=1 go build -o vanguard ./cmd/vanguard/

    # Windows release build with version info (PowerShell)
    $version = "1.0.0"
    $date = Get-Date -Format "yyyy-MM-dd"
    $commit = git rev-parse --short HEAD
    $env:CGO_ENABLED=1
    go build -ldflags "-X main.version=$version -X main.buildDate=$date -X main.commit=$commit" -o vanguard.exe ./cmd/vanguard/

    # Linux release build with version info (bash)
    VERSION=1.0.0
    DATE=$(date -u +%Y-%m-%d)
    COMMIT=$(git rev-parse --short HEAD)
    CGO_ENABLED=1 go build -ldflags "-X main.version=$VERSION -X main.buildDate=$DATE -X main.commit=$COMMIT" -o vanguard ./cmd/vanguard/

The version, buildDate, and commit values surface in the header bar, status bar,
About help page, and HTML report headers. CI builds inject the same flags
automatically (see `.github/workflows/`).

## Design Principles
1. Air-gapped first — design for offline, add online as enhancement.
2. Self-contained — every dependency bundled, works from USB.
3. Cross-platform parity — Windows and Linux equivalents where applicable.
4. Velociraptor is the PRIMARY capability.
5. Use cases drive value — 28 pre-built IR workflows.
6. Professional output — HTML reports with sorting, filtering, MITRE ATT&CK mapping.

## TUI Design
- Sidebar + content pane layout (inspired by Cyber Triage)
- Dark blue professional theme matching RidgeLine Cyber website
- Header bar with branding, status bar with platform/host/elevation/case/version
- Breadcrumb navigation in content pane
- All operations run async via tea.Cmd — TUI never blocks
- Platform-aware menus (Windows/Linux show different options)

## Tool Registry (internal/tools/manager.go)
Categories: collection, analysis, detection, rules
Auto-downloadable from GitHub: Velociraptor, Hayabusa, Chainsaw, Loki, WinPmem, AVML
Manual install required: KAPE, EZ Tools, DumpIt, Volatility3, LiME, dc3dd, plaso, chkrootkit, rkhunter

## Completed Implementation

### Phase 1 — Foundation (COMPLETE)
- Go project scaffold with full directory structure
- YAML config loader with defaults and validation (internal/config/config.go)
- Structured logger with file+stderr output and 10MB rotation (internal/logging/logger.go)
- SQLite case manager with 5 tables: cases, targets, evidence, findings, timeline_events (internal/case/manager.go)
- Bubbletea TUI with sidebar+content pane layout (internal/tui/menu.go, styles.go)
- Dark blue professional theme matching RidgeLine Cyber website
- Platform detection and privilege check at startup
- Hostname and investigator display in UI
- Status bar with platform, host, elevation, case, version

### Phase 2 — Core Operations (COMPLETE)
- Tool registry with 15+ tools across collection/analysis/detection/rules categories (internal/tools/manager.go)
- GitHub releases API integration for automated tool downloads
- Archive extraction (ZIP, tar.gz) with flexible binary name matching
- Tool status display grouped by category with install state
- Download required/all tools with progress display
- Check for updates against GitHub releases

### Configuration [8] (COMPLETE)
- Create New Case with interactive form (name, classification, description)
- List Cases with scrollable table
- Select Active Case
- Close Active Case with confirmation
- Tool Status display grouped by category
- Download Required Tools from GitHub
- Download All Available Tools
- Check for Updates
- Edit Analyst Name (persisted to vanguard.yaml)
- Edit Organization Name (persisted to vanguard.yaml)

### Velociraptor Operations [1] (COMPLETE)
- Server initialization (config generation, cert generation, admin user creation)
- Start/stop server as background process with health check
- Server status display
- Open Web UI in browser (with SSH remote session detection)
- Generate client package with platform selection and repack
- Deploy agent via WinRM/SSH/PSExec with credential prompts
- Manual deployment instructions
- Create offline collector with profile selection (full/quick/memory+triage/custom)
- Import offline collection
- Prerequisite checks (binary present, active case, elevation)

### Quick Triage [4] (COMPLETE)
- Windows full triage: system info, processes, network, event logs, persistence, user activity, browser artifacts, installed software
- Linux full triage: system info, processes, network, logs, persistence, user activity, SUID/SGID, temp files
- Individual collection options (process snapshot, event logs only, persistence only, etc.)
- Custom collection with selectable steps
- Real-time progress display with elapsed time
- Collection summary generation
- Evidence registration in case database
- All commands run async via tea.Cmd goroutines

### Threat Hunting [3] (COMPLETE)
- Hayabusa scans: full, critical/high only, lateral movement focus, persistence focus, timeline generation
- Chainsaw: hunt mode, Sigma scan mode
- Loki: full IOC scan
- YARA scanning: custom rules, all bundled rules
- Windows live hunting: suspicious processes, network anomalies, scheduled task audit, autorun audit, service anomaly detection, DLL hijack check, named pipe enumeration
- Linux live hunting: suspicious processes, network anomalies, cron audit, systemd audit, SUID/SGID audit, open port audit, kernel module audit, user login anomalies, hidden files, immutable files
- Scan target selection (live system, collected artifacts, custom path)
- Tool availability checks before operations
- Anomaly detection with pattern matching for LOLBins, C2 indicators, mining pools, reverse shells
- Findings registered in case database with severity

## Security Audit (2026-05-03)

Static analysis audit covering 10 categories, 80 individual checks. Results: 49 PASS / 23 FAIL / 8 N/I. All 26 actionable findings have been fixed. Clean build verified after every fix batch.

### Audit Scope

| Category | Pass | Fail | N/I |
|----------|------|------|-----|
| Credential Handling | 4 | 4 | 2 |
| Command Injection | 3 | 2 | 0 |
| Network Exposure | 5 | 6 | 0 |
| File System Security | 6 | 3 | 0 |
| Evidence Integrity | 8 | 2 | 1 |
| Sensitive Data Leakage | 6 | 0 | 1 |
| Supply Chain & Binary | 4 | 2 | 0 |
| Deployment & OpSec | 5 | 2 | 1 |
| TUI Input Validation | 3 | 0 | 0 |
| Configuration Security | 5 | 2 | 3 |

### Fixes Applied (26 total)

**Critical (3):**
- ZIP-SLIP: Added path separator to `extractTarGzAll` prefix guard (`tools/manager.go:2762`)
- Shell injection: Added single-quote and double-quote to `SanitizeShellArg` metachar list (`security/sanitize.go:31`)
- Chain of custody: Implemented `CustodyEvent` struct + `AppendCustodyEvent` method; `AddEvidence` now auto-records "registered" event; `VerifyEvidenceIntegrity` records "verified" events (`case/manager.go`)

**High (4):**
- Output directory permissions: 106 instances changed from `0o755` to `0o700` across 30 files (disk/, hunting/, memory/, remote/, triage/, output/)
- Velociraptor GUI: Instant GUI mode now generates 16-byte `crypto/rand` password instead of hardcoded `admin/password` (`web/handlers_velo.go`)
- Password memory safety: `Password` fields changed from `string` to `[]byte` in `network/types.go` + `remote/creds.go`; all callers updated; `Close()` on all three network clients now zeroes password bytes
- Config file permissions: `vanguard.yaml` write changed from `0o644` to `0o600` in both `config.go` and `main.go`

**Medium (7):**
- SQLite DB permissions: `os.Chmod(dbPath, 0o600)` after `db.Ping()` (`case/manager.go`)
- Velociraptor `--merge` JSON: Replaced `fmt.Sprintf` with `encoding/json.Marshal` (`velociraptor/manager.go`)
- HTTPS enforcement: `downloadFile` rejects non-`https://` URLs (`tools/manager.go`)
- GitHub domain validation: `validateGitHubDownloadURL` gates downloads to `github.com`, `objects.githubusercontent.com`, `releases.githubusercontent.com` only (`tools/manager.go`)
- WinRM HTTP warning: Log warning when connecting over HTTP (port != 5986) — NTLM relay risk (`network/winrm.go`)
- Bind address validation: `net.ParseIP` check in `Validate()` for `velociraptor.server.bind_address` (`config/config.go`)
- PSExec cleanup wiring: `SkipCleanup` field on Engine, wired from `config.Network.PSExec.Cleanup` (`remote/ops.go`)

**Low (11):**
- SSH key permissions: Rejects keys with group/other read (`0o077` mask) on non-Windows (`network/ssh.go`)
- SSH host key warning: Stderr warning when `InsecureIgnoreHostKey` is used (`network/ssh.go`)
- Remote temp paths randomised: `randomSuffix()` helper; all deployment paths include 4-byte hex suffix (`remote/ops.go`)
- PSEXESVC cleanup: Best-effort `sc delete PSEXESVC` after PSExec operations on Windows targets (`remote/ops.go`)
- Bind address config wiring: `cfg.Velociraptor.Server.BindAddress` now flows into `vrm.State.GUIBindAddress` (`main.go`)
- PSExec credential warning: Stderr warning about password visibility in process list (`network/psexec.go`)
- Configurable log level: `log_level` field in config; `ParseLevel()` at startup (`config.go`, `main.go`)
- SSH passphrase error: Clear error message for passphrase-protected keys instead of opaque parse failure (`network/ssh.go`)
- Default analyst name: Changed from `""` to `"Analyst"` placeholder; startup warning if not customised (`main.go`)
- WinRM TLS documentation: Comment documenting deliberate `insecure=true` for self-signed IR targets (`network/winrm.go`)
- Config template: GitHub PAT field includes security warning comment (`main.go`)

**Informational (confirmed PASS, no change):**
- WinRM error hint: Verified no insecure Basic auth guidance exists in error messages

### Accepted Risks (not fixable in code)

- PSExec `-p PASSWORD` visible in analyst host process list — inherent Sysinternals limitation; WinRM/SSH recommended for sensitive credentials
- Windows file permissions: Go `os.WriteFile` / `os.MkdirAll` modes have no effect on NTFS ACLs; operators must set NTFS permissions at VanGuard root directory level
- USB FAT32/exFAT: No file permissions on portable media; treat USB as untrusted after leaving analyst control
- `InsecureIgnoreHostKey` for SSH: Deliberate for IR flexibility; documented with warning

### Not Yet Implemented (deferred)

- Age encryption for credential vault (`filippo.io/age` or OS keychain)
- SSH passphrase-protected key support (requires TUI password prompt)
- Pinned/bundled SHA256 hashes for tools without upstream `.sha256` sidecar files
- Self-integrity check at startup (binary hash verification)

### Security Design Principles (established by audit)

1. **Credentials never logged** — `sanitizeLogMessage` with 14 regex patterns covers all credential formats
2. **Credentials never in argv** — Velociraptor passwords via stdin; PSExec is the only exception (inherent limitation)
3. **All SQL parameterised** — zero `fmt.Sprintf` SQL construction in the codebase
4. **All archive extraction zip-slip safe** — 7 extraction functions, all guarded with separator-inclusive prefix checks
5. **All TUI inputs validated at commit** — hostname regex, `net.ParseIP`, port range, username regex, OS/protocol/auth enums
6. **Evidence hashed on registration** — dual MD5+SHA256; integrity verification re-hashes and compares
7. **Output reports XSS-safe** — `html/template` (auto-escaping), no `template.HTML()` casts
8. **Downloads HTTPS-only** — scheme enforcement + GitHub domain validation
9. **Output directories owner-only** — `0o700` on all evidence/output paths
10. **Config files owner-only** — `0o600` on `vanguard.yaml`, Velociraptor configs, SQLite DB

### Verification Needed (manual testing)

- [ ] Velociraptor `--password` flag works with the installed Velociraptor build version
- [ ] Remote memory capture cleanup deletes randomised-suffix temp files on target

## Remaining Implementation

### Phase 3 — Memory Forensics [5]
- Memory capture (DumpIt, WinPmem, AVML, LiME, Velociraptor agent, remote capture)
- Volatility3 integration (auto-profile, process/network/malware/registry/timeline analysis)
- Symbol management
- YARA scan on memory dumps

### Disk Artifact Collection [2]
- KAPE collection with target/module selection
- EZ Tools parsing pipeline
- UAC collection for Linux
- Manual artifact copy

### Remote Operations [6]
- SSH/WinRM/PSExec remote collection
- Remote triage
- Remote Velociraptor deployment
- Multi-target operations

### Analysis & Reporting [7]
- EZ Tools parsing (MFTECmd, EvtxECmd, PECmd, RECmd, etc.)
- Volatility3 analysis interface
- Chainsaw/Hayabusa analysis views
- HTML report generation with Jinja2 templates
- CSV/timeline export
- MITRE ATT&CK mapping

### Use Cases [C]
- 28 YAML use case definitions
- Use case runner with phased execution
- Parameter substitution
- Template-based reporting

### Update [U]
- Rule updates (Sigma, YARA, Hayabusa rules)
- Binary updates from GitHub
- Offline update bundle generation

### Help [H]
- In-app documentation
- Quick start guide
- Keyboard shortcuts reference

### Polish
- Cross-platform testing
- Error handling hardening
- GitHub Actions CI/CD (build.yml, release.yml)
- README.md, CONTRIBUTING.md, CHANGELOG.md
- Air-gapped deployment packaging
- Version stamping via ldflags
