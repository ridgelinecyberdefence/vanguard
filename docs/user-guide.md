# VanGuard User Guide

## Overview

VanGuard is an enterprise DFIR (Digital Forensics and Incident Response) toolkit that runs as a single binary on Windows and Linux. It provides a unified interface for Velociraptor-based IR operations, triage collection, threat hunting, memory forensics, disk artifact analysis, and remote operations — all from a self-contained, USB-portable deployment.

VanGuard operates in two interface modes: a keyboard-driven TUI for terminal and SSH sessions, and a web UI accessible via browser.

## Prerequisites

VanGuard requires Administrator (Windows) or root (Linux) privileges for full functionality. Basic operations like process listing and configuration work without elevation, but memory capture, disk collection, Velociraptor server/agent operations, and remote deployment require elevated privileges.

VanGuard detects privilege level at startup and warns if running without elevation.

## First Run

1. Download the binary from [GitHub Releases](https://github.com/ridgelinecyberdefence/vanguard/releases) or build from source
2. Place it in a directory where VanGuard can create its subdirectories (USB drive or local folder)
3. Launch: `vanguard.exe` (Windows) or `sudo ./vanguard` (Linux)
4. On first run, VanGuard creates the directory structure and a default `config/vanguard.yaml`
5. Navigate to **Configuration** to set your analyst name, organisation, and download tools

## Main Menu

The main menu provides access to all VanGuard modules:

| Key | Module | Description |
|-----|--------|-------------|
| 1 | Velociraptor Operations | Server lifecycle, agent deployment, offline collectors |
| 2 | Disk Artifact Collection | KAPE, EZ Tools, UAC, native collection |
| 3 | Threat Hunting & Scanning | Hayabusa, Chainsaw, Loki, YARA, live hunting |
| 4 | Quick Triage | Rapid artifact collection from local or remote systems |
| 5 | Memory Forensics | Capture and analyse memory with Volatility3 |
| 6 | Remote Operations | Multi-target operations via WinRM, SSH, PSExec |
| 7 | Analysis & Reporting | HTML reports, super-timelines, finding correlation |
| 8 | Configuration | Case management, tool downloads, settings |
| U | Update Tools & Rules | Update Sigma, YARA, Hayabusa rules and tool binaries |
| C | Use Cases Library | 28 pre-built IR workflows |
| H | Help & Documentation | In-app reference |
| Q | Quit | Exit VanGuard |

---

## Configuration (Option 8)

### Case Management

Every VanGuard operation stores evidence under a case. Create a case before starting any collection or analysis.

**Create a case:** Navigate to Configuration → Case Management → Create New Case. Provide a case name and optional classification (e.g., ransomware, BEC, insider threat). VanGuard generates a case ID in the format `VG-YYYYMMDD-XXXX` and creates the output directory `output/{case_id}/`.

**Select a case:** If multiple cases exist, select the active case. All subsequent operations write evidence to the active case's output directory.

**Close a case:** Closing a case marks it as complete. Evidence files remain on disk.

### Analyst Settings

Set your analyst name and organisation under Configuration → Settings. These values appear in generated reports and evidence metadata. If left as the default "Analyst", VanGuard displays a warning at startup.

### Tool Management

VanGuard downloads external tools from GitHub releases at runtime. Navigate to Configuration → Tool Management to see the status of each tool and download any that are missing.

Tools managed by VanGuard:

| Tool | Purpose | Platform |
|------|---------|----------|
| Velociraptor | Primary IR platform | Windows, Linux |
| Hayabusa | Windows event log analysis | Windows, Linux |
| Chainsaw | Event log hunting | Windows, Linux |
| Loki | IOC scanner | Windows, Linux |
| DumpIt | Memory capture | Windows |
| WinPMEM | Memory capture | Windows |
| AVML | Memory capture | Linux |
| KAPE | Disk triage collection | Windows |
| EZ Tools | Forensic parsers (MFTECmd, EvtxECmd, etc.) | Windows |
| UAC | Unix Artifacts Collector | Linux |
| PSExec | Remote execution | Windows |

All downloads are HTTPS-only and verified against trusted GitHub domains. SHA256 checksums are validated where available.

### Configuration File

`config/vanguard.yaml` controls VanGuard's behaviour. Key settings:

| Section | Setting | Default | Description |
|---------|---------|---------|-------------|
| vanguard | analyst | "Analyst" | Your name for reports |
| vanguard | organization | "" | Your organisation |
| vanguard | log_level | "info" | Logging level: debug, info, warn, error |
| network.winrm | port | 5985 | WinRM port (5986 for HTTPS recommended) |
| network.ssh | port | 22 | SSH port |
| network.ssh | key_path | "" | Path to SSH private key |
| network.psexec | cleanup | true | Clean up PSExec artifacts after use |
| velociraptor.server | bind_address | "0.0.0.0" | Server listen address |
| velociraptor.server | frontend_port | 8000 | Client-facing port |
| velociraptor.server | gui_port | 8889 | Web UI port |
| github | token | "" | GitHub PAT for higher API rate limits |

The config file is written with 0o600 permissions (owner-only read/write) because it may contain a GitHub PAT.

---

## Velociraptor Operations (Option 1)

Velociraptor is VanGuard's primary IR capability. VanGuard manages the full Velociraptor lifecycle.

### Initialize Server

Starts a local Velociraptor server on the analyst's machine. VanGuard handles certificate generation, config creation, server startup, health checks, and admin user creation. The admin password is generated randomly using `crypto/rand` and displayed once — it is never written to logs or config files.

The server binds to the configured address (default `0.0.0.0`) on the frontend port (8000) and GUI port (8889). A warning is displayed if binding to `0.0.0.0` as this exposes the server to all network interfaces.

### Generate Client Package

Creates a Velociraptor client binary with the server's certificates embedded. The client is repacked using `velociraptor config repack` so it connects to the analyst's server automatically when executed on a target.

### Deploy Agent

Pushes the repacked client to a remote endpoint via one of three methods:

| Method | Requirements | Security Notes |
|--------|-------------|----------------|
| WinRM | Port 5985/5986, NTLM auth | NTLM over HTTP (5985) is vulnerable to relay attacks; HTTPS (5986) recommended |
| SSH | Port 22, key or password auth | Key file must be 0600 permissions; host key verification is disabled with a warning |
| PSExec | SMB access, admin credentials | Password is visible in the analyst host's process list |

### Create Offline Collector

Generates a self-contained collector executable that can be run on a target without network connectivity. The collector gathers artifacts and produces a ZIP file that can be transferred back to the analyst via USB and imported into VanGuard.

### Import Offline Collection

Imports a ZIP file produced by an offline collector back into VanGuard for analysis. The imported artifacts are registered as case evidence with SHA256 hashing.

### Launch Web UI

Opens the Velociraptor web interface in the default browser. The web UI provides direct access to Velociraptor's full feature set including VQL queries, hunts, notebooks, and artifact viewers.

### Server Start/Stop/Status

Controls the Velociraptor server lifecycle. Status shows whether the server is running, the process ID, and the ports in use.

---

## Quick Triage (Option 4)

Quick Triage performs rapid artifact collection using native OS commands — no external tools required. This is the fastest way to gather baseline forensic data from a system.

### Local Quick Triage

Collects artifacts from the local system. On Windows, this includes system information, running processes, network connections, scheduled tasks, services, event log summaries, browser history, registry hives, DNS cache, ARP table, firewall rules, and installed software. On Linux, this includes system info, processes, network connections, cron jobs, systemd units, user accounts, SSH configuration, log files, kernel modules, and running services.

Each step runs asynchronously with progress displayed in the TUI. Collected artifacts are written to `output/{case_id}/triage/` and registered as case evidence with dual MD5+SHA256 hashing.

### Remote Quick Triage

Executes triage collection on a remote target via WinRM, SSH, or PSExec. Results are transferred back to the analyst machine and stored under the active case. Remote temp files use randomised suffixes to prevent pre-placement attacks.

---

## Threat Hunting & Scanning (Option 3)

### Tool-Based Hunting

| Tool | What It Does | Output |
|------|-------------|--------|
| Hayabusa | Scans Windows event logs for suspicious patterns using Sigma-based rules | CSV/JSON with severity-rated findings |
| Chainsaw | Hunts through event logs for attack indicators | CSV with matched rules |
| Loki | IOC scanner using YARA rules and known-bad hashes | Text report with findings |
| YARA | Custom YARA rule scanning against file systems | Matched files with rule names |

Each tool scan registers results as case evidence.

### Live Hunting

Live hunting analyses the running state of a system without external tools.

**Windows live hunting** checks for: LOLBin execution (certutil, mshta, regsvr32, etc.), suspicious autorun entries, named pipe anomalies, DLL hijacking indicators, unsigned services, and suspicious scheduled tasks.

**Linux live hunting** checks for: suspicious processes, unusual cron entries, rogue systemd units, SUID/SGID binaries, kernel module anomalies, hidden files in /tmp, and unusual network listeners.

Anomaly detection applies pattern matching for C2 indicators, persistence mechanisms, and known attacker techniques.

---

## Memory Forensics (Option 5)

### Memory Capture

VanGuard supports multiple capture tools:

| Tool | Platform | Notes |
|------|----------|-------|
| DumpIt | Windows | Fastest, smallest footprint |
| WinPMEM | Windows | Open source alternative |
| AVML | Linux | Kernel-based capture |
| LiME | Linux | Loadable kernel module |

Capture can also be performed remotely — VanGuard copies the capture tool to the target, executes it, and retrieves the dump file. Remote paths are randomised to prevent TOCTOU attacks.

### Memory Analysis

VanGuard wraps Volatility3 for automated memory analysis. Analysis modes:

| Mode | What It Runs |
|------|-------------|
| Auto | Runs all relevant plugins based on OS detection |
| Process | pslist, pstree, cmdline, dlllist |
| Network | netscan, netstat |
| Malware | malfind, vadinfo, suspicious process detection |
| Registry | hivelist, printkey for common persistence locations |
| Timeline | timeliner for temporal analysis |
| YARA | yarascan with custom rules |
| Custom | Run any Volatility3 plugin by name |

Each plugin runs with progress updates displayed in the TUI. Results are written to the case output directory.

### Symbol Management

Volatility3 requires symbol tables matching the target OS kernel version. VanGuard provides symbol management to download and organise symbol files under `lib/volatility3/symbols/`.

---

## Disk Artifact Collection (Option 2)

### Windows

**KAPE (Kroll Artifact Parser and Extractor):** Select from predefined KAPE targets to collect specific artifact categories (event logs, registry hives, prefetch, browser data, etc.). KAPE runs against the local or mounted disk.

**EZ Tools:** Forensic parsers from Eric Zimmerman's toolkit. VanGuard wraps MFTECmd (MFT parsing), EvtxECmd (event log parsing), PECmd (prefetch parsing), RECmd (registry parsing), and others. Output is written as CSV for timeline integration.

**Manual Collection:** Targeted file and directory copy with per-file SHA256 hashing. Specify paths and VanGuard copies them to the case output with full hash verification.

### Linux

**UAC (Unix Artifacts Collector):** Profile-based Linux artifact collection covering logs, user data, system configuration, and process information.

**Native Collection:** VanGuard collects Linux artifacts directly using shell commands — `/var/log/` contents, user home directories, cron configurations, systemd unit files, SSH configuration, and package manifests.

---

## Remote Operations (Option 6)

### Target Management

Add remote targets with hostname, IP address, OS type, port, protocol (WinRM/SSH/PSExec), and authentication method (password or SSH key). All target inputs are validated: hostnames against a regex pattern, IPs via `net.ParseIP`, and ports for the 1–65535 range.

Targets are stored in `config/targets.yaml` (excluded from git). Credentials are cached in memory using `[]byte` and zeroed when evicted or when the connection closes.

### Remote Triage

Execute a full triage collection on one or more remote targets. VanGuard connects, runs the appropriate collection commands (PowerShell for Windows, Bash for Linux), and retrieves the results. All operations use randomised temp paths on the target.

### Remote Hunt

Run threat hunting scans (Hayabusa, Loki, YARA) on remote targets. VanGuard copies the required tool binary and rules to the target, executes the scan, retrieves results, and cleans up.

### Multi-Target Operations

VanGuard supports parallel execution across multiple targets with bounded concurrency. Progress is displayed per-target with individual success/failure tracking.

### Cleanup

After remote operations, VanGuard removes deployed files, temp directories, and (on Windows) the PSEXESVC service. Cleanup can be disabled via the `psexec.cleanup` config option for cases where you need to preserve the deployed state.

---

## Analysis & Reporting (Option 7)

### HTML Incident Report

Generates a self-contained HTML report with embedded CSS (no external dependencies — works in air-gapped environments). The report includes:

- Case summary with analyst name, dates, and classification
- Evidence inventory with file hashes
- Findings sorted by severity with MITRE ATT&CK technique references
- Timeline of key events
- Colour-coded severity indicators (critical=red, high=orange, medium=yellow)

Reports use Go's `html/template` package for automatic XSS protection.

### Super-Timeline

Merges all time-stamped records from parsed artifacts (event logs, prefetch, MFT, auth logs, browser history) into a single chronologically sorted CSV. This is the standard DFIR approach for identifying the sequence of attacker activity.

### Finding Correlation

Groups findings by 30-minute time windows per host to identify clusters of related activity. Extracts MITRE ATT&CK technique IDs for tactical mapping.

### EVTX Parsing

Parses Windows event log CSV output from EvtxECmd into structured records for timeline integration and finding generation.

### Linux Log Parsing

Parses auth.log, syslog, journald output, and web server logs into structured findings for timeline integration.

---

## Use Cases Library (Option C)

VanGuard includes 28 pre-built IR use case workflows, each with MITRE ATT&CK mapping, estimated completion time, and phased artifact collection steps.

### Windows Use Cases (13)

| ID | Name | Severity | Time |
|----|------|----------|------|
| UC-WIN-001 | Ransomware Investigation | Critical | 45–60m |
| UC-WIN-002 | Business Email Compromise | High | 30–45m |
| UC-WIN-003 | Lateral Movement Detection | High | 30–45m |
| UC-WIN-004 | Persistence Discovery | High | 20–30m |
| UC-WIN-005 | Credential Theft | Critical | 25–35m |
| UC-WIN-006 | Data Exfiltration | High | 30–40m |
| UC-WIN-007 | Insider Threat | High | 45–60m |
| UC-WIN-008 | PowerShell Attacks | High | 25–35m |
| UC-WIN-009 | LOLBins Investigation | Medium | 25–35m |
| UC-WIN-010 | Initial Access | High | 35–45m |
| UC-WIN-011 | Full System Triage | Medium | 60–90m |
| UC-WIN-012 | Timeline Analysis | Medium | 45–60m |
| UC-WIN-013 | Active Directory Attacks | Critical | 45–60m |

### Linux Use Cases (12)

| ID | Name | Severity | Time |
|----|------|----------|------|
| UC-LNX-001 | Web Server Compromise | Critical | 40–50m |
| UC-LNX-002 | SSH Brute Force | High | 25–35m |
| UC-LNX-003 | Cryptominer Detection | High | 25–35m |
| UC-LNX-004 | Container Escape | Critical | 35–45m |
| UC-LNX-005 | Rootkit Detection | Critical | 30–40m |
| UC-LNX-006 | Persistence Discovery | High | 25–35m |
| UC-LNX-007 | Privilege Escalation | High | 25–35m |
| UC-LNX-008 | Log Tampering | High | 20–30m |
| UC-LNX-009 | Cloud Credentials | Critical | 25–35m |
| UC-LNX-010 | Full Linux Triage | Medium | 45–60m |
| UC-LNX-011 | Network Intrusion | High | 30–40m |
| UC-LNX-012 | Supply Chain | Critical | 35–45m |

### Cross-Platform Use Cases (3)

| ID | Name |
|----|------|
| UC-XP-001 | IOC Sweep |
| UC-XP-002 | YARA Hunt |
| UC-XP-003 | Baseline Comparison |

Each use case defines phased Velociraptor artifact collection with specific parameters. Use cases can be customised by editing the YAML files in `usecases/`.

---

## Update System (Option U)

### Online Updates

VanGuard checks for updates to rule sets and tool binaries via GitHub:

| Component | Source | Update Method |
|-----------|--------|---------------|
| Sigma rules | SigmaHQ/sigma | Git sparse checkout |
| YARA rules | Yara-Rules/rules | Git clone |
| Hayabusa rules | Yamato-Security/hayabusa-rules | Git clone |
| Tool binaries | Various GitHub releases | GitHub releases API |

### Offline Update Bundles

For air-gapped environments, VanGuard can create an offline update bundle containing the latest rules and binaries. The bundle is a ZIP file with a manifest and SHA256 checksums. Transfer the bundle to the air-gapped system and apply it via the Update menu.

---

## Evidence Chain of Custody

Every piece of evidence collected by VanGuard is:

1. **Hashed** at collection time with both MD5 and SHA256
2. **Registered** in the SQLite case database with file path, hashes, and collection metadata
3. **Custody-chained** with an append-only JSON custody record tracking registration, transfers, and verification events
4. **Audit-logged** via HMAC-SHA256 tamper-evident JSONL logging

Evidence integrity can be verified at any time — VanGuard re-hashes the file and compares against the stored values.

---

## Output Structure

All evidence is stored under `output/{case_id}/`:

```
output/VG-20260503-a1b2/
├── triage/          # Quick triage artifacts
├── hunting/         # Threat hunt results
├── memory/          # Memory dumps and Volatility3 output
├── disk/            # Disk artifact collections
├── remote/          # Remote operation results
├── reports/         # Generated HTML reports
├── timelines/       # Super-timeline CSVs
└── velociraptor/    # Velociraptor collections and exports
```

All output directories are created with 0o700 permissions (owner-only access).

---

## Security Considerations

VanGuard is a privileged tool that handles sensitive forensic data and credentials. Key security properties:

- **Credentials are never logged** — 14 regex patterns sanitise log output
- **Credentials are never in CLI arguments** — Velociraptor passwords are passed via stdin; PSExec is the sole exception (inherent Sysinternals limitation, warning displayed)
- **Password memory is zeroed** — credential bytes are overwritten when connections close
- **All SQL is parameterised** — no string-interpolated queries
- **All archive extraction is zip-slip safe** — path traversal guards on all extraction functions
- **All user inputs are validated** — hostname, IP, port, username inputs checked before use
- **Downloads are HTTPS-only** — scheme enforcement and GitHub domain validation
- **HTML reports are XSS-safe** — `html/template` auto-escaping with no unsafe casts
- **Config files are owner-only** — 0o600 on vanguard.yaml, Velociraptor configs, SQLite database
- **Output directories are owner-only** — 0o700 on all evidence paths

### Accepted Risks

- PSExec password is visible in the analyst host's process list (inherent limitation)
- SSH host key verification is disabled for IR flexibility (warning displayed)
- Windows NTFS file permissions are not set by Go — operators should set ACLs at the VanGuard root directory level
- USB FAT32/exFAT media has no file permissions — treat USB as untrusted after leaving analyst control

---

## Troubleshooting

### Tool not found

Navigate to Configuration → Tool Management and download the required tool. VanGuard downloads tools from GitHub releases at runtime.

### WinRM connection failed

Ensure WinRM is enabled on the target: `Enable-PSRemoting -Force` (as Administrator). VanGuard uses NTLM authentication — Basic auth is not required. For HTTPS, use port 5986.

### SSH key rejected

VanGuard requires SSH key files to have 0600 permissions (owner-only). Fix with: `chmod 600 /path/to/key`. Passphrase-protected keys are not currently supported — use an unencrypted key or ssh-agent.

### Memory capture fails

Memory capture requires Administrator (Windows) or root (Linux). Ensure the capture tool binary is downloaded and the system has sufficient disk space for the dump (equal to physical RAM size).

### Velociraptor server won't start

Check that the frontend port (default 8000) and GUI port (default 8889) are not already in use. Check `logs/` for detailed error messages.

### Build from source fails

CGO must be enabled (`CGO_ENABLED=1`) and GCC must be available. On Windows, install MSYS2 or TDM-GCC. On Linux, install the `gcc` package.
