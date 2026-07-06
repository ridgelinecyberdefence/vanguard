# VanGuard: Enterprise Incident Response Toolkit

> Cross-platform DFIR toolkit for enterprise incident response. Velociraptor-native, air-gap compatible, portable, no installation required.

VanGuard is a self-contained incident response toolkit built in Go that gives DFIR teams a single binary for triage, threat hunting, memory forensics, disk collection, remote operations, and Velociraptor management. On both Windows and Linux, with or without network access.

## Why VanGuard

Most IR workflows require juggling dozens of separate tools, remembering command-line flags, and manually tracking evidence. VanGuard consolidates the full IR lifecycle into one portable binary with built-in case management, evidence hashing, chain of custody, and professional HTML reporting.

**Key differentiators:**
- **Single binary, zero install**: runs from any directory with no installation required
- **Velociraptor as a first-class citizen**: full server lifecycle, agent deployment, offline collectors, and VQL queries from one interface
- **28 pre-built IR use cases**: ransomware, BEC, lateral movement, credential theft, rootkit detection, and more. Each with MITRE ATT&CK mapping and phased artifact collection
- **Air-gapped by design**: every feature works offline; online capabilities are enhancements, not requirements
- **Dual interface**: keyboard-driven TUI for terminal/SSH sessions, plus a web UI for browser-based workflows
- **Evidence integrity built in**: dual MD5+SHA256 hashing, append-only chain of custody, HMAC-SHA256 tamper-evident audit logging

## Capabilities

### Velociraptor Operations
Full Velociraptor lifecycle management from a single menu: server initialisation with auto-generated certificates, client package creation, agent deployment via WinRM/SSH/PSExec, offline collector generation, collection import, hunt management, and web UI access. Passwords are generated securely and never written to logs or config files.

### Quick Triage
Rapid artifact collection using native OS commands. No external tools required. Collects 20+ Windows artifact categories (processes, services, event logs, scheduled tasks, browser history, registry hives, DNS cache, network connections) and 15+ Linux categories (processes, cron, systemd, SSH config, auth logs, kernel modules). Each artifact is hashed and registered as case evidence automatically.

### Threat Hunting & Scanning
Integrates Hayabusa (Sigma-based event log analysis), Chainsaw (event log hunting), Loki (IOC scanning), and YARA (custom rule scanning). Live hunting analyses running system state for LOLBin execution, suspicious autoruns, named pipe anomalies, DLL hijacking indicators, rogue systemd units, SUID binaries, and C2 network patterns, all without external tools.

### Memory Forensics
Capture memory with DumpIt, WinPMEM (Windows), AVML, or LiME (Linux). locally or on remote targets via WinRM/SSH. Analyse dumps with Volatility3 across multiple plugin categories: process analysis, network connections, malware detection, registry extraction, timeline generation, and YARA scanning. Remote capture uses randomised temp paths to prevent pre-placement attacks.

### Disk Artifact Collection
Windows: KAPE target-based collection and EZ Tools parsing (MFTECmd, EvtxECmd, PECmd, RECmd). Linux: UAC profile-based collection, native log/config harvesting, and targeted file copy with per-file SHA256 verification.

### Remote Operations
Execute triage, hunting, and memory capture across multiple remote endpoints simultaneously. Supports WinRM (NTLM authentication), SSH (key and password), and PSExec with bounded concurrent execution. Credentials used for remote connections are handled securely and never written to disk or logs.

### Analysis & Reporting
Generate self-contained HTML incident reports with embedded CSS (no external dependencies. Works air-gapped). Build super-timelines by merging all parsed artifacts into chronologically sorted CSV. Correlate findings into 30-minute host clusters with automatic MITRE ATT&CK technique extraction.

### Use Cases Library (28 pre-built workflows)

**Windows (13):**

| ID | Use Case | Severity |
|----|----------|----------|
| UC-WIN-001 | Ransomware Investigation | Critical |
| UC-WIN-002 | Business Email Compromise | High |
| UC-WIN-003 | Lateral Movement Detection | High |
| UC-WIN-004 | Persistence Discovery | High |
| UC-WIN-005 | Credential Theft | Critical |
| UC-WIN-006 | Data Exfiltration | High |
| UC-WIN-007 | Insider Threat | High |
| UC-WIN-008 | PowerShell Attacks | High |
| UC-WIN-009 | LOLBins Investigation | Medium |
| UC-WIN-010 | Initial Access | High |
| UC-WIN-011 | Full System Triage | Medium |
| UC-WIN-012 | Timeline Analysis | Medium |
| UC-WIN-013 | Active Directory Attacks (DCSync, Kerberoasting) | Critical |

**Linux (12):**

| ID | Use Case | Severity |
|----|----------|----------|
| UC-LNX-001 | Web Server Compromise | Critical |
| UC-LNX-002 | SSH Brute Force | High |
| UC-LNX-003 | Cryptominer Detection | High |
| UC-LNX-004 | Container Escape | Critical |
| UC-LNX-005 | Rootkit Detection | Critical |
| UC-LNX-006 | Persistence Discovery | High |
| UC-LNX-007 | Privilege Escalation | High |
| UC-LNX-008 | Log Tampering | High |
| UC-LNX-009 | Cloud Credential Exposure | Critical |
| UC-LNX-010 | Full Linux Triage | Medium |
| UC-LNX-011 | Network Intrusion | High |
| UC-LNX-012 | Supply Chain Compromise | Critical |

**Cross-Platform (3):** IOC Sweep, YARA Hunt, Baseline Comparison

Each use case defines phased Velociraptor artifact collection with MITRE ATT&CK mapping, estimated completion time, and severity classification. Customise by editing YAML files in `usecases/`.

### Update System
Online: automatic checks for Sigma, YARA, and Hayabusa rule updates plus tool binary updates via GitHub releases API. Offline: create update bundles as ZIP files with SHA256-verified manifests for air-gapped transfer and application.

### Case Management & Evidence Integrity
SQLite-backed case database tracking cases, targets, evidence, findings, and timeline events. Every collected artifact is dual-hashed (MD5+SHA256) at collection time with an append-only chain of custody record. HMAC-SHA256 tamper-evident audit logging provides cryptographic proof of evidence handling.

## Integrated Tools

| Tool | Purpose | Platform |
|------|---------|----------|
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Primary IR platform. Server, agents, VQL, hunts | Windows, Linux |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Windows event log analysis (Sigma rules) | Windows, Linux |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Event log hunting | Windows, Linux |
| [Loki](https://github.com/Neo23x0/Loki) | IOC scanner (YARA + hashes) | Windows, Linux |
| [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) | Disk triage collection | Windows |
| [EZ Tools](https://ericzimmerman.github.io/) | Forensic parsers (MFT, EVTX, Prefetch, Registry) | Windows |
| [UAC](https://github.com/tclahr/uac) | Unix Artifacts Collector | Linux |
| [DumpIt](https://www.comae.com/) | Memory capture | Windows |
| [WinPMEM](https://github.com/Velocidex/WinPmem) | Memory capture | Windows |
| [AVML](https://github.com/microsoft/avml) | Memory capture | Linux |
| [Volatility3](https://github.com/volatilityfoundation/volatility3) | Memory analysis framework | Windows, Linux |

All tools are downloaded at runtime from GitHub releases. Downloads are HTTPS-only with domain validation.

## Installation

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/ridgelinecyberdefence/vanguard/releases):

| Platform | Binary | Checksum |
|----------|--------|----------|
| Windows 64-bit | `vanguard-windows-amd64.exe` | `vanguard-checksums.sha256` |
| Linux 64-bit | `vanguard-linux-amd64` | `vanguard-checksums.sha256` |

```bash
# Linux
chmod +x vanguard-linux-amd64
sudo ./vanguard-linux-amd64
```

```powershell
# Windows (run as Administrator)
.\vanguard-windows-amd64.exe
```

### Build from Source

Requires Go 1.22+ and GCC (CGO is required for SQLite).

```bash
git clone https://github.com/ridgelinecyberdefence/vanguard.git
cd vanguard
CGO_ENABLED=1 go build -trimpath -o vanguard ./cmd/vanguard/
```

Windows (PowerShell):
```powershell
.\build.ps1
```

## Quick Start

1. **Launch** VanGuard as Administrator/root
2. **Create a case**: Configuration → Case Management → New Case
3. **Set analyst name**: Configuration → Settings
4. **Download tools**: Configuration → Tool Management
5. **Run triage**: Quick Triage → Local Quick Triage
6. **Hunt for threats**: Threat Hunting → select Hayabusa, Loki, or YARA
7. **Generate report**: Analysis & Reporting → Generate Report

For Velociraptor-based workflows:
1. **Initialize server**: Velociraptor Operations → Initialize Server
2. **Deploy agents**: Velociraptor Operations → Deploy Agent (WinRM/SSH/PSExec)
3. **Run use case**: Use Cases Library → select a pre-built workflow
4. **Collect and analyse**: results are automatically registered as case evidence

## Air-Gapped Deployment

VanGuard is designed for environments with no internet access:

1. On a connected machine: download tools and rules via the Configuration and Update menus
2. Copy the entire VanGuard directory to a USB drive
3. Run directly from USB on the air-gapped target. All tools and rules are self-contained
4. For rule updates: create an offline bundle (Update → Create Offline Bundle), transfer via USB, apply on the air-gapped system with SHA256 verification

## Security & Evidence Handling

VanGuard is built for environments where evidence integrity and operational security matter:

- **Tamper-evident audit trail**: every action on evidence is cryptographically logged, giving you a defensible chain of custody for legal proceedings
- **Automatic evidence hashing**: every collected artifact is dual-hashed (MD5 + SHA256) at capture time, so you can prove evidence hasn't been modified
- **Append-only custody chain**: evidence handling events are recorded and cannot be retroactively altered
- **Credential isolation**: passwords and keys used for remote connections are never written to disk or logs, protecting your operational credentials during IR
- **Self-contained reports**: HTML reports work without internet access, with no external dependencies that could leak investigation details

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Download, build, and deploy |
| [Quick Start](docs/quick-start.md) | First run and common workflows |
| [User Guide](docs/user-guide.md) | Comprehensive reference for all modules |
| [Air-Gapped Deployment](docs/air-gapped-deployment.md) | Offline setup and update bundles |
| [Contributing](CONTRIBUTING.md) | Development setup and contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history and release notes |

## Project Structure
