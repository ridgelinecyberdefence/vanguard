# VANGUARD — Enterprise DFIR Toolkit

> Cross-platform incident response toolkit for connected, isolated, and air-gapped environments.

**VanGuard** is a self-contained DFIR toolkit built by [RidgeLine Cyber](https://ridgelinecyber.com) for enterprise incident response operations. It provides a modern terminal interface wrapping industry-standard forensic tools into guided investigation workflows.

## Features

- **Velociraptor Integration** — Server deployment, agent management, offline collectors, and hunt management
- **Quick Triage** — Comprehensive system collection using native OS commands (no tools required)
- **Threat Hunting** — Hayabusa, Chainsaw, Loki, YARA scanning, and live anomaly detection
- **Memory Forensics** — Capture with DumpIt / WinPmem / AVML / Belkasoft / Magnet RAM and analyze with Volatility3
- **Disk Collection** — KAPE artifact collection and EZ Tools parsing pipeline
- **Remote Operations** — Collect from remote endpoints via WinRM, SSH, or PSExec
- **28 Investigation Use Cases** — Pre-built workflows for ransomware, BEC, lateral movement, web compromise, and more
- **Case Management** — SQLite-backed case tracking with evidence chain and findings
- **MITRE ATT&CK Mapping** — Automatic technique mapping and correlation
- **HTML Reports** — Professional investigation reports with embedded CSS/JS
- **Air-Gapped Support** — Works entirely offline; update via signed USB bundles

## Quick Start

### Download

Download the latest release from [Releases](https://github.com/ridgelinecyberdefence/vanguard/releases):

- `vanguard-windows-amd64.exe` — Windows
- `vanguard-linux-amd64` — Linux

### Run

Place the binary anywhere — VanGuard creates its directory tree (`bin/`, `config/`, `logs/`, `output/`, `rules/`, `usecases/`) on first launch alongside the executable.

```sh
# Linux
chmod +x vanguard-linux-amd64
./vanguard-linux-amd64
```

```powershell
# Windows
.\vanguard-windows-amd64.exe
```

The TUI opens immediately. From the dashboard:

1. Press `8` to open **Configuration** and create a case (`Create New Case`)
2. Press `8` → `6` to **Download Required Tools** (Velociraptor, Hayabusa, Chainsaw, Loki, WinPmem, rule sets)
3. Press `H` for in-app help — the **Quick Start Guide** walks through your first investigation

## Sidebar Navigation

| Key | Module |
|-----|--------|
| `1` | Velociraptor (server, clients, offline collectors, hunts) |
| `2` | Disk Collection (KAPE, EZ Tools, UAC) |
| `3` | Threat Hunting (Hayabusa, Chainsaw, Loki, YARA, live detection) |
| `4` | Quick Triage (native-OS evidence collection) |
| `5` | Memory Forensics (capture + Volatility3) |
| `6` | Remote Operations (WinRM, SSH, PSExec, batch ops) |
| `7` | Analysis & Reporting (parsers, super-timeline, MITRE, HTML reports) |
| `8` | Configuration (cases, tools, settings) |
| `U` | Update Tools & Rules (online + air-gapped bundles) |
| `C` | Use Cases Library (28 pre-built investigation workflows) |
| `H` | Help & Documentation |
| `Q` | Quit |

## Use Cases

VanGuard ships with 28 pre-built investigation workflows under `[C] Use Cases`:

- **Windows (13)** — Ransomware, BEC, Lateral Movement, Persistence, Credential Theft, Data Exfiltration, Insider Threat, PowerShell Attacks, LOLBins, Initial Access, Full System Triage, Timeline Analysis, Active Directory Attacks
- **Linux (12)** — Web Server Compromise, SSH Brute Force, Cryptominer, Container Escape, Rootkit, Persistence, Privilege Escalation, Log Tampering, Cloud Credential Theft, Full Triage, Network Intrusion, Supply Chain Compromise
- **Cross-Platform (3)** — IOC Sweep, YARA Hunt, Baseline Comparison

Each use case is a structured YAML workflow (`internal/usecases/defaults_*.go` for built-ins; drop your own `UC-CUSTOM-*.yaml` into `usecases/` for custom playbooks). Run produces a per-phase summary with analysis guidance and recommended follow-ups.

## Air-Gapped Operation

VanGuard is designed offline-first. Once tool binaries and rule sets are placed (or applied via update bundle), the entire toolkit runs without internet access.

- **Create a bundle** on a connected machine: `[U] Update → [8] Create Offline Update Bundle` produces `vanguard_updates_YYYYMMDD/` with manifest.json + SHA256 hashes
- **Apply the bundle** on the air-gapped host: `[U] Update → [9] Apply Offline Update Bundle` validates each component's hash before swapping it in
- All operator-installed YARA rules under `rules/yara/custom/` are preserved across rule updates

## Building from Source

VanGuard requires Go 1.22+ and a C toolchain (CGO is enabled for SQLite case storage).

### Linux

```sh
sudo apt-get install -y build-essential   # or your distro equivalent
git clone https://github.com/ridgelinecyberdefence/vanguard
cd vanguard

VERSION=1.0.0
DATE=$(date -u +%Y-%m-%d)
COMMIT=$(git rev-parse --short HEAD)
CGO_ENABLED=1 go build \
  -ldflags "-X main.version=$VERSION -X main.buildDate=$DATE -X main.commit=$COMMIT" \
  -o vanguard ./cmd/vanguard/
```

### Windows (PowerShell)

```powershell
choco install mingw -y                    # or any other GCC for Windows
git clone https://github.com/ridgelinecyberdefence/vanguard
cd vanguard

$version = "1.0.0"
$date = Get-Date -Format "yyyy-MM-dd"
$commit = git rev-parse --short HEAD
$env:CGO_ENABLED = 1
go build `
  -ldflags "-X main.version=$version -X main.buildDate=$date -X main.commit=$commit" `
  -o vanguard.exe ./cmd/vanguard/
```

### Continuous Integration

Pushes to `main` and PRs build + test on Linux and Windows via [`.github/workflows/build.yml`](.github/workflows/build.yml). Tagged commits (`v*`) produce signed release artifacts via [`.github/workflows/release.yml`](.github/workflows/release.yml).

## Repository Layout

```
cmd/vanguard/        Entry point + ldflags-injected version
internal/
  analysis/          Log/event parsing, super-timeline, correlation, MITRE mapping, HTML report
  case/              SQLite case + finding + evidence storage
  config/            YAML config loader
  disk/              KAPE + EZ Tools + UAC + native-Linux artifact collection
  help/              In-app documentation content
  hunting/           Threat hunting orchestration + live detectors
  logging/           Structured file + stderr logger
  memory/            Capture + Volatility3 analysis
  mitre/             MITRE ATT&CK technique catalog
  modules/           PowerShell / Bash module orchestration helpers
  network/           SSH / WinRM / PSExec wrappers
  output/            Output directory helpers
  remote/            Remote operations engine + target/credential management
  tools/             Tool registry + downloader + manual-install hints
  triage/            Quick Triage steps (Windows + Linux)
  tui/               bubbletea UI (sidebar + content panels)
  updates/           Update orchestration + offline bundle create/apply
  usecases/          28 pre-built workflows + runner + YAML loader
  velociraptor/      Velociraptor server lifecycle + client packaging
modules/             User-facing PowerShell / Bash modules
rules/               Sigma / YARA / Hayabusa rule sets
templates/           HTML report templates
```

## Documentation

Run VanGuard and press `H` for the full in-app guide (Quick Start, Keyboard Shortcuts, Walkthrough, Tool Reference, Use Case Reference, MITRE Reference, Output Directory Structure, Configuration Reference, About, Licenses, Changelog).

## Privilege Requirements

| Requires Administrator / root | Works without elevation |
|------------------------------|-------------------------|
| Memory capture (DumpIt, WinPmem, AVML, LiME) | Case management |
| Event log export (`wevtutil`) | Process listing |
| Registry hive export (`reg save`) | Network connections (partial) |
| Velociraptor server start | Threat hunting analysis on collected artifacts |
| Agent deployment | Report generation |
| Some Quick Triage collections | Tool management |

Recommendation: run VanGuard as Administrator / root for full capability. Individual operations will warn before failing if elevation is required but not present.

## Security Considerations

- **Case database**: `output/vanguard.db` is an unencrypted SQLite file. Use full-disk encryption (BitLocker / LUKS) on the VanGuard drive when handling sensitive investigations.
- **Credentials**: Remote-target passwords and Velociraptor admin secrets are held in memory for the session only — they are never persisted to disk.
- **Logs**: `logs/vanguard.log` is sanitised on write to redact common credential patterns (`password=`, `Bearer …`, `-p VALUE`, etc.), but may still contain hostnames and IP addresses of investigated systems. Treat it as evidence.
- **Evidence integrity**: Every evidence file is hashed (MD5 + SHA256) at collection. Run `[8] Configuration > [V] Verify Evidence Integrity` (and the auto-check fires before HTML report generation) to detect tampering or accidental modification.
- **Tool downloads**: Downloads attempt to verify against published `.sha256` checksums; mismatches abort the install. The on-disk hash is recorded so subsequent scans flag binaries that have been altered (`MODIFIED` badge in Tool Status).
- **Offline bundles**: `manifest.json` carries SHA256 for every component. `[U] Update > Apply Offline Bundle` performs a full preflight verification — a single mismatch rejects the entire bundle.
- **Velociraptor**: Uses self-signed certificates generated locally. The GUI binds to `127.0.0.1` by default (frontend stays on `0.0.0.0` so clients can connect). Rotate certificates via `[1] Velociraptor > [R] Regenerate Certificates`.
- **Remote transports**:
  - **SSH** passes passwords via the `SSHPASS` environment variable (not argv).
  - **WinRM** feeds the wrapper script via stdin (`-Command -`), so credentials never appear in argv.
  - **PSExec** is a Sysinternals limitation — `-p PASSWORD` is on argv. Logs redact it; operators who can't tolerate process-listing exposure should use WinRM/SSH.

## License

VanGuard is released under the MIT License — see [LICENSE](LICENSE) for the full text.

Bundled third-party tools retain their own licenses:

| Tool | License |
|------|---------|
| Velociraptor | AGPL-3.0 |
| Hayabusa | GPL-3.0 |
| Chainsaw | GPL-3.0 |
| Loki | GPL-3.0 |
| EZ Tools | MIT |
| AVML | MIT |
| UAC | Apache-2.0 |
| Volatility3 | Volatility Foundation License |
| KAPE | Free for DFIR use |
| DumpIt (Comae) | Free for DFIR use |
| Belkasoft RAM Capturer | Freeware |
| Magnet RAM Capture | Freeware |

## Contributing

VanGuard development happens at [github.com/ridgelinecyberdefence/vanguard](https://github.com/ridgelinecyberdefence/vanguard). Bug reports, feature requests, and pull requests welcome.

For training and enterprise support: [training.ridgelinecyber.com](https://training.ridgelinecyber.com).

---

Built by [RidgeLine Cyber](https://ridgelinecyber.com).
