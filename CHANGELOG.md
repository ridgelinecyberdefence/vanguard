# Changelog

All notable changes to VanGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.1] - 2026-07-06

### Added
- SECURITY.md with a private vulnerability-reporting policy (security@ridgelinecyber.com
  and GitHub private advisories)
- Issue templates for bug reports and feature requests, with security reports routed to
  private disclosure rather than public issues

### Changed
- Documentation and repository-hygiene updates; no changes to the VanGuard binary or its
  behaviour

## [1.0.0] - 2026-05-03

### Added
- Cross-platform DFIR toolkit (Windows/Linux) with Go bubbletea TUI and web UI
- Velociraptor integration: server lifecycle, config generation, client repack, agent deployment, offline collector creation
- Quick Triage: 20+ Windows and 15+ Linux artifact collection steps with async progress
- Threat Hunting: Hayabusa, Chainsaw, Loki, YARA scanning plus live anomaly detection (LOLBins, C2 indicators, persistence)
- Memory Forensics: DumpIt, WinPMEM, AVML, LiME capture with Volatility3 multi-plugin analysis
- Disk Collection: KAPE targets, EZ Tools parsing, UAC profiles, native Linux collection, manual targeted copy with SHA256 hashing
- Remote Operations: WinRM (NTLM), SSH (key/password), PSExec with multi-target parallel execution
- Analysis & Reporting: HTML incident reports, super-timeline CSV generation, EVTX/Linux log parsing, finding correlation
- 28 pre-built IR use cases: 13 Windows, 12 Linux, 3 cross-platform with MITRE ATT&CK mapping
- Update System: GitHub release checks, rule updates (Sigma/YARA/Hayabusa), offline update bundles
- Case Management: SQLite with evidence hashing (MD5+SHA256), chain of custody, findings, timeline events
- HMAC-SHA256 tamper-evident audit logging for chain of custody
- In-app help system with static pages and dynamic tool catalog
- GitHub Actions release workflow for automated cross-platform builds

### Security
- 26 security audit findings addressed (3 critical, 4 high, 7 medium, 11 low, 1 informational)
- All SQL queries parameterised — zero string-interpolated SQL
- All archive extraction zip-slip safe with separator-inclusive prefix checks
- All TUI inputs validated: hostname regex, IP validation, port range, username regex
- Credentials never logged (14 regex sanitisation patterns)
- Velociraptor passwords via stdin (never in CLI arguments)
- Password fields use []byte with zeroing on close
- Output directories restricted to 0o700, config files to 0o600
- Downloads HTTPS-only with GitHub domain validation
- HTML reports use html/template (auto-escaping XSS protection)
