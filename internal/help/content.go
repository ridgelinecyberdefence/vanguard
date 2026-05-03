// Package help provides VanGuard's in-app documentation content.
//
// The package is intentionally text-only: every page is either a `const string`
// (the rendered TUI handles word-wrapping + scrolling) or a small builder
// function that walks live registries (ToolManager, use case Library,
// mitre.Techniques) so reference pages stay accurate as the catalog evolves.
//
// Pages are laid out as plain monospace blocks — the TUI takes them verbatim,
// splits on newlines, and renders one line per row inside the scrolling
// viewport.
package help

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/ridgelinecyberdefence/vanguard/internal/mitre"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
	"github.com/ridgelinecyberdefence/vanguard/internal/usecases"
)

// PageID identifies one of the static / dynamic help pages.
type PageID int

const (
	PageQuickStart PageID = iota
	PageShortcuts
	PageWalkthrough
	PageToolReference
	PageUseCaseReference
	PageMITREReference
	PageOutputDirs
	PageConfigReference
	PageAbout
	PageLicenses
	PageChangelog
)

// MenuItem is one entry in the [H] Help submenu.
type MenuItem struct {
	Shortcut string
	Title    string
	Page     PageID
}

// Menu returns the catalog displayed at the top of the Help panel.
func Menu() []MenuItem {
	return []MenuItem{
		{"1", "Quick Start Guide", PageQuickStart},
		{"2", "Keyboard Shortcuts", PageShortcuts},
		{"3", "First Investigation Walkthrough", PageWalkthrough},
		{"4", "Tool Reference", PageToolReference},
		{"5", "Use Case Reference", PageUseCaseReference},
		{"6", "MITRE ATT&CK Reference", PageMITREReference},
		{"7", "Output Directory Structure", PageOutputDirs},
		{"8", "Configuration Reference", PageConfigReference},
		{"9", "About VanGuard", PageAbout},
		{"0", "License Information", PageLicenses},
		{"A", "Changelog", PageChangelog},
	}
}

// Sections of the menu — used by the renderer to insert group headers.
type SectionRange struct {
	Label string
	From  int // inclusive
	To    int // exclusive
}

// Sections returns the index ranges that should be rendered with a group
// header preceding them.
func Sections() []SectionRange {
	return []SectionRange{
		{"GETTING STARTED", 0, 3},
		{"REFERENCE", 3, 8},
		{"ABOUT", 8, 11},
	}
}

// Render returns the page text for id. The lib + tm + version inputs let us
// build the dynamic reference pages from live state without leaking package
// dependencies into the panel.
func Render(id PageID, lib *usecases.Library, tm *tools.ToolManager, version, buildDate, commit, platform string) string {
	switch id {
	case PageQuickStart:
		return quickStartText
	case PageShortcuts:
		return shortcutsText
	case PageWalkthrough:
		return walkthroughText
	case PageToolReference:
		return buildToolReference(tm)
	case PageUseCaseReference:
		return buildUseCaseReference(lib)
	case PageMITREReference:
		return buildMITREReference()
	case PageOutputDirs:
		return outputDirsText
	case PageConfigReference:
		return configReferenceText
	case PageAbout:
		return buildAboutPage(version, buildDate, commit, platform)
	case PageLicenses:
		return licensesText
	case PageChangelog:
		return changelogText
	}
	return "(no help page available)"
}

// ---------------------------------------------------------------------------
// Static pages
// ---------------------------------------------------------------------------

const quickStartText = `Quick Start Guide

1. DOWNLOAD TOOLS
   Go to Configuration [8] > Download Required Tools [6]
   This downloads Velociraptor, Hayabusa, Chainsaw, Loki, and
   WinPmem from GitHub automatically.

   KAPE and EZ Tools require manual download:
   → https://ericzimmerman.github.io
   Place in: bin/windows/kape/ and bin/windows/ez-tools/

2. CREATE A CASE
   Go to Configuration [8] > Create New Case [1]
   Enter a case name, classification, and description.
   All evidence and findings are organized by case.

3. COLLECT EVIDENCE
   Quick Triage [4] — Fast local system collection using
   native OS commands. No external tools needed. Collects
   processes, network, event logs, persistence, and more.

   Disk Collection [2] — KAPE-based artifact collection for
   deeper forensic analysis.

   Memory Forensics [5] — Capture and analyze system memory
   using DumpIt, WinPmem, AVML, or Belkasoft RAM Capturer.

4. HUNT FOR THREATS
   Threat Hunting [3] — Run Hayabusa, Chainsaw, Loki, and
   YARA scans against collected artifacts or the live system.
   Live hunting checks for suspicious processes, network
   anomalies, persistence, and more without external tools.

5. ANALYZE & REPORT
   Analysis & Reporting [7] — Parse artifacts with EZ Tools,
   build timelines, correlate findings, map to MITRE ATT&CK,
   and generate HTML reports.

6. USE CASES
   Use Cases [C] — 28 pre-built investigation workflows.
   Select a scenario (ransomware, BEC, lateral movement, etc.)
   and VanGuard runs the appropriate collection and analysis
   steps automatically.

TIPS
→ Create a case FIRST — most operations need one
→ Quick Triage works without any tools installed
→ Use the sidebar to navigate, number keys for speed
→ Press Esc to go back from any submenu
→ All output goes to output/{case_id}/

PRIVILEGE REQUIREMENTS
Operations that REQUIRE Administrator/root:
  • Memory capture (DumpIt, WinPmem, AVML, LiME)
  • Event log export (wevtutil)
  • Registry hive export (reg save)
  • Velociraptor server start
  • Agent deployment
  • Some Quick Triage collections

Operations that work WITHOUT elevation:
  • Case management
  • Process listing
  • Network connections (partial)
  • Threat hunting analysis (against collected artifacts)
  • Report generation
  • Tool management

Recommendation: Run VanGuard as Administrator/root for full
capability. Individual operations warn if elevation is
required but not available.

SECURITY
→ Case data is stored in an unencrypted SQLite database
  at output/vanguard.db. For sensitive investigations,
  rely on full-disk encryption (BitLocker on Windows,
  LUKS on Linux) for the VanGuard drive itself.
→ Credentials are NEVER persisted to disk — they are held
  in memory for the session only.
→ Log files may contain hostnames and IP addresses of
  investigated systems. Treat output/, logs/, and the
  case database as evidence with the same care.
→ Velociraptor uses self-signed certificates by default,
  bound to 127.0.0.1 for the GUI. See [1] Velociraptor >
  [R] Regenerate Certificates to rotate them.
`

const shortcutsText = `Keyboard Shortcuts

NAVIGATION
1-8         Select sidebar item (main modules)
U           Update Tools & Rules
C           Use Cases Library
H           Help & Documentation
Q           Quit VanGuard

↑ / ↓       Move cursor in sidebar or content list
k / j       vim-style up / down (where applicable)
Enter       Select / confirm
Esc         Go back one level
Tab         Switch focus between sidebar and content

WITHIN MENUS
1-9, 0      Select submenu items
A-Z         Select extended submenu items
Space       Toggle checkbox (custom collection, target picker)
y / n       Confirm / cancel dialogs

WITHIN HELP (this view)
↑ / ↓       Scroll one line
PgUp/PgDn   Scroll one page
Home / End  Jump to top / bottom
Esc         Back to the help index

GENERAL
Ctrl+C      Force quit (emergency only)
`

const walkthroughText = `Your First Investigation

Scenario: A user reports ransomware on their workstation.
You're running VanGuard on your analyst machine.

STEP 1: Create a case
→ Press 8 (Configuration) > 1 (Create New Case)
→ Name: "Ransomware - WORKSTATION01"
→ Classification: Ransomware

STEP 2: Quick triage on the affected machine
If you're ON the affected machine:
→ Press 4 (Quick Triage) > 1 (Full Triage)

If the machine is REMOTE:
→ Press 6 (Remote Ops) > 1 (Add Remote Target)
→ Enter the machine's IP, credentials
→ Press 6 (Remote Ops) > 6 (Remote Quick Triage)

STEP 3: Capture memory (before reboot)
→ Press 5 (Memory Forensics) > 1 or 2 (DumpIt/WinPmem)

STEP 4: Hunt for threats
→ Press 3 (Threat Hunting) > 1 (Hayabusa Full Scan)
→ Press 3 (Threat Hunting) > A (Suspicious Processes)

STEP 5: Run the ransomware use case
→ Press C (Use Cases) > navigate to UC-WIN-001 Ransomware
→ Follow the guided investigation

STEP 6: Generate report
→ Press 7 (Analysis) > J (Generate HTML Report)
→ Share report with your team
`

const outputDirsText = `Output Directory Structure

output/
└── {case_id}/
    ├── triage/
    │   └── {timestamp}/
    │       ├── system/           System info, installed software
    │       ├── processes/        Process listings
    │       ├── network/          Connections, config, DNS, ARP
    │       ├── eventlogs/        Exported .evtx files
    │       ├── persistence/      Autoruns, tasks, services, WMI
    │       ├── users/            User accounts, activity
    │       ├── browser/          Browser artifacts
    │       └── collection_summary.txt
    ├── disk/
    │   └── {timestamp}/
    │       ├── kape/             KAPE collections
    │       └── parsed/           EZ Tools parsed output
    ├── memory/
    │   ├── {hostname}_{ts}.dmp   Memory dumps
    │   └── analysis_{ts}/        Volatility3 output
    ├── threat_hunting/
    │   └── {timestamp}/
    │       ├── hayabusa/         Hayabusa scan results
    │       ├── chainsaw/         Chainsaw output
    │       ├── loki/             Loki scan results
    │       ├── yara/             YARA scan matches
    │       └── live/             Live hunting analysis
    ├── velociraptor/
    │   ├── clients/              Repacked client binaries
    │   ├── collectors/           Offline collector packages
    │   └── imports/              Imported offline collections
    ├── remote/
    │   ├── triage/{host}_{ts}/   Per-host remote triage output
    │   ├── eventlogs/            Remote event log pulls
    │   ├── registry/             Remote registry exports
    │   ├── acquired/             Targeted file acquisitions
    │   ├── memory/               Remote memory captures
    │   └── ioc_sweep/            IOC-sweep result CSVs
    ├── usecases/
    │   └── {uc_id}_{ts}/         Use case execution output
    ├── analysis/
    │   └── {timestamp}/          Parsed and analyzed data
    └── reports/
        ├── VG_{id}_Report.html   Full investigation report
        ├── VG_{id}_ExecSummary   Executive summary
        ├── VG_{id}_Findings.csv  Exported findings
        ├── VG_{id}_Timeline.csv  Super timeline
        └── VG_{id}_IOCs.csv      IOC export
`

const configReferenceText = `Configuration Reference — config/vanguard.yaml

vanguard:
  version       Application version
  analyst       Investigator name (shown in reports)
  organization  Organization name (shown in reports)

paths:
  output        Base output directory (default: ./output)
  logs          Log directory (default: ./logs)
  tools         Tool binary locations per platform
  rules         Detection rule locations

network:
  default_mode  Connection mode: local, ssh, winrm, psexec
  ssh           SSH settings (port, key_path, timeout)
  winrm         WinRM settings (port, ssl, timeout)
  psexec        PSExec settings (copy_binary, cleanup)

velociraptor:
  auto_download Auto-download binary if missing
  server        Server config (bind, ports, datastore)
  client        Client config (poll interval)

memory:
  capture_tool  Preferred capture tool per platform
  volatility    Volatility3 settings (symbols, plugins)

triage:
  hayabusa      Min alert level, output format
  loki          Intense mode, scan targets

updates:
  auto_check    Check for updates on startup
  interval      Hours between checks

output:
  default_format  auto, csv, html, txt
  compress        Compress large output files
`

const licensesText = `License Information

VanGuard is open source software released under the MIT License.

Copyright (c) 2026 RidgeLine Cyber

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files, to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

THIRD-PARTY TOOL LICENSES
─────────────────────────────────────
Velociraptor     AGPL-3.0
Hayabusa         GPL-3.0
Chainsaw         GPL-3.0
Loki             GPL-3.0
EZ Tools         MIT
AVML             MIT
UAC              Apache-2.0
Volatility3      Volatility Foundation License
KAPE             Free for DFIR use
DumpIt           Free for DFIR use (Comae)
Belkasoft RAM    Freeware
Magnet RAM       Freeware

VanGuard bundles these tools for convenience. Each tool retains
its own license. See individual tool documentation for details.
`

const changelogText = `Changelog

v1.0.0 — Initial Release
─────────────────────────────────────
• Sidebar + content pane TUI layout
• Case management (create, list, select, close)
• Tool registry with GitHub auto-download
• Velociraptor server management and agent deployment
• Quick Triage (Windows + Linux)
• Threat Hunting (Hayabusa, Chainsaw, Loki, YARA, live hunting)
• Memory Forensics (DumpIt, WinPmem, AVML, Belkasoft, Magnet, Volatility3)
• Disk Collection (KAPE, EZ Tools, UAC, Linux native collectors)
• Remote Operations (WinRM, SSH, PSExec — target management,
  collection, hunting, IOC sweep, batch ops, deploy tool)
• Analysis & Reporting (EvtxECmd parsing, logon / process / service
  analysis, Linux log analysis, super timeline, correlation,
  MITRE ATT&CK mapping, HTML reports, CSV / TXT / STIX exports)
• 28 pre-built investigation use cases (Windows, Linux, cross-platform)
• Air-gapped update bundle support (create + apply, SHA256-verified)
• In-app help & documentation
• Cross-platform (Windows + Linux)
`

// ---------------------------------------------------------------------------
// Dynamic pages
// ---------------------------------------------------------------------------

// buildToolReference walks the live tool registry and emits one block per
// category (Collection / Analysis / Detection / Rules) so the page reflects
// what's actually registered, including newly-added tools.
func buildToolReference(tm *tools.ToolManager) string {
	var b strings.Builder
	b.WriteString("Tool Reference\n\n")

	if tm == nil {
		b.WriteString("(tool manager unavailable)\n")
		return b.String()
	}
	groups := tm.GetStatusByCategory()
	for gi, g := range groups {
		if gi > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s\n", g.Label)
		b.WriteString("─────────────────────────────────────\n")
		for _, s := range g.Tools {
			t := tm.GetTool(s.ID)
			if t == nil {
				continue
			}
			install := "auto-downloads from GitHub"
			if t.GitHubRepo == "" {
				install = "MANUAL install required"
			} else if t.DownloadMethod == tools.DownloadRepoArchive {
				install = "auto-downloads (repo archive)"
			}
			fmt.Fprintf(&b, "%-18s %s\n", s.Name, t.Description)
			fmt.Fprintf(&b, "%-18s Install: %s\n", "", install)
			if t.License != "" {
				fmt.Fprintf(&b, "%-18s License: %s\n", "", t.License)
			}
			if t.LicenseURL != "" {
				fmt.Fprintf(&b, "%-18s URL:     %s\n", "", t.LicenseURL)
			}
			fmt.Fprintf(&b, "%-18s Path:    %s\n", "", t.LocalPath)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// buildUseCaseReference walks the loaded use case library and emits a
// condensed catalog. Custom use cases (UC-CUSTOM-*) appear under a separate
// section so they're easy to spot.
func buildUseCaseReference(lib *usecases.Library) string {
	var b strings.Builder
	b.WriteString("Use Case Reference\n\n")
	if lib == nil {
		b.WriteString("(use case library unavailable)\n")
		return b.String()
	}
	groups := groupUseCases(lib.All())
	for _, g := range groups {
		if len(g.items) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s\n", g.label)
		b.WriteString("─────────────────────────────────────\n")
		for _, uc := range g.items {
			fmt.Fprintf(&b, "%-12s %-44s %s\n",
				uc.ID, truncate(uc.Name, 44), uc.Severity)
			if uc.Description != "" {
				wrapped := wrap(uc.Description, 60)
				for _, line := range wrapped {
					fmt.Fprintf(&b, "  %s\n", line)
				}
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

type ucGroup struct {
	label string
	items []*usecases.UseCase
}

func groupUseCases(all []*usecases.UseCase) []ucGroup {
	groups := []ucGroup{
		{label: "WINDOWS INVESTIGATIONS"},
		{label: "LINUX INVESTIGATIONS"},
		{label: "CROSS-PLATFORM"},
		{label: "CUSTOM"},
	}
	for _, uc := range all {
		switch {
		case strings.HasPrefix(uc.ID, "UC-WIN-"):
			groups[0].items = append(groups[0].items, uc)
		case strings.HasPrefix(uc.ID, "UC-LNX-"):
			groups[1].items = append(groups[1].items, uc)
		case strings.HasPrefix(uc.ID, "UC-XP-"):
			groups[2].items = append(groups[2].items, uc)
		case strings.HasPrefix(uc.ID, "UC-CUSTOM-"):
			groups[3].items = append(groups[3].items, uc)
		}
	}
	return groups
}

// buildMITREReference renders mitre.Techniques grouped by tactic in
// kill-chain order.
func buildMITREReference() string {
	var b strings.Builder
	b.WriteString("MITRE ATT&CK Reference\n\n")
	b.WriteString("Techniques recognised by VanGuard's detectors and report builder.\n")
	b.WriteString("Add to internal/mitre/techniques.go to extend this catalog.\n\n")

	// Group Techniques map by tactic.
	byTactic := map[mitre.Tactic][]mitre.Technique{}
	for _, t := range mitre.Techniques {
		byTactic[t.Tactic] = append(byTactic[t.Tactic], t)
	}

	for _, tactic := range mitre.TacticOrder {
		entries := byTactic[tactic]
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].ID < entries[j].ID
		})
		fmt.Fprintf(&b, "%s\n", strings.ToUpper(string(tactic)))
		b.WriteString("─────────────────────────────────────\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "  %-12s %s\n", e.ID, e.Name)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// buildAboutPage stitches version + runtime info into the About page.
func buildAboutPage(version, buildDate, commit, platform string) string {
	if buildDate == "" {
		buildDate = "unknown"
	}
	if commit == "" {
		commit = "unknown"
	}
	if version == "" {
		version = "dev"
	}
	if platform == "" {
		platform = runtime.GOOS
	}
	return fmt.Sprintf(`VANGUARD — Enterprise DFIR Toolkit
Version: %s (built %s, commit %s)

Developed by RidgeLine Cyber
https://ridgelinecyber.com

Training: https://training.ridgelinecyber.com

VanGuard is a cross-platform incident response toolkit designed
for enterprise DFIR operations in connected, isolated, and
air-gapped environments.

Built with:
  Go %s
  bubbletea (terminal UI)
  Velociraptor (primary IR capability)
  SQLite (case management)

Platform: %s (%s)
`,
		version, buildDate, commit,
		runtime.Version(),
		platform, runtime.GOARCH)
}

// ---------------------------------------------------------------------------
// Tiny formatting helpers — reused by the dynamic builders.
// ---------------------------------------------------------------------------

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

// wrap splits s into lines no wider than width, honouring existing newlines.
func wrap(s string, width int) []string {
	var out []string
	for _, raw := range strings.Split(s, "\n") {
		words := strings.Fields(raw)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		var cur strings.Builder
		for _, w := range words {
			if cur.Len()+len(w)+1 > width && cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			if cur.Len() > 0 {
				cur.WriteByte(' ')
			}
			cur.WriteString(w)
		}
		if cur.Len() > 0 {
			out = append(out, cur.String())
		}
	}
	return out
}
