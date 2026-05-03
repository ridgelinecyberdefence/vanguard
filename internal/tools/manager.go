package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

// Tool categories.
const (
	CategoryCollection = "collection"
	CategoryAnalysis   = "analysis"
	CategoryDetection  = "detection"
	CategoryRules      = "rules"
)

// DownloadMethod identifies how a tool's payload is fetched.
//
//   - DownloadGitHubRelease — picks an asset from the latest GitHub release and
//     extracts the configured ExpectedBinary.
//   - DownloadRepoArchive — fetches the entire repo as
//     /{owner}/{repo}/archive/refs/heads/{branch}.zip and lays its contents
//     into LocalPath. Used for rule-set repositories that don't publish
//     release binaries.
//   - DownloadManual — no automated download; user must place files themselves.
const (
	DownloadGitHubRelease = "github_release"
	DownloadRepoArchive   = "repo_archive"
	DownloadManual        = "manual"
)

// CategoryOrder defines the display order for tool categories.
var CategoryOrder = []string{CategoryCollection, CategoryAnalysis, CategoryDetection, CategoryRules}

// CategoryLabels maps category IDs to display names.
var CategoryLabels = map[string]string{
	CategoryCollection: "COLLECTION",
	CategoryAnalysis:   "ANALYSIS",
	CategoryDetection:  "DETECTION",
	CategoryRules:      "RULES",
}

// Tool describes a single external DFIR dependency.
type Tool struct {
	Name             string `json:"name"`
	ID               string `json:"id"`
	Description      string `json:"description"`
	Category         string `json:"category"` // "collection", "analysis", "detection", or "rules"
	Platform         string `json:"platform"` // "windows", "linux", or "both"
	Required         bool   `json:"required"`
	GitHubRepo       string `json:"github_repo"`       // "owner/repo" — empty for manual-placement tools
	AssetPattern     string `json:"asset_pattern"`      // regex matched against release asset filenames
	ExpectedBinary   string `json:"expected_binary"`    // final binary name after download
	LocalPath        string `json:"local_path"`         // relative to VanGuard root
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	SHA256           string `json:"sha256"`           // current on-disk hash (set by ScanInstalled)
	InstalledSHA256  string `json:"installed_sha256"` // hash captured at download time
	Modified         bool   `json:"modified,omitempty"` // true when SHA256 != InstalledSHA256
	License          string `json:"license"`
	LicenseURL       string `json:"license_url"`
	// IndicatorFile is an optional file to check inside directory-based tools
	// (e.g., "MFTECmd.exe" for ez-tools). If set and LocalPath is a directory,
	// ScanInstalled checks for this file instead of just any file.
	IndicatorFile string `json:"indicator_file,omitempty"`

	// DownloadMethod selects how the tool's payload is fetched. Empty defaults
	// to DownloadGitHubRelease for backward compatibility with existing entries.
	DownloadMethod string `json:"download_method,omitempty"`

	// RepoBranch is the branch used by DownloadRepoArchive. Defaults to "main".
	RepoBranch string `json:"repo_branch,omitempty"`
}

// resolveDownloadMethod returns the effective download method for a tool.
// Empty GitHubRepo is always treated as manual; an unset DownloadMethod with a
// GitHubRepo defaults to github_release.
func resolveDownloadMethod(t *Tool) string {
	if t.GitHubRepo == "" {
		return DownloadManual
	}
	switch t.DownloadMethod {
	case DownloadRepoArchive, DownloadManual, DownloadGitHubRelease:
		return t.DownloadMethod
	}
	return DownloadGitHubRelease
}

// resolveBranch returns the branch to use for archive downloads.
func resolveBranch(t *Tool) string {
	if t.RepoBranch != "" {
		return t.RepoBranch
	}
	return "main"
}

// ToolStatus is a lightweight summary for TUI display.
type ToolStatus struct {
	Name        string
	ID          string
	Category    string
	Installed   bool
	Required    bool
	Manual      bool // true when GitHubRepo is empty (manual install only)
	Modified    bool // true when on-disk SHA256 differs from the captured InstalledSHA256
	Version     string
	Path        string
	Description string
}

// ToolUpdate describes an available update for an installed tool.
type ToolUpdate struct {
	ID             string
	Name           string
	CurrentVersion string
	LatestVersion  string
	DownloadURL    string
	AssetName      string
	AssetSize      int64
}

// ---------------------------------------------------------------------------
// Default tool registry
// ---------------------------------------------------------------------------

// DefaultTools contains every known external dependency across both platforms.
var DefaultTools = []Tool{
	// ── Windows collection tools ─────────────────────────────────────────
	{
		Name:           "Velociraptor",
		ID:             "velociraptor-win",
		Description:    "Endpoint visibility and DFIR at scale",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "Velocidex/velociraptor",
		AssetPattern:   `velociraptor-v.*-windows-amd64\.exe$`,
		ExpectedBinary: "velociraptor.exe",
		LocalPath:      "bin/windows/velociraptor.exe",
		License:        "AGPL-3.0",
		LicenseURL:     "https://github.com/Velocidex/velociraptor/blob/master/LICENSE",
	},
	{
		Name:           "KAPE",
		ID:             "kape-win",
		Description:    "Kroll Artifact Parser and Extractor (manual placement required)",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "kape.exe",
		LocalPath:      "bin/windows/kape/kape.exe",
		License:        "Commercial",
		LicenseURL:     "https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape",
	},
	{
		Name:           "WinPmem",
		ID:             "winpmem",
		Description:    "Physical memory acquisition for Windows",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "Velocidex/WinPmem",
		AssetPattern:   `winpmem_mini_x64.*\.exe$`,
		ExpectedBinary: "winpmem.exe",
		LocalPath:      "bin/windows/winpmem.exe",
		License:        "Apache-2.0",
		LicenseURL:     "https://github.com/Velocidex/WinPmem/blob/master/LICENSE",
	},
	{
		Name:           "DumpIt",
		ID:             "dumpit-win",
		Description:    "Memory acquisition tool (commercial, manual placement required)",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "",
		DownloadMethod: DownloadManual,
		ExpectedBinary: "dumpit.exe",
		LocalPath:      "bin/windows/dumpit.exe",
		License:        "Commercial",
		LicenseURL:     "https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/",
	},
	{
		Name:           "Belkasoft RAM Capturer",
		ID:             "belkasoft_ram",
		Description:    "Free memory capture tool. Download from https://belkasoft.com/ram-capturer",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "",
		DownloadMethod: DownloadManual,
		ExpectedBinary: "RamCapture64.exe",
		LocalPath:      "bin/windows/belkasoft/RamCapture64.exe",
		License:        "Freeware",
		LicenseURL:     "https://belkasoft.com/ram-capturer",
	},
	{
		Name:           "Magnet RAM Capture",
		ID:             "magnet_ram",
		Description:    "Free memory capture tool. Download from https://www.magnetforensics.com/resources/magnet-ram-capture/",
		Category:       CategoryCollection,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "",
		DownloadMethod: DownloadManual,
		ExpectedBinary: "MagnetRAMCapture.exe",
		LocalPath:      "bin/windows/magnet/MagnetRAMCapture.exe",
		License:        "Freeware",
		LicenseURL:     "https://www.magnetforensics.com/resources/magnet-ram-capture/",
	},

	// ── Windows analysis tools ───────────────────────────────────────────
	{
		Name:           "Chainsaw",
		ID:             "chainsaw-win",
		Description:    "Rapidly search and hunt through Windows forensic artefacts",
		Category:       CategoryAnalysis,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "WithSecureLabs/chainsaw",
		AssetPattern:   `chainsaw_x86_64-pc-windows-msvc\.zip$`,
		ExpectedBinary: "chainsaw.exe",
		// Lives in its own subdirectory so the bundled rules/ and
		// mappings/ trees from the release archive sit next to the
		// binary — Chainsaw resolves them relative to argv[0].
		LocalPath:      "bin/windows/chainsaw/chainsaw.exe",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/WithSecureLabs/chainsaw/blob/master/LICENCE",
	},
	{
		Name:           "EZ Tools",
		ID:             "eztools-win",
		Description:    "Eric Zimmerman forensic parsers (MFTECmd, EvtxECmd, PECmd, RECmd, AmcacheParser, etc). Download from https://ericzimmerman.github.io",
		Category:       CategoryAnalysis,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "",
		ExpectedBinary: "",
		LocalPath:      "bin/windows/ez-tools/",
		License:        "MIT",
		LicenseURL:     "https://ericzimmerman.github.io",
		IndicatorFile:  "MFTECmd.exe",
	},
	{
		Name:           "Volatility3",
		ID:             "volatility3-win",
		Description:    "Memory analysis framework. Requires Python3 (system or lib/python-embedded/).",
		Category:       CategoryAnalysis,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "volatilityfoundation/volatility3",
		DownloadMethod: DownloadRepoArchive,
		RepoBranch:     "stable",
		ExpectedBinary: "",
		LocalPath:      "lib/volatility3/",
		License:        "VSL",
		LicenseURL:     "https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt",
	},
	{
		// Pseudo-tool: Python3 is detected, never downloaded by VanGuard. We
		// surface it in the status table so users can see at a glance whether
		// their Volatility3 install will actually run.
		Name:           "Python3",
		ID:             "python3-win",
		Description:    "Python 3 interpreter — required by Volatility3. Detected from lib/python-embedded/ or system PATH.",
		Category:       CategoryAnalysis,
		Platform:       "windows",
		Required:       false,
		GitHubRepo:     "",
		DownloadMethod: DownloadManual,
		ExpectedBinary: "",
		LocalPath:      "(system PATH or lib/python-embedded/)",
		License:        "PSF",
		LicenseURL:     "https://docs.python.org/3/license.html",
	},

	// ── Windows detection tools ──────────────────────────────────────────
	{
		Name:           "Hayabusa",
		ID:             "hayabusa-win",
		Description:    "Windows event log fast forensics timeline generator",
		Category:       CategoryDetection,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "Yamato-Security/hayabusa",
		AssetPattern:   `hayabusa-.*-win-x64\.zip$`,
		ExpectedBinary: "hayabusa.exe",
		// Lives in its own subdirectory so the post-install
		// `hayabusa update-rules` deposits its rules/ + config/
		// trees next to the binary, where Hayabusa expects them.
		LocalPath:      "bin/windows/hayabusa/hayabusa.exe",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt",
	},
	{
		Name:           "Loki",
		ID:             "loki-win",
		Description:    "IOC and YARA scanner for compromise assessment",
		Category:       CategoryDetection,
		Platform:       "windows",
		Required:       true,
		GitHubRepo:     "Neo23x0/Loki2",
		AssetPattern:   `loki-windows-x86_64-v.*\.zip$`,
		ExpectedBinary: "loki.exe",
		LocalPath:      "bin/windows/loki/loki.exe",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/Neo23x0/Loki2/blob/master/LICENSE",
	},

	// ── Linux collection tools ───────────────────────────────────────────
	{
		Name:           "Velociraptor",
		ID:             "velociraptor-lnx",
		Description:    "Endpoint visibility and DFIR at scale",
		Category:       CategoryCollection,
		Platform:       "linux",
		Required:       true,
		GitHubRepo:     "Velocidex/velociraptor",
		AssetPattern:   `velociraptor-v.*-linux-amd64$`,
		ExpectedBinary: "velociraptor",
		LocalPath:      "bin/linux/velociraptor",
		License:        "AGPL-3.0",
		LicenseURL:     "https://github.com/Velocidex/velociraptor/blob/master/LICENSE",
	},
	{
		Name:           "AVML",
		ID:             "avml-lnx",
		Description:    "Acquire volatile memory from Linux systems",
		Category:       CategoryCollection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "microsoft/avml",
		AssetPattern:   `avml-.*-linux-musl$`,
		ExpectedBinary: "avml",
		LocalPath:      "bin/linux/avml",
		License:        "MIT",
		LicenseURL:     "https://github.com/microsoft/avml/blob/main/LICENSE",
	},
	{
		Name:           "UAC",
		ID:             "uac-lnx",
		Description:    "Unix-like Artifacts Collector for live forensics",
		Category:       CategoryCollection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "tclahr/uac",
		AssetPattern:   `uac-.*\.tar\.gz$`,
		ExpectedBinary: "uac",
		LocalPath:      "bin/linux/uac/",
		License:        "Apache-2.0",
		LicenseURL:     "https://github.com/tclahr/uac/blob/main/LICENSE",
	},
	{
		Name:           "dc3dd",
		ID:             "dc3dd-lnx",
		Description:    "Forensic disk imaging. Install via: apt install dc3dd",
		Category:       CategoryCollection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "dc3dd",
		LocalPath:      "bin/linux/dc3dd",
		License:        "GPL-3.0",
	},
	{
		Name:           "LiME",
		ID:             "lime-lnx",
		Description:    "Linux Memory Extractor kernel module. Must be compiled for target kernel.",
		Category:       CategoryCollection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "lime.ko",
		LocalPath:      "bin/linux/lime.ko",
		License:        "GPL-2.0",
		LicenseURL:     "https://github.com/504ensicsLabs/LiME/blob/master/LICENSE",
	},

	// ── Linux analysis tools ─────────────────────────────────────────────
	{
		Name:           "Chainsaw",
		// chainsaw-lnx ships its rules/+mappings/ inside a release
		// tarball — kept in its own subdirectory for the same reason
		// as the Windows entry above.
		ID:             "chainsaw-lnx",
		Description:    "Rapidly search and hunt through Windows forensic artefacts",
		Category:       CategoryAnalysis,
		Platform:       "linux",
		Required:       true,
		GitHubRepo:     "WithSecureLabs/chainsaw",
		AssetPattern:   `chainsaw_x86_64-unknown-linux-musl\.tar\.gz$`,
		ExpectedBinary: "chainsaw",
		LocalPath:      "bin/linux/chainsaw/chainsaw",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/WithSecureLabs/chainsaw/blob/master/LICENCE",
	},
	{
		Name:           "Volatility3",
		ID:             "volatility3-lnx",
		Description:    "Memory analysis framework. Requires Python3 (system or lib/python-embedded/).",
		Category:       CategoryAnalysis,
		Platform:       "linux",
		Required:       true,
		GitHubRepo:     "volatilityfoundation/volatility3",
		DownloadMethod: DownloadRepoArchive,
		RepoBranch:     "stable",
		ExpectedBinary: "",
		LocalPath:      "lib/volatility3/",
		License:        "VSL",
		LicenseURL:     "https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt",
	},
	{
		Name:           "Python3",
		ID:             "python3-lnx",
		Description:    "Python 3 interpreter — required by Volatility3. Detected from lib/python-embedded/ or system PATH.",
		Category:       CategoryAnalysis,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		DownloadMethod: DownloadManual,
		ExpectedBinary: "",
		LocalPath:      "(system PATH)",
		License:        "PSF",
		LicenseURL:     "https://docs.python.org/3/license.html",
	},
	{
		Name:           "AVML-convert",
		ID:             "avml-convert-lnx",
		Description:    "Convert AVML snapshots to other formats for Volatility3",
		Category:       CategoryAnalysis,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "microsoft/avml",
		AssetPattern:   `avml-convert$`,
		ExpectedBinary: "avml-convert",
		LocalPath:      "bin/linux/avml-convert",
		License:        "MIT",
		LicenseURL:     "https://github.com/microsoft/avml/blob/main/LICENSE",
	},
	{
		Name:           "plaso",
		ID:             "plaso-lnx",
		Description:    "Super timeline generation. Install via: pip install plaso",
		Category:       CategoryAnalysis,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "",
		LocalPath:      "lib/plaso/",
		License:        "Apache-2.0",
		LicenseURL:     "https://github.com/log2timeline/plaso/blob/main/LICENSE",
	},

	// ── Linux detection tools ────────────────────────────────────────────
	{
		Name:           "Hayabusa",
		ID:             "hayabusa-lnx",
		Description:    "Windows event log fast forensics timeline generator",
		Category:       CategoryDetection,
		Platform:       "linux",
		Required:       true,
		GitHubRepo:     "Yamato-Security/hayabusa",
		AssetPattern:   `hayabusa-.*-lin-x64-musl\.zip$`,
		ExpectedBinary: "hayabusa",
		LocalPath:      "bin/linux/hayabusa/hayabusa",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/Yamato-Security/hayabusa/blob/main/LICENSE.txt",
	},
	{
		Name:           "Loki",
		ID:             "loki-lnx",
		Description:    "IOC and YARA scanner for compromise assessment",
		Category:       CategoryDetection,
		Platform:       "linux",
		Required:       true,
		GitHubRepo:     "Neo23x0/Loki2",
		AssetPattern:   `loki-linux-x86_64-v.*\.tar\.gz$`,
		ExpectedBinary: "loki",
		LocalPath:      "bin/linux/loki/loki",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/Neo23x0/Loki2/blob/master/LICENSE",
	},
	{
		Name:           "chkrootkit",
		ID:             "chkrootkit-lnx",
		Description:    "Rootkit detector. Install via: apt install chkrootkit",
		Category:       CategoryDetection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "chkrootkit",
		LocalPath:      "bin/linux/chkrootkit",
		License:        "BSD-2-Clause",
	},
	{
		Name:           "rkhunter",
		ID:             "rkhunter-lnx",
		Description:    "Rootkit hunter. Install via: apt install rkhunter",
		Category:       CategoryDetection,
		Platform:       "linux",
		Required:       false,
		GitHubRepo:     "",
		ExpectedBinary: "rkhunter",
		LocalPath:      "bin/linux/rkhunter",
		License:        "GPL-2.0",
		LicenseURL:     "https://rkhunter.sourceforge.net",
	},

	// ── Cross-platform rules ────────────────────────────────────────────
	// Rule sets are git repositories — they don't publish release binaries.
	// They use DownloadRepoArchive to fetch /{repo}/archive/refs/heads/{branch}.zip
	// and lay the contents directly into LocalPath.
	{
		Name:        "Sigma Rules",
		ID:          "sigma-rules",
		Description: "Generic signature format for SIEM systems",
		Category:    CategoryRules,
		Platform:    "both",
		Required:    true,
		// SigmaHQ/core is referenced in some docs but does not exist on GitHub —
		// the canonical maintained set lives at SigmaHQ/sigma (master branch).
		GitHubRepo:     "SigmaHQ/sigma",
		DownloadMethod: DownloadRepoArchive,
		RepoBranch:     "master",
		ExpectedBinary: "",
		LocalPath:      "rules/sigma/",
		License:        "DRL-1.1",
		LicenseURL:     "https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md",
	},
	{
		Name:           "YARA Rules",
		ID:             "yara-rules",
		Description:    "Community YARA rules collection",
		Category:       CategoryRules,
		Platform:       "both",
		Required:       false,
		GitHubRepo:     "Yara-Rules/rules",
		DownloadMethod: DownloadRepoArchive,
		RepoBranch:     "master",
		ExpectedBinary: "",
		LocalPath:      "rules/yara/",
		License:        "GPL-2.0",
		LicenseURL:     "https://github.com/Yara-Rules/rules/blob/master/LICENSE",
	},
	{
		Name:           "Hayabusa Rules",
		ID:             "hayabusa-rules",
		Description:    "Detection rules for Hayabusa event log analyzer",
		Category:       CategoryRules,
		Platform:       "both",
		Required:       true,
		GitHubRepo:     "Yamato-Security/hayabusa-rules",
		DownloadMethod: DownloadRepoArchive,
		RepoBranch:     "main",
		ExpectedBinary: "",
		LocalPath:      "rules/hayabusa/",
		License:        "GPL-3.0",
		LicenseURL:     "https://github.com/Yamato-Security/hayabusa-rules/blob/main/LICENSE.txt",
	},
}

// ---------------------------------------------------------------------------
// GitHub API types
// ---------------------------------------------------------------------------

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Name    string        `json:"name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	ContentType        string `json:"content_type"`
}

// ---------------------------------------------------------------------------
// ToolManager
// ---------------------------------------------------------------------------

// ToolManager handles discovery, download, and verification of external tools.
type ToolManager struct {
	tools       []Tool
	rootDir     string
	platform    string
	logger      *logging.Logger
	httpClient  *http.Client
	githubToken string // optional PAT for higher API rate limits
	version     string // version string used in User-Agent header
}

// NewToolManager creates a manager initialised with tools filtered for the
// current platform.
func NewToolManager(rootDir, platform string, logger *logging.Logger) *ToolManager {
	filtered := make([]Tool, 0, len(DefaultTools))
	for _, t := range DefaultTools {
		if t.Platform == platform || t.Platform == "both" {
			filtered = append(filtered, t)
		}
	}

	return &ToolManager{
		tools:    filtered,
		rootDir:  rootDir,
		platform: platform,
		logger:   logger,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SetGitHubToken records a PAT used to authenticate API + asset-download
// requests. Empty disables auth (anonymous, 60 req/hr). The token is stored
// in memory only; callers source it from VANGUARD_GITHUB_TOKEN or the
// vanguard.yaml github.token field.
func (m *ToolManager) SetGitHubToken(token string) {
	m.githubToken = token
}

// SetVersion records the VanGuard version string for the GitHub User-Agent
// header. Helps Anthropic / GitHub support identify the source of API
// traffic when investigating rate-limit reports.
func (m *ToolManager) SetVersion(v string) {
	m.version = v
}

// applyGitHubAuth attaches the User-Agent header (always) and the
// Authorization header (when a token is configured) to a GitHub-bound
// request. Centralising this means every API + download path gets the same
// auth treatment automatically.
//
// SECURITY: The token is NEVER logged. logger.go's redaction filter also
// strips VANGUARD_GITHUB_TOKEN= patterns as a catch-net.
func (m *ToolManager) applyGitHubAuth(req *http.Request) {
	ua := "VanGuard-DFIR-Toolkit"
	if m.version != "" {
		ua = "VanGuard-DFIR/" + m.version
	}
	req.Header.Set("User-Agent", ua)
	if m.githubToken != "" {
		req.Header.Set("Authorization", "token "+m.githubToken)
	}
}

// rateLimitMessage formats a friendly rate-limit error from a 403 response,
// including the reset timestamp and instructions for raising the ceiling.
func rateLimitMessage(resp *http.Response) string {
	resetUnix := resp.Header.Get("X-RateLimit-Reset")
	resetStr := "unknown"
	if resetUnix != "" {
		if ts, err := strconv.ParseInt(resetUnix, 10, 64); err == nil {
			resetStr = time.Unix(ts, 0).Local().Format("15:04:05 MST")
		}
	}
	return fmt.Sprintf(
		"GitHub API rate limit reached. Resets at %s.\n"+
			"To increase rate limit, set a GitHub personal access token:\n"+
			"  • Environment variable: VANGUARD_GITHUB_TOKEN=ghp_yourtoken\n"+
			"  • Or in config/vanguard.yaml under github.token\n"+
			"No special scopes needed — public repo access only.",
		resetStr)
}

// ---------------------------------------------------------------------------
// Scanning & status
// ---------------------------------------------------------------------------

// ScanInstalled checks which tools exist on disk and computes their SHA256.
//
// Detection is intentionally permissive: many users hand-install KAPE / DumpIt /
// EZ Tools to slightly different paths than the canonical LocalPath (e.g.
// nested directories left behind by archive extraction, mismatched casing).
// We try the configured path first, then fall back to per-tool alternates,
// then to a recursive case-insensitive search of the parent directory.
func (m *ToolManager) ScanInstalled() []Tool {
	for i := range m.tools {
		t := &m.tools[i]

		// Python3 — detection-only pseudo-tool. We discover the interpreter
		// rather than checking for a file at LocalPath, then store the resolved
		// path on the Tool so the status table can show where it lives.
		if strings.HasPrefix(t.ID, "python3-") {
			if info, ok := DetectPython(m.rootDir); ok {
				t.Installed = true
				t.LocalPath = info.Path
				t.InstalledVersion = info.Version
				m.logger.Debug("tools", "scan: %s found at %s (%s)", t.Name, info.Path, info.Version)
			} else {
				t.Installed = false
				m.logger.Debug("tools", "scan: %s NOT found in lib/python-embedded/ or PATH", t.Name)
			}
			continue
		}

		absPath := filepath.Join(m.rootDir, filepath.FromSlash(t.LocalPath))

		// Directory-based tools (path ends with "/").
		if strings.HasSuffix(t.LocalPath, "/") {
			t.Installed = m.checkDirTool(t, absPath)
			if t.Installed {
				m.logger.Debug("tools", "scan: %s found (dir-based) at %s", t.Name, absPath)
			} else {
				m.logger.Debug("tools", "scan: %s NOT found (dir-based) — looked at %s", t.Name, absPath)
			}
			continue
		}

		// Single-file tools — use resolveSingleFile so we tolerate different
		// install layouts (case mismatches, nested directories from archive
		// extraction, etc.).
		resolved := m.resolveSingleFile(t, absPath)
		if resolved == "" {
			t.Installed = false
			m.logger.Debug("tools", "scan: %s NOT found — checked configured path and alternates", t.Name)
			continue
		}

		t.Installed = true
		hash, err := computeSHA256(resolved)
		if err == nil {
			t.SHA256 = hash
			// Drift detection: compare current on-disk hash against the one
			// captured at download time. If they differ the binary has been
			// modified (or replaced) — surface as a TUI warning.
			if t.InstalledSHA256 != "" && !strings.EqualFold(hash, t.InstalledSHA256) {
				t.Modified = true
				m.logger.Warn("tools", "scan: %s SHA256 changed since install (was %s, now %s)",
					t.Name, t.InstalledSHA256, hash)
			} else {
				t.Modified = false
			}
		}
		m.logger.Debug("tools", "scan: %s found at %s (sha256=%s)", t.Name, resolved, t.SHA256)
	}

	result := make([]Tool, len(m.tools))
	copy(result, m.tools)
	return result
}

// resolveSingleFile returns the absolute path at which a single-file tool was
// found, or "" if it isn't installed. Callers don't need to mutate LocalPath:
// the registry's canonical path stays as-is, and other code that needs the
// real disk location should call this resolver itself.
//
// Resolution strategy:
//  1. Configured path exactly as-is.
//  2. Case-insensitive lookup at the same parent directory.
//  3. Per-tool alternate paths (KAPE / DumpIt commonly land elsewhere).
//  4. Recursive case-insensitive scan of likely parent directories.
func (m *ToolManager) resolveSingleFile(t *Tool, absPath string) string {
	if fileExists(absPath) {
		return absPath
	}
	if hit := fileExistsCI(absPath); hit != "" {
		m.logger.Debug("tools", "scan: %s — case-insensitive match: %s", t.Name, hit)
		return hit
	}
	for _, alt := range singleFileAlternates(m.rootDir, t) {
		if hit := fileExistsCI(alt); hit != "" {
			m.logger.Debug("tools", "scan: %s — alternate path matched: %s", t.Name, hit)
			return hit
		}
	}
	for _, root := range singleFileSearchRoots(m.rootDir, t) {
		if hit := findBinaryInDir(root, singleFileSearchPatterns(t)); hit != "" {
			m.logger.Debug("tools", "scan: %s — recursive search hit: %s (root %s)", t.Name, hit, root)
			return hit
		}
	}
	return ""
}

// singleFileAlternates returns extra absolute paths to try for a single-file
// tool, beyond its configured LocalPath. Per-tool quirks are encoded by ID so
// hand-installs land where users actually put them.
func singleFileAlternates(rootDir string, t *Tool) []string {
	switch t.ID {
	case "kape-win":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "kape", "KAPE", "kape.exe"),
			filepath.Join(rootDir, "bin", "windows", "KAPE", "kape.exe"),
			filepath.Join(rootDir, "bin", "windows", "KAPE", "KAPE", "kape.exe"),
		}
	case "dumpit-win":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "DumpIt.exe"),
			filepath.Join(rootDir, "bin", "windows", "Dumpit.exe"),
			filepath.Join(rootDir, "bin", "windows", "dumpit", "dumpit.exe"),
			filepath.Join(rootDir, "bin", "windows", "dumpit", "DumpIt.exe"),
			filepath.Join(rootDir, "bin", "windows", "DumpIt", "DumpIt.exe"),
			filepath.Join(rootDir, "bin", "windows", "DumpIt", "dumpit.exe"),
			filepath.Join(rootDir, "bin", "windows", "Dumpit", "DumpIt.exe"),
		}
	case "winpmem":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "WinPmem.exe"),
			filepath.Join(rootDir, "bin", "windows", "winpmem", "winpmem.exe"),
			filepath.Join(rootDir, "bin", "windows", "winpmem_mini_x64.exe"),
		}
	case "belkasoft_ram":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "belkasoft", "RamCapture.exe"),
			filepath.Join(rootDir, "bin", "windows", "belkasoft", "RamCapturex64.exe"),
			filepath.Join(rootDir, "bin", "windows", "Belkasoft", "RamCapture64.exe"),
		}
	case "magnet_ram":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "magnet", "MagnetRAMCapture64.exe"),
			filepath.Join(rootDir, "bin", "windows", "magnet", "MRCv120.exe"),
			filepath.Join(rootDir, "bin", "windows", "Magnet", "MagnetRAMCapture.exe"),
		}
	}
	return nil
}

// singleFileSearchRoots returns directories to recursively search for the
// tool's binary when neither the configured path nor known alternates hit.
func singleFileSearchRoots(rootDir string, t *Tool) []string {
	switch t.ID {
	case "kape-win":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "kape"),
			filepath.Join(rootDir, "bin", "windows", "KAPE"),
		}
	case "dumpit-win":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "dumpit"),
			filepath.Join(rootDir, "bin", "windows", "DumpIt"),
			filepath.Join(rootDir, "bin", "windows", "Dumpit"),
			filepath.Join(rootDir, "bin", "windows"),
		}
	case "winpmem":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "winpmem"),
			filepath.Join(rootDir, "bin", "windows"),
		}
	case "belkasoft_ram":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "belkasoft"),
			filepath.Join(rootDir, "bin", "windows", "Belkasoft"),
		}
	case "magnet_ram":
		return []string{
			filepath.Join(rootDir, "bin", "windows", "magnet"),
			filepath.Join(rootDir, "bin", "windows", "Magnet"),
		}
	case "hayabusa-win":
		return []string{filepath.Join(rootDir, "bin", "windows", "hayabusa")}
	case "hayabusa-lnx":
		return []string{filepath.Join(rootDir, "bin", "linux", "hayabusa")}
	case "loki-win":
		return []string{filepath.Join(rootDir, "bin", "windows", "loki")}
	case "loki-lnx":
		return []string{filepath.Join(rootDir, "bin", "linux", "loki")}
	}
	return nil
}

// singleFileSearchPatterns returns the case-insensitive filename glob patterns
// findBinaryInDir should accept for this tool.
func singleFileSearchPatterns(t *Tool) []string {
	switch t.ID {
	case "kape-win":
		return []string{"kape.exe", "kape*.exe"}
	case "dumpit-win":
		return []string{"dumpit.exe", "dumpit*.exe"}
	case "winpmem":
		return []string{"winpmem.exe", "winpmem*.exe"}
	case "belkasoft_ram":
		return []string{"RamCapture64.exe", "RamCapture.exe", "RamCapturex64.exe", "RamCapture*.exe"}
	case "magnet_ram":
		return []string{"MagnetRAMCapture.exe", "MagnetRAMCapture64.exe", "MRCv*.exe", "MagnetRAM*.exe"}
	// Hayabusa releases ship a versioned binary (hayabusa-2.18.0-win-x64.exe).
	// Accept the canonical name first, then the versioned pattern as fallback.
	case "hayabusa-win":
		return []string{"hayabusa.exe", "hayabusa*.exe"}
	case "hayabusa-lnx":
		return []string{"hayabusa", "hayabusa-*"}
	// Loki releases ship loki.exe (or loki-windows-x86_64.exe on older tags).
	// Accept both the canonical name and the versioned pattern.
	case "loki-win":
		return []string{"loki.exe", "loki*.exe"}
	case "loki-lnx":
		return []string{"loki", "loki-*"}
	}
	if t.ExpectedBinary != "" {
		return []string{t.ExpectedBinary}
	}
	return nil
}

// checkDirTool checks whether a directory-based tool is installed.
//
// The check tries the configured directory first, then a small set of
// per-tool alternate directories (different casing or nested layouts left by
// archive extraction), then falls back to "directory exists and contains at
// least one executable file" for tools without a stricter rule.
func (m *ToolManager) checkDirTool(t *Tool, absPath string) bool {
	// Volatility3 — check several markers that indicate a working install.
	if strings.Contains(t.ID, "volatility3") {
		baseDir := filepath.Join(m.rootDir, "lib", "volatility3")
		m.logger.Info("tools", "volatility3 scan: configured LocalPath=%s absPath=%s baseDir=%s",
			t.LocalPath, absPath, baseDir)
		if info, err := os.Stat(baseDir); err == nil {
			m.logger.Info("tools", "volatility3 scan: %s exists (isDir=%v)", baseDir, info.IsDir())
			if entries, err := os.ReadDir(baseDir); err == nil {
				names := make([]string, 0, len(entries))
				for _, e := range entries {
					tag := "file"
					if e.IsDir() {
						tag = "dir"
					}
					names = append(names, fmt.Sprintf("%s(%s)", e.Name(), tag))
				}
				m.logger.Info("tools", "volatility3 scan: lib/volatility3/ contains: %s",
					strings.Join(names, ", "))
			}
		} else {
			m.logger.Info("tools", "volatility3 scan: %s does not exist (%v)", baseDir, err)
		}

		dirs := dedupe([]string{absPath, baseDir})
		for _, d := range dirs {
			if hit := volatilityMarker(d); hit != "" {
				m.logger.Info("tools", "volatility3 scan: vol.py / marker found at %s", hit)
				return true
			}
		}
		// Last-resort: ask Python.
		if pythonHasVolatility(m.logger) {
			m.logger.Info("tools", "volatility3 scan: python -c 'import volatility3' succeeded")
			return true
		}
		m.logger.Info("tools", "volatility3 scan: vol.py NOT found at any searched location")
		return false
	}

	// plaso — pip / source layouts both work.
	if strings.Contains(t.ID, "plaso") {
		if fileExistsCI(filepath.Join(absPath, "log2timeline")) != "" ||
			fileExistsCI(filepath.Join(absPath, "psteal.py")) != "" {
			return true
		}
		return dirHasFiles(absPath)
	}

	// EZ Tools — accept the configured dir or any of the common alternates,
	// and look for ANY of the indicator binaries (MFTECmd / EvtxECmd / PECmd).
	if strings.Contains(t.ID, "eztools") {
		patterns := []string{"MFTECmd.exe", "EvtxECmd.exe", "PECmd.exe"}
		dirs := []string{
			absPath,
			filepath.Join(m.rootDir, "bin", "windows", "EZTools"),
			filepath.Join(m.rootDir, "bin", "windows", "EZTools", "net6"),
			filepath.Join(m.rootDir, "bin", "windows", "EZTools", "net9"),
			filepath.Join(absPath, "net6"),
			filepath.Join(absPath, "net9"),
		}
		for _, d := range dedupe(dirs) {
			if hit := findBinaryInDir(d, patterns); hit != "" {
				m.logger.Debug("tools", "scan: %s — indicator hit: %s", t.Name, hit)
				return true
			}
		}
		return false
	}

	// Tools with a specific indicator file — case-insensitive lookup.
	if t.IndicatorFile != "" {
		if hit := fileExistsCI(filepath.Join(absPath, t.IndicatorFile)); hit != "" {
			return true
		}
		// Fall through to the generic "directory has files" check below; if
		// the user dropped a renamed binary in, we'll still catch it.
	}

	// Generic — directory exists AND contains at least one file (any depth one).
	return dirHasFiles(absPath)
}

// dedupe returns a slice with adjacent / repeated entries removed (preserving
// order). Used so we don't double-scan the same path when alternates collapse
// onto the configured one.
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// volatilityMarker checks dir for any of the markers that indicate a working
// Volatility3 install. Returns the matched path or "".
//
// Detection is permissive across these layouts:
//   - Top-level: dir/vol.py, dir/volatility3/__init__.py
//   - GitHub-archive nested: dir/volatility3-{branch}/vol.py
//   - Pip / source: dir/pyinstaller, dir/vol3, dir/vol.exe
//   - Generic: any one-level-deep subdir containing vol.py
func volatilityMarker(dir string) string {
	// 1. Direct hits at the configured directory.
	candidates := []string{
		filepath.Join(dir, "vol.py"),
		filepath.Join(dir, "setup.py"), // source layout where setup.py marks the package root
		filepath.Join(dir, "volatility3", "__init__.py"),
		filepath.Join(dir, "volatility3"), // source layout
		filepath.Join(dir, "pyinstaller"),
		filepath.Join(dir, "vol3"),
		filepath.Join(dir, "vol3.exe"),
		filepath.Join(dir, "vol.exe"),
	}
	for _, p := range candidates {
		if hit := fileExistsCI(p); hit != "" {
			return hit
		}
		if dirExists(p) {
			return p
		}
	}

	// 2. Glob: any one-level-deep subdir containing vol.py or setup.py.
	// Catches every GitHub-archive layout (volatility3-stable/,
	// volatility3-2.7.0/, etc.) without us having to enumerate names.
	for _, pat := range []string{"vol.py", "setup.py", "volatility3/__init__.py"} {
		if matches, err := filepath.Glob(filepath.Join(dir, "*", pat)); err == nil && len(matches) > 0 {
			return matches[0]
		}
	}

	// 3. Generic: walk one level deep looking for vol.py inside any subdir
	// (case-insensitive). This is a last-resort safety net.
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if hit := fileExistsCI(filepath.Join(dir, e.Name(), "vol.py")); hit != "" {
				return hit
			}
		}
	}

	return ""
}

// pythonHasVolatility runs `python3 -c "import volatility3"` (falling back to
// `python`) and returns true on success. Used as a last-resort detection
// strategy for system-wide pip installs.
func pythonHasVolatility(logger *logging.Logger) bool {
	for _, exe := range []string{"python3", "python"} {
		path, err := exec.LookPath(exe)
		if err != nil {
			continue
		}
		cmd := exec.Command(path, "-c", "import volatility3")
		if err := cmd.Run(); err == nil {
			return true
		}
		if logger != nil {
			logger.Debug("tools", "scan: %s -c 'import volatility3' failed", exe)
		}
	}
	return false
}

// PythonInfo describes a usable Python 3 interpreter.
type PythonInfo struct {
	// Path is the executable to invoke. For `py -3` discovery this is the
	// launcher itself (e.g. "C:\Windows\py.exe").
	Path string
	// Args is the argv prefix that must be passed before the script. Non-empty
	// only for `py -3` (Args = ["-3"]).
	Args []string
	// Version is the interpreter's "Python X.Y.Z" string, when detected.
	Version string
}

// DetectPython locates a working Python 3 interpreter for use by Volatility3
// / other VanGuard analysis tools. Strategy in priority order:
//
//   1. lib/python-embedded/python.exe (VanGuard's bundled portable Python).
//   2. Common installer locations on the host OS (Python.org, Anaconda /
//      Miniconda, Chocolatey, Scoop, MSYS2, Homebrew).
//   3. PATH lookup via `where` / `which` — but every candidate is verified
//      with `-c "import sys; print(sys.version_info.major)"` so the
//      Microsoft Store stub at AppData\Local\Microsoft\WindowsApps\python.exe
//      (which is a launcher that opens the Store rather than running
//      Python) is rejected.
//   4. `py -3` Python launcher on Windows.
//
// Returns (info, true) on success and (PythonInfo{}, false) otherwise. The
// returned Path can be passed straight to exec.Command, and Args (if any)
// must be the first arguments.
func DetectPython(rootDir string) (PythonInfo, bool) {
	// 1. Bundled portable Python (highest trust — no PATH games).
	if runtime.GOOS == "windows" {
		for _, bundled := range []string{
			filepath.Join(rootDir, "lib", "python-embedded", "python.exe"),
			filepath.Join(rootDir, "lib", "python-embedded", "python3.exe"),
			filepath.Join(rootDir, "lib", "python", "python.exe"),
		} {
			if isRealPython3(bundled) {
				return PythonInfo{Path: bundled, Version: pythonVersion(bundled, nil)}, true
			}
		}
	} else {
		// Allow a Linux portable copy too; less common but cheap to probe.
		for _, bundled := range []string{
			filepath.Join(rootDir, "lib", "python-embedded", "bin", "python3"),
			filepath.Join(rootDir, "lib", "python", "bin", "python3"),
		} {
			if isRealPython3(bundled) {
				return PythonInfo{Path: bundled, Version: pythonVersion(bundled, nil)}, true
			}
		}
	}

	// 2. Common installer locations.
	for _, p := range commonPythonPaths() {
		if isRealPython3(p) {
			return PythonInfo{Path: p, Version: pythonVersion(p, nil)}, true
		}
	}

	// 3. PATH lookup. We use the OS-native `where` / `which` so multiple
	//    candidates surface (LookPath only returns the first), letting us
	//    skip the WindowsApps stub even when it shadows a real install.
	for _, name := range []string{"python3", "python"} {
		for _, path := range whereAll(name) {
			if isRealPython3(path) {
				return PythonInfo{Path: path, Version: pythonVersion(path, nil)}, true
			}
		}
	}

	// 4. py -3 launcher (Windows only). Ask the launcher where Python lives
	//    and target that path directly — bypasses any WindowsApps shim.
	if runtime.GOOS == "windows" {
		if path, err := exec.LookPath("py"); err == nil {
			out, runErr := exec.Command(path, "-3", "-c",
				"import sys; print(sys.executable)").Output()
			if runErr == nil {
				resolved := strings.TrimSpace(string(out))
				if isRealPython3(resolved) {
					return PythonInfo{
						Path:    resolved,
						Version: pythonVersion(resolved, nil),
					}, true
				}
			}
			// Fall back to `py -3 <args>` if we couldn't resolve a concrete
			// path — still better than nothing on locked-down hosts.
			ver := pythonVersion(path, []string{"-3"})
			if strings.HasPrefix(ver, "Python 3") {
				return PythonInfo{Path: path, Args: []string{"-3"}, Version: ver}, true
			}
		}
	}

	return PythonInfo{}, false
}

// commonPythonPaths returns a prioritised list of well-known Python 3
// install locations for the current OS. Order roughly matches "most
// likely to be the analyst's day-to-day interpreter" first.
func commonPythonPaths() []string {
	if runtime.GOOS == "windows" {
		return windowsPythonPaths()
	}
	return unixPythonPaths()
}

func windowsPythonPaths() []string {
	var out []string
	versionsDot := []string{"3.13", "3.12", "3.11", "3.10", "3.9", "3.8"}
	versionsFlat := []string{"313", "312", "311", "310", "39", "38"}

	// Python.org user-level installs (the default since 3.5+).
	if user := os.Getenv("USERPROFILE"); user != "" {
		for _, v := range versionsFlat {
			out = append(out, filepath.Join(user,
				"AppData", "Local", "Programs", "Python",
				"Python"+v, "python.exe"))
		}
		// Anaconda / Miniconda — both casings have shipped over the years.
		for _, dir := range []string{"anaconda3", "miniconda3", "Anaconda3", "Miniconda3"} {
			out = append(out, filepath.Join(user, dir, "python.exe"))
		}
		// Scoop.
		out = append(out, filepath.Join(user,
			"scoop", "apps", "python", "current", "python.exe"))
	}

	// Python.org system-wide / legacy install roots.
	for _, v := range versionsFlat {
		out = append(out,
			"C:\\Python"+v+"\\python.exe")
	}
	out = append(out, "C:\\Python3\\python.exe")

	// Program Files installs (covers 64-bit and 32-bit).
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		pf := os.Getenv(env)
		if pf == "" {
			continue
		}
		for _, v := range versionsFlat {
			out = append(out,
				filepath.Join(pf, "Python"+v, "python.exe"),
				filepath.Join(pf, "Python", "Python"+v, "python.exe"),
			)
		}
		// Also handle the "Python 3.X" (with space) variants.
		for _, v := range versionsDot {
			out = append(out,
				filepath.Join(pf, "Python "+v, "python.exe"),
			)
		}
	}

	// System-wide Anaconda and Chocolatey/MSYS2 fallbacks.
	out = append(out,
		"C:\\Anaconda3\\python.exe",
		"C:\\Miniconda3\\python.exe",
		"C:\\ProgramData\\anaconda3\\python.exe",
		"C:\\ProgramData\\miniconda3\\python.exe",
		"C:\\ProgramData\\chocolatey\\bin\\python3.exe",
		"C:\\ProgramData\\chocolatey\\bin\\python.exe",
		"C:\\msys64\\mingw64\\bin\\python3.exe",
		"C:\\msys64\\usr\\bin\\python3.exe",
	)
	return out
}

func unixPythonPaths() []string {
	out := []string{
		"/usr/local/bin/python3",
		"/usr/bin/python3",
		"/usr/local/bin/python",
		"/usr/bin/python",
		"/opt/homebrew/bin/python3",         // macOS Homebrew on Apple Silicon
		"/usr/local/opt/python3/bin/python3", // macOS Homebrew on Intel
	}
	if home := os.Getenv("HOME"); home != "" {
		// pyenv shim and common conda installs.
		out = append(out,
			filepath.Join(home, ".pyenv", "shims", "python3"),
			filepath.Join(home, "anaconda3", "bin", "python3"),
			filepath.Join(home, "miniconda3", "bin", "python3"),
		)
	}
	return out
}

// whereAll returns every match for `name` on PATH. Equivalent to running
// `where <name>` on Windows and `which -a <name>` elsewhere. Empty slice
// when nothing is found OR when the only match is the Microsoft Store
// stub under WindowsApps (filtered here so callers don't have to).
func whereAll(name string) []string {
	var out []string
	var raw []byte
	var err error
	if runtime.GOOS == "windows" {
		raw, err = exec.Command("where", name).Output()
	} else {
		raw, err = exec.Command("which", "-a", name).Output()
	}
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if isWindowsAppsStub(line) {
				continue
			}
			out = append(out, line)
		}
	}
	// LookPath catches PATHEXT/.bat/.cmd shims which `where` sometimes
	// misses; include it as a final candidate when we got nothing.
	if len(out) == 0 {
		if path, lpErr := exec.LookPath(name); lpErr == nil && !isWindowsAppsStub(path) {
			out = append(out, path)
		}
	}
	return out
}

// isWindowsAppsStub reports whether path points at the Microsoft Store
// "App Execution Alias" launcher in
// %LOCALAPPDATA%\Microsoft\WindowsApps. That file is a 0-byte alias that
// opens the Store rather than running Python; treating it as a real
// interpreter is the regression we're fixing here.
func isWindowsAppsStub(path string) bool {
	return strings.Contains(strings.ToLower(path), `\windowsapps\`) ||
		strings.Contains(strings.ToLower(path), "/windowsapps/")
}

// isRealPython3 returns true when path exists, is not a Microsoft Store
// stub, and successfully prints "3" when asked for sys.version_info.major.
// 5-second cap so a hung interpreter doesn't stall startup.
func isRealPython3(path string) bool {
	if path == "" {
		return false
	}
	if isWindowsAppsStub(path) {
		return false
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-c",
		"import sys; print(sys.version_info.major)").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "3"
}

// pythonVersion returns the trimmed `<exe> [args...] --version` output, or "".
// Python writes the version to stdout (3.4+) so CombinedOutput catches both.
func pythonVersion(exe string, leadingArgs []string) string {
	args := append(append([]string{}, leadingArgs...), "--version")
	out, err := exec.Command(exe, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetStatus returns a lightweight summary of each tool for TUI display.
func (m *ToolManager) GetStatus() []ToolStatus {
	statuses := make([]ToolStatus, len(m.tools))
	for i, t := range m.tools {
		version := t.InstalledVersion
		if !t.Installed {
			version = ""
		}
		statuses[i] = ToolStatus{
			Name:        t.Name,
			ID:          t.ID,
			Category:    t.Category,
			Installed:   t.Installed,
			Required:    t.Required,
			Manual:      resolveDownloadMethod(&m.tools[i]) == DownloadManual,
			Modified:    t.Modified,
			Version:     version,
			Path:        t.LocalPath,
			Description: t.Description,
		}
	}
	return statuses
}

// GetStatusByCategory returns tool statuses grouped by category in display order.
func (m *ToolManager) GetStatusByCategory() []CategoryGroup {
	statuses := m.GetStatus()
	grouped := make(map[string][]ToolStatus)
	for _, s := range statuses {
		grouped[s.Category] = append(grouped[s.Category], s)
	}

	var result []CategoryGroup
	for _, cat := range CategoryOrder {
		if items, ok := grouped[cat]; ok && len(items) > 0 {
			result = append(result, CategoryGroup{
				Category: cat,
				Label:    CategoryLabels[cat],
				Tools:    items,
			})
		}
	}
	return result
}

// CategoryGroup groups tool statuses under a category heading.
type CategoryGroup struct {
	Category string
	Label    string
	Tools    []ToolStatus
}

// CountByCategory returns (installed, total) counts per category.
func (m *ToolManager) CountByCategory() map[string][2]int {
	counts := make(map[string][2]int)
	for _, t := range m.tools {
		c := counts[t.Category]
		c[1]++
		if t.Installed {
			c[0]++
		}
		counts[t.Category] = c
	}
	return counts
}

// Platform returns the platform this manager was initialised for.
func (m *ToolManager) Platform() string { return m.platform }

// GetTool returns a pointer to the tool with the given ID, or nil.
func (m *ToolManager) GetTool(id string) *Tool {
	for i := range m.tools {
		if m.tools[i].ID == id {
			return &m.tools[i]
		}
	}
	return nil
}

// AllTools returns a copy of every registered tool's current state. Used by
// diagnostic views that want to enumerate tools without leaking the manager's
// internal slice.
func (m *ToolManager) AllTools() []Tool {
	out := make([]Tool, len(m.tools))
	copy(out, m.tools)
	return out
}

// ---------------------------------------------------------------------------
// Update checks
// ---------------------------------------------------------------------------

// CheckForUpdates queries GitHub for the latest release of each downloadable
// tool and returns a list of available updates.
func (m *ToolManager) CheckForUpdates() ([]ToolUpdate, error) {
	var updates []ToolUpdate

	for i := range m.tools {
		t := &m.tools[i]
		method := resolveDownloadMethod(t)
		if method != DownloadGitHubRelease {
			// Manual tools and repo archives don't have queryable release tags.
			continue
		}
		// Rule repos don't have binary assets.
		if t.ExpectedBinary == "" {
			continue
		}

		rel, err := m.getLatestRelease(t.GitHubRepo)
		if err != nil {
			m.logger.Warn("tools", "checking updates for %s: %v", t.Name, err)
			continue
		}

		t.LatestVersion = rel.TagName

		if t.InstalledVersion != "" && t.InstalledVersion == rel.TagName {
			continue
		}

		// Find matching asset.
		asset, err := m.matchAsset(rel, t.AssetPattern)
		if err != nil {
			m.logger.Warn("tools", "no matching asset for %s in %s: %v", t.Name, rel.TagName, err)
			continue
		}

		updates = append(updates, ToolUpdate{
			ID:             t.ID,
			Name:           t.Name,
			CurrentVersion: t.InstalledVersion,
			LatestVersion:  rel.TagName,
			DownloadURL:    asset.BrowserDownloadURL,
			AssetName:      asset.Name,
			AssetSize:      asset.Size,
		})
	}

	return updates, nil
}

// ---------------------------------------------------------------------------
// Downloading
// ---------------------------------------------------------------------------

// DownloadTool fetches and installs a single tool by its ID.
func (m *ToolManager) DownloadTool(toolID string) error {
	t := m.GetTool(toolID)
	if t == nil {
		return fmt.Errorf("unknown tool ID: %s", toolID)
	}

	var downloadErr error
	switch resolveDownloadMethod(t) {
	case DownloadManual:
		return fmt.Errorf("%s must be placed manually (no GitHub source)", t.Name)
	case DownloadRepoArchive:
		downloadErr = m.downloadRepoArchive(t)
	case DownloadGitHubRelease:
		downloadErr = m.downloadGitHubRelease(t)
	default:
		return fmt.Errorf("%s: unknown download method %q", t.Name, t.DownloadMethod)
	}
	if downloadErr != nil {
		return downloadErr
	}

	// Post-download verification — warn only, don't fail the download.
	if verifyErr := m.VerifyTool(toolID); verifyErr != nil {
		m.logger.Warn("tools", "%s downloaded but verification failed: %v", t.Name, verifyErr)
	}

	// Tools that need an additional fetch step to be immediately usable.
	switch toolID {
	case "hayabusa-win", "hayabusa-lnx":
		if path := m.GetInstalledPath(toolID); path != "" {
			rulesDir := filepath.Join(filepath.Dir(path), "rules")
			if !dirExists(rulesDir) {
				m.logger.Info("tools", "fetching Hayabusa detection rules…")
				_ = m.ExecuteTool(toolID, []string{"update-rules"}, "")
			}
		}
	case "loki-win", "loki-lnx":
		if path := m.GetInstalledPath(toolID); path != "" {
			m.runLokiUtil(path)
		}
	}
	return nil
}

// verifyChecksumOutcome captures what verifyDownloadChecksum found.
type verifyChecksumOutcome int

const (
	checksumVerified  verifyChecksumOutcome = iota // matched a published .sha256
	checksumNotFound                                // no .sha256/.sha256sum sibling on the release
	checksumMismatch                                // a .sha256 was found but didn't match
)

// verifyDownloadChecksum tries to fetch a published SHA256 file alongside
// assetURL and compares it against the on-disk file at localFilePath.
//
// Many GitHub releases publish "<asset>.sha256" or "<asset>.sha256sum"
// alongside the binary, or a checksums file like "<basename>.sha256". We try
// the common variants and return:
//
//   - (checksumVerified, expectedHash, nil) — published file matched
//   - (checksumMismatch, expectedHash, error) — published file present but
//     differed (the caller MUST treat this as a tampering signal)
//   - (checksumNotFound, "", nil) — no published checksum to compare against
//
// Network errors fetching individual checksum URLs are NOT propagated as
// errors — they're treated as "this URL doesn't have a checksum file".
func (m *ToolManager) verifyDownloadChecksum(assetURL, localFilePath string) (verifyChecksumOutcome, string, error) {
	checksumURLs := []string{
		assetURL + ".sha256",
		assetURL + ".sha256sum",
	}
	if ext := filepath.Ext(assetURL); ext != "" {
		checksumURLs = append(checksumURLs, strings.TrimSuffix(assetURL, ext)+".sha256")
	}

	actual, err := computeSHA256(localFilePath)
	if err != nil {
		return checksumNotFound, "", fmt.Errorf("hashing local file: %w", err)
	}
	actual = strings.ToLower(actual)

	for _, url := range checksumURLs {
		resp, err := m.httpClient.Get(url)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		// Format: "<hash>  <filename>" or just "<hash>" — take the first token.
		parts := strings.Fields(strings.TrimSpace(string(body)))
		if len(parts) == 0 {
			continue
		}
		expected := strings.ToLower(parts[0])
		if expected == actual {
			return checksumVerified, expected, nil
		}
		return checksumMismatch, expected,
			fmt.Errorf("SHA256 mismatch: expected %s, got %s", expected, actual)
	}
	return checksumNotFound, "", nil
}

// downloadGitHubRelease downloads the configured release asset and extracts
// (or moves) the expected binary into LocalPath.
func (m *ToolManager) downloadGitHubRelease(t *Tool) error {
	m.logger.Info("tools", "downloading %s from %s (github release)", t.Name, t.GitHubRepo)

	// Fetch latest release metadata.
	rel, err := m.getLatestRelease(t.GitHubRepo)
	if err != nil {
		return fmt.Errorf("fetching release for %s: %w", t.Name, err)
	}

	// Find matching asset.
	asset, err := m.matchAsset(rel, t.AssetPattern)
	if err != nil {
		return fmt.Errorf("no matching asset for %s in %s: %w", t.Name, rel.TagName, err)
	}

	m.logger.Info("tools", "downloading %s (%d bytes)", asset.Name, asset.Size)

	// Ensure destination directory exists.
	destPath := filepath.Join(m.rootDir, filepath.FromSlash(t.LocalPath))
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return fmt.Errorf("creating directory for %s: %w", t.Name, err)
	}

	// Download to a temp file.
	tmpFile, err := os.CreateTemp(filepath.Dir(destPath), "vg-download-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // clean up on any error path

	if err := validateGitHubDownloadURL(asset.BrowserDownloadURL); err != nil {
		tmpFile.Close()
		return fmt.Errorf("rejecting download URL for %s: %w", asset.Name, err)
	}
	if err := m.downloadFile(asset.BrowserDownloadURL, tmpFile, asset.Size); err != nil {
		tmpFile.Close()
		return fmt.Errorf("downloading %s: %w", asset.Name, err)
	}
	tmpFile.Close()

	// Verify the downloaded asset against any published .sha256 checksum
	// BEFORE we touch the install path. A mismatch means the file was
	// corrupted in transit or tampered with — DELETE the temp file and bail
	// out so we don't install a compromised binary.
	switch outcome, expected, err := m.verifyDownloadChecksum(asset.BrowserDownloadURL, tmpPath); outcome {
	case checksumVerified:
		m.logger.Info("tools", "%s download verified against published SHA256 (%s)", t.Name, expected)
	case checksumMismatch:
		_ = os.Remove(tmpPath)
		return fmt.Errorf(
			"%s: download failed integrity check — file may be corrupted or tampered with. %v",
			t.Name, err)
	case checksumNotFound:
		// Many tool repos don't publish .sha256 files. Compute and log the
		// hash we got so it's at least recorded for audit.
		if local, hashErr := computeSHA256(tmpPath); hashErr == nil {
			m.logger.Info("tools", "%s no published checksum — computed SHA256: %s",
				t.Name, local)
		}
	}

	// If the asset is an archive, extract the target binary. Hayabusa and
	// Chainsaw ship the binary alongside required rules/+mappings/+config/
	// trees; for those we extract the entire archive into the binary's
	// directory so the tool can resolve its bundled assets at run time.
	// Every other tool gets the targeted single-binary extractor.
	assetLower := strings.ToLower(asset.Name)
	wantsFullTree := needsFullTreeExtraction(t.ID)
	switch {
	case strings.HasSuffix(assetLower, ".zip"):
		if wantsFullTree {
			if err := m.extractZipAll(tmpPath, filepath.Dir(destPath)); err != nil {
				return fmt.Errorf("extracting %s: %w", asset.Name, err)
			}
		} else if err := m.extractArchive(tmpPath, filepath.Dir(destPath), t.ExpectedBinary, t.ID); err != nil {
			return fmt.Errorf("extracting %s: %w", asset.Name, err)
		}
	case strings.HasSuffix(assetLower, ".tar.gz") || strings.HasSuffix(assetLower, ".tgz"):
		if wantsFullTree {
			if err := m.extractTarGzAll(tmpPath, filepath.Dir(destPath)); err != nil {
				return fmt.Errorf("extracting %s: %w", asset.Name, err)
			}
			// extractTarGzAll names the entry verbatim; if the archive
			// nested everything under a single top-level dir (release
			// archives almost always do) we end up with the binary one
			// level too deep. Lift everything up so destPath resolves.
			if _, err := os.Stat(destPath); err != nil {
				_ = liftSingleSubdirectory(filepath.Dir(destPath))
			}
		} else if err := m.extractTarGz(tmpPath, filepath.Dir(destPath), t.ExpectedBinary, t.ID); err != nil {
			return fmt.Errorf("extracting %s: %w", asset.Name, err)
		}
	default:
		// Direct binary — move temp file to final location.
		if err := os.Rename(tmpPath, destPath); err != nil {
			return fmt.Errorf("moving %s to %s: %w", tmpPath, destPath, err)
		}
	}

	// For full-tree tools (Hayabusa, Chainsaw) the release binary often
	// carries a versioned name like "hayabusa-2.18.0-win-x64.exe".
	// Rename it to the canonical ExpectedBinary so all downstream code
	// (ScanInstalled, BinaryPath, postInstallHook) sees a stable path.
	if wantsFullTree && t.ExpectedBinary != "" {
		if _, statErr := os.Stat(destPath); statErr != nil {
			if renErr := renameVersionedBinary(filepath.Dir(destPath), t.ExpectedBinary); renErr != nil {
				m.logger.Warn("tools", "%s: could not rename versioned binary: %v", t.Name, renErr)
			} else {
				m.logger.Info("tools", "%s: renamed versioned binary to %s", t.Name, t.ExpectedBinary)
			}
		}
	}

	// Post-install hook: tools that need an additional fetch step to be
	// usable (Hayabusa pulls its detection ruleset via `update-rules`).
	if wantsFullTree {
		m.postInstallHook(t, destPath)
	}

	// Set executable permission on Linux.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(destPath, 0o755); err != nil {
			m.logger.Warn("tools", "chmod %s: %v", destPath, err)
		}
	}

	// Verify the file landed.
	if _, err := os.Stat(destPath); err != nil {
		return fmt.Errorf("verification failed — %s not found after download: %w", destPath, err)
	}

	// Update tool state. Record InstalledSHA256 alongside SHA256 so future
	// ScanInstalled() calls can detect post-install modification.
	t.Installed = true
	t.InstalledVersion = rel.TagName
	hash, err := computeSHA256(destPath)
	if err == nil {
		t.SHA256 = hash
		t.InstalledSHA256 = hash
		t.Modified = false
	}

	m.logger.Info("tools", "%s %s installed at %s (sha256=%s)", t.Name, rel.TagName, destPath, t.SHA256)
	return nil
}

// downloadRepoArchive downloads /{owner}/{repo}/archive/refs/heads/{branch}.zip
// and lays the archive's top-level contents (everything inside the
// "{repo}-{branch}/" directory the archive contains) into LocalPath.
//
// If LocalPath already has content, it is removed first so re-runs produce a
// clean tree rather than a stale-and-fresh mix.
func (m *ToolManager) downloadRepoArchive(t *Tool) error {
	branch := resolveBranch(t)
	url := fmt.Sprintf("https://github.com/%s/archive/refs/heads/%s.zip", t.GitHubRepo, branch)
	m.logger.Info("tools", "downloading %s repo archive: %s", t.Name, url)

	if t.LocalPath == "" {
		return fmt.Errorf("%s: LocalPath required for repo archive download", t.Name)
	}

	destDir := filepath.Join(m.rootDir, filepath.FromSlash(t.LocalPath))
	parent := filepath.Dir(strings.TrimSuffix(destDir, string(os.PathSeparator)))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("creating parent dir: %w", err)
	}

	// Stream the archive to a temp file in the parent dir (so rename is on the
	// same filesystem).
	tmpFile, err := os.CreateTemp(parent, "vg-repo-*.zip")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := m.downloadFile(url, tmpFile, 0); err != nil {
		tmpFile.Close()
		return fmt.Errorf("downloading repo archive: %w", err)
	}
	tmpFile.Close()

	// Replace destDir contents atomically-ish: extract into a sibling temp
	// directory, then swap.
	stagingDir, err := os.MkdirTemp(parent, "vg-repo-stage-*")
	if err != nil {
		return fmt.Errorf("creating staging dir: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	if err := m.extractRepoArchive(tmpPath, stagingDir); err != nil {
		return fmt.Errorf("extracting repo archive: %w", err)
	}

	// Wipe the existing destination and replace with the staging contents.
	if err := os.RemoveAll(destDir); err != nil {
		return fmt.Errorf("removing existing %s: %w", destDir, err)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("creating dest dir: %w", err)
	}

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return fmt.Errorf("reading staging dir: %w", err)
	}
	for _, e := range entries {
		from := filepath.Join(stagingDir, e.Name())
		to := filepath.Join(destDir, e.Name())
		if err := os.Rename(from, to); err != nil {
			return fmt.Errorf("moving %s -> %s: %w", from, to, err)
		}
	}

	// Defensive flatten: if extractRepoArchive's prefix-stripping ever fails
	// (or the archive layout changes), destDir might still contain a single
	// "{repo}-{branch}/" directory holding everything. Detect that and pull
	// its contents up one level so the rest of VanGuard finds the files at
	// their expected paths (e.g. lib/volatility3/vol.py rather than
	// lib/volatility3/volatility3-stable/vol.py).
	if flattened, err := flattenSingleSubdir(destDir); err != nil {
		m.logger.Warn("tools", "flatten %s: %v", destDir, err)
	} else if flattened != "" {
		m.logger.Info("tools", "flattened %s/ contents up to %s", flattened, destDir)
	}

	// Mark installed. Repo archives don't carry a release tag, so record the
	// branch name as the version.
	t.Installed = true
	t.InstalledVersion = "branch:" + branch

	m.logger.Info("tools", "%s installed at %s (branch %s)", t.Name, destDir, branch)
	return nil
}

// flattenSingleSubdir collapses a "destDir contains exactly one subdirectory
// and nothing else" layout by moving the subdir's contents up to destDir and
// removing the now-empty subdir. Returns the name of the flattened subdir
// (or "" if no flatten was needed) and any error encountered.
//
// Used as a post-extraction defensive measure for GitHub repo archives, which
// nest everything under "{repo}-{branch}/" and break callers that expect files
// at known paths.
func flattenSingleSubdir(destDir string) (string, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return "", fmt.Errorf("reading dir: %w", err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", nil // nothing to do
	}

	innerName := entries[0].Name()
	inner := filepath.Join(destDir, innerName)
	innerEntries, err := os.ReadDir(inner)
	if err != nil {
		return "", fmt.Errorf("reading inner dir: %w", err)
	}

	// Move every entry of the inner dir up one level.
	for _, e := range innerEntries {
		from := filepath.Join(inner, e.Name())
		to := filepath.Join(destDir, e.Name())
		if _, err := os.Stat(to); err == nil {
			// Conflict — bail out rather than overwrite.
			return "", fmt.Errorf("flatten: %s already exists at destination", e.Name())
		}
		if err := os.Rename(from, to); err != nil {
			return "", fmt.Errorf("moving %s -> %s: %w", from, to, err)
		}
	}

	if err := os.Remove(inner); err != nil {
		return "", fmt.Errorf("removing empty %s: %w", inner, err)
	}
	return innerName, nil
}

// extractRepoArchive unpacks a GitHub repo zip. The archive contains a single
// top-level directory like "repo-branch/"; this function strips that prefix so
// callers see only the repo contents in destDir.
func (m *ToolManager) extractRepoArchive(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip %s: %w", archivePath, err)
	}
	defer r.Close()

	if len(r.File) == 0 {
		return fmt.Errorf("repo archive is empty")
	}

	// Discover the top-level prefix from the first entry. GitHub archives put
	// everything under "{repo}-{branch}/".
	topPrefix := ""
	for _, f := range r.File {
		idx := strings.Index(f.Name, "/")
		if idx <= 0 {
			continue
		}
		topPrefix = f.Name[:idx+1] // include trailing slash
		break
	}
	if topPrefix == "" {
		return fmt.Errorf("repo archive has no top-level directory")
	}

	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, topPrefix) {
			// Stray file outside the prefix — skip.
			continue
		}
		rel := strings.TrimPrefix(f.Name, topPrefix)
		if rel == "" {
			continue
		}

		// Sanitise against zip-slip.
		target := filepath.Join(destDir, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) &&
			target != filepath.Clean(destDir) {
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent of %s: %w", target, err)
		}

		mode := f.Mode()
		if mode == 0 {
			mode = 0o644
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s in archive: %w", f.Name, err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return fmt.Errorf("creating %s: %w", target, err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return fmt.Errorf("writing %s: %w", target, err)
		}
		rc.Close()
		out.Close()
	}
	return nil
}

// DownloadAllRequired downloads every required tool that is not already installed.
// It does not stop on the first failure — all errors are collected and returned.
func (m *ToolManager) DownloadAllRequired() []error {
	var errs []error
	for i := range m.tools {
		t := &m.tools[i]
		if !t.Required || t.Installed {
			continue
		}
		if resolveDownloadMethod(t) == DownloadManual {
			continue
		}
		if err := m.DownloadTool(t.ID); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Name, err))
		}
	}
	return errs
}

// ---------------------------------------------------------------------------
// GitHub API helpers (private)
// ---------------------------------------------------------------------------

func (m *ToolManager) getLatestRelease(repo string) (*githubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	m.applyGitHubAuth(req)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden &&
		resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return nil, fmt.Errorf("%s", rateLimitMessage(resp))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s", resp.StatusCode, repo)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding release JSON for %s: %w", repo, err)
	}

	return &rel, nil
}

// skipAssetSuffixes are file extensions that should never be matched as
// downloadable tool assets (checksums, signatures, docs).
var skipAssetSuffixes = []string{
	".sha256", ".sha512", ".sig", ".asc", ".gpg",
	".pdf", ".md", ".txt", ".json",
}

func (m *ToolManager) matchAsset(rel *githubRelease, pattern string) (*githubAsset, error) {
	if pattern == "" {
		return nil, fmt.Errorf("no asset pattern defined")
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compiling pattern %q: %w", pattern, err)
	}

	for i := range rel.Assets {
		name := rel.Assets[i].Name

		// Skip checksum, signature, and documentation files.
		skip := false
		nameLower := strings.ToLower(name)
		for _, suffix := range skipAssetSuffixes {
			if strings.HasSuffix(nameLower, suffix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		if re.MatchString(name) {
			m.logger.Info("tools", "asset matched: %q (pattern: %s, release: %s)",
				name, pattern, rel.TagName)
			return &rel.Assets[i], nil
		}
	}

	names := make([]string, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		names = append(names, a.Name)
	}
	return nil, fmt.Errorf("pattern %q matched none of: %s", pattern, strings.Join(names, ", "))
}

// validateGitHubDownloadURL returns an error if rawURL is not an HTTPS URL
// hosted on github.com or objects.githubusercontent.com. This prevents
// BrowserDownloadURL values from a tampered GitHub API response (or a
// compromised redirect) from sending tool downloads to an attacker-controlled
// host.
func validateGitHubDownloadURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be https, got %q", parsed.Scheme)
	}
	allowed := map[string]bool{
		"github.com":                   true,
		"objects.githubusercontent.com": true,
		"releases.githubusercontent.com": true,
	}
	if !allowed[parsed.Hostname()] {
		return fmt.Errorf("URL host %q is not a trusted GitHub domain", parsed.Hostname())
	}
	return nil
}

// downloadFile streams the content from url into dest. expectedSize is used for
// logging progress; pass 0 to skip size verification.
func (m *ToolManager) downloadFile(url string, dest *os.File, expectedSize int64) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("refusing non-HTTPS download URL: %s", url)
	}
	// Use a longer timeout for actual file downloads.
	client := &http.Client{Timeout: 10 * time.Minute}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating download request: %w", err)
	}
	m.applyGitHubAuth(req) // adds User-Agent + optional GitHub PAT

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden &&
		resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return fmt.Errorf("%s", rateLimitMessage(resp))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	written, err := io.Copy(dest, resp.Body)
	if err != nil {
		return fmt.Errorf("writing download: %w", err)
	}

	if expectedSize > 0 && written != expectedSize {
		return fmt.Errorf("size mismatch: expected %d bytes, got %d", expectedSize, written)
	}

	m.logger.Debug("tools", "downloaded %d bytes to %s", written, dest.Name())
	return nil
}

// ---------------------------------------------------------------------------
// Archive extraction (private)
// ---------------------------------------------------------------------------

// toolBaseName returns the short base name used for fuzzy matching inside
// archives. For "hayabusa-win" it returns "hayabusa", for "loki-lnx" it
// returns "loki", etc.
func toolBaseName(toolID string) string {
	// Strip platform suffix (-win, -lnx).
	base := toolID
	for _, suffix := range []string{"-win", "-lnx"} {
		base = strings.TrimSuffix(base, suffix)
	}
	return strings.ToLower(base)
}

// isExecutableCandidate returns true if the file looks like a binary we
// might want to extract (not a readme, license, config, etc.).
func isExecutableCandidate(name string) bool {
	lower := strings.ToLower(name)
	// Skip known non-binary files.
	for _, ext := range []string{".md", ".txt", ".yml", ".yaml", ".json", ".toml",
		".cfg", ".conf", ".log", ".sha256", ".sig", ".asc", ".pdf"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// On Windows, executables end in .exe / .dll.
	if strings.HasSuffix(lower, ".exe") || strings.HasSuffix(lower, ".dll") {
		return true
	}
	// On Linux, executables typically have no extension.
	if !strings.Contains(filepath.Base(name), ".") {
		return true
	}
	return false
}

// pickBestFile selects the best binary from a list of archive entries using
// multiple strategies:
//  1. Exact basename match against expectedBinary.
//  2. Fuzzy match: entry contains the tool base name AND is an executable.
//  3. If only one executable exists, use it.
func pickBestFile(entries []string, expectedBinary, toolID string) string {
	base := toolBaseName(toolID)
	expectExt := strings.ToLower(filepath.Ext(expectedBinary)) // ".exe" or ""

	// Strategy 1: exact basename match.
	for _, e := range entries {
		if filepath.Base(e) == expectedBinary {
			return e
		}
	}

	// Strategy 2: fuzzy — basename contains tool name and has matching extension.
	var fuzzy []string
	for _, e := range entries {
		nameLower := strings.ToLower(filepath.Base(e))
		if !strings.Contains(nameLower, base) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e))
		if expectExt != "" {
			// Windows: must match .exe
			if ext == expectExt {
				fuzzy = append(fuzzy, e)
			}
		} else {
			// Linux: prefer files with no extension.
			if isExecutableCandidate(e) {
				fuzzy = append(fuzzy, e)
			}
		}
	}
	if len(fuzzy) == 1 {
		return fuzzy[0]
	}
	// If multiple fuzzy matches, prefer the shortest name (most likely the
	// main binary vs a helper like hayabusa-3.8.1-win-x64/hayabusa-rules-updater.exe).
	if len(fuzzy) > 1 {
		best := fuzzy[0]
		for _, f := range fuzzy[1:] {
			if len(filepath.Base(f)) < len(filepath.Base(best)) {
				best = f
			}
		}
		return best
	}

	// Strategy 3: exactly one executable candidate in the archive.
	var execs []string
	for _, e := range entries {
		if !isExecutableCandidate(e) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e))
		if expectExt != "" {
			if ext == expectExt {
				execs = append(execs, e)
			}
		} else {
			execs = append(execs, e)
		}
	}
	if len(execs) == 1 {
		return execs[0]
	}

	return "" // no match
}

// extractArchive extracts a binary from a ZIP archive into destDir,
// renaming it to expectedBinary. It uses multi-strategy matching to find the
// correct file inside the archive.
func (m *ToolManager) extractArchive(archivePath, destDir, expectedBinary, toolID string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip %s: %w", archivePath, err)
	}
	defer r.Close()

	// Collect all file entries for logging and matching.
	var entries []string
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		entries = append(entries, f.Name)
	}

	m.logger.Debug("tools", "zip %s contains %d files: %s",
		filepath.Base(archivePath), len(entries), strings.Join(entries, ", "))

	// Pick the best matching file.
	match := pickBestFile(entries, expectedBinary, toolID)
	if match == "" {
		return fmt.Errorf("%s not found in archive %s (files: %s)",
			expectedBinary, filepath.Base(archivePath), strings.Join(entries, ", "))
	}

	m.logger.Info("tools", "extracting %q as %q from %s",
		match, expectedBinary, filepath.Base(archivePath))

	// Extract the matched file.
	for _, f := range r.File {
		if f.Name != match {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s in archive: %w", f.Name, err)
		}

		destPath := filepath.Join(destDir, expectedBinary)
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o755)
		if err != nil {
			rc.Close()
			return fmt.Errorf("creating %s: %w", destPath, err)
		}

		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return fmt.Errorf("extracting %s: %w", match, err)
		}
		return nil
	}

	return fmt.Errorf("matched file %s disappeared from archive (should not happen)", match)
}

// needsFullTreeExtraction reports whether a tool ships supporting
// directories (rules/, mappings/, config/) inside its release archive
// that have to land alongside the binary. The scanner runs these tools
// from the binary's parent directory so the bundled assets resolve.
func needsFullTreeExtraction(toolID string) bool {
	switch toolID {
	case "hayabusa-win", "hayabusa-lnx",
		"chainsaw-win", "chainsaw-lnx",
		"loki-win", "loki-lnx":
		return true
	}
	return false
}

// extractZipAll explodes an entire zip archive into destDir. If every
// entry in the archive sits under a single top-level directory (the
// common GitHub release layout, e.g. `chainsaw_x86_64-pc-windows-msvc/…`),
// that prefix is stripped so the binary lands at destDir/<binary> rather
// than destDir/<wrapper>/<binary>. Used for tools whose rules/ and
// mappings/ trees are required at run time.
func (m *ToolManager) extractZipAll(archivePath, destDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("opening zip %s: %w", archivePath, err)
	}
	defer r.Close()

	rootPrefix := detectZipRootPrefix(r.File)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	extracted := 0
	for _, f := range r.File {
		name := f.Name
		if rootPrefix != "" {
			name = strings.TrimPrefix(name, rootPrefix)
		}
		if name == "" {
			continue
		}
		// Reject path-traversal — never trust archive entry names with
		// "..", absolute roots, or windows drive letters.
		if !safeArchivePath(name) {
			m.logger.Warn("tools", "skipping unsafe archive entry %q", f.Name)
			continue
		}
		target := filepath.Join(destDir, filepath.FromSlash(name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("opening %s: %w", f.Name, err)
		}
		out, err := os.OpenFile(target,
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode()|0o644)
		if err != nil {
			rc.Close()
			return fmt.Errorf("creating %s: %w", target, err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return fmt.Errorf("writing %s: %w", target, err)
		}
		rc.Close()
		out.Close()
		// Restore executable bit on POSIX — the zip header carries it but
		// our umask may have masked it off when creating the file.
		if runtime.GOOS != "windows" && f.Mode()&0o111 != 0 {
			_ = os.Chmod(target, 0o755)
		}
		extracted++
	}
	m.logger.Info("tools", "extracted %d files from %s into %s",
		extracted, filepath.Base(archivePath), destDir)
	return nil
}

// detectZipRootPrefix returns the single top-level directory shared by
// every entry in files (with its trailing slash), or "" if entries live at
// the archive root or under multiple top-level directories.
func detectZipRootPrefix(files []*zip.File) string {
	prefix := ""
	for _, f := range files {
		first := f.Name
		if i := strings.IndexByte(first, '/'); i >= 0 {
			first = first[:i+1]
		} else {
			// Top-level file — no shared prefix possible.
			return ""
		}
		switch {
		case prefix == "":
			prefix = first
		case prefix != first:
			return ""
		}
	}
	return prefix
}

// safeArchivePath rejects entry names that try to escape destDir.
func safeArchivePath(name string) bool {
	if name == "" {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return false
	}
	if len(name) >= 2 && name[1] == ':' {
		return false // windows drive letter
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return false
		}
	}
	return true
}

// renameVersionedBinary looks for a file in dir whose name begins with
// the base name of expectedBinary (without extension) and renames it to
// expectedBinary. It is a no-op when expectedBinary already exists.
//
// This handles tools like Hayabusa whose releases ship a versioned binary
// (hayabusa-2.18.0-win-x64.exe) rather than the canonical name the tool
// registry and ScanInstalled expect (hayabusa.exe).
func renameVersionedBinary(dir, expectedBinary string) error {
	dest := filepath.Join(dir, expectedBinary)
	if fileExists(dest) {
		return nil
	}

	wantExt := strings.ToLower(filepath.Ext(expectedBinary))
	baseName := strings.ToLower(strings.TrimSuffix(expectedBinary, filepath.Ext(expectedBinary)))

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		nl := strings.ToLower(e.Name())
		if !strings.HasPrefix(nl, baseName) {
			continue
		}
		if wantExt != "" {
			if strings.HasSuffix(nl, wantExt) {
				return os.Rename(filepath.Join(dir, e.Name()), dest)
			}
		} else {
			// Linux: match files that start with baseName and have no extension.
			suffix := nl[len(baseName):]
			if !strings.Contains(suffix, ".") {
				src := filepath.Join(dir, e.Name())
				if err := os.Rename(src, dest); err != nil {
					return err
				}
				return os.Chmod(dest, 0o755)
			}
		}
	}
	return fmt.Errorf("no file matching %s*%s found in %s", baseName, wantExt, dir)
}

// liftSingleSubdirectory checks whether destDir contains exactly one
// directory and no files. If so, every entry inside that directory is
// moved up one level and the wrapper is removed. Used after
// extractTarGzAll to flatten release archives that embed everything
// under a `<name>-<version>/` wrapper.
func liftSingleSubdirectory(destDir string) error {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return nil
	}
	wrapper := filepath.Join(destDir, entries[0].Name())
	inner, err := os.ReadDir(wrapper)
	if err != nil {
		return err
	}
	for _, e := range inner {
		from := filepath.Join(wrapper, e.Name())
		to := filepath.Join(destDir, e.Name())
		if err := os.Rename(from, to); err != nil {
			return err
		}
	}
	return os.Remove(wrapper)
}

// postInstallHook runs tool-specific provisioning that happens once after
// a fresh install. Currently used to fetch Hayabusa's rule pack via the
// tool's own `update-rules` subcommand.
func (m *ToolManager) postInstallHook(t *Tool, destPath string) {
	switch t.ID {
	case "hayabusa-win", "hayabusa-lnx":
		m.runHayabusaUpdateRules(destPath)
	case "loki-win", "loki-lnx":
		m.runLokiUtil(destPath)
		// Create a loki-rs alias alongside loki.exe / loki so any reference
		// that still uses the old binary name continues to resolve.
		lokiDir := filepath.Dir(destPath)
		ext := filepath.Ext(destPath) // ".exe" on Windows, "" on Linux
		lokiRsPath := filepath.Join(lokiDir, "loki-rs"+ext)
		if fileExists(destPath) && !fileExists(lokiRsPath) {
			if err := copyToolFile(destPath, lokiRsPath); err != nil {
				m.logger.Warn("tools", "loki: could not create loki-rs alias: %v", err)
			} else {
				m.logger.Info("tools", "loki: created loki-rs alias at %s", lokiRsPath)
			}
		}
	}
}

// copyToolFile streams src into dst. Used to create binary aliases (e.g.
// loki-rs.exe alongside loki.exe so both names resolve).
func copyToolFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// runHayabusaUpdateRules executes `<hayabusa> update-rules` from the
// binary's own directory so the rules/ tree lands where Hayabusa expects.
// The download is best-effort — failures don't block the install (the
// analyst can re-run from the Update page) but they're logged so the
// next scan failure has context.
func (m *ToolManager) runHayabusaUpdateRules(binPath string) {
	binDir := filepath.Dir(binPath)
	rulesDir := filepath.Join(binDir, "rules")
	if info, err := os.Stat(rulesDir); err == nil && info.IsDir() {
		// Already populated — likely from the release archive itself or
		// a previous run. Skip the network round-trip.
		m.logger.Info("tools", "hayabusa rules/ already present at %s", rulesDir)
		return
	}
	m.logger.Info("tools",
		"hayabusa: running `update-rules` to populate %s", rulesDir)

	// 5 min cap — update-rules clones the hayabusa-rules repo over HTTPS;
	// constrained networks may stall but we don't want to wait forever.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "update-rules")
	cmd.Dir = binDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Warn("tools",
			"hayabusa update-rules failed (%v): %s — analyst can retry from Update page",
			err, strings.TrimSpace(string(out)))
		return
	}
	m.logger.Info("tools",
		"hayabusa update-rules complete (%d bytes output)", len(out))
}

// runLokiUtil runs `loki-util update` from the directory that contains
// loki-rs to download the signatures/ tree. Best-effort — failures don't
// block the install; the analyst can re-run from the Update page or by
// clicking Update YARA Rules.
func (m *ToolManager) runLokiUtil(lokiBinPath string) {
	lokiDir := filepath.Dir(lokiBinPath)
	sigDir := filepath.Join(lokiDir, "signatures")
	if info, err := os.Stat(sigDir); err == nil && info.IsDir() {
		m.logger.Info("tools", "loki signatures/ already present at %s", sigDir)
		return
	}
	var utilPath string
	for _, name := range []string{"loki-util.exe", "loki-util"} {
		p := filepath.Join(lokiDir, name)
		if fileExists(p) {
			utilPath = p
			break
		}
	}
	if utilPath == "" {
		m.logger.Warn("tools",
			"loki-util not found in %s — signatures must be downloaded manually", lokiDir)
		return
	}
	m.logger.Info("tools", "loki-util: downloading signatures into %s", sigDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, utilPath, "update")
	cmd.Dir = lokiDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Warn("tools",
			"loki-util update failed (%v): %s — analyst can retry from Update page",
			err, strings.TrimSpace(string(out)))
		return
	}
	m.logger.Info("tools", "loki-util update complete (%d bytes output)", len(out))
}

// RunLokiUtil is the exported wrapper called by the web-layer update handler
// after a YARA rule refresh. It locates the Loki binary for the given platform
// and delegates to runLokiUtil.
func (m *ToolManager) RunLokiUtil(platform string) {
	toolID := "loki-win"
	if platform == "linux" {
		toolID = "loki-lnx"
	}
	if path := m.GetInstalledPath(toolID); path != "" {
		m.runLokiUtil(path)
	}
}

// extractTarGz extracts a binary from a .tar.gz archive into destDir,
// renaming it to expectedBinary. For directory-mode tools (expectedBinary is
// empty or ends with "/"), it extracts all files instead.
func (m *ToolManager) extractTarGz(archivePath, destDir, expectedBinary, toolID string) error {
	// If expectedBinary is empty this is a directory extraction (e.g., UAC).
	extractAll := expectedBinary == "" || strings.HasSuffix(expectedBinary, "/")

	if extractAll {
		return m.extractTarGzAll(archivePath, destDir)
	}

	// --- Single binary extraction ---
	// We need two passes: one to list entries, one to extract. Since tar.gz
	// is a stream, we re-open the file for the second pass.
	entries, err := listTarGzEntries(archivePath)
	if err != nil {
		return err
	}

	m.logger.Debug("tools", "tar.gz %s contains %d files: %s",
		filepath.Base(archivePath), len(entries), strings.Join(entries, ", "))

	match := pickBestFile(entries, expectedBinary, toolID)
	if match == "" {
		return fmt.Errorf("%s not found in archive %s (files: %s)",
			expectedBinary, filepath.Base(archivePath), strings.Join(entries, ", "))
	}

	m.logger.Info("tools", "extracting %q as %q from %s",
		match, expectedBinary, filepath.Base(archivePath))

	// Second pass: extract the matched file.
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader for %s: %w", archivePath, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		if hdr.Name != match {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}

		destPath := filepath.Join(destDir, expectedBinary)
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0o755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", destPath, err)
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return fmt.Errorf("extracting %s: %w", match, err)
		}
		return nil
	}

	return fmt.Errorf("matched file %s disappeared from archive (should not happen)", match)
}

// listTarGzEntries returns all file names inside a .tar.gz archive.
func listTarGzEntries(archivePath string) ([]string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader for %s: %w", archivePath, err)
	}
	defer gz.Close()

	var entries []string
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		entries = append(entries, hdr.Name)
	}
	return entries, nil
}

// extractTarGzAll extracts every file from a .tar.gz archive into destDir.
func (m *ToolManager) extractTarGzAll(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", archivePath, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader for %s: %w", archivePath, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		target := filepath.Join(destDir, filepath.FromSlash(hdr.Name))
		// Guard against path traversal. Separator required on both sides to prevent
		// a sibling-directory bypass where "../chainsaw-lnx-extra/..." passes a
		// plain HasPrefix check against "chainsaw-lnx" without the separator.
		cleanTarget := filepath.Clean(target)
		cleanDest := filepath.Clean(destDir)
		sep := string(os.PathSeparator)
		if cleanTarget != cleanDest && !strings.HasPrefix(cleanTarget+sep, cleanDest+sep) {
			m.logger.Warn("tools", "skipping unsafe tar entry: %s", hdr.Name)
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", target, err)
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)|0o755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", target, err)
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return fmt.Errorf("extracting %s: %w", target, err)
		}
		found = true
	}

	if !found {
		return fmt.Errorf("archive %s was empty", archivePath)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Utility helpers (private)
// ---------------------------------------------------------------------------

// computeSHA256 returns the hex-encoded SHA-256 hash of the file at path.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s for hashing: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// fileExists returns true if path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// dirExists returns true if path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// dirHasFiles returns true if dir exists and contains at least one file.
func dirHasFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
		// Check one level deep for directories containing files.
		sub := filepath.Join(dir, e.Name())
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		if len(subEntries) > 0 {
			return true
		}
	}
	return false
}

// fileExistsCI returns the actual on-disk path matching `path` case-insensitively
// in its parent directory, or "" if no match exists. The exact path is checked
// first (cheap fast path) before falling back to the directory scan.
//
// This is necessary on Windows-installed tools where the user may have
// extracted the binary with different casing than the registry expects
// (DumpIt.exe vs dumpit.exe, KAPE/ vs kape/).
func fileExistsCI(path string) string {
	if fileExists(path) {
		return path
	}
	parent := filepath.Dir(path)
	want := strings.ToLower(filepath.Base(path))
	entries, err := os.ReadDir(parent)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(e.Name(), want) {
			return filepath.Join(parent, e.Name())
		}
	}
	// No exact match — try suffix wildcard if the input had one
	// (e.g. "winpmem*.exe").
	if strings.Contains(want, "*") {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if matchGlobCI(e.Name(), want) {
				return filepath.Join(parent, e.Name())
			}
		}
	}
	return ""
}

// findBinaryInDir recursively searches dir for any file matching one of the
// case-insensitive glob patterns. Returns the first hit (depth-first) or "".
//
// patterns may be exact filenames ("MFTECmd.exe") or simple globs ("kape*.exe").
// This is intentionally a small matcher — full filepath.Match doesn't go
// case-insensitive, so we lower both sides and use matchGlobCI.
func findBinaryInDir(dir string, patterns []string) string {
	if dir == "" || len(patterns) == 0 {
		return ""
	}
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	var found string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		for _, pat := range patterns {
			if matchGlobCI(name, pat) {
				found = p
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

// matchGlobCI compares name to a simple glob pattern case-insensitively.
// Supported metacharacters: '*' (any sequence) and '?' (single char). No
// character classes — keep it simple, the patterns we feed in are tiny.
func matchGlobCI(name, pattern string) bool {
	n := strings.ToLower(name)
	p := strings.ToLower(pattern)
	return globMatch(p, n)
}

// globMatch implements * / ? matching iteratively (no recursion stack blowup
// on pathological inputs).
func globMatch(pattern, s string) bool {
	pi, si := 0, 0
	starP, starS := -1, -1
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			pi++
			si++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starP = pi
			starS = si
			pi++
		} else if starP != -1 {
			pi = starP + 1
			starS++
			si = starS
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
