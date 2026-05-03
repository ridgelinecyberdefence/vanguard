package memory

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// VolatilityRunner wraps Volatility3 plugin invocations.
type VolatilityRunner struct {
	RootDir string
	Logger  *logging.Logger
}

// NewVolatilityRunner returns a runner rooted at rootDir.
func NewVolatilityRunner(rootDir string, logger *logging.Logger) *VolatilityRunner {
	return &VolatilityRunner{RootDir: rootDir, Logger: logger}
}

// Available returns true when both Python and a vol.py script exist locally.
// Use HasPython / HasVolatilityScript when callers need to distinguish which
// piece is missing.
func (r *VolatilityRunner) Available() bool {
	return r.HasPython() && r.HasVolatilityScript()
}

// HasPython reports whether a Python 3 interpreter is available.
func (r *VolatilityRunner) HasPython() bool {
	_, ok := tools.DetectPython(r.RootDir)
	return ok
}

// HasVolatilityScript reports whether vol.py / cli.py is on disk.
func (r *VolatilityRunner) HasVolatilityScript() bool {
	_, ok := r.VolatilityScript()
	return ok
}

// Python returns the resolved Python 3 interpreter info (path + leading args).
func (r *VolatilityRunner) Python() (tools.PythonInfo, bool) {
	return tools.DetectPython(r.RootDir)
}

// PythonPath returns just the executable path of the detected Python 3
// interpreter — kept for backward compatibility with existing callers.
func (r *VolatilityRunner) PythonPath() (string, bool) {
	info, ok := tools.DetectPython(r.RootDir)
	if !ok {
		return "", false
	}
	return info.Path, true
}

// DepsMarkerPath returns the file path that marks "Volatility3 dependencies
// have already been installed", so we only run pip install once.
func (r *VolatilityRunner) DepsMarkerPath() string {
	return filepath.Join(r.RootDir, "lib", "volatility3", ".vanguard_deps_installed")
}

// DepsInstalled reports whether the one-shot pip install has already run.
func (r *VolatilityRunner) DepsInstalled() bool {
	return fileExists(r.DepsMarkerPath())
}

// InstallDeps runs `<python> -m pip install -r requirements.txt` against the
// installed Volatility3 source tree, then writes the marker file. Errors are
// returned with combined stdout+stderr appended for diagnostics.
//
// If requirements.txt is missing (some pyinstaller/binary layouts), the call
// short-circuits to success and writes the marker — there's nothing to install.
func (r *VolatilityRunner) InstallDeps(ctx context.Context) error {
	info, ok := tools.DetectPython(r.RootDir)
	if !ok {
		return fmt.Errorf("python interpreter not found")
	}

	vol3Dir := filepath.Join(r.RootDir, "lib", "volatility3")
	req := filepath.Join(vol3Dir, "requirements.txt")
	if _, err := os.Stat(req); err != nil {
		// Nothing to install — mark done so we don't retry every run.
		return r.writeDepsMarker()
	}

	args := append(append([]string{}, info.Args...), "-m", "pip", "install", "-r", req)
	if r.Logger != nil {
		r.Logger.Info("memory", "installing Volatility3 deps: %s %s", info.Path, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, info.Path, args...)
	cmd.Dir = vol3Dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pip install failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return r.writeDepsMarker()
}

func (r *VolatilityRunner) writeDepsMarker() error {
	path := r.DepsMarkerPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating marker dir: %w", err)
	}
	stamp := fmt.Sprintf("installed=%s\n", time.Now().UTC().Format(time.RFC3339))
	return os.WriteFile(path, []byte(stamp), 0o644)
}

// VolatilityScript returns the path to vol.py and whether it exists.
//
// Detection order matches volatilityMarker in the tools package:
//  1. lib/volatility3/vol.py (canonical)
//  2. lib/volatility3/volatility3/cli.py (alternate entry point)
//  3. lib/volatility3/volatility3-{stable,main,develop}/vol.py (GitHub archive
//     layouts that haven't been flattened)
//  4. Any one-level-deep subdir containing vol.py (defensive catch-all)
func (r *VolatilityRunner) VolatilityScript() (string, bool) {
	base := filepath.Join(r.RootDir, "lib", "volatility3")
	candidates := []string{
		filepath.Join(base, "vol.py"),
		filepath.Join(base, "volatility3", "cli.py"),
	}
	for _, sub := range []string{"volatility3-stable", "volatility3-main", "volatility3-develop"} {
		candidates = append(candidates, filepath.Join(base, sub, "vol.py"))
	}
	for _, p := range candidates {
		if fileExists(p) {
			return p, true
		}
	}
	// Generic one-level-deep scan.
	if entries, err := os.ReadDir(base); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			candidate := filepath.Join(base, e.Name(), "vol.py")
			if fileExists(candidate) {
				return candidate, true
			}
		}
	}
	return "", false
}

// SymbolsDir returns the symbols directory for the OS family.
func (r *VolatilityRunner) SymbolsDir(osFamily string) string {
	return filepath.Join(r.RootDir, "lib", "volatility3", "symbols", osFamily)
}

// CountSymbolFiles returns the number of files in the symbols directory.
func (r *VolatilityRunner) CountSymbolFiles(osFamily string) int {
	dir := r.SymbolsDir(osFamily)
	count := 0
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			count++
		}
		return nil
	})
	return count
}

// RunPlugin executes a single plugin against dumpFile. Output is written to
// outDir/{plugin}.txt. Returns a structured PluginResult.
func (r *VolatilityRunner) RunPlugin(ctx context.Context, dumpFile, plugin, outDir string, extraArgs ...string) PluginResult {
	result := PluginResult{Plugin: plugin}
	started := time.Now()

	info, ok := r.Python()
	if !ok {
		result.Status = StepFailed
		result.Error = "python interpreter not found"
		result.Duration = time.Since(started)
		return result
	}
	script, ok := r.VolatilityScript()
	if !ok {
		result.Status = StepFailed
		result.Error = "Volatility3 vol.py not found"
		result.Duration = time.Since(started)
		return result
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		result.Status = StepFailed
		result.Error = fmt.Sprintf("creating output dir: %v", err)
		result.Duration = time.Since(started)
		return result
	}

	// Build argv: <leading-args> <vol.py> -f <dump> -r csv <plugin> [extra...]
	// -r csv enables Volatility3's built-in CSV renderer so output is
	// machine-readable by default. extraArgs follow the plugin name so callers
	// can pass per-plugin options (--yara-file, --pid, etc.) without clashing
	// with the global renderer flag.
	args := append(append([]string{}, info.Args...), script, "-f", dumpFile, "-r", "csv", plugin)
	args = append(args, extraArgs...)

	if r.Logger != nil {
		r.Logger.Info("memory", "vol3 exec: %s %s", info.Path, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, info.Path, args...)
	cmd.Dir = r.RootDir
	out, err := cmd.CombinedOutput()

	outFile := filepath.Join(outDir, sanitizePlugin(plugin)+".csv")
	if writeErr := os.WriteFile(outFile, out, 0o644); writeErr != nil && r.Logger != nil {
		r.Logger.Warn("memory", "writing %s: %v", outFile, writeErr)
	}
	result.OutFile = outFile
	result.Lines = strings.Count(string(out), "\n")
	result.Duration = time.Since(started)

	if err != nil {
		result.Status = StepFailed
		// Detect missing-symbols errors so the TUI can guide the user.
		text := string(out)
		if strings.Contains(text, "Unable to validate the plugin requirements") ||
			strings.Contains(text, "No suitable kernel found") ||
			strings.Contains(text, "could not be located") ||
			strings.Contains(text, "SymbolError") {
			result.Error = "missing symbol tables — open Symbol Management to install"
		} else {
			result.Error = fmt.Sprintf("%v", err)
		}
		return result
	}

	result.Status = StepSuccess
	return result
}

func sanitizePlugin(p string) string {
	s := strings.ReplaceAll(p, ".", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}

// DetectOS attempts to determine the OS family of a memory dump.
// Returns ("windows" | "linux" | "", description, error).
func (r *VolatilityRunner) DetectOS(ctx context.Context, dumpFile, outDir string) (osFamily, desc string, err error) {
	bannersResult := r.RunPlugin(ctx, dumpFile, "banners.Banners", outDir)
	bannersData, _ := os.ReadFile(bannersResult.OutFile)
	banners := strings.ToLower(string(bannersData))

	if strings.Contains(banners, "linux version") {
		return "linux", extractLinuxBanner(string(bannersData)), nil
	}
	if strings.Contains(banners, "windows") || strings.Contains(banners, "ntoskrnl") {
		return "windows", "Windows (banner detected)", nil
	}

	// Fallback: try windows.info.
	winInfo := r.RunPlugin(ctx, dumpFile, "windows.info", outDir)
	if winInfo.Status == StepSuccess {
		data, _ := os.ReadFile(winInfo.OutFile)
		return "windows", extractWindowsInfo(string(data)), nil
	}

	// Try linux.banner.
	lnxBanner := r.RunPlugin(ctx, dumpFile, "banners.Banners", outDir)
	if lnxBanner.Status == StepSuccess {
		data, _ := os.ReadFile(lnxBanner.OutFile)
		txt := string(data)
		if strings.Contains(strings.ToLower(txt), "linux") {
			return "linux", extractLinuxBanner(txt), nil
		}
	}

	return "", "Unknown", fmt.Errorf("could not detect OS — %s", winInfo.Error)
}

func extractLinuxBanner(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(strings.ToLower(line), "linux version") {
			line = strings.TrimSpace(line)
			if len(line) > 100 {
				line = line[:100] + "..."
			}
			return line
		}
	}
	return "Linux (banner detected)"
}

func extractWindowsInfo(s string) string {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "NTBuildLab") || strings.HasPrefix(l, "NtMajorVersion") ||
			strings.HasPrefix(l, "NtProductType") {
			return l
		}
	}
	return "Windows (info detected)"
}

// ---------------------------------------------------------------------------
// Plugin sets
// ---------------------------------------------------------------------------

// Vol3Plugin describes one Volatility3 plugin in the catalogue surfaced to
// the SPA's plugin browser. The Name field is the canonical fully-qualified
// plugin path (windows.pslist.PsList) — that's what `vol -f dump <plugin>`
// expects on the command line. Category groups plugins for the SPA UI;
// OS narrows the list to "windows", "linux", "mac", or "all" (cross-platform).
type Vol3Plugin struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	OS          string `json:"os"`
}

// Vol3Plugins is the catalogue of plugins shipped with Volatility3 v2.28.1
// (per volatility3.readthedocs.io) plus a handful of widely-used community
// plugins. Order is per-OS by category, matching the SPA plugin browser.
//
// Adding a plugin here surfaces it in the SPA but does NOT make it work — it
// has to actually be present in the running Volatility3 build. Plugins
// missing from the installed framework will fail at run time with a
// SymbolError; that path is already handled in RunPlugin.
var Vol3Plugins = []Vol3Plugin{
	// ───────────────────────── WINDOWS ─────────────────────────

	// Process Analysis
	{"windows.pslist.PsList", "List running processes via EPROCESS linked list", "process", "windows"},
	{"windows.psscan.PsScan", "Scan for EPROCESS structures (finds hidden/terminated processes)", "process", "windows"},
	{"windows.pstree.PsTree", "Process tree showing parent-child relationships", "process", "windows"},
	{"windows.cmdline.CmdLine", "Command line arguments for each process", "process", "windows"},
	{"windows.envars.Envars", "Environment variables per process", "process", "windows"},
	{"windows.getsids.GetSIDs", "SID (Security Identifier) per process", "process", "windows"},
	{"windows.getservicesids.GetServiceSIDs", "Service SIDs", "process", "windows"},
	{"windows.privileges.Privs", "Process token privileges", "process", "windows"},
	{"windows.dlllist.DllList", "Loaded DLLs per process", "process", "windows"},
	{"windows.handles.Handles", "Open handles (files, registry, mutexes, etc.)", "process", "windows"},
	{"windows.memmap.Memmap", "Memory map of a process", "process", "windows"},
	{"windows.virtmap.VirtMap", "Virtual memory map", "process", "windows"},
	{"windows.vadinfo.VadInfo", "Virtual Address Descriptor details", "process", "windows"},
	{"windows.vadwalk.VadWalk", "Walk the VAD tree", "process", "windows"},
	{"windows.threads.Threads", "Process threads with start addresses", "process", "windows"},
	{"windows.joblinks.JobLinks", "Process job object links", "process", "windows"},
	{"windows.sessions.Sessions", "User logon sessions", "process", "windows"},
	{"windows.tokens.Tokens", "Process token information", "process", "windows"},

	// Network
	{"windows.netscan.NetScan", "Scan for TCP/UDP connections and listeners", "network", "windows"},
	{"windows.netstat.NetStat", "Active network connections via active process scan", "network", "windows"},

	// Malware / Rootkit Detection
	{"windows.malfind.Malfind", "Detect injected code (RWX memory with MZ/PE headers)", "malware", "windows"},
	{"windows.malware.direct_system_calls.DirectSystemCalls", "Detect direct syscall usage (EDR evasion)", "malware", "windows"},
	{"windows.malware.indirect_system_calls.IndirectSystemCalls", "Detect indirect syscall usage (EDR evasion)", "malware", "windows"},
	{"windows.malware.unhooked_system_calls.UnhookedSystemCalls", "Find unhooked syscall stubs", "malware", "windows"},
	{"windows.malware.hollowprocesses.HollowProcesses", "Detect process hollowing", "malware", "windows"},
	{"windows.malware.processghosting.ProcessGhosting", "Detect process ghosting", "malware", "windows"},
	{"windows.malware.pebmasquerade.PebMasquerade", "Detect PEB masquerading (process name spoofing)", "malware", "windows"},
	{"windows.malware.ldrmodules.LdrModules", "Detect unlinked DLLs (hidden from PEB)", "malware", "windows"},
	{"windows.malware.drivermodule.DriverModule", "Detect driver objects without a module", "malware", "windows"},
	{"windows.malware.psxview.PsXView", "Cross-reference process lists to find hidden processes", "malware", "windows"},
	{"windows.malware.svcdiff.SvcDiff", "Compare services in registry vs memory (detect tampering)", "malware", "windows"},
	{"windows.malware.suspicious_threads.SuspiciousThreads", "Detect threads with suspicious start addresses", "malware", "windows"},
	{"windows.malware.skeleton_key_check.Skeleton_Key_Check", "Detect Skeleton Key attack on domain controllers", "malware", "windows"},
	{"windows.callbacks.Callbacks", "Kernel notification callbacks (rootkit hooks)", "malware", "windows"},
	{"windows.ssdt.SSDT", "System Service Descriptor Table (syscall hooks)", "malware", "windows"},
	{"windows.idt.IDT", "Interrupt Descriptor Table analysis", "malware", "windows"},
	{"windows.vadyarascan.VadYaraScan", "YARA scan within process VADs", "malware", "windows"},

	// Registry
	{"windows.registry.hivelist.HiveList", "List registry hives loaded in memory", "registry", "windows"},
	{"windows.registry.hivescan.HiveScan", "Scan for registry hive structures", "registry", "windows"},
	{"windows.registry.printkey.PrintKey", "Print registry key and subkey values", "registry", "windows"},
	{"windows.registry.userassist.UserAssist", "UserAssist program execution history", "registry", "windows"},
	{"windows.registry.amcache.Amcache", "Amcache application execution history", "registry", "windows"},
	{"windows.registry.scheduled_tasks.ScheduledTasks", "Scheduled tasks from registry", "registry", "windows"},
	{"windows.registry.getcellroutine.GetCellRoutine", "Detect registry callback hooks", "registry", "windows"},

	// Credentials
	{"windows.registry.hashdump.Hashdump", "Dump NTLM password hashes from SAM", "credential", "windows"},
	{"windows.registry.lsadump.Lsadump", "Dump LSA secrets", "credential", "windows"},
	{"windows.registry.cachedump.Cachedump", "Dump cached domain credentials (DCC2)", "credential", "windows"},

	// Filesystem
	{"windows.filescan.FileScan", "Scan for FILE_OBJECT structures", "filesystem", "windows"},
	{"windows.dumpfiles.DumpFiles", "Extract cached files from memory", "filesystem", "windows"},
	{"windows.mftscan.MFTScan", "Scan for MFT entries in memory", "filesystem", "windows"},
	{"windows.mbrscan.MBRScan", "Scan for Master Boot Record", "filesystem", "windows"},

	// Kernel / Drivers
	{"windows.driverscan.DriverScan", "Scan for DRIVER_OBJECT structures", "kernel", "windows"},
	{"windows.driverirp.DriverIrp", "Driver IRP function hook detection", "kernel", "windows"},
	{"windows.drivermodule.DriverModule", "Driver objects without associated modules", "kernel", "windows"},
	{"windows.modules.Modules", "List loaded kernel modules", "kernel", "windows"},
	{"windows.modscan.ModScan", "Scan for kernel modules", "kernel", "windows"},
	{"windows.devicetree.DeviceTree", "Device object tree", "kernel", "windows"},

	// Services
	{"windows.svcscan.SvcScan", "Scan for Windows service records", "services", "windows"},

	// Misc / Info
	{"windows.info.Info", "OS version, build, architecture from memory", "info", "windows"},
	{"windows.crashinfo.Crashinfo", "Windows crash dump header information", "info", "windows"},
	{"windows.verinfo.VerInfo", "Version information from PE files", "info", "windows"},
	{"windows.mutantscan.MutantScan", "Scan for named mutexes", "misc", "windows"},
	{"windows.symlinkscan.SymlinkScan", "Scan for symbolic link objects", "misc", "windows"},
	{"windows.poolscanner.PoolScanner", "Generic pool tag scanner", "misc", "windows"},
	{"windows.bigpools.BigPools", "List big pool allocations", "misc", "windows"},
	{"windows.statistics.Statistics", "Image statistics and layer info", "misc", "windows"},
	{"windows.strings.Strings", "Map physical strings to virtual addresses", "misc", "windows"},
	{"windows.pedump.PEDump", "Dump PE files from memory", "misc", "windows"},
	{"windows.debugregisters.DebugRegisters", "Debug register analysis", "misc", "windows"},

	// ───────────────────────── LINUX ─────────────────────────

	// Process
	{"linux.pslist.PsList", "List running processes", "process", "linux"},
	{"linux.pstree.PsTree", "Process tree", "process", "linux"},
	{"linux.psaux.PsAux", "Processes with full arguments (like ps aux)", "process", "linux"},
	{"linux.psscan.PsScan", "Scan for task_struct structures", "process", "linux"},
	{"linux.bash.Bash", "Bash command history from process memory", "process", "linux"},
	{"linux.zsh.Zsh", "Zsh command history from process memory", "process", "linux"},
	{"linux.elfs.Elfs", "List ELF binaries mapped in process memory", "process", "linux"},
	{"linux.envars.Envars", "Process environment variables", "process", "linux"},
	{"linux.library_list.LibraryList", "Shared libraries loaded per process", "process", "linux"},
	{"linux.proc.Maps", "Process memory maps (/proc/pid/maps equivalent)", "process", "linux"},
	{"linux.threads.Threads", "List process threads", "process", "linux"},

	// Network
	{"linux.sockstat.Sockstat", "Network socket statistics", "network", "linux"},
	{"linux.netstat.Netstat", "Active network connections", "network", "linux"},
	{"linux.netfilter.Netfilter", "Netfilter/iptables hook analysis", "network", "linux"},

	// Kernel / Rootkit Detection
	{"linux.lsmod.Lsmod", "Loaded kernel modules", "kernel", "linux"},
	{"linux.hidden_modules.Hidden_modules", "Detect hidden kernel modules", "kernel", "linux"},
	{"linux.check_modules.Check_modules", "Compare module lists for discrepancies", "kernel", "linux"},
	{"linux.check_idt.Check_idt", "Interrupt Descriptor Table integrity check", "kernel", "linux"},
	{"linux.check_syscall.Check_syscall", "System call table hook detection", "kernel", "linux"},
	{"linux.check_creds.Check_creds", "Detect processes with elevated credentials", "kernel", "linux"},
	{"linux.keyboard_notifiers.Keyboard_notifiers", "Keyboard notifier chain hooks (keylogger detection)", "kernel", "linux"},
	{"linux.tty_check.Tty_check", "TTY driver hook detection", "kernel", "linux"},

	// Filesystem
	{"linux.mountinfo.MountInfo", "Mounted filesystems", "filesystem", "linux"},
	{"linux.iomem.IOMem", "Physical memory map (/proc/iomem)", "filesystem", "linux"},
	{"linux.pagecache.PageCache", "Files in the page cache", "filesystem", "linux"},

	// Malware
	{"linux.malfind.Malfind", "Detect injected/suspicious memory regions", "malware", "linux"},

	// Misc / Info
	{"linux.boottime.Boottime", "System boot timestamp", "info", "linux"},
	{"linux.capabilities.Capabilities", "Process Linux capabilities", "misc", "linux"},
	{"linux.kmsg.Kmsg", "Kernel message buffer (dmesg equivalent)", "misc", "linux"},
	{"linux.ptrace.Ptrace", "Detect ptraced processes", "misc", "linux"},

	// ───────────────────────── macOS ─────────────────────────

	// Process
	{"mac.pslist.PsList", "List running processes", "process", "mac"},
	{"mac.pstree.PsTree", "Process tree", "process", "mac"},
	{"mac.psaux.PsAux", "Processes with arguments", "process", "mac"},
	{"mac.bash.Bash", "Bash command history", "process", "mac"},
	{"mac.zsh.Zsh", "Zsh command history", "process", "mac"},

	// Network
	{"mac.netstat.Netstat", "Active network connections", "network", "mac"},
	{"mac.socket_filters.Socket_filters", "Socket filter hooks (network interception)", "network", "mac"},

	// Kernel
	{"mac.lsmod.Lsmod", "Loaded kernel extensions (kexts)", "kernel", "mac"},
	{"mac.check_syscall.Check_syscall", "System call table hook detection", "kernel", "mac"},
	{"mac.check_sysctl.Check_sysctl", "Sysctl hook detection", "kernel", "mac"},
	{"mac.check_trap_table.Check_trap_table", "Trap table integrity check", "kernel", "mac"},
	{"mac.kauth_listeners.Kauth_listeners", "Kauth listener hooks", "kernel", "mac"},
	{"mac.kauth_scopes.Kauth_scopes", "Kauth scope hooks", "kernel", "mac"},
	{"mac.trustedbsd.Trustedbsd", "TrustedBSD MAC framework policy hooks", "kernel", "mac"},

	// Filesystem
	{"mac.mount.Mount", "Mounted filesystems", "filesystem", "mac"},
	{"mac.list_files.List_Files", "Open file descriptors per process", "filesystem", "mac"},

	// Malware
	{"mac.malfind.Malfind", "Detect injected code regions", "malware", "mac"},

	// Misc
	{"mac.ifconfig.Ifconfig", "Network interface configuration", "info", "mac"},
	{"mac.timers.Timers", "Kernel timers", "misc", "mac"},
	{"mac.proc_maps.Maps", "Process memory maps", "misc", "mac"},
	{"mac.vfsevents.VFSEvents", "VFS event monitoring", "misc", "mac"},

	// ─────────────────── Cross-platform / framework ───────────────────
	{"banners.Banners", "Identify OS version from string banners in memory", "info", "all"},
	{"timeliner.Timeliner", "Generate unified timeline of all timestamped artifacts", "timeline", "all"},
	{"yarascan.YaraScan", "YARA rule scan across entire memory image", "malware", "all"},
	{"layerwriter.LayerWriter", "Write memory layers to disk for external analysis", "misc", "all"},
	{"isfinfo.IsfInfo", "Display Intermediate Symbol Format (ISF) metadata", "info", "all"},
	{"configwriter.ConfigWriter", "Write running configuration to file", "misc", "all"},
	{"frameworkinfo.FrameworkInfo", "Volatility3 framework version and capabilities", "info", "all"},
}

// PluginsForOS returns the catalogue filtered to a specific OS family,
// always including cross-platform ("all") entries. osFamily of "" returns
// the entire catalogue. Used by the SPA browser to show only relevant
// plugins per dump type.
func PluginsForOS(osFamily string) []Vol3Plugin {
	if osFamily == "" {
		return Vol3Plugins
	}
	out := make([]Vol3Plugin, 0, len(Vol3Plugins))
	for _, p := range Vol3Plugins {
		if p.OS == osFamily || p.OS == "all" {
			out = append(out, p)
		}
	}
	return out
}

// WindowsFullAnalysisPlugins returns the plugin set used by Auto-Profile &
// Full Analysis on a Windows dump. Comprehensive IR-focused selection
// covering process discovery, network state, malware indicators (multiple
// detection angles), persistence, and credential dumping.
func WindowsFullAnalysisPlugins() []string {
	return []string{
		"windows.info.Info",
		"windows.pslist.PsList",
		"windows.pstree.PsTree",
		"windows.psscan.PsScan",
		"windows.cmdline.CmdLine",
		"windows.dlllist.DllList",
		"windows.netscan.NetScan",
		"windows.netstat.NetStat",
		"windows.malfind.Malfind",
		"windows.malware.hollowprocesses.HollowProcesses",
		"windows.malware.ldrmodules.LdrModules",
		"windows.malware.psxview.PsXView",
		"windows.malware.suspicious_threads.SuspiciousThreads",
		"windows.svcscan.SvcScan",
		"windows.handles.Handles",
		"windows.registry.hivelist.HiveList",
		"windows.registry.userassist.UserAssist",
		"windows.registry.scheduled_tasks.ScheduledTasks",
		"windows.filescan.FileScan",
		"windows.driverscan.DriverScan",
		"windows.callbacks.Callbacks",
		"windows.ssdt.SSDT",
		"windows.registry.hashdump.Hashdump",
		"windows.mutantscan.MutantScan",
		"timeliner.Timeliner",
	}
}

// LinuxFullAnalysisPlugins returns the plugin set used by Auto-Profile &
// Full Analysis on a Linux dump.
func LinuxFullAnalysisPlugins() []string {
	return []string{
		"linux.pslist.PsList",
		"linux.pstree.PsTree",
		"linux.psaux.PsAux",
		"linux.bash.Bash",
		"linux.zsh.Zsh",
		"linux.lsmod.Lsmod",
		"linux.hidden_modules.Hidden_modules",
		"linux.sockstat.Sockstat",
		"linux.netstat.Netstat",
		"linux.malfind.Malfind",
		"linux.check_syscall.Check_syscall",
		"linux.check_idt.Check_idt",
		"linux.check_creds.Check_creds",
		"linux.check_modules.Check_modules",
		"linux.keyboard_notifiers.Keyboard_notifiers",
		"linux.tty_check.Tty_check",
		"linux.mountinfo.MountInfo",
		"linux.capabilities.Capabilities",
		"linux.kmsg.Kmsg",
		"timeliner.Timeliner",
	}
}

// MacFullAnalysisPlugins returns the plugin set used by Auto-Profile &
// Full Analysis on a macOS dump.
func MacFullAnalysisPlugins() []string {
	return []string{
		"mac.pslist.PsList",
		"mac.pstree.PsTree",
		"mac.psaux.PsAux",
		"mac.bash.Bash",
		"mac.zsh.Zsh",
		"mac.lsmod.Lsmod",
		"mac.netstat.Netstat",
		"mac.malfind.Malfind",
		"mac.check_syscall.Check_syscall",
		"mac.check_sysctl.Check_sysctl",
		"mac.check_trap_table.Check_trap_table",
		"mac.trustedbsd.Trustedbsd",
		"mac.mount.Mount",
		"mac.ifconfig.Ifconfig",
		"timeliner.Timeliner",
	}
}

// PluginPretty returns a human-friendly label for a plugin name.
func PluginPretty(plugin string) string {
	switch plugin {
	case "windows.pslist", "linux.pslist":
		return "Process listing"
	case "windows.pstree", "linux.pstree":
		return "Process tree"
	case "windows.cmdline":
		return "Command lines"
	case "windows.netscan":
		return "Network connections (netscan)"
	case "windows.netstat":
		return "Network connections (netstat)"
	case "windows.malfind", "linux.malfind":
		return "Malware detection (malfind)"
	case "windows.dlllist":
		return "Loaded DLLs"
	case "windows.handles":
		return "Open handles"
	case "windows.svcscan":
		return "Services"
	case "windows.registry.hivelist":
		return "Registry hives"
	case "windows.hashdump":
		return "Password hashes"
	case "windows.filescan":
		return "File objects"
	case "linux.bash":
		return "Bash history"
	case "linux.check_idt":
		return "IDT check"
	case "linux.check_syscall":
		return "Syscall table check"
	case "linux.lsmod":
		return "Kernel modules"
	case "linux.sockstat":
		return "Network sockets"
	case "linux.tty_check":
		return "TTY devices"
	case "linux.proc.Maps":
		return "Process memory maps"
	case "timeliner.Timeliner":
		return "Timeline"
	case "yarascan.YaraScan", "windows.yarascan":
		return "YARA scan"
	case "banners.Banners":
		return "Kernel banners"
	}
	return plugin
}

// ---------------------------------------------------------------------------
// Output parsing helpers
// ---------------------------------------------------------------------------

// CountTableRows counts data rows in CSV plugin output. The first non-blank,
// non-noise line is treated as the CSV header and skipped; every subsequent
// non-blank line that isn't a Volatility3 progress message is a data row.
func CountTableRows(outFile string) int {
	data, err := os.ReadFile(outFile)
	if err != nil {
		return 0
	}
	count := 0
	seenHeader := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Skip Volatility3 progress/noise lines that leak into stdout.
		if strings.HasPrefix(line, "Progress:") || strings.HasPrefix(line, "Volatility") ||
			strings.HasPrefix(line, "WARNING:") || strings.HasPrefix(line, "*") {
			continue
		}
		if !seenHeader {
			seenHeader = true // first real line is the CSV header
			continue
		}
		count++
	}
	return count
}

// ParseMalfindFindings inspects malfind CSV output for injected-code indicators.
// CSV columns (Volatility3 -r csv): PID,Process,Start VPN,End VPN,Tag,Protection,...
func ParseMalfindFindings(outFile, plugin string) []Finding {
	data, err := os.ReadFile(outFile)
	if err != nil {
		return nil
	}
	var findings []Finding
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue // skip CSV header
		}
		if strings.HasPrefix(line, "Progress:") || strings.HasPrefix(line, "WARNING:") {
			continue
		}
		fields := splitCSVLine(line)
		if len(fields) < 3 {
			continue
		}
		pidStr := strings.Trim(fields[0], `"`)
		if !isInt(pidStr) {
			continue
		}
		pid := atoi(pidStr)
		process := strings.Trim(fields[1], `"`)
		address := strings.Trim(fields[2], `"`)

		sev := "high"
		// Protection field (col 4 in Volatility3 malfind CSV) or any field
		// containing "PAGE_EXECUTE_READWRITE" / "MZ" signals injected PE.
		lineUpper := strings.ToUpper(line)
		if strings.Contains(lineUpper, "MZ") ||
			strings.Contains(lineUpper, "PAGE_EXECUTE_READWRITE") {
			sev = "critical"
		}

		title := fmt.Sprintf("Suspicious memory region in %s (PID %d)", process, pid)
		if sev == "critical" {
			title = fmt.Sprintf("MZ header / RWX region — likely injected PE in %s (PID %d)",
				process, pid)
		}
		findings = append(findings, Finding{
			Severity: sev,
			Title:    title,
			Source:   plugin,
			PID:      pid,
			Process:  process,
			Address:  address,
		})
	}
	return findings
}

// ParseYaraFindings parses yarascan CSV output for rule matches.
// CSV columns (Volatility3 -r csv): Rule,Offset,HexData,Vars,Process,PID,...
// (exact column order varies by Volatility3 version; we search all fields).
func ParseYaraFindings(outFile string) []Finding {
	data, err := os.ReadFile(outFile)
	if err != nil {
		return nil
	}
	var findings []Finding
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue // skip CSV header
		}
		if strings.HasPrefix(line, "Progress:") || strings.HasPrefix(line, "WARNING:") {
			continue
		}
		fields := splitCSVLine(line)
		if len(fields) < 3 {
			continue
		}
		// Try to locate rule, process, PID from the field set regardless of
		// column order. Rule is always a non-numeric non-empty first field in
		// yarascan output.
		rule := strings.Trim(fields[0], `"`)
		if rule == "" || isInt(rule) {
			continue
		}
		// Scan for a numeric PID field.
		pid := 0
		process := ""
		addr := ""
		for fi, f := range fields {
			f = strings.Trim(f, `"`)
			if isInt(f) && pid == 0 {
				pid = atoi(f)
			}
			// Process name heuristic: non-numeric, looks like a .exe
			if strings.HasSuffix(strings.ToLower(f), ".exe") && process == "" {
				process = f
			}
			// Address heuristic: starts with "0x"
			if strings.HasPrefix(f, "0x") && addr == "" && fi > 0 {
				addr = f
			}
		}

		sev := "high"
		ruleLower := strings.ToLower(rule)
		switch {
		case strings.Contains(ruleLower, "cobalt") || strings.Contains(ruleLower, "mimikatz") ||
			strings.Contains(ruleLower, "meterpreter") || strings.Contains(ruleLower, "ransomware"):
			sev = "critical"
		case strings.Contains(ruleLower, "shellcode") || strings.Contains(ruleLower, "loader"):
			sev = "high"
		}
		title := fmt.Sprintf("YARA rule %s matched", rule)
		if process != "" {
			title = fmt.Sprintf("YARA rule %s matched in %s (PID %d)", rule, process, pid)
		}
		findings = append(findings, Finding{
			Severity: sev,
			Title:    title,
			Source:   "yarascan",
			PID:      pid,
			Process:  process,
			Address:  addr,
		})
	}
	return findings
}

// splitCSVLine splits a single CSV line into fields, respecting double-quoted
// values that may contain commas. Does not handle escaped quotes (\" inside
// quoted fields) — Volatility3's CSV renderer uses the RFC 4180 convention of
// doubling quotes (""), which is handled by stripping outer quotes on each
// field at the call site.
func splitCSVLine(line string) []string {
	var fields []string
	current := strings.Builder{}
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
		case c == ',' && !inQuotes:
			fields = append(fields, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func isInt(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
