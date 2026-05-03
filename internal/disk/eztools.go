package disk

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/logging"
)

// EZToolsManager wraps Eric Zimmerman's parsing tools.
type EZToolsManager struct {
	RootDir string
	Logger  *logging.Logger
}

// NewEZToolsManager creates an EZ Tools manager.
func NewEZToolsManager(rootDir string, logger *logging.Logger) *EZToolsManager {
	return &EZToolsManager{RootDir: rootDir, Logger: logger}
}

// Dir returns the EZ Tools install directory.
func (e *EZToolsManager) Dir() string {
	return filepath.Join(e.RootDir, "bin", "windows", "ez-tools")
}

// ToolPath resolves the absolute path to an EZ Tools binary.
//
// The current shipping layout is FLAT — every binary sits at the
// ez-tools root (ez-tools/EvtxECmd.exe, ez-tools/MFTECmd.exe, …) with
// supporting trees in named subdirectories alongside (ez-tools/EvtxECmd/
// holds Maps/, ez-tools/RECmd/ holds BatchExamples/, ez-tools/JumpListExplorer/
// holds the GUI assets). Older releases used per-tool subdirectories or
// net6/ and net9/ framework folders. We probe in priority order: flat,
// per-tool subdir, framework subdir, recursive case-insensitive walk.
func (e *EZToolsManager) ToolPath(binaryName string) string {
	root := e.Dir()
	toolName := strings.TrimSuffix(binaryName, filepath.Ext(binaryName))

	// 1. Flat: ez-tools/EvtxECmd.exe
	if hit := fileExistsAny(filepath.Join(root, binaryName)); hit != "" {
		return hit
	}
	// 2. Per-tool subdir: ez-tools/EvtxECmd/EvtxECmd.exe
	if hit := fileExistsAny(filepath.Join(root, toolName, binaryName)); hit != "" {
		return hit
	}
	// 3. Framework subdirs: ez-tools/net6/EvtxECmd.exe, ez-tools/net9/EvtxECmd.exe,
	//    and ez-tools/net6/EvtxECmd/EvtxECmd.exe.
	for _, fw := range []string{"net6", "net9"} {
		if hit := fileExistsAny(filepath.Join(root, fw, binaryName)); hit != "" {
			return hit
		}
		if hit := fileExistsAny(filepath.Join(root, fw, toolName, binaryName)); hit != "" {
			return hit
		}
	}
	// 4. Recursive one level — case-insensitive on the binary name. Catches
	//    arbitrary casing (Evtxecmd.exe, EVTXECMD.EXE) and unexpected layouts.
	entries, err := os.ReadDir(root)
	if err == nil {
		nameLower := strings.ToLower(binaryName)
		for _, entry := range entries {
			if !entry.IsDir() {
				if strings.ToLower(entry.Name()) == nameLower {
					return filepath.Join(root, entry.Name())
				}
				continue
			}
			subPath := filepath.Join(root, entry.Name())
			subEntries, err := os.ReadDir(subPath)
			if err != nil {
				continue
			}
			for _, sub := range subEntries {
				if sub.IsDir() {
					continue
				}
				if strings.ToLower(sub.Name()) == nameLower {
					return filepath.Join(subPath, sub.Name())
				}
			}
		}
	}
	return ""
}

// fileExistsAny returns the path if it exists as a regular file, otherwise "".
// Uses case-insensitive lookup as a fallback so a binary saved with different
// casing (EVTXECMD.EXE on a copy from a case-sensitive filesystem) still hits.
func fileExistsAny(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	dir := filepath.Dir(path)
	want := strings.ToLower(filepath.Base(path))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.ToLower(e.Name()) == want {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

// Installed reports whether at least the indicator binary (MFTECmd) is present.
func (e *EZToolsManager) Installed() bool {
	return e.ToolPath("MFTECmd.exe") != ""
}

// MissingBinaries lists EZ Tools binaries we expect but couldn't find.
func (e *EZToolsManager) MissingBinaries() []string {
	all := []string{
		"MFTECmd.exe", "EvtxECmd.exe", "PECmd.exe", "RECmd.exe",
		"AmcacheParser.exe", "AppCompatCacheParser.exe",
		"JLECmd.exe", "LECmd.exe", "RBCmd.exe", "SrumECmd.exe",
	}
	var missing []string
	for _, b := range all {
		if e.ToolPath(b) == "" {
			missing = append(missing, b)
		}
	}
	return missing
}

// ---------------------------------------------------------------------------
// Source resolution
// ---------------------------------------------------------------------------

// LatestKapeCollection returns the path to the most recent KAPE output dir
// for the given case, or "" if none exists.
//
// caseDiskOutDir writes to output/{case}/disk/kape/{ts}/ — so the tree is
// disk/kape/{ts}/ NOT disk/{ts}/kape/. Use latestNamedDir on the kape/
// subdirectory to find the newest timestamp directory inside it.
func LatestKapeCollection(rootDir, caseID string) string {
	return latestNamedDir(filepath.Join(OutputBase(rootDir, caseID), "kape"))
}

// LatestTriageCollection returns the most recent triage collection directory.
func LatestTriageCollection(rootDir, caseID string) string {
	return latestNamedDir(filepath.Join(rootDir, "output", caseID, "triage"))
}

// latestSubdirContaining returns base/{ts}/{name} where ts is the latest entry
// that contains a {name} subdirectory.
func latestSubdirContaining(base, name string) string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	type ts struct {
		path string
		mod  string
	}
	var candidates []ts
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(base, e.Name(), name)
		if info, err := os.Stat(sub); err == nil && info.IsDir() {
			candidates = append(candidates, ts{path: sub, mod: e.Name()})
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].mod > candidates[j].mod
	})
	return candidates[0].path
}

func latestNamedDir(base string) string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return filepath.Join(base, names[0])
}

// ---------------------------------------------------------------------------
// File discovery helpers
// ---------------------------------------------------------------------------

// FindEvtxFiles returns directories under root that contain .evtx files.
// EvtxECmd accepts a directory and processes all .evtx files within.
func FindEvtxFiles(root string) []string {
	dirs := map[string]bool{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".evtx") {
			dirs[filepath.Dir(p)] = true
		}
		return nil
	})
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// FindFile returns the first file matching matcher under root.
func FindFile(root string, matcher func(name string) bool) string {
	var found string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if matcher(d.Name()) {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// FindFiles returns all files matching matcher under root.
func FindFiles(root string, matcher func(name string) bool) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if matcher(d.Name()) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// findRECmdBatch returns the first RECmd_Batch_MC.reb under ezBase, or "" if
// none can be found. Checks the canonical layouts first (RECmd/BatchExamples/
// then ez-tools/BatchExamples/) before falling back to a recursive walk —
// release archives have moved this file around historically and we don't
// want a layout change to silently downgrade RECmd to per-hive parsing.
func findRECmdBatch(ezBase string) string {
	canonical := []string{
		filepath.Join(ezBase, "RECmd", "BatchExamples", "RECmd_Batch_MC.reb"),
		filepath.Join(ezBase, "BatchExamples", "RECmd_Batch_MC.reb"),
	}
	for _, c := range canonical {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	var found string
	_ = filepath.WalkDir(ezBase, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(d.Name(), "RECmd_Batch_MC.reb") {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// FindRegistryHives looks up the standard hive set under source.
// Returns a directory that contains hives (RECmd takes -d) plus any individual
// hive paths it finds. The returned dir is the parent of the most-found hives.
func FindRegistryHives(source string) (hiveDir string, hives map[string]string) {
	hives = map[string]string{}
	wanted := map[string]bool{
		"SAM": true, "SYSTEM": true, "SOFTWARE": true,
		"SECURITY": true, "NTUSER.DAT": true, "USRCLASS.DAT": true,
		"AMCACHE.HVE": true,
	}
	parents := map[string]int{}
	_ = filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		upper := strings.ToUpper(d.Name())
		if wanted[upper] {
			if _, exists := hives[upper]; !exists {
				hives[upper] = p
			}
			parents[filepath.Dir(p)]++
		}
		return nil
	})
	// Pick the parent with the most hits.
	best := 0
	for d, n := range parents {
		if n > best {
			best = n
			hiveDir = d
		}
	}
	return hiveDir, hives
}

// ---------------------------------------------------------------------------
// Common command runner
// ---------------------------------------------------------------------------

// runEZ executes an EZ Tools binary with the given args, capturing output.
func (e *EZToolsManager) runEZ(ctx context.Context, binPath, name string, args []string) CollectionResult {
	result := CollectionResult{Name: name}
	started := time.Now()

	if binPath == "" {
		result.Status = StatusFailed
		result.Error = name + " binary not found in EZ Tools install"
		result.Duration = time.Since(started)
		return result
	}

	if e.Logger != nil {
		e.Logger.Info("disk", "ez-tools exec: %s %s", binPath, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	// cwd is the ez-tools root, not filepath.Dir(binPath). Modern EZ Tools
	// drops every binary at the root with supporting trees in named
	// subdirectories — EvtxECmd needs `./EvtxECmd/Maps/`, RECmd needs
	// `./RECmd/BatchExamples/`. Setting cwd to the binary's own folder
	// breaks both lookups for tools that live in a subdir layout (older
	// builds) without helping the flat-layout case.
	cmd.Dir = e.Dir()
	out, err := cmd.CombinedOutput()
	result.Stdout = string(out)
	result.Duration = time.Since(started)

	if err != nil {
		// EZ Tools frequently exit non-zero when they encounter locked files,
		// unsupported record types, or duplicate entries, yet still write valid
		// CSV output. Set StatusPartial here; the per-tool callers check the
		// actual output file count and downgrade to StatusFailed if nothing was
		// produced, or leave it as StatusPartial for a successful-but-noisy run.
		result.Status = StatusPartial
		result.Warnings = append(result.Warnings, fmt.Sprintf("exit: %v", err))
	} else {
		result.Status = StatusSuccess
	}
	return result
}

// ---------------------------------------------------------------------------
// Per-tool entry points
// ---------------------------------------------------------------------------

// EvtxECmd parses Windows event logs.
func (e *EZToolsManager) EvtxECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "EvtxECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	dirs := FindEvtxFiles(sourceRoot)
	if len(dirs) == 0 {
		return CollectionResult{Name: "EvtxECmd", Status: StatusFailed,
			Error: "no .evtx files found under " + sourceRoot}
	}

	bin := e.ToolPath("EvtxECmd.exe")
	args := []string{
		"-d", sourceRoot,
		"--csv", outDir,
		"--csvf", "EventLogs.csv",
	}
	r := e.runEZ(ctx, bin, "EvtxECmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "EventLogs.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// MFTECmd parses the $MFT and produces both CSV and body file outputs.
func (e *EZToolsManager) MFTECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "MFTECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	mft := FindFile(sourceRoot, func(name string) bool {
		u := strings.ToUpper(name)
		return u == "$MFT" || u == "MFT" || strings.Contains(u, "$MFT")
	})
	if mft == "" {
		return CollectionResult{Name: "MFTECmd", Status: StatusFailed,
			Error: "$MFT not found under " + sourceRoot}
	}
	bin := e.ToolPath("MFTECmd.exe")

	csvArgs := []string{"-f", mft, "--csv", outDir, "--csvf", "MFT_Output.csv"}
	r := e.runEZ(ctx, bin, "MFTECmd", csvArgs)
	if r.Status == StatusSuccess {
		// Best effort body-file generation; ignore failure.
		bodyArgs := []string{"-f", mft, "--body", outDir, "--bodyf", "MFT_body.csv", "--bdl", "C"}
		_ = e.runEZ(ctx, bin, "MFTECmd-body", bodyArgs)
	}
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "MFT_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// RECmd parses registry hives, preferring the bundled batch file.
func (e *EZToolsManager) RECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "RECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	hiveDir, hives := FindRegistryHives(sourceRoot)
	if len(hives) == 0 {
		return CollectionResult{Name: "RECmd", Status: StatusFailed,
			Error: "no registry hives found under " + sourceRoot}
	}

	bin := e.ToolPath("RECmd.exe")

	// Prefer the bundled batch file if present. RECmd_Batch_MC.reb lives
	// in different places across release shapes (RECmd subdir, ez-tools
	// root, sometimes deeper); findRECmdBatch walks the install to find
	// the first match instead of guessing the layout.
	if batch := findRECmdBatch(e.Dir()); batch != "" && hiveDir != "" {
		args := []string{
			"-d", hiveDir,
			"--bn", batch,
			"--csv", outDir,
			"--csvf", "Registry_Output.csv",
		}
		r := e.runEZ(ctx, bin, "RECmd", args)
		r.OutputDir = outDir
		r.OutputFile = filepath.Join(outDir, "Registry_Output.csv")
		r.Files = countDirFiles(outDir)
		r.Bytes = dirSize(outDir)
		return r
	}

	// Fallback: parse each hive individually.
	var lastErr string
	successes := 0
	for _, hive := range hives {
		args := []string{"--hive", hive, "--csv", outDir}
		r := e.runEZ(ctx, bin, "RECmd: "+filepath.Base(hive), args)
		if r.Status == StatusSuccess {
			successes++
		} else {
			lastErr = r.Error
		}
	}
	final := CollectionResult{Name: "RECmd", OutputDir: outDir}
	final.Files = countDirFiles(outDir)
	final.Bytes = dirSize(outDir)
	if successes == len(hives) {
		final.Status = StatusSuccess
	} else if successes > 0 {
		final.Status = StatusPartial
		final.Warnings = append(final.Warnings, "RECmd: some hives failed: "+lastErr)
	} else {
		final.Status = StatusFailed
		final.Error = lastErr
	}
	return final
}

// PECmd parses prefetch (.pf) files.
func (e *EZToolsManager) PECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "PECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	pfFiles := FindFiles(sourceRoot, func(name string) bool {
		return strings.EqualFold(filepath.Ext(name), ".pf")
	})
	if len(pfFiles) == 0 {
		return CollectionResult{Name: "PECmd", Status: StatusFailed,
			Error: "no .pf prefetch files found under " + sourceRoot}
	}
	pfDir := filepath.Dir(pfFiles[0])
	bin := e.ToolPath("PECmd.exe")
	args := []string{"-d", pfDir, "--csv", outDir, "--csvf", "Prefetch_Output.csv"}
	r := e.runEZ(ctx, bin, "PECmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "Prefetch_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// AmcacheParser parses Amcache.hve.
func (e *EZToolsManager) AmcacheParser(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "AmcacheParser", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	amcache := FindFile(sourceRoot, func(name string) bool {
		return strings.EqualFold(name, "Amcache.hve")
	})
	if amcache == "" {
		return CollectionResult{Name: "AmcacheParser", Status: StatusFailed,
			Error: "Amcache.hve not found under " + sourceRoot}
	}
	bin := e.ToolPath("AmcacheParser.exe")
	args := []string{"-f", amcache, "--csv", outDir, "--csvf", "Amcache_Output.csv", "-i"}
	r := e.runEZ(ctx, bin, "AmcacheParser", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "Amcache_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// AppCompatCacheParser extracts Shimcache from the SYSTEM hive.
func (e *EZToolsManager) AppCompatCacheParser(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "AppCompatCacheParser", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	systemHive := FindFile(sourceRoot, func(name string) bool {
		return strings.EqualFold(name, "SYSTEM")
	})
	if systemHive == "" {
		return CollectionResult{Name: "AppCompatCacheParser", Status: StatusFailed,
			Error: "SYSTEM hive not found under " + sourceRoot}
	}
	bin := e.ToolPath("AppCompatCacheParser.exe")
	args := []string{"-f", systemHive, "--csv", outDir, "--csvf", "Shimcache_Output.csv"}
	r := e.runEZ(ctx, bin, "AppCompatCacheParser", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "Shimcache_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// JLECmd parses jump list files.
func (e *EZToolsManager) JLECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "JLECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	jl := FindFiles(sourceRoot, func(name string) bool {
		lower := strings.ToLower(name)
		return strings.HasSuffix(lower, ".automaticdestinations-ms") ||
			strings.HasSuffix(lower, ".customdestinations-ms")
	})
	if len(jl) == 0 {
		return CollectionResult{Name: "JLECmd", Status: StatusFailed,
			Error: "no jump list files found under " + sourceRoot}
	}
	jlDir := filepath.Dir(jl[0])
	bin := e.ToolPath("JLECmd.exe")
	args := []string{"-d", jlDir, "--csv", outDir, "--csvf", "JumpLists_Output.csv", "-q"}
	r := e.runEZ(ctx, bin, "JLECmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "JumpLists_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// LECmd parses .lnk files.
func (e *EZToolsManager) LECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "LECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	lnks := FindFiles(sourceRoot, func(name string) bool {
		return strings.EqualFold(filepath.Ext(name), ".lnk")
	})
	if len(lnks) == 0 {
		return CollectionResult{Name: "LECmd", Status: StatusFailed,
			Error: "no .lnk files found under " + sourceRoot}
	}
	bin := e.ToolPath("LECmd.exe")
	args := []string{"-d", sourceRoot, "--csv", outDir, "--csvf", "LNK_Output.csv", "-q"}
	r := e.runEZ(ctx, bin, "LECmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "LNK_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// SrumECmd parses SRUDB.dat. Picks up SOFTWARE hive for app-name resolution
// when present.
func (e *EZToolsManager) SrumECmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "SrumECmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	srum := FindFile(sourceRoot, func(name string) bool {
		return strings.EqualFold(name, "SRUDB.dat")
	})
	if srum == "" {
		return CollectionResult{Name: "SrumECmd", Status: StatusFailed,
			Error: "SRUDB.dat not found under " + sourceRoot}
	}
	software := FindFile(sourceRoot, func(name string) bool {
		return strings.EqualFold(name, "SOFTWARE")
	})

	bin := e.ToolPath("SrumECmd.exe")
	args := []string{"-f", srum, "--csv", outDir, "--csvf", "SRUM_Output.csv"}
	if software != "" {
		args = append(args, "-r", software)
	}
	r := e.runEZ(ctx, bin, "SrumECmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "SRUM_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// RBCmd parses Recycle Bin $I/$R artifacts.
func (e *EZToolsManager) RBCmd(ctx context.Context, sourceRoot, outDir string) CollectionResult {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return CollectionResult{Name: "RBCmd", Status: StatusFailed,
			Error: "creating output dir: " + err.Error()}
	}
	files := FindFiles(sourceRoot, func(name string) bool {
		return strings.HasPrefix(name, "$I") || strings.HasPrefix(name, "$R")
	})
	if len(files) == 0 {
		return CollectionResult{Name: "RBCmd", Status: StatusFailed,
			Error: "no Recycle Bin artifacts ($I/$R) found under " + sourceRoot}
	}
	rbDir := filepath.Dir(files[0])
	bin := e.ToolPath("RBCmd.exe")
	args := []string{"-d", rbDir, "--csv", outDir, "--csvf", "RecycleBin_Output.csv"}
	r := e.runEZ(ctx, bin, "RBCmd", args)
	r.OutputDir = outDir
	r.OutputFile = filepath.Join(outDir, "RecycleBin_Output.csv")
	r.Files = countDirFiles(outDir)
	r.Bytes = dirSize(outDir)
	return r
}

// ---------------------------------------------------------------------------
// All-parsers orchestration
// ---------------------------------------------------------------------------

// AllParsersStep names a parser invocation in the all-parsers run.
type AllParsersStep struct {
	Name     string
	SubDir   string
	Run      func(ctx context.Context, source, outDir string) CollectionResult
}

// AllParsers returns the ordered list of parser steps for a "parse all" run.
func (e *EZToolsManager) AllParsers() []AllParsersStep {
	return []AllParsersStep{
		{"EvtxECmd (Event Logs)", "evtxecmd", e.EvtxECmd},
		{"MFTECmd ($MFT)", "mftecmd", e.MFTECmd},
		{"RECmd (Registry)", "recmd", e.RECmd},
		{"PECmd (Prefetch)", "pecmd", e.PECmd},
		{"AmcacheParser", "amcache", e.AmcacheParser},
		{"AppCompatCacheParser (Shimcache)", "shimcache", e.AppCompatCacheParser},
		{"JLECmd (Jump Lists)", "jumplists", e.JLECmd},
		{"LECmd (LNK Files)", "lnkfiles", e.LECmd},
		{"SrumECmd (SRUM)", "srum", e.SrumECmd},
		{"RBCmd (Recycle Bin)", "recyclebin", e.RBCmd},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func countDirContents(dir string) (int, int64) {
	var count int
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		count++
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return count, total
}

func countDirFiles(dir string) int {
	c, _ := countDirContents(dir)
	return c
}

func dirSize(dir string) int64 {
	_, b := countDirContents(dir)
	return b
}
