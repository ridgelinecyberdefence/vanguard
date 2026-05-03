package updates

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ridgelinecyberdefence/vanguard/internal/tools"
)

// BundleManifest describes the contents of an offline update bundle. It's
// serialized as manifest.json at the bundle root.
type BundleManifest struct {
	Created         time.Time         `json:"created"`
	CreatedBy       string            `json:"created_by"`
	VanGuardVersion string            `json:"vanguard_version"`
	Components      []BundleComponent `json:"components"`
}

// BundleComponent is a single file inside the bundle.
type BundleComponent struct {
	Name     string `json:"name"`     // tool ID or rule-set ID
	Kind     string `json:"kind"`     // "tool" or "rules"
	Version  string `json:"version"`  // installed_version OR a date for rule sets
	Platform string `json:"platform,omitempty"` // windows / linux / both
	File     string `json:"file"`     // path inside the bundle (forward slashes)
	SHA256   string `json:"sha256"`
}

// BundleSpec is what CreateBundle consumes — selectable subset of components.
type BundleSpec struct {
	IncludeTools     []string // tool IDs to include
	IncludeRuleSets  []string // rule-set tool IDs to include
	IncludeVanGuard  bool     // include the running vanguard binary?
	OutputDir        string   // parent directory; bundle dir created underneath
	CreatedBy        string
	VanGuardVersion  string
	VanGuardBinary   string   // absolute path to the running vanguard binary
}

// CreateResult is returned by CreateBundle.
type CreateResult struct {
	BundleDir   string
	ManifestPath string
	ZipPath     string // empty if not zipped
	Bytes       int64  // total bundle size
	Components  int
}

// CreateBundle builds an offline update bundle on disk.
//
// Tool binaries are pulled from the local install (we assume the analyst
// machine itself is up to date). Rule sets are zipped from their local
// directories. Each file is hashed with SHA256 and recorded in the manifest.
func (m *Manager) CreateBundle(spec BundleSpec) (CreateResult, error) {
	if spec.OutputDir == "" {
		spec.OutputDir = filepath.Join(m.RootDir, "output")
	}
	stamp := time.Now().Format("20060102")
	bundleDir := filepath.Join(spec.OutputDir, "vanguard_updates_"+stamp)
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return CreateResult{}, fmt.Errorf("creating bundle dir: %w", err)
	}

	mani := BundleManifest{
		Created:         time.Now().UTC(),
		CreatedBy:       spec.CreatedBy,
		VanGuardVersion: spec.VanGuardVersion,
	}

	// Tools.
	for _, id := range spec.IncludeTools {
		t := m.Tools.GetTool(id)
		if t == nil || !t.Installed {
			continue
		}
		src := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
		platform := t.Platform
		dest := filepath.Join(bundleDir, "tools", platform, filepath.Base(src))
		if err := copyFile(src, dest); err != nil {
			return CreateResult{}, fmt.Errorf("copy tool %s: %w", id, err)
		}
		hash, _ := sha256OfFile(dest)
		mani.Components = append(mani.Components, BundleComponent{
			Name:     id,
			Kind:     string(ItemTool),
			Version:  t.InstalledVersion,
			Platform: platform,
			File:     toBundlePath("tools", platform, filepath.Base(src)),
			SHA256:   hash,
		})
	}

	// Rule sets — zip each directory tree.
	if len(spec.IncludeRuleSets) > 0 {
		_ = os.MkdirAll(filepath.Join(bundleDir, "rules"), 0o755)
	}
	for _, id := range spec.IncludeRuleSets {
		t := m.Tools.GetTool(id)
		if t == nil {
			continue
		}
		src := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
		zipName := strings.TrimSuffix(filepath.Base(strings.TrimRight(src, "/\\")), "/") + ".zip"
		dest := filepath.Join(bundleDir, "rules", zipName)
		if err := zipDir(src, dest); err != nil {
			return CreateResult{}, fmt.Errorf("zip rules %s: %w", id, err)
		}
		hash, _ := sha256OfFile(dest)
		mani.Components = append(mani.Components, BundleComponent{
			Name:    id,
			Kind:    string(ItemRuleSet),
			Version: ReadTimestamp(m.RootDir, t.LocalPath).UTC().Format("2006-01-02"),
			File:    toBundlePath("rules", zipName),
			SHA256:  hash,
		})
	}

	// VanGuard binary.
	if spec.IncludeVanGuard && spec.VanGuardBinary != "" {
		dest := filepath.Join(bundleDir, "vanguard", filepath.Base(spec.VanGuardBinary))
		if err := copyFile(spec.VanGuardBinary, dest); err != nil {
			return CreateResult{}, fmt.Errorf("copy vanguard: %w", err)
		}
		hash, _ := sha256OfFile(dest)
		mani.Components = append(mani.Components, BundleComponent{
			Name:    "vanguard",
			Kind:    string(ItemVanGuard),
			Version: spec.VanGuardVersion,
			File:    toBundlePath("vanguard", filepath.Base(spec.VanGuardBinary)),
			SHA256:  hash,
		})
	}

	// Manifest.
	manPath := filepath.Join(bundleDir, "manifest.json")
	mf, err := os.Create(manPath)
	if err != nil {
		return CreateResult{}, fmt.Errorf("creating manifest: %w", err)
	}
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(mani)
	mf.Close()

	res := CreateResult{
		BundleDir:    bundleDir,
		ManifestPath: manPath,
		Components:   len(mani.Components),
		Bytes:        dirSize(bundleDir),
	}
	return res, nil
}

// CompressBundle zips the bundle directory in place and returns the zip path.
func (m *Manager) CompressBundle(bundleDir string) (string, error) {
	zipPath := bundleDir + ".zip"
	if err := zipDir(bundleDir, zipPath); err != nil {
		return "", err
	}
	return zipPath, nil
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

// ApplyResult is returned by ApplyBundle.
type ApplyResult struct {
	Manifest BundleManifest
	Outcomes []UpdateOutcome
}

// ApplyBundle reads bundlePath (directory OR zip file) and copies validated
// components into the analyst's tree. Components with bad SHA256 are skipped
// and reported in the result.
func (m *Manager) ApplyBundle(bundlePath string) (*ApplyResult, error) {
	bundleDir, cleanup, err := materialiseBundle(bundlePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	manPath := filepath.Join(bundleDir, "manifest.json")
	data, err := os.ReadFile(manPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var mani BundleManifest
	if err := json.Unmarshal(data, &mani); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	res := &ApplyResult{Manifest: mani}

	// PREFLIGHT: verify EVERY component's SHA256 against the manifest before
	// applying anything. A single mismatch means the bundle is corrupted or
	// tampered — applying ANY component from a compromised bundle is unsafe,
	// even if other components hash OK. This is stricter than the previous
	// per-component skip behaviour (which silently dropped bad components).
	if err := preflightVerifyBundle(bundleDir, mani.Components); err != nil {
		return nil, fmt.Errorf(
			"offline update bundle integrity check failed. Do not apply — "+
				"the bundle may have been tampered with. %w", err)
	}

	for _, comp := range mani.Components {
		started := time.Now()
		out := UpdateOutcome{Name: comp.Name, To: comp.Version}
		switch ItemKind(comp.Kind) {
		case ItemTool:
			out.Kind = ItemTool
		case ItemRuleSet:
			out.Kind = ItemRuleSet
		case ItemVanGuard:
			out.Kind = ItemVanGuard
		default:
			out.Error = "unknown component kind: " + comp.Kind
			out.Duration = time.Since(started)
			res.Outcomes = append(res.Outcomes, out)
			continue
		}

		src := filepath.Join(bundleDir, filepath.FromSlash(comp.File))

		// Apply per-kind. Hashes were already verified in the preflight pass.
		switch ItemKind(comp.Kind) {
		case ItemTool:
			out = m.applyToolFromBundle(comp, src, started)
		case ItemRuleSet:
			out = m.applyRuleSetFromBundle(comp, src, started)
		case ItemVanGuard:
			out.Error = "VanGuard self-update from bundle is manual — copy " +
				src + " to your install path."
			out.Duration = time.Since(started)
		}
		res.Outcomes = append(res.Outcomes, out)
	}
	return res, nil
}

// preflightVerifyBundle hashes every component file declared in the manifest
// and compares against the recorded SHA256. Returns the first mismatch as an
// error so the caller can abort the entire apply. Missing files are also
// fatal — a manifest entry without a corresponding payload means the bundle
// was tampered with after manifest generation.
func preflightVerifyBundle(bundleDir string, comps []BundleComponent) error {
	for _, comp := range comps {
		src := filepath.Join(bundleDir, filepath.FromSlash(comp.File))
		if _, err := os.Stat(src); err != nil {
			return fmt.Errorf("%s: file %s not found in bundle: %w",
				comp.Name, comp.File, err)
		}
		got, err := sha256OfFile(src)
		if err != nil {
			return fmt.Errorf("%s: hashing %s: %w", comp.Name, comp.File, err)
		}
		if !strings.EqualFold(got, comp.SHA256) {
			return fmt.Errorf(
				"%s (%s): SHA256 mismatch — expected %s, got %s",
				comp.Name, comp.File, comp.SHA256, got)
		}
	}
	return nil
}

// applyToolFromBundle copies a tool binary from a bundle into LocalPath, with
// backup-then-restore semantics.
func (m *Manager) applyToolFromBundle(comp BundleComponent, src string, started time.Time) UpdateOutcome {
	out := UpdateOutcome{Name: comp.Name, Kind: ItemTool, To: comp.Version}
	t := m.Tools.GetTool(comp.Name)
	if t == nil {
		out.Error = "tool not registered locally"
		out.Duration = time.Since(started)
		return out
	}
	out.From = t.InstalledVersion
	dest := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
	bak, _ := backupPath(dest)
	if err := copyFile(src, dest); err != nil {
		if bak != "" {
			_ = restoreBackup(bak, dest)
		}
		out.Error = err.Error()
		out.Duration = time.Since(started)
		return out
	}
	if bak != "" {
		_ = removeBackup(bak)
	}
	t.Installed = true
	t.InstalledVersion = comp.Version
	out.Success = true
	out.Duration = time.Since(started)
	return out
}

// applyRuleSetFromBundle extracts a rules zip from the bundle into LocalPath
// (preserving rules/yara/custom/ for the YARA case).
func (m *Manager) applyRuleSetFromBundle(comp BundleComponent, src string, started time.Time) UpdateOutcome {
	out := UpdateOutcome{Name: comp.Name, Kind: ItemRuleSet, To: comp.Version}
	t := m.Tools.GetTool(comp.Name)
	if t == nil {
		out.Error = "rule set not registered locally"
		out.Duration = time.Since(started)
		return out
	}
	dest := filepath.Join(m.RootDir, filepath.FromSlash(t.LocalPath))
	dest = strings.TrimRight(dest, string(os.PathSeparator))

	customSnap := ""
	if comp.Name == "yara-rules" {
		if cs, err := snapshotYaraCustom(dest); err == nil {
			customSnap = cs
		}
	}

	bak, _ := backupPath(dest)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		if bak != "" {
			_ = restoreBackup(bak, dest)
		}
		out.Error = err.Error()
		out.Duration = time.Since(started)
		return out
	}
	if err := unzipInto(src, dest); err != nil {
		if bak != "" {
			_ = restoreBackup(bak, dest)
		}
		out.Error = err.Error()
		out.Duration = time.Since(started)
		return out
	}
	if customSnap != "" {
		_ = restoreYaraCustom(customSnap, dest)
		_ = os.RemoveAll(filepath.Dir(customSnap))
	}
	if bak != "" {
		_ = removeBackup(bak)
	}

	_ = WriteTimestamp(m.RootDir, t.LocalPath, time.Now().UTC())
	out.Success = true
	out.Duration = time.Since(started)
	return out
}

// ---------------------------------------------------------------------------
// Bundle materialisation: accept a directory OR a .zip path.
// ---------------------------------------------------------------------------

// materialiseBundle returns the path of an unpacked bundle directory plus a
// cleanup func. When the input is already a directory, the cleanup is a no-op.
func materialiseBundle(path string) (string, func(), error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", func() {}, err
	}
	if info.IsDir() {
		return path, func() {}, nil
	}
	if !strings.HasSuffix(strings.ToLower(path), ".zip") {
		return "", func() {}, fmt.Errorf("bundle must be a directory or a .zip file")
	}
	tmp, err := os.MkdirTemp("", "vg-bundle-")
	if err != nil {
		return "", func() {}, err
	}
	if err := unzipInto(path, tmp); err != nil {
		os.RemoveAll(tmp)
		return "", func() {}, err
	}
	// Some zips wrap their contents in a single top-level directory; detect that.
	entries, err := os.ReadDir(tmp)
	if err == nil && len(entries) == 1 && entries[0].IsDir() {
		inner := filepath.Join(tmp, entries[0].Name())
		if _, err := os.Stat(filepath.Join(inner, "manifest.json")); err == nil {
			return inner, func() { os.RemoveAll(tmp) }, nil
		}
	}
	return tmp, func() { os.RemoveAll(tmp) }, nil
}

// ---------------------------------------------------------------------------
// VanGuard self-version check
// ---------------------------------------------------------------------------

// VanGuardCheck queries the VanGuard repo's latest release and compares it
// against currentVersion. Returns "(version, body)" pair when a newer
// release exists; otherwise (currentVersion, "").
func VanGuardCheck(repo, currentVersion string) (latest, body string, hasUpdate bool, err error) {
	tag, body, err := LatestRelease(repo)
	if err != nil {
		return currentVersion, "", false, err
	}
	if normaliseVersion(tag) == normaliseVersion(currentVersion) {
		return tag, body, false, nil
	}
	return tag, body, true, nil
}

func normaliseVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	return s
}

// ---------------------------------------------------------------------------
// Tiny helpers
// ---------------------------------------------------------------------------

func toBundlePath(parts ...string) string { return strings.Join(parts, "/") }

func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dirSize(dir string) int64 {
	var b int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		b += info.Size()
		return nil
	})
	return b
}

// zipDir compresses src (a directory) into dst (a .zip path).
func zipDir(src, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	w := zip.NewWriter(out)
	defer w.Close()

	srcAbs, _ := filepath.Abs(src)
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(srcAbs, p)
		if rel == "." {
			return nil
		}
		if info.IsDir() {
			_, err := w.Create(filepath.ToSlash(rel) + "/")
			return err
		}
		f, err := w.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(f, in)
		return err
	})
}

// unzipInto extracts src (a .zip path) into dst (a directory). Zip-slip safe.
func unzipInto(src, dst string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	cleanDst := filepath.Clean(dst)
	for _, f := range r.File {
		target := filepath.Join(dst, f.Name)
		if !strings.HasPrefix(target, cleanDst+string(os.PathSeparator)) && target != cleanDst {
			continue
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			return err
		}
		rc.Close()
		out.Close()
	}
	return nil
}

// _ keeps tools.Tool referenced to make grep + diff easier when reviewing.
var _ = (*tools.Tool)(nil)
