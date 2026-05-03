package analysis

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// SourceKind groups data sources by where they came from.
type SourceKind string

const (
	SourceTriage    SourceKind = "triage"
	SourceDisk      SourceKind = "disk"
	SourceRemote    SourceKind = "remote"
	SourceMemory    SourceKind = "memory"
	SourceAnalysis  SourceKind = "analysis"
	SourceCustom    SourceKind = "custom"
)

// DataSource is one collection on disk that an analysis op can be pointed at.
type DataSource struct {
	Kind      SourceKind
	Label     string // human-readable, includes timestamp + collection type
	Path      string // absolute path to the collection directory
	Files     int
	Bytes     int64
	Modified  time.Time
}

// SourceFilter narrows the pool of returned sources.
//
// When set, only sources that contain at least one file matching one of the
// extensions are returned. Use empty to get everything.
type SourceFilter struct {
	Extensions []string // e.g. []string{".evtx"}
	Names      []string // exact filename matches (case-insensitive), e.g. []string{"$MFT"}
}

// DiscoverDataSources walks the case's output tree under
// output/{caseID}/{triage,disk,remote,memory,analysis} and returns the
// collections it finds. Per-source file counts and total size are computed.
//
// When filter is non-zero, only sources whose tree contains at least one
// matching file pass through.
func DiscoverDataSources(rootDir, caseID string, filter SourceFilter) ([]DataSource, error) {
	if caseID == "" {
		return nil, fmt.Errorf("active case required")
	}
	base := filepath.Join(rootDir, "output", caseID)
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []DataSource

	// Per-kind collection roots: each immediate subdirectory under one of
	// these is treated as a collection.
	roots := []struct {
		kind SourceKind
		path string
	}{
		{SourceTriage, filepath.Join(base, "triage")},
		{SourceDisk, filepath.Join(base, "disk")},
		{SourceRemote, filepath.Join(base, "remote", "triage")},
		{SourceRemote, filepath.Join(base, "remote", "eventlogs")},
		{SourceRemote, filepath.Join(base, "remote", "registry")},
		{SourceRemote, filepath.Join(base, "remote", "acquired")},
		{SourceAnalysis, filepath.Join(base, "analysis")},
	}

	for _, r := range roots {
		entries, err := os.ReadDir(r.path)
		if err != nil {
			continue // missing root just means no collections yet
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ds := newDataSource(r.kind, filepath.Join(r.path, e.Name()), e.Name())
			if !filter.matches(ds.Path) {
				continue
			}
			out = append(out, ds)
		}
	}

	// Memory dumps — flat files under output/{case}/memory.
	memDir := filepath.Join(base, "memory")
	if entries, err := os.ReadDir(memDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(filepath.Ext(e.Name()))
			if lower != ".dmp" && lower != ".raw" && lower != ".lime" &&
				lower != ".vmem" && lower != ".mem" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			path := filepath.Join(memDir, e.Name())
			ds := DataSource{
				Kind:     SourceMemory,
				Label:    e.Name(),
				Path:     path,
				Files:    1,
				Bytes:    info.Size(),
				Modified: info.ModTime(),
			}
			if !filter.matches(path) {
				continue
			}
			out = append(out, ds)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		// Group by kind in display order, then most recent first.
		if out[i].Kind != out[j].Kind {
			return kindOrder(out[i].Kind) < kindOrder(out[j].Kind)
		}
		return out[i].Modified.After(out[j].Modified)
	})
	return out, nil
}

func kindOrder(k SourceKind) int {
	switch k {
	case SourceTriage:
		return 0
	case SourceDisk:
		return 1
	case SourceRemote:
		return 2
	case SourceMemory:
		return 3
	case SourceAnalysis:
		return 4
	}
	return 99
}

// newDataSource fills the file count + total size lazily.
func newDataSource(kind SourceKind, path, name string) DataSource {
	files, bytes := dirContents(path)
	info, _ := os.Stat(path)
	mod := time.Time{}
	if info != nil {
		mod = info.ModTime()
	}
	return DataSource{
		Kind:     kind,
		Label:    name,
		Path:     path,
		Files:    files,
		Bytes:    bytes,
		Modified: mod,
	}
}

// matches reports whether a directory tree contains at least one file matching
// the filter. Empty filters always match.
func (f SourceFilter) matches(root string) bool {
	if len(f.Extensions) == 0 && len(f.Names) == 0 {
		return true
	}
	matched := false
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		lowerName := strings.ToLower(name)
		lowerExt := strings.ToLower(filepath.Ext(name))
		for _, ext := range f.Extensions {
			if strings.EqualFold(ext, lowerExt) {
				matched = true
				return filepath.SkipAll
			}
		}
		for _, want := range f.Names {
			if strings.EqualFold(want, name) || strings.EqualFold(want, lowerName) {
				matched = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return matched
}

// dirContents returns (file count, total bytes) under dir, recursively.
func dirContents(dir string) (int, int64) {
	var c int
	var b int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		c++
		if info, err := d.Info(); err == nil {
			b += info.Size()
		}
		return nil
	})
	return c, b
}

// FormatBytes is a tiny helper used by the TUI source picker.
func FormatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FindEventLogCSV searches src for a parsed-EvtxECmd CSV. Returns the most
// recent match or "" if none. Used by the event-log analysis ops which
// require a previous parse pass.
func FindEventLogCSV(src string) string {
	var best string
	var bestMod time.Time
	_ = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		// EvtxECmd default output filename is <something>.csv with the column
		// signature we look for at parse-time. Match common variants.
		if !strings.HasSuffix(name, ".csv") {
			return nil
		}
		if !strings.Contains(name, "event") {
			return nil
		}
		info, _ := d.Info()
		if info != nil && info.ModTime().After(bestMod) {
			bestMod = info.ModTime()
			best = p
		}
		return nil
	})
	return best
}
