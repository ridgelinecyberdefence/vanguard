package memory

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// dumpExtensions is the set of recognised memory dump file extensions.
var dumpExtensions = []string{".dmp", ".raw", ".lime", ".vmem", ".mem", ".bin"}

// ListDumps scans dir for memory dump files and returns them sorted by modified
// time (newest first).
func ListDumps(dir string) ([]DumpInfo, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var dumps []DumpInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if !isDumpExt(ext) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		dumps = append(dumps, DumpInfo{
			Name:     name,
			Path:     filepath.Join(dir, name),
			Size:     info.Size(),
			Modified: info.ModTime(),
			Format:   strings.TrimPrefix(ext, "."),
		})
	}

	sort.Slice(dumps, func(i, j int) bool {
		return dumps[i].Modified.After(dumps[j].Modified)
	})
	return dumps, nil
}

func isDumpExt(ext string) bool {
	for _, d := range dumpExtensions {
		if d == ext {
			return true
		}
	}
	return false
}
