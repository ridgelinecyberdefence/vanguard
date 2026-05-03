package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// handleFileBrowse — GET /api/files/browse?dir=<path>&filter=<exts>
//
// Returns a directory listing as JSON so the SPA can render a file picker
// modal. `dir` defaults to the user's home directory when empty. `filter`
// is a comma-separated list of extensions (e.g. ".raw,.dmp,.vmem") used to
// hide non-matching files; directories are always shown.
//
// SECURITY: VanGuard runs locally on the analyst's own machine. Restricting
// filesystem access would prevent analysts from reaching evidence on mounted
// drives, USB sticks, or UNC paths. We intentionally let the analyst browse
// anywhere os.ReadDir permits — the process inherits whatever access the
// VanGuard user account has, which is correct for a local forensics tool.
func handleFileBrowse(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	filter := r.URL.Query().Get("filter")

	if dir == "" {
		if runtime.GOOS == "windows" {
			dir = os.Getenv("USERPROFILE")
			if dir == "" {
				dir = `C:\`
			}
		} else {
			dir = os.Getenv("HOME")
			if dir == "" {
				dir = "/"
			}
		}
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid path: "+err.Error())
		return
	}
	dir = absDir

	entries, err := os.ReadDir(dir)
	if err != nil {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("cannot read directory: %s", err.Error()))
		return
	}

	// Parse comma-separated extension filter (normalise to lowercase with leading dot).
	var filterExts []string
	if filter != "" {
		for _, ext := range strings.Split(filter, ",") {
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			filterExts = append(filterExts, strings.ToLower(ext))
		}
	}

	type FileEntry struct {
		Name  string `json:"name"`
		Path  string `json:"path"`
		IsDir bool   `json:"is_dir"`
		Size  int64  `json:"size"`
		Date  string `json:"date"`
	}

	var files []FileEntry

	// Parent navigation entry, unless already at a filesystem root.
	parentDir := filepath.Dir(dir)
	if parentDir != dir {
		files = append(files, FileEntry{Name: "..", Path: parentDir, IsDir: true})
	}

	// On Windows, show available drive letters when the analyst is at a
	// drive root (len ≤ 3 covers "C:\") so they can switch drives without
	// leaving the modal.
	if runtime.GOOS == "windows" && len(dir) <= 3 {
		for _, letter := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			drivePath := string(letter) + `:\`
			if _, err := os.Stat(drivePath); err == nil {
				files = append(files, FileEntry{
					Name:  string(letter) + ":",
					Path:  drivePath,
					IsDir: true,
				})
			}
		}
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fe := FileEntry{
			Name:  entry.Name(),
			Path:  filepath.Join(dir, entry.Name()),
			IsDir: entry.IsDir(),
			Size:  info.Size(),
			Date:  info.ModTime().Format("2006-01-02 15:04"),
		}

		// Apply extension filter to files only; directories always pass.
		if !entry.IsDir() && len(filterExts) > 0 {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			matched := false
			for _, fExt := range filterExts {
				if ext == fExt {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		files = append(files, fe)
	}

	// Sort: ".." first, then directories alphabetically, then files.
	sort.Slice(files, func(i, j int) bool {
		if files[i].Name == ".." {
			return true
		}
		if files[j].Name == ".." {
			return false
		}
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"current_dir": dir,
		"entries":     files,
	})
}
