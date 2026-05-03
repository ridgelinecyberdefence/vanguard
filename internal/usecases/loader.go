package usecases

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Library is the loaded set of use cases — a flat catalog keyed by ID.
type Library struct {
	usecases []*UseCase
}

// All returns every loaded use case in stable sort order: built-ins first by
// ID, then custom (UC-CUSTOM-* prefix) alphabetically.
func (l *Library) All() []*UseCase { return l.usecases }

// ByID looks up a use case by exact ID, or returns nil.
func (l *Library) ByID(id string) *UseCase {
	for _, uc := range l.usecases {
		if uc.ID == id {
			return uc
		}
	}
	return nil
}

// ForPlatform returns use cases whose Platform matches host (always includes
// cross-platform). Custom use cases bypass the filter — operators put them
// where they want them.
func (l *Library) ForPlatform(host string) []*UseCase {
	out := make([]*UseCase, 0, len(l.usecases))
	for _, uc := range l.usecases {
		if strings.HasPrefix(uc.ID, "UC-CUSTOM-") {
			out = append(out, uc)
			continue
		}
		if MatchesPlatform(uc.Platform, host) {
			out = append(out, uc)
		}
	}
	return out
}

// Load builds a Library by combining:
//   1. The embedded built-in use cases (always present).
//   2. Any *.yaml files in dir (operator-customised + custom use cases).
//
// When an operator-supplied file shares an ID with a built-in, the file wins
// — that's how customisation works.
func Load(dir string) (*Library, error) {
	lib := &Library{}

	// Built-ins keyed by ID so custom files can override.
	byID := map[string]*UseCase{}
	for _, uc := range Defaults() {
		copy := uc
		byID[uc.ID] = &copy
	}

	// Overlay files from dir.
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading %s: %w", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".yaml") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			uc, err := LoadFile(path)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", path, err)
			}
			if uc.ID == "" {
				return nil, fmt.Errorf("%s: missing 'id' field", path)
			}
			byID[uc.ID] = uc
		}
	}

	for _, uc := range byID {
		lib.usecases = append(lib.usecases, uc)
	}

	// Built-ins first by ID, then custom alphabetically.
	sort.Slice(lib.usecases, func(i, j int) bool {
		ic := strings.HasPrefix(lib.usecases[i].ID, "UC-CUSTOM-")
		jc := strings.HasPrefix(lib.usecases[j].ID, "UC-CUSTOM-")
		if ic != jc {
			return !ic
		}
		return lib.usecases[i].ID < lib.usecases[j].ID
	})
	return lib, nil
}

// LoadFile parses a single YAML file into a UseCase.
func LoadFile(path string) (*UseCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}
	var uc UseCase
	if err := yaml.Unmarshal(data, &uc); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	return &uc, nil
}
