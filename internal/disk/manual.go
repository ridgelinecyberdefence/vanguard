package disk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManualCopyResult describes a single targeted-copy operation.
type ManualCopyResult struct {
	Source      string
	Destination string
	Description string
	Files       int
	Bytes       int64
	SHA256      string // single-file SHA256; empty when source is a directory
	IsDir       bool
	Duration    time.Duration
	Error       string
	Success     bool
}

// ManualCopy copies src into outDir/{basename}. For directories the entire tree
// is copied recursively, preserving the relative path.
func ManualCopy(src, outDir, description string) ManualCopyResult {
	result := ManualCopyResult{Source: src, Description: description}
	started := time.Now()

	if src == "" {
		result.Error = "source path is required"
		result.Duration = time.Since(started)
		return result
	}

	info, err := os.Stat(src)
	if err != nil {
		result.Error = "source not found: " + err.Error()
		result.Duration = time.Since(started)
		return result
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		result.Error = "creating output dir: " + err.Error()
		result.Duration = time.Since(started)
		return result
	}

	dest := filepath.Join(outDir, filepath.Base(src))
	result.Destination = dest
	result.IsDir = info.IsDir()

	if info.IsDir() {
		count, bytes, err := copyTree(src, dest)
		result.Files = count
		result.Bytes = bytes
		result.Duration = time.Since(started)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		result.Success = true
		return result
	}

	// Single file: copy + hash.
	hash, err := copyFileHash(src, dest)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(started)
		return result
	}
	result.SHA256 = hash
	result.Files = 1
	if di, _ := os.Stat(dest); di != nil {
		result.Bytes = di.Size()
	}
	result.Success = true
	result.Duration = time.Since(started)
	return result
}

// copyFileHash copies src → dst and returns the SHA256 of the file content.
func copyFileHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("opening source: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", fmt.Errorf("creating dest dir: %w", err)
	}
	out, err := os.Create(dst)
	if err != nil {
		return "", fmt.Errorf("creating dest: %w", err)
	}
	defer out.Close()

	h := sha256.New()
	w := io.MultiWriter(out, h)
	if _, err := io.Copy(w, in); err != nil {
		return "", fmt.Errorf("copying: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyTree recursively copies src into dst, returning file count and byte total.
// Per-file copy errors are accumulated as warnings but don't abort the walk.
func copyTree(src, dst string) (int, int64, error) {
	var count int
	var bytes int64
	var firstErr error

	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if err := copyFileSimple(p, target); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		count++
		bytes += info.Size()
		return nil
	})
	if err != nil && firstErr == nil {
		firstErr = err
	}
	return count, bytes, firstErr
}

// copyFileSimple is a no-hash copy used by directory walks.
func copyFileSimple(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ---------------------------------------------------------------------------
// Evidence directory browser
// ---------------------------------------------------------------------------

// EvidenceNode is a node in the evidence-directory tree.
type EvidenceNode struct {
	Name     string
	Path     string
	IsDir    bool
	Files    int   // for directories: file count under this node
	Bytes    int64 // for directories: total size; for files: file size
	Modified time.Time
	Children []*EvidenceNode // populated lazily by Expand
	Expanded bool
	Depth    int
}

// LoadEvidenceTree returns the top-level entries under output/{case}/disk/.
// Children are NOT populated until Expand() is called on a node.
func LoadEvidenceTree(rootDir, caseID string) (*EvidenceNode, error) {
	base := OutputBase(rootDir, caseID)
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return &EvidenceNode{Name: "disk/", Path: base, IsDir: true}, nil
		}
		return nil, err
	}

	root := &EvidenceNode{Name: "disk/", Path: base, IsDir: true, Expanded: true}
	if err := readDirChildren(root, 1); err != nil {
		return nil, err
	}
	return root, nil
}

// readDirChildren populates n.Children from disk (one level only).
func readDirChildren(n *EvidenceNode, depth int) error {
	entries, err := os.ReadDir(n.Path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		child := &EvidenceNode{
			Name:     e.Name(),
			Path:     filepath.Join(n.Path, e.Name()),
			IsDir:    e.IsDir(),
			Modified: info.ModTime(),
			Depth:    depth,
		}
		if e.IsDir() {
			child.Name += "/"
		} else {
			child.Bytes = info.Size()
		}
		n.Children = append(n.Children, child)
	}
	sort.Slice(n.Children, func(i, j int) bool {
		// Directories first, then alphabetical.
		if n.Children[i].IsDir != n.Children[j].IsDir {
			return n.Children[i].IsDir
		}
		return strings.ToLower(n.Children[i].Name) < strings.ToLower(n.Children[j].Name)
	})
	return nil
}

// Expand loads children for n if it's an unexpanded directory, computing
// recursive file/byte totals as a side effect.
func (n *EvidenceNode) Expand() error {
	if !n.IsDir || n.Expanded {
		return nil
	}
	if err := readDirChildren(n, n.Depth+1); err != nil {
		return err
	}
	n.Expanded = true
	files, bytes := DirTotals(n.Path)
	n.Files = files
	n.Bytes = bytes
	return nil
}

// DirTotals returns (file count, total size) under dir.
func DirTotals(dir string) (int, int64) {
	return countDirContents(dir)
}

// FlattenVisible walks the tree producing a flat ordered list of nodes
// suitable for line-by-line rendering.
func FlattenVisible(root *EvidenceNode) []*EvidenceNode {
	var out []*EvidenceNode
	var walk func(n *EvidenceNode)
	walk = func(n *EvidenceNode) {
		// Skip the root node itself in the output.
		if n.Depth > 0 {
			out = append(out, n)
		}
		if n.IsDir && n.Expanded {
			for _, c := range n.Children {
				walk(c)
			}
		}
	}
	walk(root)
	return out
}
