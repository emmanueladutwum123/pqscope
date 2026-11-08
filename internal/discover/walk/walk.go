// Package walk finds the files each discovery layer scans, with one shared
// list of directories to skip.
package walk

import (
	"io/fs"
	"os"
	"path/filepath"
)

// SkipDirs are directory names never descended into: version control,
// vendored dependencies and virtual environments. Lockfiles and manifests at
// a project's top level are still found.
var SkipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true,
}

// File is one file to scan.
type File struct {
	Path string // as opened
	Rel  string // slash-separated, relative to the scan root; the base name when the root is a file
}

// Skipped records a file a layer did not scan.
type Skipped struct {
	Path   string
	Reason string
}

// Files returns every regular file under root that accept approves, given its
// relative path. Symlinks are not followed. A root that is a file is returned
// if accepted.
func Files(root string, accept func(rel string) bool) ([]File, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		rel := filepath.ToSlash(filepath.Base(root))
		if accept(rel) {
			return []File{{root, rel}}, nil
		}
		return nil, nil
	}
	var out []File
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && SkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if accept(rel) {
			out = append(out, File{path, rel})
		}
		return nil
	})
	return out, err
}
