// Package deps is the dependency layer. It reads manifests and lockfiles
// (go.mod, go.sum, requirements*.txt, poetry.lock, package-lock.json, pom.xml
// and Cargo.lock), matches each package against the knowledge library table,
// and reports what every known crypto library provides at its version.
//
// A dependency finding means "available to this project", not "in use": its
// confidence is CapabilityConfidence, and the policy gate leaves deps-only
// assets out unless asked. Packages the library table does not know produce
// no findings.
package deps

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/discover/walk"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// CapabilityConfidence is the confidence of every dependency finding: the
// library certainly provides the asset, but nothing shows it is used.
const CapabilityConfidence = 0.5

// MaxFileSize bounds the manifests read, in bytes.
const MaxFileSize = 16 << 20

// Result is the outcome of a dependency scan.
type Result struct {
	Findings     []model.Finding
	FilesScanned int
	Packages     int // dependencies parsed, known to the library table or not
	Skipped      []walk.Skipped
}

// Scanner matches dependencies against a library table.
type Scanner struct {
	db   *knowledge.DB
	libs *knowledge.Libs
}

// New returns a Scanner.
func New(db *knowledge.DB, libs *knowledge.Libs) *Scanner {
	return &Scanner{db: db, libs: libs}
}

// Scan reads every manifest under root.
func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	files, err := walk.Files(root, func(rel string) bool {
		_, ok := parserFor(path.Base(rel))
		return ok
	})
	if err != nil {
		return Result{}, err
	}
	var res Result
	seen := map[string]bool{}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		base := path.Base(f.Rel)
		// Since Go 1.17, go.mod lists every module the build needs, so a
		// go.sum next to a go.mod adds nothing but versions MVS discarded.
		if base == "go.sum" {
			if _, err := os.Stat(filepath.Join(filepath.Dir(f.Path), "go.mod")); err == nil {
				res.Skipped = append(res.Skipped, walk.Skipped{Path: f.Rel, Reason: "go.mod in the same directory takes precedence"})
				continue
			}
		}
		info, err := os.Stat(f.Path)
		if err != nil {
			return Result{}, err
		}
		if info.Size() > MaxFileSize {
			res.Skipped = append(res.Skipped, walk.Skipped{Path: f.Rel, Reason: fmt.Sprintf("larger than %d bytes", MaxFileSize)})
			continue
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return Result{}, err
		}
		parse, _ := parserFor(base)
		deps, err := parse(data)
		if err != nil {
			res.Skipped = append(res.Skipped, walk.Skipped{Path: f.Rel, Reason: "parse error: " + err.Error()})
			continue
		}
		res.FilesScanned++
		res.Packages += len(deps)
		for _, d := range deps {
			for _, fd := range s.findings(f.Rel, d) {
				if !seen[fd.ID] {
					seen[fd.ID] = true
					res.Findings = append(res.Findings, fd)
				}
			}
		}
	}
	return res, nil
}

func (s *Scanner) findings(rel string, d Dependency) []model.Finding {
	lib, ok := s.libs.Lookup(d.Package)
	if !ok {
		return nil
	}
	version := d.Version
	label := d.Name + " " + version
	if version == "" {
		label = d.Name + " (version not pinned)"
	}
	var out []model.Finding
	for _, p := range s.libs.Provides(lib, version) {
		a := p.Asset
		name := s.db.Name(a)
		evidence := fmt.Sprintf("%s provides %s", label, name)
		if p.Since != "0" {
			evidence += " (since " + p.Since + ")"
		}
		f := model.NewFinding(a, model.Location{Layer: model.LayerDeps, Path: rel, Line: d.Line, Symbol: PURL(d)}, CapabilityConfidence)
		f.RuleID = "deps." + lib.ID
		f.Evidence = evidence
		out = append(out, f)
	}
	return out
}

// purlType maps ecosystems to Package URL types.
var purlType = map[string]string{"golang": "golang", "pypi": "pypi", "npm": "npm", "maven": "maven", "cargo": "cargo"}

// PURL returns the Package URL of a dependency, such as
// pkg:pypi/cryptography@48.0.0 or pkg:npm/%40noble/post-quantum@0.2.0.
func PURL(d Dependency) string {
	name := d.Name
	switch d.Ecosystem {
	case "pypi":
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	case "maven":
		name = strings.Replace(name, ":", "/", 1)
	}
	segments := strings.Split(name, "/")
	for i, seg := range segments {
		segments[i] = strings.ReplaceAll(url.PathEscape(seg), "@", "%40")
	}
	p := "pkg:" + purlType[d.Ecosystem] + "/" + strings.Join(segments, "/")
	if d.Version != "" {
		p += "@" + strings.ReplaceAll(url.PathEscape(d.Version), "+", "%2B")
	}
	return p
}
