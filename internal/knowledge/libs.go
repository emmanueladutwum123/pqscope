package knowledge

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed libs.yaml
var libsYAML []byte

// Package identifies a library in one package ecosystem: golang, pypi, npm,
// maven ("group:artifact") or cargo.
type Package struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
}

// Capability is what a library provides from a version on.
type Capability struct {
	Since    string   `yaml:"since"`
	Provides []string `yaml:"provides"` // entry IDs or algorithm families
	Source   string   `yaml:"source"`
}

// Library is one crypto library and its capabilities by version.
type Library struct {
	ID           string       `yaml:"id"`
	Name         string       `yaml:"name"`
	Packages     []Package    `yaml:"packages"`
	VersionFrom  string       `yaml:"version_from"` // "" or "build-metadata"
	Note         string       `yaml:"note"`
	Capabilities []Capability `yaml:"capabilities"`
}

// Provided is one asset a library makes available, and the capability row
// that grants it.
type Provided struct {
	Asset model.Asset
	Since string
	// Exact is true when the asset is a specific parameter set; false when it
	// stands for a whole family, with Params "unknown".
	Exact bool
}

// Libs is a validated library capability table.
type Libs struct {
	db      *DB
	checked string
	sources map[string]Source
	libs    []Library
	byPkg   map[Package]int
}

type libsDocument struct {
	Version   int               `yaml:"version"`
	Checked   string            `yaml:"checked"`
	Sources   map[string]Source `yaml:"sources"`
	Libraries []Library         `yaml:"libraries"`
}

// ParseLibs decodes and validates a capability table against db.
func ParseLibs(db *DB, data []byte) (*Libs, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc libsDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("knowledge: decoding libs: %w", err)
	}
	l := &Libs{db: db, checked: doc.Checked, sources: doc.Sources, libs: doc.Libraries, byPkg: map[Package]int{}}
	var errs []error
	if doc.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported version %d", doc.Version))
	}
	if doc.Checked == "" {
		errs = append(errs, errors.New("checked date is required"))
	}
	for key, s := range doc.Sources {
		if s.Title == "" || !strings.HasPrefix(s.URL, "https://") {
			errs = append(errs, fmt.Errorf("source %q needs a title and an https url", key))
		}
	}
	ids := map[string]bool{}
	for i, lib := range doc.Libraries {
		report := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("library %q: "+format, append([]any{lib.ID}, args...)...))
		}
		if lib.ID == "" || ids[lib.ID] || lib.Name == "" {
			report("missing or duplicate id, or no name")
		}
		ids[lib.ID] = true
		if lib.VersionFrom != "" && lib.VersionFrom != "build-metadata" {
			report("unknown version_from %q", lib.VersionFrom)
		}
		if len(lib.Packages) == 0 || len(lib.Capabilities) == 0 {
			report("needs packages and capabilities")
		}
		for _, p := range lib.Packages {
			p.Name = normalizePackage(p)
			if _, dup := l.byPkg[p]; dup {
				report("package %s:%s listed twice", p.Ecosystem, p.Name)
			}
			l.byPkg[p] = i
		}
		for _, c := range lib.Capabilities {
			if c.Since == "" {
				report("capability without since")
			}
			if _, ok := doc.Sources[c.Source]; !ok {
				report("capability since %s cites unknown source %q", c.Since, c.Source)
			}
			for _, p := range c.Provides {
				if _, ok := db.ByID(p); !ok && !db.hasFamily(p) {
					report("%q is neither a knowledge DB entry nor an algorithm family", p)
				}
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("knowledge: invalid libs: %w", err)
	}
	return l, nil
}

func (db *DB) hasFamily(algorithm string) bool {
	return slices.ContainsFunc(db.entries, func(e Entry) bool { return e.Algorithm == algorithm })
}

// DefaultLibs returns the embedded capability table, parsed once.
var DefaultLibs = sync.OnceValues(func() (*Libs, error) {
	db, err := Default()
	if err != nil {
		return nil, err
	}
	return ParseLibs(db, libsYAML)
})

// Checked returns the date the table's absence claims were last checked.
func (l *Libs) Checked() string { return l.checked }

// Libraries returns a copy of every library.
func (l *Libs) Libraries() []Library { return slices.Clone(l.libs) }

// Source returns the source with the given key.
func (l *Libs) Source(key string) (Source, bool) {
	s, ok := l.sources[key]
	return s, ok
}

// Lookup returns the library a package belongs to.
func (l *Libs) Lookup(p Package) (Library, bool) {
	p.Name = normalizePackage(p)
	i, ok := l.byPkg[p]
	if !ok {
		return Library{}, false
	}
	return l.libs[i], true
}

// normalizePackage applies each ecosystem's name equivalence: PyPI names
// ignore case and treat runs of -, _ and . alike (PEP 503); npm and Maven
// names are case-sensitive but compared case-insensitively here, as
// registries refuse names that differ only by case.
func normalizePackage(p Package) string {
	name := strings.TrimSpace(p.Name)
	switch p.Ecosystem {
	case "pypi":
		name = strings.ToLower(name)
		var b strings.Builder
		sep := false
		for _, r := range name {
			if r == '-' || r == '_' || r == '.' {
				sep = true
				continue
			}
			if sep && b.Len() > 0 {
				b.WriteByte('-')
			}
			sep = false
			b.WriteRune(r)
		}
		return b.String()
	case "npm", "maven", "cargo":
		return strings.ToLower(name)
	}
	return name
}

// Provides returns the assets a library makes available at a version. An
// empty version is unknown, and only capabilities available in every version
// (since "0") count.
func (l *Libs) Provides(lib Library, version string) []Provided {
	if lib.VersionFrom == "build-metadata" {
		if _, meta, ok := strings.Cut(version, "+"); ok {
			version = meta
		} else {
			version = ""
		}
	}
	var out []Provided
	for _, c := range lib.Capabilities {
		if c.Since != "0" && (version == "" || CompareVersions(version, c.Since) < 0) {
			continue
		}
		for _, p := range c.Provides {
			if e, ok := l.db.ByID(p); ok {
				prims := e.Primitives
				if e.Quantum == model.QuantumHybrid {
					// A hybrid's kem and key-agreement uses are one capability;
					// report it as a KEM, as the source and config layers do.
					prims = []string{model.PrimitiveKEM}
				}
				for _, prim := range prims {
					a, _ := e.Asset(prim) // prim comes from e.Primitives
					out = append(out, Provided{a, c.Since, true})
				}
				continue
			}
			for _, prim := range l.db.familyPrimitives(p) {
				q, _ := l.db.FamilyQuantum(p)
				out = append(out, Provided{model.Asset{Primitive: prim, Algorithm: p, Params: model.ParamsUnknown, Quantum: q}, c.Since, false})
			}
		}
	}
	return out
}

// familyPrimitives returns every primitive any entry of a family is used as,
// in first-seen order.
func (db *DB) familyPrimitives(algorithm string) []string {
	var out []string
	for _, e := range db.entries {
		if e.Algorithm != algorithm {
			continue
		}
		for _, p := range e.Primitives {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// CompareVersions compares two version strings, returning -1, 0 or 1. A
// leading "v" and "+build" metadata are ignored. Dot-separated segments
// compare numerically when both are numbers, else as text. A pre-release,
// written "-rc1" or as letters after the last number ("48.0.0rc1"), sorts
// before the release.
func CompareVersions(a, b string) int {
	ra, pa := splitVersion(a)
	rb, pb := splitVersion(b)
	for i := range max(len(ra), len(rb)) {
		x, y := "0", "0"
		if i < len(ra) {
			x = ra[i]
		}
		if i < len(rb) {
			y = rb[i]
		}
		if c := compareSegment(x, y); c != 0 {
			return c
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	return compareSegment(pa, pb)
}

func splitVersion(v string) (release []string, pre string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "+")
	v, pre, _ = strings.Cut(v, "-")
	release = strings.Split(v, ".")
	// Python-style "0rc1": split letters off the last numeric segment.
	last := release[len(release)-1]
	if i := strings.IndexFunc(last, func(r rune) bool { return !unicode.IsDigit(r) }); i > 0 && pre == "" {
		release[len(release)-1], pre = last[:i], last[i:]
	}
	return release, pre
}

func compareSegment(x, y string) int {
	nx, ex := strconv.Atoi(x)
	ny, ey := strconv.Atoi(y)
	if ex == nil && ey == nil {
		switch {
		case nx < ny:
			return -1
		case nx > ny:
			return 1
		}
		return 0
	}
	return strings.Compare(x, y)
}

// ByID returns the library with the given ID.
func (l *Libs) ByID(id string) (Library, bool) {
	for _, lib := range l.libs {
		if lib.ID == id {
			return lib, true
		}
	}
	return Library{}, false
}

// FirstPQC returns the earliest version from which a library provides a
// post-quantum or hybrid asset, and those assets' names. ok is false if no
// version does.
func (l *Libs) FirstPQC(lib Library) (since string, names []string, ok bool) {
	for _, c := range lib.Capabilities {
		var pq []string
		for _, p := range c.Provides {
			q := ""
			if e, found := l.db.ByID(p); found {
				q = e.Quantum
			} else {
				q, _ = l.db.FamilyQuantum(p)
			}
			if q == model.QuantumSafe || q == model.QuantumHybrid {
				pq = append(pq, p)
			}
		}
		if len(pq) > 0 && (!ok || CompareVersions(c.Since, since) < 0) {
			since, names, ok = c.Since, pq, true
		}
	}
	return since, names, ok
}
