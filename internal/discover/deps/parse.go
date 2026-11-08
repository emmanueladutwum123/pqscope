package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
)

// Dependency is one package a manifest or lockfile declares.
type Dependency struct {
	knowledge.Package
	Version string // "" when the file does not pin one
	Line    int
}

// parser reads one manifest format.
type parser func(data []byte) ([]Dependency, error)

// parsers maps file base names to their parser. requirements*.txt is matched
// separately.
var parsers = map[string]parser{
	"go.mod":            parseGoMod,
	"go.sum":            parseGoSum,
	"poetry.lock":       parseTOMLLock("pypi"),
	"Cargo.lock":        parseTOMLLock("cargo"),
	"package-lock.json": parsePackageLock,
	"pom.xml":           parsePom,
	"requirements.txt":  parseRequirements,
}

// parserFor returns the parser for a file's base name.
func parserFor(base string) (parser, bool) {
	if p, ok := parsers[base]; ok {
		return p, true
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return parseRequirements, true
	}
	return nil, false
}

func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// parseGoMod reads require directives, and the toolchain (or go) directive
// as the version of the standard library.
func parseGoMod(data []byte) ([]Dependency, error) {
	var out []Dependency
	var goVersion, toolchain string
	var goLine, toolchainLine int
	inRequire := false
	for i, raw := range lines(data) {
		line, _, _ := strings.Cut(raw, "//")
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
			continue
		case inRequire && fields[0] == ")":
			inRequire = false
		case inRequire && len(fields) >= 2:
			out = append(out, Dependency{knowledge.Package{Ecosystem: "golang", Name: fields[0]}, fields[1], i + 1})
		case fields[0] == "require" && len(fields) == 2 && fields[1] == "(":
			inRequire = true
		case fields[0] == "require" && len(fields) >= 3:
			out = append(out, Dependency{knowledge.Package{Ecosystem: "golang", Name: fields[1]}, fields[2], i + 1})
		case fields[0] == "go" && len(fields) == 2:
			goVersion, goLine = fields[1], i+1
		case fields[0] == "toolchain" && len(fields) == 2:
			toolchain, toolchainLine = strings.TrimPrefix(fields[1], "go"), i+1
		}
	}
	switch {
	case toolchain != "" && knowledge.CompareVersions(toolchain, goVersion) >= 0:
		out = append(out, Dependency{knowledge.Package{Ecosystem: "golang", Name: "stdlib"}, toolchain, toolchainLine})
	case goVersion != "":
		out = append(out, Dependency{knowledge.Package{Ecosystem: "golang", Name: "stdlib"}, goVersion, goLine})
	}
	return out, nil
}

// parseGoSum reads module versions whose source was downloaded. Lines for a
// module's go.mod alone are skipped, as are older versions of a module.
func parseGoSum(data []byte) ([]Dependency, error) {
	best := map[string]Dependency{}
	var order []string
	for i, line := range lines(data) {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		d := Dependency{knowledge.Package{Ecosystem: "golang", Name: fields[0]}, fields[1], i + 1}
		cur, seen := best[fields[0]]
		if !seen {
			order = append(order, fields[0])
		}
		if !seen || knowledge.CompareVersions(d.Version, cur.Version) > 0 {
			best[fields[0]] = d
		}
	}
	out := make([]Dependency, 0, len(order))
	for _, name := range order {
		out = append(out, best[name])
	}
	return out, nil
}

var requirementLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;,\s]*)`)

// parseRequirements reads pip requirement lines. Only == and === pin a
// version; other specifiers leave it unknown.
func parseRequirements(data []byte) ([]Dependency, error) {
	var out []Dependency
	for i, raw := range lines(data) {
		line := strings.TrimSpace(raw)
		if j := strings.Index(line, " #"); j >= 0 {
			line = strings.TrimSpace(line[:j])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") || strings.Contains(line, "://") {
			continue
		}
		m := requirementLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version := ""
		if m[3] == "==" || m[3] == "===" {
			version = m[4]
		}
		out = append(out, Dependency{knowledge.Package{Ecosystem: "pypi", Name: m[1]}, version, i + 1})
	}
	return out, nil
}

var tomlString = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"`)

// parseTOMLLock reads the [[package]] tables of poetry.lock and Cargo.lock.
// Both formats write name and version as plain string keys, so a line reader
// is enough.
func parseTOMLLock(ecosystem string) parser {
	return func(data []byte) ([]Dependency, error) {
		var out []Dependency
		var cur *Dependency
		flush := func() {
			if cur != nil && cur.Name != "" {
				out = append(out, *cur)
			}
			cur = nil
		}
		for i, raw := range lines(data) {
			line := strings.TrimSpace(raw)
			if strings.HasPrefix(line, "[") {
				flush()
				if line == "[[package]]" {
					cur = &Dependency{Package: knowledge.Package{Ecosystem: ecosystem}}
				}
				continue
			}
			if cur == nil {
				continue
			}
			if m := tomlString.FindStringSubmatch(line); m != nil {
				switch m[1] {
				case "name":
					cur.Name, cur.Line = m[2], i+1
				case "version":
					cur.Version = m[2]
				}
			}
		}
		flush()
		return out, nil
	}
}

// parsePackageLock reads npm lockfiles: the "packages" map of lockfile
// versions 2 and 3, or the nested "dependencies" of version 1.
func parsePackageLock(data []byte) ([]Dependency, error) {
	var doc struct {
		Packages     map[string]struct{ Version string } `json:"packages"`
		Dependencies map[string]json.RawMessage          `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Dependency
	if len(doc.Packages) > 0 {
		keys := make([]string, 0, len(doc.Packages))
		for k := range doc.Packages {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			i := strings.LastIndex(k, "node_modules/")
			if i < 0 {
				continue // the root project, or a workspace link
			}
			out = append(out, Dependency{knowledge.Package{Ecosystem: "npm", Name: k[i+len("node_modules/"):]},
				doc.Packages[k].Version, lineOf(data, `"`+k+`"`)})
		}
		return out, nil
	}
	var walk func(deps map[string]json.RawMessage) error
	walk = func(deps map[string]json.RawMessage) error {
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			var d struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if err := json.Unmarshal(deps[n], &d); err != nil {
				return err
			}
			out = append(out, Dependency{knowledge.Package{Ecosystem: "npm", Name: n}, d.Version, lineOf(data, `"`+n+`"`)})
			if err := walk(d.Dependencies); err != nil {
				return err
			}
		}
		return nil
	}
	return out, walk(doc.Dependencies)
}

var pomProperty = regexp.MustCompile(`\$\{([^}]+)\}`)

// parsePom reads <dependency> elements, including dependencyManagement, and
// substitutes ${property} references from <properties>.
func parsePom(data []byte) ([]Dependency, error) {
	type dependency struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	var doc struct {
		Version    string `xml:"version"`
		Properties struct {
			Entries []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
		Dependencies []dependency `xml:"dependencies>dependency"`
		Managed      []dependency `xml:"dependencyManagement>dependencies>dependency"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	props := map[string]string{"project.version": doc.Version}
	for _, e := range doc.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	expand := func(s string) string {
		s = strings.TrimSpace(s)
		for range 5 { // properties may refer to properties
			if !strings.Contains(s, "${") {
				break
			}
			s = pomProperty.ReplaceAllStringFunc(s, func(ref string) string {
				if v, ok := props[ref[2:len(ref)-1]]; ok {
					return v
				}
				return ref
			})
		}
		if strings.Contains(s, "${") {
			return "" // unresolved, so unknown
		}
		return s
	}
	var out []Dependency
	for _, d := range append(doc.Dependencies, doc.Managed...) {
		name := fmt.Sprintf("%s:%s", strings.TrimSpace(d.GroupID), strings.TrimSpace(d.ArtifactID))
		out = append(out, Dependency{knowledge.Package{Ecosystem: "maven", Name: name},
			expand(d.Version), lineOf(data, "<artifactId>"+strings.TrimSpace(d.ArtifactID)+"</artifactId>")})
	}
	return out, nil
}

// lineOf returns the 1-based line of the first occurrence of s, or 0.
func lineOf(data []byte, s string) int {
	i := bytes.Index(data, []byte(s))
	if i < 0 {
		return 0
	}
	return bytes.Count(data[:i], []byte("\n")) + 1
}
