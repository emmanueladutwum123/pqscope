package eval

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Item is one finding reduced to what scoring compares.
type Item struct {
	Case   string // corpus case ID
	File   string // relative to the case directory
	Line   int    // 0 when the tool reports none
	Family string
}

// ToolRun describes one tool's run, from eval/out/<tool>/tool.json.
type ToolRun struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Status  string `json:"status"` // ran, failed, partial, unavailable
	Reason  string `json:"reason"`
}

// competitors are the tools eval/run.sh runs, with the adapter for each
// one's output.
var competitors = []struct {
	name  string
	parse func(dir string) ([]rawFinding, error)
}{
	{"cbomkit-theia", parseCBOMDir},
	{"cbomkit-action", parseCBOMDir},
	{"cryptoscan-pqc", parseCBOMDir},
	{"semgrep", parseSemgrep},
	{"pqc-audit", parseGenericJSON},
	{"keylens", parseGenericJSON},
}

// rawFinding is a tool's finding before it is assigned to a case.
type rawFinding struct {
	path string // as the tool reported it
	line int
	name string // algorithm name as the tool reported it
}

// mountPrefixes are the corpus mount points eval/run.sh uses. Some tools
// report them without the leading slash.
var mountPrefixes = []string{"/data/", "/workspace/", "/src/", "workspace/", "data/", "src/"}

// answerKey lists corpus files that are not part of the system under test.
// eval/run.sh hides them from competitors; a finding in one is dropped.
var answerKey = []string{"labels.yaml", "README.md", "server.env", "server.sh"}

// lineSuffix matches a location written as "path:line".
var lineSuffix = regexp.MustCompile(`^(.*):(\d+)$`)

// assign maps a tool path to a case and a file within it. Tool paths are
// relative to the corpus root, after a mount prefix.
func assign(path string, cases map[string]bool) (caseID, file string, ok bool) {
	p := strings.TrimPrefix(filepath.ToSlash(path), "file://")
	// Mount points only ever begin a path (file:// is already stripped), so
	// a directory of the same name inside a case is left alone.
	for _, m := range mountPrefixes {
		if strings.HasPrefix(p, m) {
			p = p[len(m):]
			break
		}
	}
	if strings.HasPrefix(p, "/") {
		return "", "", false // an absolute path outside every mount
	}
	p = strings.TrimPrefix(p, "./")
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 3 || !cases[parts[0]+"/"+parts[1]] {
		return "", "", false
	}
	return parts[0] + "/" + parts[1], parts[2], true
}

// loadCompetitor reads one tool's run.
func loadCompetitor(runs, name string, parse func(string) ([]rawFinding, error), cases map[string]bool) (ToolRun, []Item, error) {
	dir := filepath.Join(runs, name)
	run := ToolRun{Tool: name, Status: "unavailable", Reason: "not run (no " + filepath.Join(dir, "tool.json") + ")"}
	data, err := os.ReadFile(filepath.Join(dir, "tool.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return run, nil, nil
	case err != nil:
		return run, nil, err
	}
	if err := json.Unmarshal(data, &run); err != nil {
		return run, nil, fmt.Errorf("%s: %w", name, err)
	}
	if run.Status != "ran" && run.Status != "partial" {
		return run, nil, nil
	}
	raw, err := parse(dir)
	if err != nil {
		run.Status, run.Reason = "unparsed", err.Error()
		return run, nil, nil
	}
	var items []Item
	for _, r := range raw {
		if m := lineSuffix.FindStringSubmatch(r.path); m != nil && r.line == 0 {
			r.path = m[1]
			r.line, _ = strconv.Atoi(m[2])
		}
		c, file, ok := assign(r.path, cases)
		if ok && slices.Contains(answerKey, filepath.Base(file)) {
			continue
		}
		fam := Family(r.name)
		if !ok || fam == "" {
			continue
		}
		items = append(items, Item{Case: c, File: file, Line: r.line, Family: fam})
	}
	return run, items, nil
}

// --- CycloneDX CBOM (CBOMkit, cryptoscan-pqc) ---

func parseCBOMDir(dir string) ([]rawFinding, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	var out []rawFinding
	parsed := 0
	for _, f := range files {
		if filepath.Base(f) == "tool.json" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var bom struct {
			BOMFormat  string            `json:"bomFormat"`
			Components []json.RawMessage `json:"components"`
		}
		if json.Unmarshal(data, &bom) != nil || bom.BOMFormat != "CycloneDX" {
			continue
		}
		parsed++
		for _, raw := range bom.Components {
			out = append(out, cbomComponent(raw)...)
		}
	}
	if parsed == 0 {
		return nil, errors.New("no CycloneDX output found")
	}
	return out, nil
}

// cbomComponent extracts findings from one component: its name and
// algorithm-describing fields, at each occurrence. Tools differ in where they
// put locations, so occurrences, then properties naming a path, are tried.
func cbomComponent(raw json.RawMessage) []rawFinding {
	var c struct {
		Name             string `json:"name"`
		CryptoProperties struct {
			AlgorithmProperties struct {
				ParameterSetIdentifier string `json:"parameterSetIdentifier"`
				Curve                  string `json:"curve"`
			} `json:"algorithmProperties"`
			CertificateProperties map[string]any `json:"certificateProperties"`
		} `json:"cryptoProperties"`
		Evidence struct {
			Occurrences []struct {
				Location string `json:"location"`
				Line     int    `json:"line"`
			} `json:"occurrences"`
		} `json:"evidence"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Name == "" {
		return nil
	}
	name := c.Name
	if Family(name) == "" {
		name += " " + c.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier + " " + c.CryptoProperties.AlgorithmProperties.Curve
	}
	var out []rawFinding
	for _, o := range c.Evidence.Occurrences {
		out = append(out, rawFinding{o.Location, o.Line, name})
	}
	if len(out) == 0 {
		for _, p := range c.Properties {
			n := strings.ToLower(p.Name)
			if strings.Contains(n, "path") || strings.Contains(n, "location") || strings.Contains(n, "file") {
				out = append(out, rawFinding{p.Value, 0, name})
			}
		}
	}
	return out
}

// --- Semgrep JSON ---

func parseSemgrep(dir string) ([]rawFinding, error) {
	data, err := os.ReadFile(filepath.Join(dir, "results.json"))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	out := make([]rawFinding, 0, len(doc.Results))
	for _, r := range doc.Results {
		// The rule ID names the algorithm (use-of-md5, des-is-deprecated);
		// messages are not used, as they often name the replacement too.
		id := r.CheckID
		if i := strings.LastIndex(id, "."); i >= 0 {
			id = id[i+1:]
		}
		out = append(out, rawFinding{r.Path, r.Start.Line, id})
	}
	return out, nil
}

// --- Generic JSON (pqc-audit) ---

// parseGenericJSON reads any JSON report that lists objects with a file path
// and an algorithm name, for tools without a documented schema. Path keys:
// file, path, file_path, filename, location; line keys: line, line_number,
// lineno; name keys: algorithm, algo, name, type, crypto, primitive.
func parseGenericJSON(dir string) ([]rawFinding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []rawFinding
	parsed := 0
	for _, f := range files {
		if filepath.Base(f) == "tool.json" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			continue
		}
		parsed++
		walkJSON(v, &out)
	}
	if parsed == 0 {
		return nil, errors.New("no JSON report found")
	}
	return out, nil
}

func walkJSON(v any, out *[]rawFinding) {
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			walkJSON(e, out)
		}
	case map[string]any:
		path := firstString(t, "file", "path", "file_path", "filename", "location")
		name := firstString(t, "algorithm", "algo", "name", "type", "crypto", "primitive")
		if path != "" && name != "" {
			*out = append(*out, rawFinding{path, firstInt(t, "line", "line_number", "lineno"), name})
		}
		for _, e := range t {
			walkJSON(e, out)
		}
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func firstInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case string:
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return 0
}
