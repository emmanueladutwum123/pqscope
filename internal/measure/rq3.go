package measure

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/risk"
)

// Project is a GitHub repository from the OpenSSF Criticality Score data.
type Project struct {
	Rank     int // in the score order, before deduplication
	Repo     string
	Language string
	Score    float64
}

// ReadCriticality reads the OpenSSF Criticality Score CSV (gzipped or not),
// keeps github.com repositories with a score, and returns them by descending
// score, ties broken by name.
func ReadCriticality(r io.Reader) ([]Project, error) {
	br := bufio.NewReader(r)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		br = bufio.NewReader(zr)
	}
	cr := csv.NewReader(br)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("criticality: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"repo.url", "repo.language", "default_score"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("criticality: no %q column", need)
		}
	}
	var out []Project
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("criticality: %w", err)
		}
		repo, ok := strings.CutPrefix(rec[col["repo.url"]], "https://github.com/")
		score, err := strconv.ParseFloat(rec[col["default_score"]], 64)
		if !ok || err != nil || strings.Count(repo, "/") != 1 {
			continue
		}
		out = append(out, Project{Repo: repo, Language: rec[col["repo.language"]], Score: score})
	}
	slices.SortFunc(out, func(a, b Project) int { return cmp.Or(cmp.Compare(b.Score, a.Score), cmp.Compare(a.Repo, b.Repo)) })
	for i := range out {
		out[i].Rank = i + 1
	}
	return out, nil
}

// RepoInfo is what bench/run.sh's selection step looked up for a candidate.
type RepoInfo struct {
	Root   string // the root commit's SHA
	SizeKB int    // GitHub's repository size field
}

// MaxRepoKB caps a repository's size (GitHub's size field, which counts all
// history). Above it, the project is listed as skipped: cloning even its
// latest tree would take hours. Only chromium/chromium exceeds it in the
// candidate set.
const MaxRepoKB = 20 * 1024 * 1024

// Selection is one candidate's fate.
type Selection struct {
	Project
	RepoInfo
	Status string // "selected", "duplicate of <repo>", "skipped: <why>"
}

// Select walks candidates in score order and selects n distinct code bases.
// Repositories sharing a root commit are the same code base (kernel trees,
// mirrors), so only the highest-ranked is kept. Candidates without info are
// an error: the dedupe would be silently wrong. Skipped projects count
// towards n, so the top n is still the top n, reported with what could not
// be scanned.
func Select(candidates []Project, info map[string]RepoInfo, n int) ([]Selection, error) {
	var out []Selection
	owner := map[string]string{} // root commit → repo
	selected := 0
	for _, p := range candidates {
		if selected == n {
			break
		}
		in, ok := info[p.Repo]
		if !ok || in.Root == "" {
			return nil, fmt.Errorf("no root commit for %s", p.Repo)
		}
		s := Selection{Project: p, RepoInfo: in}
		switch first, dup := owner[in.Root]; {
		case dup:
			s.Status = "duplicate of " + first
		case in.SizeKB > MaxRepoKB:
			s.Status = fmt.Sprintf("skipped: repository is %d GB, above the %d GB cap", in.SizeKB>>20, MaxRepoKB>>20)
			owner[in.Root] = p.Repo
			selected++
		default:
			s.Status = "selected"
			owner[in.Root] = p.Repo
			selected++
		}
		out = append(out, s)
	}
	if selected < n {
		return nil, fmt.Errorf("only %d distinct projects among %d candidates; pass more candidates", selected, len(candidates))
	}
	return out, nil
}

// ScanStatus is what bench/run.sh recorded for one selected project.
type ScanStatus struct {
	Repo, Commit, Status string // Status: "scanned" or why not
	Seconds              int
}

// ProjectRow is one project in rq3_projects.csv.
type ProjectRow struct {
	Selection
	Scan     ScanStatus
	Findings int
	// Quantum-vulnerable findings (excluding reconciliation's derived ones)
	// by layer and by exposure class.
	ByLayer    map[model.Layer]int
	ByExposure map[string]int
	Derived    map[string]int // derived findings by type
	Algorithms map[string]int // vulnerable findings by algorithm
}

// vulnerable reports whether f is a quantum-vulnerable asset found directly
// by a layer: what RQ3 counts.
func vulnerable(f model.Finding) bool {
	return f.Derived == "" && f.Asset.Quantum == model.QuantumVulnerable
}

// AnalyzeRQ3 reads each scanned project's findings (pqscope scan --json)
// from dir/<owner>__<repo>.json.
func AnalyzeRQ3(sel []Selection, scans map[string]ScanStatus, dir string) ([]ProjectRow, error) {
	w, err := risk.Default()
	if err != nil {
		return nil, err
	}
	var rows []ProjectRow
	for _, s := range sel {
		if s.Status != "selected" && !strings.HasPrefix(s.Status, "skipped") {
			continue // duplicates are listed in rq3_selection.csv only
		}
		row := ProjectRow{Selection: s, ByLayer: map[model.Layer]int{}, ByExposure: map[string]int{}, Derived: map[string]int{}, Algorithms: map[string]int{}}
		row.Scan = scans[s.Repo]
		if s.Status != "selected" {
			row.Scan.Status = s.Status
		}
		switch row.Scan.Status {
		case "":
			row.Scan.Status = "not run"
		case "scanned":
			findings, err := readFindings(filepath.Join(dir, FindingsFile(s.Repo)))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", s.Repo, err)
			}
			row.Findings = len(findings)
			for _, f := range findings {
				switch {
				case f.Derived != "":
					row.Derived[f.Derived]++
				case vulnerable(f):
					row.ByLayer[f.Location.Layer]++
					row.ByExposure[w.ExposureOf(f)]++
					row.Algorithms[f.Asset.Algorithm]++
				}
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// FindingsFile names a project's findings file.
func FindingsFile(repo string) string { return strings.ReplaceAll(repo, "/", "__") + ".json" }

func readFindings(path string) ([]model.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fs []model.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		return nil, err
	}
	return fs, nil
}

// RQ3 layers, in table order. Network is not scanned for projects.
var rq3Layers = []model.Layer{model.LayerSource, model.LayerConfig, model.LayerDeps, model.LayerBinary}

var rq3Exposures = []string{risk.ExposureNetwork, risk.ExposureInternal, risk.ExposureTest}

// RQ3Summary returns rq3_summary.csv: over scanned projects, the share with
// at least one quantum-vulnerable finding in any layer, in each layer, in
// code (any layer but deps, whose findings are what a library offers, not
// what the project uses) and at each exposure, with 95% intervals.
func RQ3Summary(rows []ProjectRow) [][]string {
	var scanned []ProjectRow
	for _, r := range rows {
		if r.Scan.Status == "scanned" {
			scanned = append(scanned, r)
		}
	}
	out := [][]string{{"metric", "projects_with", "projects_scanned", "share", "ci95_low", "ci95_high", "findings"}}
	add := func(metric string, count func(ProjectRow) int) {
		k, total := 0, 0
		for _, r := range scanned {
			c := count(r)
			total += c
			if c > 0 {
				k++
			}
		}
		p := Wilson(k, len(scanned))
		out = append(out, []string{metric, strconv.Itoa(k), strconv.Itoa(len(scanned)), f4(p.Value), f4(p.Low), f4(p.High), strconv.Itoa(total)})
	}
	sum := func(m map[model.Layer]int, layers ...model.Layer) int {
		n := 0
		for _, l := range layers {
			n += m[l]
		}
		return n
	}
	add("vulnerable:any-layer", func(r ProjectRow) int { return sum(r.ByLayer, rq3Layers...) })
	add("vulnerable:used (source, config, binary)", func(r ProjectRow) int {
		return sum(r.ByLayer, model.LayerSource, model.LayerConfig, model.LayerBinary)
	})
	for _, l := range rq3Layers {
		add("vulnerable:layer:"+string(l), func(r ProjectRow) int { return r.ByLayer[l] })
	}
	for _, e := range rq3Exposures {
		add("vulnerable:exposure:"+e, func(r ProjectRow) int { return r.ByExposure[e] })
	}
	types := map[string]bool{}
	for _, r := range scanned {
		for t := range r.Derived {
			types[t] = true
		}
	}
	for _, t := range slices.Sorted(mapKeys(types)) {
		add("derived:"+t, func(r ProjectRow) int { return r.Derived[t] })
	}
	return out
}

// RQ3Algorithms returns rq3_algorithms.csv: each quantum-vulnerable
// algorithm, the number of scanned projects using it and its findings.
func RQ3Algorithms(rows []ProjectRow) [][]string {
	projects, findings := map[string]int{}, map[string]int{}
	for _, r := range rows {
		for a, c := range r.Algorithms {
			projects[a]++
			findings[a] += c
		}
	}
	algs := slices.Sorted(mapKeys(projects))
	slices.SortStableFunc(algs, func(a, b string) int { return cmp.Compare(projects[b], projects[a]) })
	out := [][]string{{"algorithm", "projects", "findings"}}
	for _, a := range algs {
		out = append(out, []string{a, strconv.Itoa(projects[a]), strconv.Itoa(findings[a])})
	}
	return out
}

// WriteRQ3 writes rq3_selection.csv, rq3_projects.csv, rq3_summary.csv,
// rq3_algorithms.csv and rq3_meta.csv to dir.
func WriteRQ3(dir string, sel []Selection, rows []ProjectRow, meta [][2]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	selection := [][]string{{"rank", "repo", "language", "criticality_score", "root_commit", "size_kb", "status"}}
	for _, s := range sel {
		selection = append(selection, []string{strconv.Itoa(s.Rank), s.Repo, s.Language, strconv.FormatFloat(s.Score, 'f', -1, 64),
			s.Root, strconv.Itoa(s.SizeKB), s.Status})
	}
	header := []string{"rank", "repo", "language", "criticality_score", "commit", "status", "scan_seconds", "findings"}
	for _, l := range rq3Layers {
		header = append(header, "vulnerable_"+string(l))
	}
	for _, e := range rq3Exposures {
		header = append(header, "vulnerable_exposure_"+e)
	}
	header = append(header, "derived")
	projects := [][]string{header}
	for _, r := range rows {
		row := []string{strconv.Itoa(r.Rank), r.Repo, r.Language, strconv.FormatFloat(r.Score, 'f', -1, 64),
			r.Scan.Commit, r.Scan.Status, strconv.Itoa(r.Scan.Seconds), strconv.Itoa(r.Findings)}
		for _, l := range rq3Layers {
			row = append(row, strconv.Itoa(r.ByLayer[l]))
		}
		for _, e := range rq3Exposures {
			row = append(row, strconv.Itoa(r.ByExposure[e]))
		}
		var derived []string
		for _, t := range slices.Sorted(mapKeys(r.Derived)) {
			derived = append(derived, fmt.Sprintf("%s=%d", t, r.Derived[t]))
		}
		projects = append(projects, append(row, strings.Join(derived, ";")))
	}
	m := [][]string{{"key", "value"}}
	for _, kv := range meta {
		m = append(m, kv[:])
	}
	for name, data := range map[string][][]string{
		"rq3_selection.csv": selection, "rq3_projects.csv": projects, "rq3_summary.csv": RQ3Summary(rows),
		"rq3_algorithms.csv": RQ3Algorithms(rows), "rq3_meta.csv": m,
	} {
		if err := writeCSV(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	return nil
}

// ReadTSV reads a tab-separated file into rows, skipping blank lines and
// lines starting with #.
func ReadTSV(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, sc.Err()
}
