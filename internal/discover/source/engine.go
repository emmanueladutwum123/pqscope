// Package source discovers cryptographic assets in source code. It parses
// files with tree-sitter and matches them against the YAML rule packs in
// rules/, resolving each reference through the file's imports so that aliased
// imports match and unrelated packages that share a name do not.
package source

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// UnresolvedParamsFactor scales a rule's confidence when it tries to resolve
// parameters (params_from) but cannot see them statically.
const UnresolvedParamsFactor = 0.8

// MaxFileSize is the largest file scanned; larger files are reported as skipped.
const MaxFileSize = 2 << 20

const maxEvalDepth = 4
const maxEvidenceLen = 160

// skipDirs are directory names never descended into.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true,
}

// Scanner runs the source rule packs.
type Scanner struct {
	db    *knowledge.DB
	sets  map[string]*ruleSet
	byExt map[string]*ruleSet
}

// New compiles the rule packs in fsys against db.
func New(db *knowledge.DB, packs fs.FS) (*Scanner, error) {
	sets, err := loadRules(db, packs)
	if err != nil {
		return nil, fmt.Errorf("source: loading rules: %w", err)
	}
	s := &Scanner{db: db, sets: sets, byExt: make(map[string]*ruleSet)}
	for _, set := range sets {
		for _, ext := range set.lang.exts {
			s.byExt[ext] = set
		}
	}
	return s, nil
}

// RuleCounts returns the number of rules loaded per language.
func (s *Scanner) RuleCounts() map[string]int {
	out := make(map[string]int, len(s.sets))
	for lang, set := range s.sets {
		out[lang] = set.count
	}
	return out
}

// RuleInfo describes a loaded rule for output formats such as SARIF.
type RuleInfo struct {
	ID          string
	Lang        string
	Description string // one line, generated from what the rule matches
	Notes       string // known limitations, from the rule pack
	Source      string // citation for the API behaviour the rule relies on
}

// Rules returns every loaded rule, sorted by ID.
func (s *Scanner) Rules() []RuleInfo {
	seen := map[*Rule]bool{}
	var out []RuleInfo
	add := func(lang string, r *Rule) {
		if seen[r] {
			return
		}
		seen[r] = true
		out = append(out, RuleInfo{ID: r.ID, Lang: lang, Description: describe(r), Notes: r.Notes, Source: r.Source})
	}
	for lang, set := range s.sets {
		for _, r := range set.calls {
			add(lang, r)
		}
		for _, r := range set.refs {
			add(lang, r)
		}
		for _, r := range set.queries {
			add(lang, r)
		}
	}
	slices.SortFunc(out, func(a, b RuleInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func describe(r *Rule) string {
	symbols := strings.Join(append(slices.Clone(r.Call), r.Ref...), ", ")
	switch {
	case len(r.Select) > 0:
		return "Algorithm selected by the argument to " + symbols
	case r.Query != "":
		return fmt.Sprintf("%s (%s) matched by a tree-sitter query", r.Asset.Algorithm, r.Asset.Primitive)
	default:
		return fmt.Sprintf("%s (%s) via %s", r.Asset.Algorithm, r.Asset.Primitive, symbols)
	}
}

// Skipped records a file that was not scanned.
type Skipped struct {
	Path   string
	Reason string
}

// Result is the outcome of scanning a directory tree.
type Result struct {
	Findings     []model.Finding
	FilesScanned int
	SyntaxErrors []string // files tree-sitter could only parse with errors; still scanned
	Skipped      []Skipped
}

// Scan walks root (a directory or a single file) and scans every file in a
// supported language.
func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}
	type job struct{ path, rel string }
	var jobs []job
	var res Result
	if !info.IsDir() {
		jobs = append(jobs, job{root, filepath.ToSlash(filepath.Base(root))})
	} else {
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != root && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if _, ok := s.byExt[filepath.Ext(path)]; !ok || d.Type()&fs.ModeSymlink != 0 {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			jobs = append(jobs, job{path, filepath.ToSlash(rel)})
			return nil
		})
		if err != nil {
			return Result{}, err
		}
	}

	type out struct {
		findings    []model.Finding
		skip        *Skipped
		syntaxError bool
		err         error
	}
	results := make([]out, len(jobs))
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsers := make(map[*sitter.Language]*sitter.Parser)
			defer func() {
				for _, p := range parsers {
					p.Close()
				}
			}()
			for i := range next {
				j := jobs[i]
				info, err := os.Stat(j.path)
				if err != nil {
					results[i].err = err
					continue
				}
				if info.Size() > MaxFileSize {
					results[i].skip = &Skipped{j.rel, fmt.Sprintf("larger than %d bytes", MaxFileSize)}
					continue
				}
				src, err := os.ReadFile(j.path)
				if err != nil {
					results[i].err = err
					continue
				}
				f, syntaxErr, err := s.scanFile(ctx, parsers, j.rel, src)
				results[i] = out{findings: f, syntaxError: syntaxErr, err: err}
			}
		}()
	}
	for i := range jobs {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	var errs []error
	for i, r := range results {
		switch {
		case r.err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", jobs[i].rel, r.err))
		case r.skip != nil:
			res.Skipped = append(res.Skipped, *r.skip)
		default:
			res.FilesScanned++
			res.Findings = append(res.Findings, r.findings...)
			if r.syntaxError {
				res.SyntaxErrors = append(res.SyntaxErrors, jobs[i].rel)
			}
		}
	}
	sortFindings(res.Findings)
	return res, errors.Join(errs...)
}

// ScanFile scans one file's contents. rel is the path recorded in findings.
func (s *Scanner) ScanFile(ctx context.Context, rel string, src []byte) ([]model.Finding, error) {
	parsers := make(map[*sitter.Language]*sitter.Parser)
	defer func() {
		for _, p := range parsers {
			p.Close()
		}
	}()
	f, _, err := s.scanFile(ctx, parsers, rel, src)
	return f, err
}

func (s *Scanner) scanFile(ctx context.Context, parsers map[*sitter.Language]*sitter.Parser, rel string, src []byte) ([]model.Finding, bool, error) {
	set, ok := s.byExt[filepath.Ext(rel)]
	if !ok {
		return nil, false, nil
	}
	p := parsers[set.lang.grammar]
	if p == nil {
		p = sitter.NewParser()
		p.SetLanguage(set.lang.grammar)
		parsers[set.lang.grammar] = p
	}
	tree, err := p.ParseCtx(ctx, nil, src)
	if err != nil {
		return nil, false, err
	}
	defer tree.Close()
	root := tree.RootNode()

	front := set.lang.front
	f := &file{
		scanner: s,
		set:     set,
		rel:     rel,
		src:     src,
		imports: front.collectImports(root, src),
		consts:  front.collectConsts(root, src),
		seen:    make(map[string]bool),
	}
	f.matchSymbols(root)
	f.matchQueries(root)
	sortFindings(f.findings)
	return f.findings, root.HasError(), nil
}

type file struct {
	scanner  *Scanner
	set      *ruleSet
	rel      string
	src      []byte
	imports  map[string]string
	consts   map[string]*sitter.Node
	seen     map[string]bool
	findings []model.Finding
}

type frame struct {
	n          *sitter.Node
	parentType string
	field      string
	dead       bool
}

// matchSymbols walks the tree once, matching call and ref rules. Code inside
// the body of an `if false` (or Python `if 0`) is skipped as dead.
func (f *file) matchSymbols(root *sitter.Node) {
	front := f.set.lang.front
	stack := []frame{{n: root}}
	for len(stack) > 0 {
		fr := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := fr.n
		if front.skipSubtree(n) {
			continue
		}
		if !fr.dead {
			if fn, args, ok := front.callParts(n); ok {
				if sym, ok := front.resolve(f, fn); ok {
					if r := f.set.calls[sym]; r != nil {
						pos, kw := front.args(args, f.src)
						f.emit(r, fn, sym, pos, kw, nil)
					}
				}
			}
			if front.refCandidate(n, fr.parentType, fr.field) {
				if sym, ok := front.resolve(f, n); ok {
					if r := f.set.refs[sym]; r != nil {
						f.emit(r, n, sym, nil, nil, nil)
					}
				}
			}
		}
		deadBody := n.Type() == "if_statement" && front.falseCondition(n.ChildByFieldName("condition"), f.src)
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			field := n.FieldNameForChild(i)
			stack = append(stack, frame{
				n:          n.Child(i),
				parentType: n.Type(),
				field:      field,
				dead:       fr.dead || (deadBody && field == "consequence"),
			})
		}
	}
}

func (f *file) matchQueries(root *sitter.Node) {
	for _, r := range f.set.queries {
		qc := sitter.NewQueryCursor()
		qc.Exec(r.query, root)
		for {
			m, ok := qc.NextMatch()
			if !ok {
				break
			}
			m = qc.FilterPredicates(m, f.src)
			if len(m.Captures) == 0 {
				continue
			}
			captures := make(map[string]*sitter.Node, len(m.Captures))
			for _, c := range m.Captures {
				captures[r.query.CaptureNameForId(c.Index)] = c.Node
			}
			loc := captures["match"]
			if loc == nil {
				loc = m.Captures[0].Node
			}
			if f.isDead(loc) {
				continue
			}
			f.emit(r, loc, r.ID, nil, nil, captures)
		}
		qc.Close()
	}
}

func (f *file) isDead(n *sitter.Node) bool {
	front := f.set.lang.front
	for child, p := n, n.Parent(); p != nil; child, p = p, p.Parent() {
		if p.Type() != "if_statement" || !front.falseCondition(p.ChildByFieldName("condition"), f.src) {
			continue
		}
		if c := p.ChildByFieldName("consequence"); c != nil && c.StartByte() == child.StartByte() && c.EndByte() == child.EndByte() {
			return true
		}
	}
	return false
}

// eval statically evaluates an expression to a literal value or a fully
// qualified symbol, following same-file single-assignment names.
func (f *file) eval(n *sitter.Node, depth int) (string, bool) {
	if n == nil || depth > maxEvalDepth {
		return "", false
	}
	front := f.set.lang.front
	if v, ok := front.literal(n, f.src); ok {
		return v, true
	}
	if fn, _, ok := front.callParts(n); ok {
		return front.resolve(f, fn)
	}
	if sym, ok := front.resolve(f, n); ok {
		return sym, true
	}
	if name, ok := front.identifier(n, f.src); ok {
		if v := f.consts[name]; v != nil {
			return f.eval(v, depth+1)
		}
		return "", false
	}
	if n.Type() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		return f.eval(n.NamedChild(0), depth+1)
	}
	return "", false
}

func (f *file) extract(r *Rule, pos []*sitter.Node, kw map[string]*sitter.Node, captures map[string]*sitter.Node) (string, bool) {
	for _, e := range r.extractors {
		var n *sitter.Node
		switch e.kind {
		case "arg":
			if e.index < len(pos) {
				n = pos[e.index]
			}
		case "kwarg":
			n = kw[e.name]
		case "capture":
			n = captures[e.name]
		}
		if n == nil {
			continue
		}
		if v, ok := f.eval(n, 0); ok {
			return v, true
		}
	}
	return "", false
}

func (f *file) emit(r *Rule, n *sitter.Node, sym string, pos []*sitter.Node, kw map[string]*sitter.Node, captures map[string]*sitter.Node) {
	spec := r.Asset
	confidence := r.Confidence
	value, resolved := f.extract(r, pos, kw, captures)

	switch {
	case r.selectBy != nil:
		chosen, ok := r.selectBy[normalizeKey(value)]
		if !resolved || !ok {
			return // the algorithm itself is unknown; nothing to report
		}
		spec = chosen
	case len(r.extractors) > 0:
		spec.Params = ""
		if resolved {
			if r.ParamsMap == nil {
				spec.Params = value
			} else if mapped, ok := r.ParamsMap[value]; ok {
				spec.Params = mapped
			}
		}
		if spec.Params == "" {
			confidence *= UnresolvedParamsFactor
		}
	}
	if spec.Params == "" {
		spec.Params = model.ParamsUnknown
	}

	asset := model.Asset{Primitive: spec.Primitive, Algorithm: spec.Algorithm, Params: spec.Params}
	if e, ok := f.scanner.db.Lookup(spec.Algorithm, spec.Params); ok {
		asset.Algorithm, asset.Params = e.Algorithm, e.Params
		asset.ClassicalBits, asset.Quantum = e.ClassicalBits, e.Quantum
	} else {
		// Validated at load time: every rule algorithm is a uniform family.
		asset.Quantum, _ = f.scanner.db.FamilyQuantum(spec.Algorithm)
	}

	loc := model.Location{
		Layer:  model.LayerSource,
		Path:   f.rel,
		Line:   int(n.StartPoint().Row) + 1,
		Symbol: sym,
	}
	finding := model.NewFinding(asset, loc, confidence)
	if f.seen[finding.ID] {
		return
	}
	f.seen[finding.ID] = true
	finding.RuleID = r.ID
	finding.Evidence = lineText(f.src, int(n.StartByte()))
	f.findings = append(f.findings, finding)
}

// lineText returns the trimmed source line containing offset, truncated.
func lineText(src []byte, offset int) string {
	start := bytes.LastIndexByte(src[:offset], '\n') + 1
	end := bytes.IndexByte(src[offset:], '\n')
	if end < 0 {
		end = len(src)
	} else {
		end += offset
	}
	line := strings.TrimSpace(string(src[start:end]))
	if utf8.RuneCountInString(line) > maxEvidenceLen {
		line = string([]rune(line)[:maxEvidenceLen]) + "…"
	}
	return line
}

func sortFindings(fs []model.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Location.Symbol < b.Location.Symbol
	})
}
