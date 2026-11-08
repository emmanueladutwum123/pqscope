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

	fswalk "github.com/emmanueladutwum123/pqscope/internal/discover/walk"
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

// SymbolAsset is the asset a fully qualified symbol denotes, and the rule
// that says so.
type SymbolAsset struct {
	Asset  model.Asset
	RuleID string
}

// SymbolAssets maps every fully qualified symbol of a language's call and ref
// rules, as written in the rule pack (such as "crypto/rsa.GenerateKey"), to
// its asset. Params are unknown unless the rule fixes
// them, since no argument is visible. Rules that choose the algorithm from an
// argument (select) are left out.
func (s *Scanner) SymbolAssets(lang string) map[string]SymbolAsset {
	set, ok := s.sets[lang]
	if !ok {
		return nil
	}
	out := map[string]SymbolAsset{}
	for _, m := range []map[string]*Rule{set.calls, set.refs} {
		for sym, r := range m {
			if len(r.Select) > 0 {
				continue
			}
			a, ok := s.ruleAsset(r)
			if ok {
				out[sym] = SymbolAsset{a, r.ID}
			}
		}
	}
	return out
}

func (s *Scanner) ruleAsset(r *Rule) (model.Asset, bool) {
	if r.Asset.Params != "" {
		if e, ok := s.db.Lookup(r.Asset.Algorithm, r.Asset.Params); ok {
			a, err := e.Asset(r.Asset.Primitive)
			return a, err == nil
		}
	}
	q, ok := s.db.FamilyQuantum(r.Asset.Algorithm)
	if !ok {
		return model.Asset{}, false
	}
	return model.Asset{Primitive: r.Asset.Primitive, Algorithm: r.Asset.Algorithm, Params: model.ParamsUnknown, Quantum: q}, true
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
type Skipped = fswalk.Skipped

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
	type job struct{ path, rel string }
	files, err := fswalk.Files(root, func(rel string) bool {
		_, ok := s.byExt[filepath.Ext(rel)]
		return ok
	})
	if err != nil {
		return Result{}, err
	}
	var res Result
	jobs := make([]job, len(files))
	for i, f := range files {
		jobs[i] = job{f.Path, f.Rel}
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
					results[i].skip = &Skipped{Path: j.rel, Reason: fmt.Sprintf("larger than %d bytes", MaxFileSize)}
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
	grammar := set.lang.grammarFor(filepath.Ext(rel))
	p := parsers[grammar]
	if p == nil {
		p = sitter.NewParser()
		p.SetLanguage(grammar)
		parsers[grammar] = p
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
		grammar: grammar,
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
	grammar  *sitter.Language
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
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			field := n.FieldNameForChild(i)
			stack = append(stack, frame{
				n:          n.Child(i),
				parentType: n.Type(),
				field:      field,
				dead:       fr.dead || front.dead(n, field, f.src),
			})
		}
	}
}

func (f *file) matchQueries(root *sitter.Node) {
	for _, r := range f.set.queries {
		qc := sitter.NewQueryCursor()
		qc.Exec(r.queries[f.grammar], root)
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
				captures[r.queries[f.grammar].CaptureNameForId(c.Index)] = c.Node
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
		for i := 0; i < int(p.ChildCount()); i++ {
			c := p.Child(i)
			if c.StartByte() == child.StartByte() && c.EndByte() == child.EndByte() && c.Type() == child.Type() {
				if front.dead(p, p.FieldNameForChild(i), f.src) {
					return true
				}
				break
			}
		}
	}
	return false
}

// value is the result of static evaluation: a literal, or a fully qualified
// symbol.
type value struct {
	text    string
	literal bool
}

// eval statically evaluates an expression to a literal value or a fully
// qualified symbol, following same-file single-assignment names.
func (f *file) eval(n *sitter.Node, depth int) (value, bool) {
	if n == nil || depth > maxEvalDepth {
		return value{}, false
	}
	front := f.set.lang.front
	if v, ok := front.literal(n, f.src); ok {
		return value{v, true}, true
	}
	if fn, _, ok := front.callParts(n); ok {
		sym, ok := front.resolve(f, fn)
		return value{text: sym}, ok
	}
	if name, ok := front.identifier(n, f.src); ok {
		if v := f.consts[name]; v != nil {
			return f.eval(v, depth+1)
		}
	}
	if sym, ok := front.resolve(f, n); ok {
		return value{text: sym}, true
	}
	if n.Type() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		return f.eval(n.NamedChild(0), depth+1)
	}
	return value{}, false
}

func (f *file) extract(r *Rule, pos []*sitter.Node, kw map[string]*sitter.Node, captures map[string]*sitter.Node) (value, bool) {
	return f.extractWith(r.extractors, pos, kw, captures)
}

func (f *file) extractWith(extractors []extractor, pos []*sitter.Node, kw map[string]*sitter.Node, captures map[string]*sitter.Node) (value, bool) {
	for _, e := range extractors {
		var n *sitter.Node
		switch e.kind {
		case "arg":
			if e.index < len(pos) {
				n = pos[e.index]
			}
			if n != nil && e.prop != "" {
				n = f.objectProperty(n, e.prop, 0)
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
	return value{}, false
}

// objectProperty returns key's value in an object literal, following a
// same-file name bound to one.
func (f *file) objectProperty(n *sitter.Node, key string, depth int) *sitter.Node {
	front := f.set.lang.front
	if v := front.property(n, key, f.src); v != nil {
		return v
	}
	if name, ok := front.identifier(n, f.src); ok && depth < maxEvalDepth {
		if v := f.consts[name]; v != nil {
			return f.objectProperty(v, key, depth+1)
		}
	}
	return nil
}

func (f *file) emit(r *Rule, n *sitter.Node, sym string, pos []*sitter.Node, kw map[string]*sitter.Node, captures map[string]*sitter.Node) {
	spec := r.Asset
	confidence := r.Confidence
	v, resolved := f.extract(r, pos, kw, captures)

	switch {
	case r.selectBy != nil:
		chosen, ok := r.choose(v.text)
		if !resolved || !ok {
			return // the algorithm itself is unknown; nothing to report
		}
		spec = chosen
		if spec.Params == "" && len(r.selectParamsFrom) > 0 {
			// Params come from another argument. Each candidate is kept only if
			// the knowledge DB knows it for the chosen algorithm, so a curve
			// name can never become an RSA key size.
			for _, e := range r.selectParamsFrom {
				p, ok := f.extractWith([]extractor{e}, pos, kw, captures)
				if !ok {
					continue
				}
				candidate := p.text
				if mapped, ok := r.ParamsMap[p.text]; ok {
					candidate = mapped
				} else if !p.literal {
					continue
				}
				if _, known := f.scanner.db.Lookup(spec.Algorithm, candidate); known {
					spec.Params = candidate
					break
				}
			}
		}
	case len(r.extractors) > 0:
		spec.Params = ""
		if resolved {
			switch {
			case r.ParamsMap != nil:
				spec.Params = r.ParamsMap[v.text]
			case v.literal:
				spec.Params = v.text
			}
			// A symbol with no params_map entry, such as a variable from
			// another package, says nothing about params.
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
		if a.Location.Symbol != b.Location.Symbol {
			return a.Location.Symbol < b.Location.Symbol
		}
		// One call can match twice on a line; the asset settles the order.
		return a.ID < b.ID
	})
}
