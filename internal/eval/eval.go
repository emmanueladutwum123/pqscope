package eval

import (
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/discover/binary"
	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/discover/deps"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/rules"
)

// Granularities.
const (
	ByFile = "file"
	ByLine = "line"
)

// Layers lists the discovery layers in report order.
var Layers = []string{"source", "config", "deps", "binary", "network"}

// Scanners holds pqscope's discovery layers.
type Scanners struct {
	db     *knowledge.DB
	source *source.Scanner
	config *config.Scanner
	deps   *deps.Scanner
	binary *binary.Scanner
}

// NewScanners builds pqscope's file layers.
func NewScanners(db *knowledge.DB, libs *knowledge.Libs) (*Scanners, error) {
	src, err := source.New(db, rules.FS)
	if err != nil {
		return nil, err
	}
	cs, err := config.New(db)
	if err != nil {
		return nil, err
	}
	bs, err := binary.New(db, libs, src.SymbolAssets("go"))
	if err != nil {
		return nil, err
	}
	return &Scanners{db: db, source: src, config: cs, deps: deps.New(db, libs), binary: bs}, nil
}

// pqscope scans every case with the enabled layers. Network cases read the
// findings eval/run.sh recorded in runs/pqscope-network.
func (s *Scanners) pqscope(ctx context.Context, cases []Case, runs string, enabled map[string]bool) ([]Item, error) {
	var items []Item
	add := func(c Case, fs []model.Finding) {
		for _, f := range fs {
			file, line := f.Location.Path, f.Location.Line
			if f.Location.Layer == model.LayerNetwork {
				file, line = "target", 0
			}
			items = append(items, Item{Case: c.ID, File: file, Line: line, Family: f.Asset.Algorithm})
		}
	}
	for _, c := range cases {
		if c.Layer == "network" {
			if !enabled["network"] {
				continue
			}
			data, err := os.ReadFile(filepath.Join(runs, "pqscope-network", filepath.Base(c.Dir)+".json"))
			if errors.Is(err, os.ErrNotExist) {
				continue // not run; scored as missed
			}
			if err != nil {
				return nil, err
			}
			var fs []model.Finding
			if err := json.Unmarshal(data, &fs); err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			add(c, fs)
			continue
		}
		if enabled["source"] {
			res, err := s.source.Scan(ctx, c.Dir)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			add(c, res.Findings)
		}
		if enabled["config"] {
			res, err := s.config.Scan(ctx, c.Dir)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			add(c, res.Findings)
		}
		if enabled["deps"] {
			res, err := s.deps.Scan(ctx, c.Dir)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			add(c, res.Findings)
		}
		if enabled["binary"] {
			res, err := s.binary.Scan(ctx, c.Dir)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			for _, f := range res.Findings {
				if f.Location.Layer == model.LayerBinary { // build-info capabilities belong to deps scoring
					add(c, []model.Finding{f})
				}
			}
		}
	}
	return items, nil
}

// Outcome is one scored item.
type Outcome struct {
	Tool, Granularity, Case, Layer, Language string
	File                                     string
	Line                                     int
	Family                                   string
	Result                                   string // tp, fp or fn
}

type key struct {
	file   string
	line   int
	family string
}

// score compares one tool's items with the labels of every case.
func score(tool string, cases []Case, items []Item) []Outcome {
	byCase := map[string][]Item{}
	for _, it := range items {
		byCase[it.Case] = append(byCase[it.Case], it)
	}
	var out []Outcome
	for _, c := range cases {
		for _, g := range []string{ByFile, ByLine} {
			mk := func(file string, line int, family string) key {
				if g == ByFile {
					line = 0
				}
				return key{file, line, family}
			}
			want := map[key]bool{}
			for _, l := range c.Expect {
				want[mk(l.File, l.Line, l.Algorithm)] = true
			}
			got := map[key]bool{}
			for _, it := range byCase[c.ID] {
				if c.Layer == "deps" && !slices.Contains(pqFamilies, it.Family) {
					continue
				}
				got[mk(it.File, it.Line, it.Family)] = true
			}
			emit := func(k key, result string) {
				out = append(out, Outcome{tool, g, c.ID, c.Layer, c.Language, k.file, k.line, k.family, result})
			}
			for _, k := range sortedKeys(want) {
				if got[k] {
					emit(k, "tp")
				} else {
					emit(k, "fn")
				}
			}
			for _, k := range sortedKeys(got) {
				if !want[k] {
					emit(k, "fp")
				}
			}
		}
	}
	return out
}

func sortedKeys(m map[key]bool) []key {
	out := make([]key, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b key) int {
		return cmp.Or(strings.Compare(a.file, b.file), cmp.Compare(a.line, b.line), strings.Compare(a.family, b.family))
	})
	return out
}

// Tally counts outcomes.
type Tally struct{ TP, FP, FN int }

// Precision, Recall and F1 follow the usual definitions; an empty
// denominator gives 1 for precision and recall (nothing claimed, or nothing
// to find) and 0 for F1 only when both are 0.
func (t Tally) Precision() float64 { return ratio(t.TP, t.TP+t.FP) }
func (t Tally) Recall() float64    { return ratio(t.TP, t.TP+t.FN) }
func (t Tally) F1() float64 {
	p, r := t.Precision(), t.Recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

// Report is the result of an evaluation.
type Report struct {
	Tools    []ToolRun
	Outcomes []Outcome
	Ablation []AblationRow
	Cases    []Case
}

// AblationRow is pqscope's score with one layer turned off.
type AblationRow struct {
	Config string // "all", or "without <layer>"
	Tally
}

// Run evaluates pqscope and every competitor run found under runs.
func Run(ctx context.Context, corpus, runs string) (*Report, error) {
	db, err := knowledge.Default()
	if err != nil {
		return nil, err
	}
	libs, err := knowledge.DefaultLibs()
	if err != nil {
		return nil, err
	}
	cases, err := LoadCorpus(corpus)
	if err != nil {
		return nil, err
	}
	s, err := NewScanners(db, libs)
	if err != nil {
		return nil, err
	}
	all := map[string]bool{}
	for _, l := range Layers {
		all[l] = true
	}
	rep := &Report{Cases: cases}

	items, err := s.pqscope(ctx, cases, runs, all)
	if err != nil {
		return nil, err
	}
	netRun := ToolRun{Tool: "pqscope-network", Status: "unavailable", Reason: "eval/run.sh network was not run"}
	if data, err := os.ReadFile(filepath.Join(runs, "pqscope-network", "tool.json")); err == nil {
		_ = json.Unmarshal(data, &netRun)
	}
	rep.Tools = append(rep.Tools, ToolRun{Tool: "pqscope", Version: "this tree", Source: "in-process", Status: "ran",
		Reason: "network cases: " + netRun.Status})
	rep.Outcomes = append(rep.Outcomes, score("pqscope", cases, items)...)

	ids := map[string]bool{}
	for _, c := range cases {
		ids[c.ID] = true
	}
	for _, comp := range competitors {
		run, items, err := loadCompetitor(runs, comp.name, comp.parse, ids)
		if err != nil {
			return nil, err
		}
		rep.Tools = append(rep.Tools, run)
		if run.Status == "ran" || run.Status == "partial" {
			rep.Outcomes = append(rep.Outcomes, score(comp.name, cases, items)...)
		}
	}

	// Ablation: which layers contribute most (RQ1).
	configs := append([]string{"all"}, Layers...)
	for _, cfg := range configs {
		enabled := map[string]bool{}
		for _, l := range Layers {
			enabled[l] = cfg == "all" || l != cfg
		}
		items, err := s.pqscope(ctx, cases, runs, enabled)
		if err != nil {
			return nil, err
		}
		var t Tally
		for _, o := range score("pqscope", cases, items) {
			if o.Granularity == ByFile {
				t.add(o.Result)
			}
		}
		name := cfg
		if cfg != "all" {
			name = "without " + cfg
		}
		rep.Ablation = append(rep.Ablation, AblationRow{name, t})
	}
	return rep, nil
}

func (t *Tally) add(result string) {
	switch result {
	case "tp":
		t.TP++
	case "fp":
		t.FP++
	case "fn":
		t.FN++
	}
}

// Summary aggregates outcomes by tool, granularity, layer and language, with
// "all" rows for every layer and overall.
func Summary(rep *Report) [][]string {
	type sk struct{ tool, g, layer, lang string }
	tallies := map[sk]*Tally{}
	casesBy := map[sk]map[string]bool{}
	bump := func(k sk, o Outcome) {
		if tallies[k] == nil {
			tallies[k] = &Tally{}
			casesBy[k] = map[string]bool{}
		}
		tallies[k].add(o.Result)
		casesBy[k][o.Case] = true
	}
	for _, o := range rep.Outcomes {
		bump(sk{o.Tool, o.Granularity, o.Layer, o.Language}, o)
		bump(sk{o.Tool, o.Granularity, o.Layer, "all"}, o)
		bump(sk{o.Tool, o.Granularity, "all", "all"}, o)
	}
	// Cases with no labels and no findings still count as cases scored.
	for _, c := range rep.Cases {
		for _, t := range rep.Tools {
			if t.Status != "ran" && t.Status != "partial" {
				continue
			}
			for _, g := range []string{ByFile, ByLine} {
				for _, k := range []sk{{t.Tool, g, c.Layer, c.Language}, {t.Tool, g, c.Layer, "all"}, {t.Tool, g, "all", "all"}} {
					if tallies[k] == nil {
						tallies[k] = &Tally{}
						casesBy[k] = map[string]bool{}
					}
					casesBy[k][c.ID] = true
				}
			}
		}
	}
	keys := make([]sk, 0, len(tallies))
	for k := range tallies {
		keys = append(keys, k)
	}
	layerRank := func(l string) int { return slices.Index(append([]string{"all"}, Layers...), l) }
	slices.SortFunc(keys, func(a, b sk) int {
		return cmp.Or(strings.Compare(a.tool, b.tool), strings.Compare(a.g, b.g),
			cmp.Compare(layerRank(a.layer), layerRank(b.layer)), strings.Compare(a.lang, b.lang))
	})
	rows := [][]string{{"tool", "granularity", "layer", "language", "cases", "tp", "fp", "fn", "precision", "recall", "f1"}}
	for _, k := range keys {
		t := tallies[k]
		rows = append(rows, []string{k.tool, k.g, k.layer, k.lang, strconv.Itoa(len(casesBy[k])),
			strconv.Itoa(t.TP), strconv.Itoa(t.FP), strconv.Itoa(t.FN), f4(t.Precision()), f4(t.Recall()), f4(t.F1())})
	}
	return rows
}

func f4(x float64) string { return strconv.FormatFloat(math.Round(x*1e4)/1e4, 'f', 4, 64) }

// WriteCSVs writes the rq1_*.csv files into dir.
func WriteCSVs(rep *Report, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	items := [][]string{{"tool", "granularity", "case", "layer", "language", "file", "line", "algorithm", "outcome"}}
	for _, o := range rep.Outcomes {
		items = append(items, []string{o.Tool, o.Granularity, o.Case, o.Layer, o.Language, o.File, strconv.Itoa(o.Line), o.Family, o.Result})
	}
	tools := [][]string{{"tool", "version", "source", "status", "reason"}}
	for _, t := range rep.Tools {
		tools = append(tools, []string{t.Tool, t.Version, t.Source, t.Status, t.Reason})
	}
	ablation := [][]string{{"config", "tp", "fp", "fn", "precision", "recall", "f1"}}
	for _, a := range rep.Ablation {
		ablation = append(ablation, []string{a.Config, strconv.Itoa(a.TP), strconv.Itoa(a.FP), strconv.Itoa(a.FN), f4(a.Precision()), f4(a.Recall()), f4(a.F1())})
	}
	corpus := [][]string{{"case", "layer", "language", "kind", "labels"}}
	for _, c := range rep.Cases {
		corpus = append(corpus, []string{c.ID, c.Layer, c.Language, c.Kind, strconv.Itoa(len(c.Expect))})
	}
	for name, rows := range map[string][][]string{
		"rq1_summary.csv": Summary(rep), "rq1_items.csv": items, "rq1_tools.csv": tools,
		"rq1_ablation.csv": ablation, "rq1_corpus.csv": corpus,
	} {
		if err := writeCSV(filepath.Join(dir, name), rows); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
