package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

const corpusDir = "../../../testdata/corpus"

// minScore is the acceptance bar for each language.
const minScore = 0.9

type label struct {
	File      string `yaml:"file"`
	Line      int    `yaml:"line"`
	Algorithm string `yaml:"algorithm"`
	Params    string `yaml:"params"`
	Primitive string `yaml:"primitive"`
}

type labels struct {
	Kind        string  `yaml:"kind"`
	Description string  `yaml:"description"`
	Expect      []label `yaml:"expect"`
}

// matchKey identifies a finding for scoring. Params and primitive are scored
// separately so that a correct detection with unresolved params still counts.
type matchKey struct {
	file, algorithm string
	line            int
}

type tally struct {
	tp, fp, fn            int
	paramsOK, primitiveOK int
}

func (t *tally) add(o tally) {
	t.tp += o.tp
	t.fp += o.fp
	t.fn += o.fn
	t.paramsOK += o.paramsOK
	t.primitiveOK += o.primitiveOK
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func (t tally) precision() float64 { return ratio(t.tp, t.tp+t.fp) }
func (t tally) recall() float64    { return ratio(t.tp, t.tp+t.fn) }
func (t tally) f1() float64 {
	p, r := t.precision(), t.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func scoreCase(want []label, got []model.Finding) (tally, []string) {
	var t tally
	var notes []string
	gotBy := make(map[matchKey]model.Finding)
	for _, f := range got {
		gotBy[matchKey{f.Location.Path, strings.ToLower(f.Asset.Algorithm), f.Location.Line}] = f
	}
	wantBy := make(map[matchKey]label)
	for _, l := range want {
		wantBy[matchKey{l.File, strings.ToLower(l.Algorithm), l.Line}] = l
	}
	for k, l := range wantBy {
		f, ok := gotBy[k]
		if !ok {
			t.fn++
			notes = append(notes, fmt.Sprintf("missed   %s:%d %s %s", l.File, l.Line, l.Algorithm, l.Params))
			continue
		}
		t.tp++
		if strings.EqualFold(f.Asset.Params, l.Params) {
			t.paramsOK++
		} else {
			notes = append(notes, fmt.Sprintf("params   %s:%d %s got %s want %s", l.File, l.Line, l.Algorithm, f.Asset.Params, l.Params))
		}
		if f.Asset.Primitive == l.Primitive {
			t.primitiveOK++
		} else {
			notes = append(notes, fmt.Sprintf("primitive %s:%d %s got %s want %s", l.File, l.Line, l.Algorithm, f.Asset.Primitive, l.Primitive))
		}
	}
	for k, f := range gotBy {
		if _, ok := wantBy[k]; !ok {
			t.fp++
			notes = append(notes, fmt.Sprintf("spurious %s:%d %s %s (%s)", f.Location.Path, f.Location.Line, f.Asset.Algorithm, f.Asset.Params, f.RuleID))
		}
	}
	sort.Strings(notes)
	return t, notes
}

func TestCorpus(t *testing.T) {
	s := testScanner(t)
	for _, lang := range []string{"go", "python", "java", "c", "js"} {
		t.Run(lang, func(t *testing.T) {
			dirs, err := filepath.Glob(filepath.Join(corpusDir, lang, "*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(dirs) == 0 {
				t.Fatal("no corpus cases")
			}
			var total tally
			byKind := map[string]*tally{}
			for _, dir := range dirs {
				data, err := os.ReadFile(filepath.Join(dir, "labels.yaml"))
				if err != nil {
					t.Fatalf("%s: %v", dir, err)
				}
				var ls labels
				if err := yaml.Unmarshal(data, &ls); err != nil {
					t.Fatalf("%s: %v", dir, err)
				}
				switch ls.Kind {
				case "positive", "hard-positive", "hard-negative":
				default:
					t.Fatalf("%s: unknown kind %q", dir, ls.Kind)
				}
				res, err := s.Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("%s: %v", dir, err)
				}
				if len(res.SyntaxErrors) > 0 {
					t.Errorf("%s: syntax errors in %v", dir, res.SyntaxErrors)
				}
				ct, notes := scoreCase(ls.Expect, res.Findings)
				for _, n := range notes {
					t.Logf("%s: %s", filepath.Base(dir), n)
				}
				total.add(ct)
				if byKind[ls.Kind] == nil {
					byKind[ls.Kind] = &tally{}
				}
				byKind[ls.Kind].add(ct)
			}
			for _, kind := range []string{"positive", "hard-positive", "hard-negative"} {
				if k := byKind[kind]; k != nil {
					t.Logf("%-14s tp=%d fp=%d fn=%d P=%.3f R=%.3f", kind, k.tp, k.fp, k.fn, k.precision(), k.recall())
				}
			}
			t.Logf("%-14s tp=%d fp=%d fn=%d P=%.3f R=%.3f F1=%.3f params=%d/%d primitive=%d/%d (%d cases)",
				"total", total.tp, total.fp, total.fn, total.precision(), total.recall(), total.f1(),
				total.paramsOK, total.tp, total.primitiveOK, total.tp, len(dirs))
			if total.precision() < minScore || total.recall() < minScore {
				t.Errorf("precision %.3f / recall %.3f below %.2f", total.precision(), total.recall(), minScore)
			}
		})
	}
}
