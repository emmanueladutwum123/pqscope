package measure

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/risk"
)

// Risk-score ablation: how much each factor of the risk score changes the
// order in which a project's findings are ranked for migration. Each
// configuration sets one factor to 1 for every finding and re-scores; the
// ranking is compared with the full score's within each project, since a
// project migrates its own findings, not another project's.

// Ablation is one way of scoring: the full score or the score without one
// factor.
type Ablation struct {
	Name  string
	Score func(risk.Factors) float64
}

// Ablations are the full score first, then one factor removed at a time.
var Ablations = []Ablation{
	{"all factors", func(x risk.Factors) float64 { return x.Product() }},
	{"without exposure", func(x risk.Factors) float64 { x.Exposure = 1; return x.Product() }},
	{"without secrecy lifetime", func(x risk.Factors) float64 { x.SecrecyLifetime = 1; return x.Product() }},
	{"without quantum status", func(x risk.Factors) float64 { x.QuantumStatus = 1; return x.Product() }},
	{"without confidence", func(x risk.Factors) float64 { x.Confidence = 1; return x.Product() }},
}

// AblationRow compares one scoring with the full score, pooled over projects.
type AblationRow struct {
	Config   string
	Projects int // projects with at least two findings
	Findings int
	// Pairs of findings in the same project that the full score orders
	// strictly, and of those, the pairs this scoring orders the other way or
	// ties.
	Ordered, Reversed, Tied int64
	// Pairs the full score ties that this scoring separates.
	Split int64
	// Projects whose highest-risk findings (all those at the top score) are
	// not the same set under this scoring.
	TopChanged int
	// Median over projects of Kendall's tau-b against the full score, over
	// projects where it is defined (neither scoring ties every pair).
	TauB      float64
	TauBCount int
}

// AblateRisk scores every finding in each project under each of Ablations
// and compares the result with the full score. Derived findings are left
// out: they restate what layers found.
func AblateRisk(projects map[string][]model.Finding, w *risk.Weights) []AblationRow {
	names := slices.Sorted(mapKeys(projects))
	factors := map[string][]risk.Factors{}
	for _, name := range names {
		for _, f := range projects[name] {
			if f.Derived == "" {
				factors[name] = append(factors[name], w.FactorsOf(f))
			}
		}
	}
	var out []AblationRow
	for _, a := range Ablations {
		row := AblationRow{Config: a.Name}
		var taus []float64
		for _, name := range names {
			fs := factors[name]
			if len(fs) < 2 {
				continue
			}
			row.Projects++
			row.Findings += len(fs)
			full := make([]float64, len(fs))
			abl := make([]float64, len(fs))
			for i, x := range fs {
				full[i] = Ablations[0].Score(x)
				abl[i] = a.Score(x)
			}
			c := comparePairs(full, abl)
			row.Ordered += c.ordered
			row.Reversed += c.reversed
			row.Tied += c.tied
			row.Split += c.split
			if !sameTop(full, abl) {
				row.TopChanged++
			}
			if t, ok := c.tauB(); ok {
				taus = append(taus, t)
			}
		}
		row.TauBCount = len(taus)
		row.TauB = median(taus)
		out = append(out, row)
	}
	return out
}

type pairCounts struct {
	n                       int64 // all pairs
	ordered, reversed, tied int64 // relative to x
	split                   int64 // tied in x, ordered in y
	concordant, discordant  int64
	tiedX, tiedY            int64
}

// comparePairs counts every pair (i, j) by how x and y order it.
func comparePairs(x, y []float64) pairCounts {
	var c pairCounts
	for i := range x {
		for j := i + 1; j < len(x); j++ {
			c.n++
			dx, dy := sign(x[i]-x[j]), sign(y[i]-y[j])
			if dx == 0 {
				c.tiedX++
			}
			if dy == 0 {
				c.tiedY++
			}
			switch {
			case dx == 0 && dy != 0:
				c.split++
			case dx != 0 && dy == 0:
				c.ordered++
				c.tied++
			case dx != 0 && dx == dy:
				c.ordered++
				c.concordant++
			case dx != 0:
				c.ordered++
				c.reversed++
				c.discordant++
			}
		}
	}
	return c
}

// tauB is Kendall's tau-b, undefined when either ranking ties every pair.
func (c pairCounts) tauB() (float64, bool) {
	d := math.Sqrt(float64(c.n-c.tiedX) * float64(c.n-c.tiedY))
	if d == 0 {
		return 0, false
	}
	return float64(c.concordant-c.discordant) / d, true
}

func sign(v float64) int {
	switch {
	case v > 0:
		return 1
	case v < 0:
		return -1
	}
	return 0
}

// sameTop reports whether the findings at x's maximum are those at y's.
func sameTop(x, y []float64) bool {
	mx, my := slices.Max(x), slices.Max(y)
	for i := range x {
		if (x[i] == mx) != (y[i] == my) {
			return false
		}
	}
	return true
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := slices.Clone(v)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// ReadFindingsArchive reads every <owner>__<repo>.json in a .tar.gz of
// findings files, as measure/rq3.sh publishes them, keyed by owner/repo.
func ReadFindingsArchive(file string) (map[string][]model.Finding, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]model.Finding{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		name := path.Base(h.Name)
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, "._") {
			continue
		}
		var fs []model.Finding
		if err := json.NewDecoder(tr).Decode(&fs); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", file, h.Name, err)
		}
		out[strings.Replace(strings.TrimSuffix(name, ".json"), "__", "/", 1)] = fs
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no findings files", file)
	}
	return out, nil
}

// WriteRiskAblation writes risk_ablation.csv and risk_ablation_meta.csv.
func WriteRiskAblation(dir string, rows []AblationRow, meta [][2]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	table := [][]string{{"config", "projects", "findings", "pairs_ordered", "reversed", "reversed_share",
		"tied", "tied_share", "split", "top_changed", "top_changed_share", "tau_b_median", "tau_b_projects"}}
	share := func(k, n int64) string {
		if n == 0 {
			return f4(0)
		}
		return f4(float64(k) / float64(n))
	}
	for _, r := range rows {
		table = append(table, []string{r.Config, strconv.Itoa(r.Projects), strconv.Itoa(r.Findings),
			strconv.FormatInt(r.Ordered, 10), strconv.FormatInt(r.Reversed, 10), share(r.Reversed, r.Ordered),
			strconv.FormatInt(r.Tied, 10), share(r.Tied, r.Ordered), strconv.FormatInt(r.Split, 10),
			strconv.Itoa(r.TopChanged), share(int64(r.TopChanged), int64(r.Projects)), f4(r.TauB), strconv.Itoa(r.TauBCount)})
	}
	if err := writeCSV(filepath.Join(dir, "risk_ablation.csv"), table); err != nil {
		return err
	}
	m := [][]string{{"key", "value"}}
	for _, kv := range meta {
		m = append(m, []string{kv[0], kv[1]})
	}
	return writeCSV(filepath.Join(dir, "risk_ablation_meta.csv"), m)
}
