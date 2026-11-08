// Package report renders findings for terminals and as a self-contained HTML
// page.
package report

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Summary describes the scan that produced the findings.
type Summary struct {
	Target       string
	Counted      bool // false when findings were loaded from a file and counts are unknown
	FilesScanned int
	Skipped      int
	SyntaxErrors int
}

// Line returns the one-line scan summary, such as
// "3 findings in 2 files scanned, 1 skipped".
func (s Summary) Line(findings int) string {
	if !s.Counted {
		return fmt.Sprintf("%d findings", findings)
	}
	line := fmt.Sprintf("%d findings in %d files scanned", findings, s.FilesScanned)
	if s.Skipped > 0 {
		line += fmt.Sprintf(", %d skipped", s.Skipped)
	}
	if s.SyntaxErrors > 0 {
		line += fmt.Sprintf(", %d with syntax errors", s.SyntaxErrors)
	}
	return line
}

// severity orders quantum statuses from most to least urgent.
var severity = map[string]int{
	model.QuantumBrokenNow:  0,
	model.QuantumVulnerable: 1,
	model.QuantumWeakened:   2,
	model.QuantumHybrid:     3,
	model.QuantumSafe:       4,
}

// statuses lists quantum statuses in severity order.
var statuses = []string{model.QuantumBrokenNow, model.QuantumVulnerable, model.QuantumWeakened, model.QuantumHybrid, model.QuantumSafe}

func rank(quantum string) int {
	if r, ok := severity[quantum]; ok {
		return r
	}
	return len(severity)
}

// StatusCount is the number of findings with one quantum status.
type StatusCount struct {
	Status string
	Count  int
}

// CountByStatus counts findings per quantum status, most urgent first,
// omitting statuses with no findings.
func CountByStatus(findings []model.Finding) []StatusCount {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Asset.Quantum]++
	}
	var out []StatusCount
	for _, s := range statuses {
		if counts[s] > 0 {
			out = append(out, StatusCount{s, counts[s]})
			delete(counts, s)
		}
	}
	for _, s := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, StatusCount{s, counts[s]})
	}
	return out
}

// Group is one distinct asset and how often it was found.
type Group struct {
	Name      string
	Primitive string
	Quantum   string
	Migration string // "" when no replacement is needed or recorded
	Count     int
}

// Groups collapses findings into distinct assets, most urgent first, then by
// descending count and name.
func Groups(db *knowledge.DB, findings []model.Finding) []Group {
	type key struct{ algorithm, params, primitive string }
	index := map[key]int{}
	var out []Group
	for _, f := range findings {
		k := key{f.Asset.Algorithm, f.Asset.Params, f.Asset.Primitive}
		if i, ok := index[k]; ok {
			out[i].Count++
			continue
		}
		index[k] = len(out)
		out = append(out, Group{
			Name:      db.Name(f.Asset),
			Primitive: f.Asset.Primitive,
			Quantum:   f.Asset.Quantum,
			Migration: db.Migration(f.Asset),
			Count:     1,
		})
	}
	slices.SortStableFunc(out, func(a, b Group) int {
		return cmp.Or(
			cmp.Compare(rank(a.Quantum), rank(b.Quantum)),
			cmp.Compare(b.Count, a.Count),
			strings.Compare(a.Name, b.Name),
			strings.Compare(a.Primitive, b.Primitive),
		)
	})
	return out
}

// Text writes a findings table, an asset summary with migration targets, and
// the scan summary.
func Text(w io.Writer, db *knowledge.DB, findings []model.Finding, sum Summary) error {
	var b strings.Builder // strings.Builder never fails, so its errors are dropped
	if len(findings) > 0 {
		table(&b, "LOCATION\tALGORITHM\tPARAMS\tQUANTUM\tCONFIDENCE\tRULE", func(row func(...any)) {
			for _, f := range findings {
				row(location(f), f.Asset.Algorithm, f.Asset.Params, f.Asset.Quantum, fmt.Sprintf("%.2f", f.Confidence), cmp.Or(f.RuleID, "-"))
			}
		})
		b.WriteString("\n")
		table(&b, "ASSET\tPRIMITIVE\tQUANTUM\tFINDINGS\tMIGRATE TO", func(row func(...any)) {
			for _, g := range Groups(db, findings) {
				row(g.Name, g.Primitive, g.Quantum, g.Count, cmp.Or(g.Migration, "-"))
			}
		})
		b.WriteString("\n")
		var parts []string
		for _, c := range CountByStatus(findings) {
			parts = append(parts, fmt.Sprintf("%d %s", c.Count, c.Status))
		}
		b.WriteString("Quantum status: " + strings.Join(parts, ", ") + "\n")
	}
	b.WriteString(sum.Line(len(findings)) + "\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func table(b *strings.Builder, header string, rows func(row func(...any))) {
	tw := tabwriter.NewWriter(b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, header)
	rows(func(cells ...any) {
		strs := make([]string, len(cells))
		for i, c := range cells {
			strs[i] = fmt.Sprint(c)
		}
		_, _ = fmt.Fprintln(tw, strings.Join(strs, "\t"))
	})
	_ = tw.Flush()
}

func location(f model.Finding) string {
	if f.Location.Line > 0 {
		return fmt.Sprintf("%s:%d", f.Location.Path, f.Location.Line)
	}
	return f.Location.Path
}
