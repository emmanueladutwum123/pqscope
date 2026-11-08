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
	// Notes record material seen but not classified, such as an encrypted
	// private key, as "path: line N: reason".
	Notes []string
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
	Migration string            // "" when no replacement is needed or recorded
	Policy    map[string]string // policy ID to the most urgent status among the findings
	Risk      float64           // highest risk among the findings
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
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, Group{
				Name:      db.Name(f.Asset),
				Primitive: f.Asset.Primitive,
				Quantum:   f.Asset.Quantum,
				Migration: db.Migration(f.Asset),
				Policy:    map[string]string{},
			})
		}
		g := &out[i]
		g.Count++
		g.Risk = max(g.Risk, f.Risk)
		for _, r := range f.Policy {
			if cur, seen := g.Policy[r.Policy]; !seen || model.PolicySeverity(r.Status) > model.PolicySeverity(cur) {
				g.Policy[r.Policy] = r.Status
			}
		}
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

// PolicyIDs lists the policies that evaluated any finding, in order of first
// appearance.
func PolicyIDs(findings []model.Finding) []string {
	var ids []string
	for _, f := range findings {
		for _, r := range f.Policy {
			if !slices.Contains(ids, r.Policy) {
				ids = append(ids, r.Policy)
			}
		}
	}
	return ids
}

// CountByPolicy counts findings per status under one policy, most urgent
// first and unknown last, omitting statuses with no findings.
func CountByPolicy(findings []model.Finding, policyID string) []StatusCount {
	counts := map[string]int{}
	for _, f := range findings {
		for _, r := range f.Policy {
			if r.Policy == policyID {
				counts[r.Status]++
			}
		}
	}
	var out []StatusCount
	for _, s := range []string{model.PolicyBrokenNow, model.PolicyDisallowedNow, model.PolicyDeprecated,
		model.PolicyDisallowed, model.PolicyCompliant, model.PolicyUnknown} {
		if counts[s] > 0 {
			out = append(out, StatusCount{s, counts[s]})
		}
	}
	return out
}

func joinCounts(counts []StatusCount) string {
	parts := make([]string, len(counts))
	for i, c := range counts {
		parts[i] = fmt.Sprintf("%d %s", c.Count, c.Status)
	}
	return strings.Join(parts, ", ")
}

// Text writes a findings table, an asset summary with policy statuses and
// migration targets, and the scan summary.
func Text(w io.Writer, db *knowledge.DB, findings []model.Finding, sum Summary) error {
	var b strings.Builder // strings.Builder never fails, so its errors are dropped
	if len(findings) > 0 {
		table(&b, "LOCATION\tLAYER\tALGORITHM\tPARAMS\tQUANTUM\tCONFIDENCE\tRISK\tRULE", func(row func(...any)) {
			for _, f := range findings {
				row(location(f), f.Location.Layer, f.Asset.Algorithm, f.Asset.Params, f.Asset.Quantum,
					fmt.Sprintf("%.2f", f.Confidence), fmt.Sprintf("%.2f", f.Risk), cmp.Or(f.RuleID, "-"))
			}
		})
		b.WriteString("\n")
		policies := PolicyIDs(findings)
		header := "ASSET\tPRIMITIVE\tQUANTUM\tFINDINGS"
		for _, id := range policies {
			header += "\t" + strings.ToUpper(id)
		}
		table(&b, header+"\tMIGRATE TO", func(row func(...any)) {
			for _, g := range Groups(db, findings) {
				cells := []any{g.Name, g.Primitive, g.Quantum, g.Count}
				for _, id := range policies {
					cells = append(cells, cmp.Or(g.Policy[id], "-"))
				}
				row(append(cells, cmp.Or(g.Migration, "-"))...)
			}
		})
		b.WriteString("\n")
		b.WriteString("Quantum status: " + joinCounts(CountByStatus(findings)) + "\n")
		for _, id := range policies {
			b.WriteString(id + ": " + joinCounts(CountByPolicy(findings, id)) + "\n")
		}
	}
	b.WriteString(sum.Line(len(findings)) + "\n")
	if len(sum.Notes) > 0 {
		b.WriteString("\nNot classified:\n")
		for _, n := range sum.Notes {
			b.WriteString("  " + n + "\n")
		}
	}
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
