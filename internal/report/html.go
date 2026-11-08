package report

import (
	"cmp"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed report.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

// HTMLOptions controls metadata in the HTML report.
type HTMLOptions struct {
	ToolVersion string
	Generated   time.Time // zero means now
}

type htmlRow struct {
	Location, Algorithm, Params, Primitive, Quantum, Confidence, Risk, Rule, Evidence string
	Statuses                                                                          []string // one per policy, in the order of PolicyIDs
}

// HTML writes a self-contained HTML report. It loads nothing from the network,
// and its content security policy forbids it from doing so.
func HTML(w io.Writer, db *knowledge.DB, findings []model.Finding, sum Summary, opts HTMLOptions) error {
	generated := opts.Generated
	if generated.IsZero() {
		generated = time.Now()
	}
	policies := PolicyIDs(findings)
	rows := make([]htmlRow, 0, len(findings))
	for _, f := range findings {
		statuses := make([]string, len(policies))
		for i, id := range policies {
			statuses[i] = "-"
			for _, r := range f.Policy {
				if r.Policy == id {
					statuses[i] = r.Status
				}
			}
		}
		rows = append(rows, htmlRow{
			Risk:       fmt.Sprintf("%.2f", f.Risk),
			Statuses:   statuses,
			Location:   location(f),
			Algorithm:  f.Asset.Algorithm,
			Params:     f.Asset.Params,
			Primitive:  f.Asset.Primitive,
			Quantum:    f.Asset.Quantum,
			Confidence: fmt.Sprintf("%.2f", f.Confidence),
			Rule:       cmp.Or(f.RuleID, "-"),
			Evidence:   f.Evidence,
		})
	}
	return htmlTemplate.Execute(w, map[string]any{
		"ToolVersion": opts.ToolVersion,
		"Target":      sum.Target,
		"SummaryLine": sum.Line(len(findings)),
		"Generated":   generated.UTC().Format(time.RFC3339),
		"Findings":    findings,
		"Counts":      CountByStatus(findings),
		"Groups":      Groups(db, findings),
		"Rows":        rows,
		"Policies":    policies,
	})
}
