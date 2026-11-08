package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/cbom"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/policy"
	"github.com/emmanueladutwum123/pqscope/internal/risk"
	"github.com/emmanueladutwum123/pqscope/policies"
)

// errPolicyFailed means the policy gate found assets at or above the failure
// threshold. main maps it to exit code 1; every other error is exit code 2.
var errPolicyFailed = errors.New("policy gate failed")

const defaultPolicy = "nist-ir-8547-2026"

// verdict is one asset's result under one policy.
type verdict struct {
	Name     string             `json:"name"`
	DepsOnly bool               `json:"deps_only,omitempty"`
	Asset    model.Asset        `json:"asset"`
	Resolved bool               `json:"resolved"`
	Findings int                `json:"findings"`
	Result   model.PolicyResult `json:"result"`
	Fails    bool               `json:"fails"`
}

func newPolicyCmd() *cobra.Command {
	var names []string
	var failOn string
	var asJSON, includeDeps bool
	cmd := &cobra.Command{
		Use:   "policy [--policy name]... <cbom.json|findings.json>",
		Short: "Evaluate a CBOM or saved findings against a policy, for CI gating",
		Long: "Evaluate every asset in a CycloneDX CBOM, or in findings saved with\n" +
			"`pqscope scan --json`, against one or more policies (\"-\" reads standard input).\n\n" +
			"Exit status: 0 when no asset reaches --fail-on, 1 when one does, 2 on errors.\n" +
			"An asset whose status is unknown fails only if every status it could have\n" +
			"reaches the threshold. Assets seen only in dependency manifests are what a\n" +
			"library makes available, not what the code uses, so they are listed but do\n" +
			"not fail the gate unless --include-deps is set.\n\n" +
			"Statuses, least to most urgent: compliant, disallowed-2035, deprecated-2030,\n" +
			"disallowed-now, broken-now. The default threshold, disallowed-2035, fails on\n" +
			"any asset the policy disallows now or later. Use disallowed-now to fail only\n" +
			"on what is disallowed today.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !policy.ValidThreshold(failOn) {
				return fmt.Errorf("--fail-on %q: want one of disallowed-2035, deprecated-2030, disallowed-now, broken-now", failOn)
			}
			db, err := knowledge.Default()
			if err != nil {
				return err
			}
			selected, err := selectPolicies(db, names)
			if err != nil {
				return err
			}
			items, err := readItems(cmd.InOrStdin(), args[0], db)
			if err != nil {
				return err
			}
			var verdicts []verdict
			for _, p := range selected {
				for _, it := range items {
					r := p.Evaluate(it.Asset)
					fails := policy.Fails(r, failOn) && (includeDeps || !it.DepsOnly)
					verdicts = append(verdicts, verdict{it.Name, it.DepsOnly, it.Asset, it.Resolved, it.Findings, r, fails})
				}
			}
			if asJSON {
				err = writeVerdictsJSON(cmd.OutOrStdout(), verdicts)
			} else {
				err = writeVerdicts(cmd.OutOrStdout(), selected, verdicts, failOn)
			}
			if err != nil {
				return err
			}
			if slices.ContainsFunc(verdicts, func(v verdict) bool { return v.Fails }) {
				return errPolicyFailed
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&names, "policy", nil, "policy to apply, repeatable (default "+defaultPolicy+")")
	cmd.Flags().StringVar(&failOn, "fail-on", model.PolicyDisallowed, "exit 1 if any asset reaches this `status`")
	cmd.Flags().BoolVar(&asJSON, "json", false, "write verdicts as JSON")
	cmd.Flags().BoolVar(&includeDeps, "include-deps", false, "let assets seen only in dependency manifests fail the gate")
	return cmd
}

// selectPolicies returns the named bundled policies, or the default.
func selectPolicies(db *knowledge.DB, names []string) ([]*policy.Policy, error) {
	all, err := policy.Load(db, policies.FS)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		names = []string{defaultPolicy}
	}
	var out []*policy.Policy
	for _, n := range names {
		p, ok := all[n]
		if !ok {
			ids := make([]string, 0, len(all))
			for id := range all {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			return nil, fmt.Errorf("unknown policy %q; bundled policies: %s", n, strings.Join(ids, ", "))
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// item is one distinct asset to evaluate.
type item struct {
	Name     string
	Asset    model.Asset
	Resolved bool
	Findings int
	DepsOnly bool
}

// readItems reads a CBOM (a JSON object) or a findings array, telling them
// apart by the first JSON token.
func readItems(stdin io.Reader, path string, db *knowledge.DB) ([]item, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		cs, err := cbom.Read(bytes.NewReader(data), db)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		items := make([]item, 0, len(cs))
		for _, c := range cs {
			items = append(items, item{c.Name, c.Asset, c.Resolved, len(c.Occurrences), c.DepsOnly()})
		}
		return items, nil
	}
	findings, err := readFindings(bytes.NewReader(data), "-")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var items []item
	index := map[[3]string]int{}
	for _, f := range findings {
		k := [3]string{f.Asset.Algorithm, f.Asset.Params, f.Asset.Primitive}
		deps := f.Location.Layer == model.LayerDeps
		if i, ok := index[k]; ok {
			items[i].Findings++
			items[i].DepsOnly = items[i].DepsOnly && deps
			continue
		}
		index[k] = len(items)
		items = append(items, item{db.Name(f.Asset), f.Asset, true, 1, deps})
	}
	return items, nil
}

func writeVerdicts(w io.Writer, selected []*policy.Policy, verdicts []verdict, failOn string) error {
	var b strings.Builder // never fails
	for _, p := range selected {
		var vs []verdict
		for _, v := range verdicts {
			if v.Result.Policy == p.ID {
				vs = append(vs, v)
			}
		}
		slices.SortStableFunc(vs, func(a, b verdict) int {
			return cmp.Or(
				cmp.Compare(model.PolicySeverity(b.Result.Status), model.PolicySeverity(a.Result.Status)),
				strings.Compare(a.Name, b.Name),
				strings.Compare(a.Asset.Primitive, b.Asset.Primitive),
			)
		})
		fmt.Fprintf(&b, "%s: %s\n\n", p.ID, p.Title)
		if len(vs) > 0 {
			tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "ASSET\tPRIMITIVE\tSTATUS\tFINDINGS\tGATE\tSCHEDULE")
			for _, v := range vs {
				status := v.Result.Status
				if v.Result.AtBest != "" {
					status += " (at best " + v.Result.AtBest + ")"
				}
				gate := "pass"
				switch {
				case v.Fails:
					gate = "FAIL"
				case v.DepsOnly && policy.Fails(v.Result, failOn):
					gate = "deps" // would fail, but only a dependency provides it
				}
				name := v.Name
				if !v.Resolved {
					name += " (unresolved)"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", name, cmp.Or(v.Asset.Primitive, "-"), status, v.Findings, gate, cmp.Or(v.Result.Schedule, "-"))
			}
			_ = tw.Flush()
			b.WriteString("\n")
		}
		failed := 0
		for _, v := range vs {
			if v.Fails {
				failed++
			}
		}
		result := "PASS"
		if failed > 0 {
			result = "FAIL"
		}
		fmt.Fprintf(&b, "%s: %d of %d assets at or above %s\n", result, failed, len(vs), failOn)
		deps := 0
		for _, v := range vs {
			if v.DepsOnly && !v.Fails && policy.Fails(v.Result, failOn) {
				deps++
			}
		}
		if deps > 0 {
			fmt.Fprintf(&b, "%d more only provided by dependencies (GATE \"deps\"); --include-deps gates them\n", deps)
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, strings.TrimSuffix(b.String(), "\n"))
	return err
}

func writeVerdictsJSON(w io.Writer, verdicts []verdict) error {
	if verdicts == nil {
		verdicts = []verdict{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(verdicts)
}

// annotate fills each finding's policy results, under every bundled policy,
// and its risk score.
func annotate(db *knowledge.DB, findings []model.Finding) error {
	all, err := policy.Load(db, policies.FS)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	// The default policy comes first in every finding's results.
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Or(cmp.Compare(boolInt(b == defaultPolicy), boolInt(a == defaultPolicy)), strings.Compare(a, b))
	})
	for _, id := range ids {
		policy.Apply(findings, all[id])
	}
	w, err := risk.Default()
	if err != nil {
		return err
	}
	w.Apply(findings)
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
