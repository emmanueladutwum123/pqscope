// Package policy evaluates findings against versioned YAML policies, such as
// NIST IR 8547 and CNSA 2.0.
//
// A policy is a list of rules, each matching knowledge DB entries (optionally
// restricted to some primitives) and assigning one status. Every (entry,
// primitive) pair in the knowledge DB must be matched by exactly one rule, so
// a policy can never silently skip an algorithm the scanner reports.
package policy

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Source is a citable reference.
type Source struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
}

// Cite points to the passage a rule relies on.
type Cite struct {
	Source  string `yaml:"source"`
	Section string `yaml:"section"`
}

// Rule assigns a status to some knowledge DB entries.
type Rule struct {
	ID         string   `yaml:"id"`
	Entries    []string `yaml:"entries"`
	Primitives []string `yaml:"primitives"` // empty means every primitive of each entry
	Status     string   `yaml:"status"`
	Schedule   string   `yaml:"schedule"`
	LegacyUse  string   `yaml:"legacy_use"`
	Note       string   `yaml:"note"`
	Cite       Cite     `yaml:"cite"`
}

// Policy is a validated policy.
type Policy struct {
	ID      string            `yaml:"id"`
	Title   string            `yaml:"title"`
	Version int               `yaml:"version"`
	Sources map[string]Source `yaml:"sources"`
	Rules   []Rule            `yaml:"rules"`

	db    *knowledge.DB
	index map[target]*Rule
}

// target is one (entry ID, primitive) pair.
type target struct{ entry, primitive string }

// Parse decodes and validates a policy against db. Unknown fields are errors.
func Parse(db *knowledge.DB, data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: decoding: %w", err)
	}
	p.db = db
	p.index = map[target]*Rule{}

	var errs []error
	if p.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported version %d", p.Version))
	}
	if p.ID == "" || p.Title == "" {
		errs = append(errs, errors.New("id and title are required"))
	}
	for key, s := range p.Sources {
		if s.Title == "" || !strings.HasPrefix(s.URL, "https://") {
			errs = append(errs, fmt.Errorf("source %q needs a title and an https url", key))
		}
	}
	ids := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		report := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("rule %q: "+format, append([]any{r.ID}, args...)...))
		}
		if r.ID == "" || ids[r.ID] {
			report("missing or duplicate id")
		}
		ids[r.ID] = true
		if !model.ValidPolicyStatus(r.Status) {
			report("unknown status %q", r.Status)
		}
		if r.Schedule == "" {
			report("no schedule")
		}
		if _, ok := p.Sources[r.Cite.Source]; !ok || r.Cite.Section == "" {
			report("cite needs a known source and a section")
		}
		if len(r.Entries) == 0 {
			report("no entries")
		}
		for _, id := range r.Entries {
			e, ok := db.ByID(id)
			if !ok {
				report("entry %q is not in the knowledge DB", id)
				continue
			}
			prims := r.Primitives
			if len(prims) == 0 {
				prims = e.Primitives
			}
			for _, prim := range prims {
				if !slices.Contains(e.Primitives, prim) {
					report("%s is not used as %q", e.ID, prim)
					continue
				}
				t := target{e.ID, prim}
				if other, dup := p.index[t]; dup {
					report("%s as %s is also matched by rule %q", e.ID, prim, other.ID)
				}
				p.index[t] = r
			}
			// A broken primitive can't be anything but broken under a policy.
			if e.Quantum == model.QuantumBrokenNow && r.Status != model.PolicyBrokenNow {
				report("%s is broken-now in the knowledge DB but %s here", e.ID, r.Status)
			}
		}
	}
	for _, e := range db.Entries() {
		for _, prim := range e.Primitives {
			if _, ok := p.index[target{e.ID, prim}]; !ok {
				errs = append(errs, fmt.Errorf("no rule for %s as %s", e.ID, prim))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("policy %s: invalid: %w", cmp.Or(p.ID, "?"), err)
	}
	return &p, nil
}

// Load parses every *.yaml policy in fsys, keyed by policy ID.
func Load(db *knowledge.DB, fsys fs.FS) (map[string]*Policy, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("policy: no policies found")
	}
	out := map[string]*Policy{}
	for _, name := range files {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		p, err := Parse(db, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if strings.TrimSuffix(name, ".yaml") != p.ID {
			return nil, fmt.Errorf("%s: policy id %q must match the file name", name, p.ID)
		}
		out[p.ID] = p
	}
	return out, nil
}

// Evaluate returns the policy's verdict on an asset.
//
// An asset whose params are in the knowledge DB gets its rule's status. For
// other params, typically "unknown", every entry of the algorithm family used
// as the asset's primitive is considered: if their rules agree, that status
// applies; otherwise the result is unknown, with AtBest set to the least
// urgent status among them.
func (p *Policy) Evaluate(a model.Asset) model.PolicyResult {
	res := model.PolicyResult{Policy: p.ID, Status: model.PolicyUnknown}
	if e, ok := p.db.Lookup(a.Algorithm, a.Params); ok {
		if r, ok := p.index[target{e.ID, a.Primitive}]; ok {
			return p.result(r)
		}
		return res
	}
	var rules []*Rule
	for _, e := range p.db.Entries() {
		if !strings.EqualFold(e.Algorithm, a.Algorithm) {
			continue
		}
		if r, ok := p.index[target{e.ID, a.Primitive}]; ok && !slices.Contains(rules, r) {
			rules = append(rules, r)
		}
	}
	switch {
	case len(rules) == 0:
		return res
	case len(rules) == 1:
		return p.result(rules[0])
	}
	best := rules[0].Status
	same := true
	for _, r := range rules[1:] {
		if r.Status != rules[0].Status {
			same = false
		}
		if model.PolicySeverity(r.Status) < model.PolicySeverity(best) {
			best = r.Status
		}
	}
	if same {
		res.Status = best
		res.Schedule = rules[0].Schedule
		return res
	}
	if model.PolicySeverity(best) >= 0 {
		res.AtBest = best
	}
	return res
}

func (p *Policy) result(r *Rule) model.PolicyResult {
	return model.PolicyResult{Policy: p.ID, Status: r.Status, Rule: r.ID, Schedule: r.Schedule}
}

// Rule returns the rule with the given ID.
func (p *Policy) Rule(id string) (Rule, bool) {
	for _, r := range p.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Apply sets each finding's Policy results, in the order the policies are
// given, replacing earlier results from the same policies.
func Apply(findings []model.Finding, policies ...*Policy) {
	for i := range findings {
		f := &findings[i]
		for _, p := range policies {
			f.Policy = slices.DeleteFunc(f.Policy, func(r model.PolicyResult) bool { return r.Policy == p.ID })
			f.Policy = append(f.Policy, p.Evaluate(f.Asset))
		}
	}
}

// Fails reports whether a result reaches the threshold status. An unknown
// result fails only when even its best case reaches the threshold.
func Fails(r model.PolicyResult, threshold string) bool {
	status := r.Status
	if status == model.PolicyUnknown {
		status = r.AtBest
	}
	sev := model.PolicySeverity(status)
	return sev >= 0 && sev >= model.PolicySeverity(threshold)
}

// ValidThreshold reports whether s can be used as a failure threshold: any
// status more urgent than compliant.
func ValidThreshold(s string) bool {
	return model.PolicySeverity(s) > 0
}
