package source

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// AssetSpec is the asset a rule reports. Params may be empty, meaning unknown
// unless a params_from extractor resolves it.
type AssetSpec struct {
	Primitive string `yaml:"primitive"`
	Algorithm string `yaml:"algorithm"`
	Params    string `yaml:"params"`
}

// Strings decodes either a YAML scalar or a sequence of scalars.
type Strings []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Strings) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = Strings{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// Rule is one detection rule. Exactly one of Call, Ref or Query is set:
//   - Call matches calls whose callee resolves, through the file's imports, to
//     one of the listed fully qualified symbols. Arguments are available to
//     params_from.
//   - Ref matches any reference to one of the listed symbols, called or not.
//   - Query is a raw tree-sitter query. The node captured as @match (or the
//     first capture) is the location; params_from may use capture[name].
type Rule struct {
	ID         string               `yaml:"id"`
	Lang       string               `yaml:"lang"`
	Call       Strings              `yaml:"call"`
	Ref        Strings              `yaml:"ref"`
	Query      string               `yaml:"query"`
	Asset      AssetSpec            `yaml:"asset"`
	ParamsFrom Strings              `yaml:"params_from"`
	ParamsMap  map[string]string    `yaml:"params_map"`
	Select     map[string]AssetSpec `yaml:"select"`
	Confidence float64              `yaml:"confidence"`
	Source     string               `yaml:"source"`
	Notes      string               `yaml:"notes"`

	extractors []extractor
	selectBy   map[string]AssetSpec
	query      *sitter.Query
}

type pack struct {
	Version int     `yaml:"version"`
	Lang    string  `yaml:"lang"`
	Rules   []*Rule `yaml:"rules"`
}

type extractor struct {
	kind  string // "arg", "kwarg" or "capture"
	index int
	name  string
}

var extractorRE = regexp.MustCompile(`^(?:arg\[(\d+)\]|(kwarg|capture)\[([A-Za-z_][A-Za-z0-9_]*)\])$`)

func parseExtractor(s string) (extractor, error) {
	m := extractorRE.FindStringSubmatch(s)
	if m == nil {
		return extractor{}, fmt.Errorf("invalid params_from %q (want arg[N], kwarg[name] or capture[name])", s)
	}
	if m[1] != "" {
		i, err := strconv.Atoi(m[1])
		if err != nil {
			return extractor{}, err
		}
		return extractor{kind: "arg", index: i}, nil
	}
	return extractor{kind: m[2], name: m[3]}, nil
}

// ruleSet is the compiled rules for one language.
type ruleSet struct {
	lang    *language
	calls   map[string]*Rule
	refs    map[string]*Rule
	queries []*Rule
	count   int
}

func normalizeKey(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// loadRules parses and validates every *.yaml pack in fsys.
func loadRules(db *knowledge.DB, fsys fs.FS) (map[string]*ruleSet, error) {
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("source: no rule packs found")
	}
	sets := make(map[string]*ruleSet)
	ids := make(map[string]string)
	var errs []error
	for _, name := range files {
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var p pack
		if err := dec.Decode(&p); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		lang, ok := languages[p.Lang]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unsupported lang %q", name, p.Lang))
			continue
		}
		if p.Version != 1 {
			errs = append(errs, fmt.Errorf("%s: unsupported version %d", name, p.Version))
		}
		set := sets[p.Lang]
		if set == nil {
			set = &ruleSet{lang: lang, calls: map[string]*Rule{}, refs: map[string]*Rule{}}
			sets[p.Lang] = set
		}
		for _, r := range p.Rules {
			if prev, dup := ids[r.ID]; dup {
				errs = append(errs, fmt.Errorf("%s: duplicate rule id %q (also in %s)", name, r.ID, prev))
			}
			ids[r.ID] = name
			if err := compileRule(db, set, p.Lang, r); err != nil {
				errs = append(errs, fmt.Errorf("%s: rule %q: %w", name, r.ID, err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return sets, nil
}

func compileRule(db *knowledge.DB, set *ruleSet, lang string, r *Rule) error {
	var errs []error
	report := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if r.ID == "" {
		report("missing id")
	}
	if r.Lang != "" && r.Lang != lang {
		report("lang %q does not match pack lang %q", r.Lang, lang)
	}
	if !strings.HasPrefix(r.Source, "https://") {
		report("source must be an https citation")
	}
	if !(r.Confidence > 0 && r.Confidence <= 1) {
		report("confidence %v outside (0,1]", r.Confidence)
	}

	kinds := 0
	for _, set := range []bool{len(r.Call) > 0, len(r.Ref) > 0, r.Query != ""} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		report("exactly one of call, ref or query is required")
	}

	for _, s := range r.ParamsFrom {
		e, err := parseExtractor(s)
		if err != nil {
			report("%v", err)
			continue
		}
		switch {
		case len(r.Ref) > 0:
			report("ref rules have no arguments for params_from")
		case len(r.Call) > 0 && e.kind == "capture":
			report("capture[...] is only valid in query rules")
		case r.Query != "" && e.kind != "capture":
			report("query rules take params from capture[...] only")
		}
		r.extractors = append(r.extractors, e)
	}

	if len(r.Select) > 0 {
		if len(r.ParamsFrom) == 0 {
			report("select requires params_from")
		}
		if r.Asset != (AssetSpec{}) || len(r.ParamsMap) > 0 {
			report("select replaces asset and params_map; do not set them too")
		}
		r.selectBy = make(map[string]AssetSpec, len(r.Select))
		for key, spec := range r.Select {
			if err := validateAsset(db, spec); err != nil {
				report("select %q: %v", key, err)
			}
			r.selectBy[normalizeKey(key)] = spec
		}
	} else {
		if err := validateAsset(db, r.Asset); err != nil {
			report("asset: %v", err)
		}
		if len(r.ParamsMap) > 0 && len(r.ParamsFrom) == 0 {
			report("params_map requires params_from")
		}
		if r.Asset.Params != "" && len(r.ParamsFrom) > 0 {
			report("fixed params and params_from are mutually exclusive")
		}
		for from, to := range r.ParamsMap {
			spec := r.Asset
			spec.Params = to
			if err := validateAsset(db, spec); err != nil {
				report("params_map %q: %v", from, err)
			}
		}
	}

	if r.Query != "" {
		q, err := sitter.NewQuery([]byte(r.Query), set.lang.grammar)
		if err != nil {
			report("query: %v", err)
		} else {
			r.query = q
			set.queries = append(set.queries, r)
		}
	}
	for _, sym := range r.Call {
		if claimSymbol(set, sym) {
			report("symbol %q is claimed by another rule", sym)
		}
		set.calls[sym] = r
	}
	for _, sym := range r.Ref {
		if claimSymbol(set, sym) {
			report("symbol %q is claimed by another rule", sym)
		}
		set.refs[sym] = r
	}
	set.count++
	return errors.Join(errs...)
}

// claimSymbol reports whether sym is already used. One symbol maps to one rule
// so a single reference can never produce duplicate findings.
func claimSymbol(set *ruleSet, sym string) bool {
	_, inCalls := set.calls[sym]
	_, inRefs := set.refs[sym]
	return inCalls || inRefs
}

// validateAsset checks an asset spec against the knowledge DB, so a typo in a
// rule fails at load time instead of producing unclassifiable findings.
func validateAsset(db *knowledge.DB, a AssetSpec) error {
	if !model.ValidPrimitive(a.Primitive) {
		return fmt.Errorf("unknown primitive %q", a.Primitive)
	}
	if _, ok := db.FamilyQuantum(a.Algorithm); !ok {
		return fmt.Errorf("algorithm %q is not a uniform family in the knowledge DB", a.Algorithm)
	}
	if a.Params != "" && a.Params != model.ParamsUnknown {
		e, ok := db.Lookup(a.Algorithm, a.Params)
		if !ok {
			return fmt.Errorf("%s %s is not in the knowledge DB", a.Algorithm, a.Params)
		}
		if !slices.Contains(e.Primitives, a.Primitive) {
			return fmt.Errorf("%s is not used as %s", e.ID, a.Primitive)
		}
		return nil
	}
	for _, e := range db.Entries() {
		if strings.EqualFold(e.Algorithm, a.Algorithm) && slices.Contains(e.Primitives, a.Primitive) {
			return nil
		}
	}
	return fmt.Errorf("no %s entry is used as %s", a.Algorithm, a.Primitive)
}
