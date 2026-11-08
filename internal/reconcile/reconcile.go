// Package reconcile links findings across layers for the same component and
// derives findings no single layer can produce:
//
//   - declared-pqc-deployed-classical: source or dependencies show
//     post-quantum key establishment, but a network endpoint negotiates
//     (TLS) or offers (SSH) classical key exchange only;
//   - config-overrides-library: a library in the component supports a hybrid
//     group, but a configuration directive lists only classical ones;
//   - binary-without-source: crypto in a shipped binary that no source file
//     in the component uses;
//   - stale-dependency: a library version with no post-quantum algorithms,
//     where a later version adds them.
//
// It also fuses confidence: a finding observed in two or more layers (source,
// config, binary, network) has its confidence raised and its corroborating
// findings linked; a configuration that a network endpoint contradicts is
// flagged for review. Dependency findings are capabilities, so they neither
// corroborate nor contradict.
package reconcile

import (
	"cmp"
	"fmt"
	"math"
	"net/url"
	"slices"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Derived finding types.
const (
	DeclaredPQCDeployedClassical = "declared-pqc-deployed-classical"
	ConfigOverridesLibrary       = "config-overrides-library"
	BinaryWithoutSource          = "binary-without-source"
	StaleDependency              = "stale-dependency"
)

// Types lists the derived finding types with a one-line description each.
var Types = map[string]string{
	DeclaredPQCDeployedClassical: "Post-quantum key establishment is declared in source or dependencies, but the endpoint deploys classical key exchange only",
	ConfigOverridesLibrary:       "A library supports a hybrid post-quantum group, but configuration lists only classical groups",
	BinaryWithoutSource:          "A shipped binary contains crypto that no source file in the component uses",
	StaleDependency:              "The dependency's version has no post-quantum algorithms; a later version adds them",
}

// maxLinks bounds LinkedIDs on one finding.
const maxLinks = 20

// Reconciler links and derives findings.
type Reconciler struct {
	db         *knowledge.DB
	libs       *knowledge.Libs
	components []Component
}

// New returns a Reconciler. With no components, everything is one component.
func New(db *knowledge.DB, libs *knowledge.Libs, components []Component) *Reconciler {
	if len(components) == 0 {
		components = []Component{DefaultComponent}
	}
	return &Reconciler{db: db, libs: libs, components: components}
}

// Run returns the findings, with linked IDs, fused confidence and review
// flags filled in, followed by the derived findings. Input findings that were
// themselves derived by an earlier run are dropped and derived again.
func (r *Reconciler) Run(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Derived == "" {
			out = append(out, f)
		}
	}
	groups := map[string][]int{}
	var names []string
	for i, f := range out {
		c := r.componentOf(f)
		if c == "" {
			continue
		}
		if _, ok := groups[c]; !ok {
			names = append(names, c)
		}
		groups[c] = append(groups[c], i)
	}
	var derived []model.Finding
	for _, name := range names {
		// A canonical order makes every choice below, such as which asset
		// labels a derived finding, independent of the input order.
		idx := groups[name]
		slices.SortFunc(idx, func(a, b int) int { return compareFindings(out[a], out[b]) })
		g := &group{name: name, all: out, idx: idx}
		r.corroborate(g)
		r.contradict(g)
		derived = append(derived, r.declaredDeployed(g)...)
		derived = append(derived, r.configOverrides(g)...)
		derived = append(derived, r.binaryWithoutSource(g)...)
		derived = append(derived, r.staleDependencies(g)...)
	}
	seen := map[string]bool{}
	for _, d := range derived {
		if !seen[d.ID] {
			seen[d.ID] = true
			out = append(out, d)
		}
	}
	return out
}

func compareFindings(a, b model.Finding) int {
	return cmp.Or(
		strings.Compare(string(a.Location.Layer), string(b.Location.Layer)),
		strings.Compare(a.Location.Path, b.Location.Path),
		cmp.Compare(a.Location.Line, b.Location.Line),
		strings.Compare(a.Location.Symbol, b.Location.Symbol),
		strings.Compare(a.Asset.Algorithm, b.Asset.Algorithm),
		strings.Compare(a.Asset.Params, b.Asset.Params),
		strings.Compare(a.Asset.Primitive, b.Asset.Primitive),
		strings.Compare(a.ID, b.ID),
	)
}

func (r *Reconciler) componentOf(f model.Finding) string {
	for _, c := range r.components {
		if c.contains(f) {
			return c.Name
		}
	}
	return ""
}

// group is one component's findings, as indexes into all.
type group struct {
	name string
	all  []model.Finding
	idx  []int
}

func (g *group) each(fn func(*model.Finding)) {
	for _, i := range g.idx {
		fn(&g.all[i])
	}
}

func (g *group) filter(keep func(model.Finding) bool) []*model.Finding {
	var out []*model.Finding
	g.each(func(f *model.Finding) {
		if keep(*f) {
			out = append(out, f)
		}
	})
	return out
}

func observed(f model.Finding) bool { return f.Location.Layer != model.LayerDeps }

func family(a model.Asset) string { return a.Algorithm + "/" + a.Primitive }

func pq(a model.Asset) bool {
	return a.Quantum == model.QuantumSafe || a.Quantum == model.QuantumHybrid
}

func keyEstablishment(a model.Asset) bool {
	return a.Primitive == model.PrimitiveKEM || a.Primitive == model.PrimitiveKeyAgreement
}

func link(f *model.Finding, ids ...string) {
	for _, id := range ids {
		if id != f.ID && !slices.Contains(f.LinkedIDs, id) && len(f.LinkedIDs) < maxLinks {
			f.LinkedIDs = append(f.LinkedIDs, id)
		}
	}
}

func ids(fs []*model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func round(x float64) float64 { return math.Round(x*1000) / 1000 }

// corroborate raises the confidence of a finding whose algorithm family is
// also observed in another layer, by noisy-OR with the strongest other
// observation: 1 - (1-c)(1-c').
func (r *Reconciler) corroborate(g *group) {
	byFamily := map[string][]*model.Finding{}
	g.each(func(f *model.Finding) {
		if observed(*f) {
			byFamily[family(f.Asset)] = append(byFamily[family(f.Asset)], f)
		}
	})
	// Every fused value is computed from the original confidences, so the
	// result does not depend on the order findings are visited.
	original := map[*model.Finding]float64{}
	for _, fs := range byFamily {
		for _, f := range fs {
			original[f] = f.Confidence
		}
	}
	for _, fs := range byFamily {
		for _, f := range fs {
			var others []*model.Finding
			best := 0.0
			for _, o := range fs {
				if o.Location.Layer != f.Location.Layer {
					others = append(others, o)
					best = max(best, original[o])
				}
			}
			if len(others) == 0 {
				continue
			}
			link(f, ids(others)...)
			f.Confidence = round(1 - (1-original[f])*(1-best))
		}
	}
}

// isGroupDirective reports whether a config finding comes from a directive
// that lists key-exchange groups.
func isGroupDirective(f model.Finding) bool {
	if f.Location.Layer != model.LayerConfig {
		return false
	}
	s := strings.ToLower(f.Location.Symbol)
	return strings.Contains(s, "ecdh_curve") || strings.Contains(s, "ecdh-curve") || strings.HasSuffix(s, "groups") ||
		strings.HasSuffix(s, "curves") || isSSHKexDirective(f)
}

func isSSHKexDirective(f model.Finding) bool {
	return f.Location.Layer == model.LayerConfig && strings.EqualFold(f.Location.Symbol, "ssh:KexAlgorithms")
}

// directive is the key-exchange assets one configuration line lists.
type directive struct {
	path, symbol string
	line         int
	findings     []*model.Finding
	ssh          bool
}

func (d directive) assets() []model.Asset {
	var out []model.Asset
	for _, f := range d.findings {
		if keyEstablishment(f.Asset) {
			out = append(out, f.Asset)
		}
	}
	return out
}

func (d directive) lists(a model.Asset) bool {
	for _, x := range d.assets() {
		if x.Algorithm == a.Algorithm && x.Params == a.Params {
			return true
		}
	}
	return false
}

func (d directive) classicalOnly() bool {
	as := d.assets()
	return len(as) > 0 && !slices.ContainsFunc(as, pq)
}

func (d directive) where() string { return fmt.Sprintf("%s:%d", d.path, d.line) }

func groupDirectives(g *group) []directive {
	byLine := map[string]*directive{}
	var order []string
	g.each(func(f *model.Finding) {
		if !isGroupDirective(*f) {
			return
		}
		k := fmt.Sprintf("%s:%d:%s", f.Location.Path, f.Location.Line, f.Location.Symbol)
		d, ok := byLine[k]
		if !ok {
			d = &directive{path: f.Location.Path, line: f.Location.Line, symbol: f.Location.Symbol, ssh: isSSHKexDirective(*f)}
			byLine[k] = d
			order = append(order, k)
		}
		d.findings = append(d.findings, f)
	})
	out := make([]directive, 0, len(order))
	for _, k := range order {
		out = append(out, *byLine[k])
	}
	return out
}

func negotiatedTLS(f model.Finding) bool {
	return f.Location.Layer == model.LayerNetwork &&
		(f.Location.Symbol == "tls:negotiated-group" || f.Location.Symbol == "tls:hello-retry-group")
}

func offeredSSHKex(f model.Finding) bool {
	return f.Location.Layer == model.LayerNetwork && f.Location.Symbol == "ssh:kex" && keyEstablishment(f.Asset)
}

// contradict flags configuration that a network endpoint in the same
// component contradicts: a negotiated TLS group, or an offered SSH key
// exchange, that the directive does not list. The file may not be the one
// deployed.
func (r *Reconciler) contradict(g *group) {
	tls := g.filter(negotiatedTLS)
	ssh := g.filter(offeredSSHKex)
	for _, d := range groupDirectives(g) {
		endpoints := tls
		if d.ssh {
			endpoints = ssh
		}
		for _, n := range endpoints {
			if d.lists(n.Asset) {
				continue
			}
			name := r.db.Name(n.Asset)
			verb := "negotiated"
			if d.ssh {
				verb = "offers"
			}
			for _, f := range d.findings {
				f.Review = appendReason(f.Review, fmt.Sprintf("%s %s %s, which %s does not list; this file may not be the deployed configuration",
					n.Location.Path, verb, name, d.where()))
				link(f, n.ID)
			}
			n.Review = appendReason(n.Review, fmt.Sprintf("%s does not list %s; the deployed configuration differs from the scanned file", d.where(), name))
			link(n, ids(d.findings)...)
		}
	}
}

func appendReason(cur, reason string) string {
	if cur == "" {
		return reason
	}
	if strings.Contains(cur, reason) {
		return cur
	}
	return cur + "; " + reason
}

// declaration is evidence that a component means to use post-quantum key
// establishment.
func declarations(g *group) []*model.Finding {
	return g.filter(func(f model.Finding) bool {
		return (f.Location.Layer == model.LayerSource || f.Location.Layer == model.LayerDeps) && pq(f.Asset) && keyEstablishment(f.Asset)
	})
}

func describeDeclarations(ds []*model.Finding, db *knowledge.DB) string {
	var parts []string
	for _, d := range ds {
		s := ""
		if d.Location.Layer == model.LayerDeps {
			s = fmt.Sprintf("%s (%s) provides %s", d.Location.Symbol, d.Location.Path, db.Name(d.Asset))
		} else {
			s = fmt.Sprintf("%s:%d uses %s", d.Location.Path, d.Location.Line, db.Name(d.Asset))
		}
		if !slices.Contains(parts, s) {
			parts = append(parts, s)
		}
		if len(parts) == 3 {
			break
		}
	}
	more := ""
	if len(ds) > len(parts) {
		more = fmt.Sprintf(" and %d more", len(ds)-len(parts))
	}
	return strings.Join(parts, "; ") + more
}

func derive(typ string, base model.Finding, asset model.Asset, confidence float64, evidence string, links []string) model.Finding {
	loc := base.Location
	loc.Symbol = "reconcile:" + typ
	d := model.NewFinding(asset, loc, round(confidence))
	d.RuleID = "reconcile." + typ
	d.Derived = typ
	d.Evidence = evidence
	for _, id := range links {
		link(&d, id)
	}
	return d
}

func maxConfidence(fs []*model.Finding) float64 {
	m := 0.0
	for _, f := range fs {
		m = max(m, f.Confidence)
	}
	return m
}

// declaredDeployed derives one finding per endpoint that negotiates (TLS) or
// offers (SSH) only classical key exchange while the component declares
// post-quantum key establishment.
func (r *Reconciler) declaredDeployed(g *group) []model.Finding {
	decl := declarations(g)
	if len(decl) == 0 {
		return nil
	}
	byEndpoint := map[string][]*model.Finding{}
	var order []string
	for _, f := range g.filter(func(f model.Finding) bool { return negotiatedTLS(f) || offeredSSHKex(f) }) {
		k := f.Location.Path + "|" + strings.SplitN(f.Location.Symbol, ":", 2)[0]
		if _, ok := byEndpoint[k]; !ok {
			order = append(order, k)
		}
		byEndpoint[k] = append(byEndpoint[k], f)
	}
	var out []model.Finding
	for _, k := range order {
		fs := byEndpoint[k]
		if slices.ContainsFunc(fs, func(f *model.Finding) bool { return pq(f.Asset) }) {
			continue
		}
		first := fs[0]
		verb := "negotiated"
		if first.Location.Symbol == "ssh:kex" {
			verb = "offers only"
		}
		var classical []string
		for _, f := range fs {
			if n := r.db.Name(f.Asset); !slices.Contains(classical, n) {
				classical = append(classical, n)
			}
		}
		evidence := fmt.Sprintf("%s, but %s %s %s", describeDeclarations(decl, r.db), first.Location.Path, verb, strings.Join(classical, ", "))
		out = append(out, derive(DeclaredPQCDeployedClassical, *first, first.Asset,
			min(maxConfidence(fs), maxConfidence(decl)), evidence, append(ids(fs), ids(decl)...)))
	}
	return out
}

// tlsHybrids and sshHybrids are the hybrid key exchanges a library can offer
// in each protocol.
var (
	tlsHybrids = []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
	sshHybrids = []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512"}
)

// configOverrides derives one finding per group directive that lists only
// classical groups although a library in the component supports a hybrid for
// that protocol.
func (r *Reconciler) configOverrides(g *group) []model.Finding {
	libraryHybrids := func(names []string) []*model.Finding {
		return g.filter(func(f model.Finding) bool {
			return f.Location.Layer == model.LayerDeps && f.Asset.Quantum == model.QuantumHybrid && slices.Contains(names, f.Asset.Params)
		})
	}
	tls, ssh := libraryHybrids(tlsHybrids), libraryHybrids(sshHybrids)
	var out []model.Finding
	for _, d := range groupDirectives(g) {
		libs := tls
		if d.ssh {
			libs = ssh
		}
		if len(libs) == 0 || !d.classicalOnly() {
			continue
		}
		var listed []string
		for _, a := range d.assets() {
			if n := r.db.Name(a); !slices.Contains(listed, n) {
				listed = append(listed, n)
			}
		}
		evidence := fmt.Sprintf("%s, but %s (%s) lists only classical %s", describeDeclarations(libs, r.db), d.where(), d.symbol, strings.Join(listed, ", "))
		first := d.findings[0]
		var classical model.Asset
		for _, f := range d.findings {
			if keyEstablishment(f.Asset) {
				classical = f.Asset
				break
			}
		}
		out = append(out, derive(ConfigOverridesLibrary, *first, classical, first.Confidence, evidence,
			append(ids(d.findings), ids(libs)...)))
	}
	return out
}

// binaryWithoutSource derives one finding per binary and algorithm family
// that no source file in the component uses.
func (r *Reconciler) binaryWithoutSource(g *group) []model.Finding {
	inSource := map[string]bool{}
	g.each(func(f *model.Finding) {
		if f.Location.Layer == model.LayerSource {
			inSource[family(f.Asset)] = true
		}
	})
	type key struct{ path, family string }
	byKey := map[key][]*model.Finding{}
	var order []key
	g.each(func(f *model.Finding) {
		if f.Location.Layer != model.LayerBinary || inSource[family(f.Asset)] {
			return
		}
		k := key{f.Location.Path, family(f.Asset)}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], f)
	})
	var out []model.Finding
	for _, k := range order {
		fs := byKey[k]
		best := fs[0]
		for _, f := range fs {
			if f.Confidence > best.Confidence {
				best = f
			}
		}
		evidence := fmt.Sprintf("%s contains %s (%s), but no source file in component %q uses %s",
			k.path, best.Asset.Algorithm, best.Location.Symbol, g.name, best.Asset.Algorithm)
		out = append(out, derive(BinaryWithoutSource, *best, best.Asset, best.Confidence, evidence, ids(fs)))
	}
	return out
}

// staleConfidence is the confidence of a stale-dependency finding: the
// version and the capability table are both explicit.
const staleConfidence = 0.9

// staleDependencies derives one finding per dependency whose version has no
// post-quantum algorithms although a later version of the library adds them.
func (r *Reconciler) staleDependencies(g *group) []model.Finding {
	type dep struct {
		path, purl, lib, version string
		line                     int
	}
	byDep := map[dep][]*model.Finding{}
	var order []dep
	g.each(func(f *model.Finding) {
		if f.Location.Layer != model.LayerDeps || !strings.HasPrefix(f.RuleID, "deps.") {
			return
		}
		_, version, ok := strings.Cut(f.Location.Symbol, "@")
		if !ok {
			return // unpinned: staleness can't be judged
		}
		version, err := url.PathUnescape(version)
		if err != nil {
			return
		}
		d := dep{f.Location.Path, f.Location.Symbol, strings.TrimPrefix(f.RuleID, "deps."), version, f.Location.Line}
		if _, ok := byDep[d]; !ok {
			order = append(order, d)
		}
		byDep[d] = append(byDep[d], f)
	})
	var out []model.Finding
	for _, d := range order {
		fs := byDep[d]
		if slices.ContainsFunc(fs, func(f *model.Finding) bool { return pq(f.Asset) }) {
			continue
		}
		lib, ok := r.libs.ByID(d.lib)
		if !ok {
			continue
		}
		since, names, ok := r.libs.FirstPQC(lib)
		if !ok {
			continue // no version of this library has post-quantum algorithms
		}
		// The asset is the classical key establishment the stale version
		// leaves in place, else whatever classical asset it provides.
		slices.SortStableFunc(fs, func(a, b *model.Finding) int {
			return cmp.Compare(rankStale(a.Asset), rankStale(b.Asset))
		})
		evidence := fmt.Sprintf("%s %s provides no post-quantum algorithms; %s %s adds %s",
			lib.Name, d.version, lib.Name, since, strings.Join(names, ", "))
		out = append(out, derive(StaleDependency, *fs[0], fs[0].Asset, staleConfidence, evidence, ids(fs)))
	}
	return out
}

func rankStale(a model.Asset) int {
	switch {
	case keyEstablishment(a):
		return 0
	case a.Primitive == model.PrimitiveSignature:
		return 1
	}
	return 2
}
