package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/discover/binary"
	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/discover/deps"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/rules"
)

func kb(t *testing.T) (*knowledge.DB, *knowledge.Libs) {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	libs, err := knowledge.DefaultLibs()
	if err != nil {
		t.Fatal(err)
	}
	return db, libs
}

func asset(t *testing.T, db *knowledge.DB, id, primitive string) model.Asset {
	t.Helper()
	e, ok := db.ByID(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	a, err := e.Asset(primitive)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func netFinding(t *testing.T, db *knowledge.DB, id, primitive, target, symbol string) model.Finding {
	t.Helper()
	f := model.NewFinding(asset(t, db, id, primitive), model.Location{Layer: model.LayerNetwork, Path: target, Symbol: symbol}, 1)
	f.RuleID = "network." + strings.SplitN(symbol, ":", 2)[0]
	return f
}

// scanFixture runs every file layer over a copy of testdata/reconcile/app
// with a binary added, then appends crafted network findings.
func scanFixture(t *testing.T) []model.Finding {
	t.Helper()
	db, libs := kb(t)
	dir := t.TempDir()
	src := "../../testdata/reconcile/app"
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	copyFile := func(from, to string) {
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range entries {
		copyFile(filepath.Join(src, e.Name()), filepath.Join(dir, e.Name()))
	}
	copyFile("../../testdata/binaries/crypto-elf", filepath.Join(dir, "bin", "server"))

	ctx := context.Background()
	var all []model.Finding
	srcScanner, err := source.New(db, rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	sres, err := srcScanner.Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, sres.Findings...)
	cs, err := config.New(db)
	if err != nil {
		t.Fatal(err)
	}
	cres, err := cs.Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, cres.Findings...)
	dres, err := deps.New(db, libs).Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, dres.Findings...)
	bs, err := binary.New(db, libs, srcScanner.SymbolAssets("go"))
	if err != nil {
		t.Fatal(err)
	}
	bres, err := bs.Scan(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, bres.Findings...)
	return append(all,
		netFinding(t, db, "X25519", "key-agreement", "app.example:443", "tls:negotiated-group"),
		netFinding(t, db, "mlkem768x25519-sha256", "kem", "app.example:22", "ssh:kex"),
		netFinding(t, db, "X25519", "key-agreement", "app.example:22", "ssh:kex"),
	)
}

func derived(fs []model.Finding, typ string) []model.Finding {
	var out []model.Finding
	for _, f := range fs {
		if f.Derived == typ {
			out = append(out, f)
		}
	}
	return out
}

func byID(fs []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

// The milestone 8 acceptance test: all four derived types from one crafted
// multi-layer fixture.
func TestAllDerivedTypes(t *testing.T) {
	db, libs := kb(t)
	in := scanFixture(t)
	out := New(db, libs, nil).Run(in)
	index := byID(out)

	for _, f := range out {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", f.Location.Symbol, err)
		}
	}

	d := derived(out, DeclaredPQCDeployedClassical)
	if len(d) != 1 || d[0].Location.Path != "app.example:443" || d[0].Asset.Algorithm != "X25519" ||
		!strings.Contains(d[0].Evidence, "pkg:pypi/cryptography@48.0.0 (requirements.txt) provides ML-KEM") ||
		!strings.Contains(d[0].Evidence, "but app.example:443 negotiated X25519") {
		t.Errorf("declared-pqc-deployed-classical = %+v", d)
	}
	// The SSH endpoint offers a hybrid, so it is not classical-only.
	for _, f := range d {
		if f.Location.Path == "app.example:22" {
			t.Error("app.example:22 offers mlkem768x25519-sha256 and must not be reported")
		}
	}

	c := derived(out, ConfigOverridesLibrary)
	if len(c) != 1 || c[0].Location.Path != "nginx.conf" || c[0].Location.Line != 3 || c[0].Location.Layer != model.LayerConfig ||
		!strings.Contains(c[0].Evidence, "provides X25519MLKEM768") || !strings.Contains(c[0].Evidence, "lists only classical ECDH-P256, X25519") {
		t.Errorf("config-overrides-library = %+v", c)
	}

	b := derived(out, BinaryWithoutSource)
	var families []string
	for _, f := range b {
		if f.Location.Path != "bin/server" || f.Location.Layer != model.LayerBinary {
			t.Errorf("binary-without-source at %s/%s", f.Location.Layer, f.Location.Path)
		}
		families = append(families, f.Asset.Algorithm)
	}
	slices.Sort(families)
	if !slices.Equal(families, []string{"AES", "ECDSA", "MD5", "RSA", "SHA-2"}) {
		t.Errorf("binary-without-source families = %v", families)
	}

	s := derived(out, StaleDependency)
	if len(s) != 1 || s[0].Location.Symbol != "reconcile:stale-dependency" || s[0].Location.Path != "Cargo.lock" ||
		!strings.Contains(s[0].Evidence, "rustls 0.23.10 provides no post-quantum algorithms; rustls 0.23.22 adds X25519MLKEM768") {
		t.Errorf("stale-dependency = %+v", s)
	}
	// cryptography 48.0.0 and openssl-src 3.5.4 already have PQC: not stale.
	for _, f := range s {
		if strings.Contains(f.Evidence, "cryptography") || strings.Contains(f.Evidence, "OpenSSL") {
			t.Errorf("not stale: %s", f.Evidence)
		}
	}

	// Every derived finding links back to findings that exist.
	for _, f := range out {
		if f.Derived == "" {
			continue
		}
		if len(f.LinkedIDs) == 0 {
			t.Errorf("%s at %s links nothing", f.Derived, f.Location.Path)
		}
		for _, id := range f.LinkedIDs {
			if _, ok := index[id]; !ok {
				t.Errorf("%s links unknown finding %s", f.Derived, id)
			}
		}
		if f.RuleID != "reconcile."+f.Derived {
			t.Errorf("rule %s for %s", f.RuleID, f.Derived)
		}
	}
}

func TestCorroborationAndReview(t *testing.T) {
	db, libs := kb(t)
	in := scanFixture(t)
	before := byID(in)
	out := New(db, libs, nil).Run(in)

	var x25519Source, sshConfig, sshNet *model.Finding
	for i := range out {
		f := &out[i]
		switch {
		case f.Location.Path == "app.py" && f.Asset.Algorithm == "X25519":
			x25519Source = f
		case f.Location.Path == "sshd_config" && f.Asset.Algorithm == "X25519":
			sshConfig = f
		case f.Location.Path == "app.example:22" && f.Asset.Params == "mlkem768x25519-sha256":
			sshNet = f
		}
	}
	if x25519Source == nil || sshConfig == nil || sshNet == nil {
		t.Fatal("fixture findings missing")
	}
	// X25519 in source (0.9), corroborated by config (0.9) and the network (1.0).
	orig := before[x25519Source.ID].Confidence
	if x25519Source.Confidence <= orig || x25519Source.Confidence != 1 {
		t.Errorf("source X25519 confidence %v (was %v), want raised to 1", x25519Source.Confidence, orig)
	}
	if len(x25519Source.LinkedIDs) < 2 {
		t.Errorf("source X25519 links %v", x25519Source.LinkedIDs)
	}
	// sshd_config allows curve25519 only; the server offers the ML-KEM hybrid.
	if !strings.Contains(sshConfig.Review, "app.example:22 offers mlkem768x25519-sha256, which sshd_config:1 does not list") {
		t.Errorf("sshd_config review = %q", sshConfig.Review)
	}
	if !strings.Contains(sshNet.Review, "sshd_config:1 does not list mlkem768x25519-sha256") {
		t.Errorf("network review = %q", sshNet.Review)
	}
	// Dependency capabilities neither corroborate nor get corroborated.
	for _, f := range out {
		if f.Location.Layer == model.LayerDeps && f.Derived == "" && f.Confidence != deps.CapabilityConfidence {
			t.Errorf("deps finding confidence changed to %v", f.Confidence)
		}
	}
}

// Reconciling twice gives the same result: derived inputs are dropped and
// derived again, and fusion does not depend on order.
func TestStableAndIdempotent(t *testing.T) {
	db, libs := kb(t)
	in := scanFixture(t)
	r := New(db, libs, nil)
	first := r.Run(slices.Clone(in))
	reversed := slices.Clone(in)
	slices.Reverse(reversed)
	second := r.Run(reversed)
	a, b := byID(first), byID(second)
	if len(a) != len(b) {
		t.Fatalf("%d vs %d findings", len(a), len(b))
	}
	for id, f := range a {
		g, ok := b[id]
		if !ok || g.Confidence != f.Confidence || g.Derived != f.Derived || (g.Review == "") != (f.Review == "") {
			t.Errorf("%s differs between orders: %+v vs %+v", id, f, g)
		}
	}
	// A second pass over its own output adds nothing new.
	again := byID(r.Run(first))
	if len(again) != len(a) {
		t.Errorf("rerun: %d findings, want %d", len(again), len(a))
	}
}

func TestNegativeCases(t *testing.T) {
	db, libs := kb(t)
	r := New(db, libs, nil)
	hybridNet := netFinding(t, db, "X25519MLKEM768", "kem", "h:443", "tls:negotiated-group")
	classicalNet := netFinding(t, db, "X25519", "key-agreement", "h:443", "tls:negotiated-group")
	declare := model.NewFinding(asset(t, db, "ML-KEM-768", "kem"), model.Location{Layer: model.LayerSource, Path: "a.go", Line: 3}, 0.95)
	conf := func(id string) model.Finding {
		f := model.NewFinding(asset(t, db, id, "key-agreement"), model.Location{Layer: model.LayerConfig, Path: "nginx.conf", Line: 7, Symbol: "nginx:ssl_ecdh_curve"}, 0.9)
		return f
	}
	hybridConf := model.NewFinding(asset(t, db, "X25519MLKEM768", "kem"), model.Location{Layer: model.LayerConfig, Path: "nginx.conf", Line: 7, Symbol: "nginx:ssl_ecdh_curve"}, 0.9)
	libHybrid := model.NewFinding(asset(t, db, "X25519MLKEM768", "kem"), model.Location{Layer: model.LayerDeps, Path: "go.mod", Line: 3, Symbol: "pkg:golang/stdlib@1.24"}, 0.5)
	libHybrid.RuleID = "deps.go-stdlib"

	tests := []struct {
		name string
		in   []model.Finding
		not  string
	}{
		{"endpoint negotiates a hybrid", []model.Finding{declare, hybridNet}, DeclaredPQCDeployedClassical},
		{"nothing declared", []model.Finding{classicalNet}, DeclaredPQCDeployedClassical},
		{"config lists a hybrid", []model.Finding{libHybrid, conf("X25519"), hybridConf}, ConfigOverridesLibrary},
		{"no hybrid-capable library", []model.Finding{conf("X25519")}, ConfigOverridesLibrary},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d := derived(r.Run(tt.in), tt.not); len(d) != 0 {
				t.Errorf("unexpected %s: %+v", tt.not, d)
			}
		})
	}
	if d := derived(r.Run([]model.Finding{declare, classicalNet}), DeclaredPQCDeployedClassical); len(d) != 1 {
		t.Errorf("source ML-KEM + classical endpoint: %d derived", len(d))
	}
	if d := derived(r.Run([]model.Finding{libHybrid, conf("X25519"), conf("ECDH-P256")}), ConfigOverridesLibrary); len(d) != 1 {
		t.Errorf("hybrid library + classical config: %d derived", len(d))
	}
}

func TestBinaryAndStaleNegatives(t *testing.T) {
	db, libs := kb(t)
	r := New(db, libs, nil)
	bin := model.NewFinding(model.Asset{Primitive: "signature", Algorithm: "RSA", Params: "unknown", Quantum: "vulnerable"},
		model.Location{Layer: model.LayerBinary, Path: "bin/app", Symbol: "import:RSA_new"}, 0.8)
	srcRSA := model.NewFinding(asset(t, db, "RSA-2048", "signature"), model.Location{Layer: model.LayerSource, Path: "main.go", Line: 9}, 0.95)
	if d := derived(r.Run([]model.Finding{bin, srcRSA}), BinaryWithoutSource); len(d) != 0 {
		t.Errorf("source uses RSA: %+v", d)
	}

	dep := func(purl, rule string, a model.Asset) model.Finding {
		f := model.NewFinding(a, model.Location{Layer: model.LayerDeps, Path: "requirements.txt", Line: 1, Symbol: purl}, 0.5)
		f.RuleID = rule
		return f
	}
	rsa := model.Asset{Primitive: "signature", Algorithm: "RSA", Params: "unknown", Quantum: "vulnerable"}
	mlkem := model.Asset{Primitive: "kem", Algorithm: "ML-KEM", Params: "unknown", Quantum: "safe"}
	for _, tt := range []struct {
		name  string
		in    []model.Finding
		stale bool
	}{
		{"old cryptography", []model.Finding{dep("pkg:pypi/cryptography@47.0.0", "deps.pyca-cryptography", rsa)}, true},
		{"current cryptography", []model.Finding{dep("pkg:pypi/cryptography@48.0.0", "deps.pyca-cryptography", rsa), dep("pkg:pypi/cryptography@48.0.0", "deps.pyca-cryptography", mlkem)}, false},
		{"unpinned", []model.Finding{dep("pkg:pypi/cryptography", "deps.pyca-cryptography", rsa)}, false},
		{"no version has PQC", []model.Finding{dep("pkg:npm/node-forge@1.3.1", "deps.node-forge", rsa)}, false},
		{"escaped version", []model.Finding{dep("pkg:cargo/openssl-src@300.4.2%2B3.4.1", "deps.openssl", rsa)}, true},
	} {
		if got := len(derived(r.Run(tt.in), StaleDependency)) == 1; got != tt.stale {
			t.Errorf("%s: stale = %v, want %v", tt.name, got, tt.stale)
		}
	}
}

func TestComponents(t *testing.T) {
	db, libs := kb(t)
	comps, err := ParseComponents(strings.NewReader(`
components:
  - name: web
    paths: [web]
    hosts: [web.example]
  - name: api
    paths: [api]
    hosts: [api.example:443]
`))
	if err != nil {
		t.Fatal(err)
	}
	declare := model.NewFinding(asset(t, db, "ML-KEM-768", "kem"), model.Location{Layer: model.LayerSource, Path: "web/main.go", Line: 3}, 0.95)
	apiNet := netFinding(t, db, "X25519", "key-agreement", "api.example:443", "tls:negotiated-group")
	webNet := netFinding(t, db, "X25519", "key-agreement", "web.example:8443", "tls:negotiated-group")
	other := netFinding(t, db, "X25519", "key-agreement", "elsewhere.example:443", "tls:negotiated-group")
	out := New(db, libs, comps).Run([]model.Finding{declare, apiNet, webNet, other})
	d := derived(out, DeclaredPQCDeployedClassical)
	if len(d) != 1 || d[0].Location.Path != "web.example:8443" {
		t.Errorf("only web's endpoint shares web's declaration: %+v", d)
	}
	if len(out) != 5 {
		t.Errorf("findings outside every component must still be returned: %d", len(out))
	}
	for _, doc := range []string{"components: []", "components:\n  - name: a\n", "components:\n  - {name: a, paths: [x]}\n  - {name: a, paths: [y]}\n"} {
		if _, err := ParseComponents(strings.NewReader(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}
