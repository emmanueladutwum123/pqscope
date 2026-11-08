package binary

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed symbols.yaml
var symbolsYAML []byte

type symbolRule struct {
	names    []string
	prefixes []string
	asset    model.Asset
}

type constant struct {
	name     string
	patterns [][]byte
	asset    model.Asset
}

type goPackage struct {
	packages []string
	asset    model.Asset
}

type table struct {
	symbols   []symbolRule
	packages  []goPackage
	generic   map[string]bool
	constants []constant
}

func parseTable(db *knowledge.DB, data []byte) (*table, error) {
	var doc struct {
		Version int                         `yaml:"version"`
		Sources map[string]knowledge.Source `yaml:"sources"`
		Symbols []struct {
			Names    []string `yaml:"names"`
			Prefixes []string `yaml:"prefixes"`
			Asset    string   `yaml:"asset"`
			Source   string   `yaml:"source"`
		} `yaml:"symbols"`
		GoPackages []struct {
			Packages []string `yaml:"packages"`
			Asset    string   `yaml:"asset"`
			Source   string   `yaml:"source"`
		} `yaml:"go_packages"`
		Generic struct {
			Source string   `yaml:"source"`
			Names  []string `yaml:"names"`
		} `yaml:"generic"`
		Constants []struct {
			Name       string `yaml:"name"`
			Hex        string `yaml:"hex"`
			BothEndian bool   `yaml:"both_endian"`
			Asset      string `yaml:"asset"`
			Source     string `yaml:"source"`
		} `yaml:"constants"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("binary: decoding symbols: %w", err)
	}
	var errs []error
	if doc.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported version %d", doc.Version))
	}
	for key, s := range doc.Sources {
		if s.Title == "" || !strings.HasPrefix(s.URL, "https://") {
			errs = append(errs, fmt.Errorf("source %q needs a title and an https url", key))
		}
	}
	cited := func(what, src string) {
		if _, ok := doc.Sources[src]; !ok {
			errs = append(errs, fmt.Errorf("%s cites unknown source %q", what, src))
		}
	}
	t := &table{generic: map[string]bool{}}
	seen := map[string]bool{}
	for _, s := range doc.Symbols {
		what := strings.Join(append(slices.Clone(s.Names), s.Prefixes...), ",")
		cited(what, s.Source)
		a, err := config.ResolveAsset(db, s.Asset)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
			continue
		}
		if len(s.Names)+len(s.Prefixes) == 0 {
			errs = append(errs, fmt.Errorf("symbol rule for %s has no names or prefixes", s.Asset))
		}
		for _, n := range append(slices.Clone(s.Names), s.Prefixes...) {
			if seen[n] {
				errs = append(errs, fmt.Errorf("symbol %q listed twice", n))
			}
			seen[n] = true
		}
		t.symbols = append(t.symbols, symbolRule{s.Names, s.Prefixes, a})
	}
	for _, g := range doc.GoPackages {
		what := strings.Join(g.Packages, ",")
		cited(what, g.Source)
		a, err := config.ResolveAsset(db, g.Asset)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
			continue
		}
		t.packages = append(t.packages, goPackage{g.Packages, a})
	}
	cited("generic", doc.Generic.Source)
	for _, n := range doc.Generic.Names {
		t.generic[n] = true
	}
	for _, c := range doc.Constants {
		cited(c.Name, c.Source)
		b, err := hex.DecodeString(c.Hex)
		if err != nil || len(b) < 8 {
			errs = append(errs, fmt.Errorf("constant %s: need at least 8 bytes of hex", c.Name))
			continue
		}
		a, err := config.ResolveAsset(db, c.Asset)
		if err != nil {
			errs = append(errs, fmt.Errorf("constant %s: %w", c.Name, err))
			continue
		}
		patterns := [][]byte{b}
		if c.BothEndian {
			r := slices.Clone(b)
			slices.Reverse(r)
			patterns = append(patterns, r)
		}
		t.constants = append(t.constants, constant{c.Name, patterns, a})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("binary: invalid symbols table: %w", err)
	}
	return t, nil
}

// goPackageOf returns the package path of a Go function name, such as
// "crypto/internal/fips140/rsa" for "crypto/internal/fips140/rsa.(*PrivateKey).Sign".
func goPackageOf(fn string) string {
	slash := strings.LastIndex(fn, "/")
	dot := strings.Index(fn[slash+1:], ".")
	if dot < 0 {
		return ""
	}
	return fn[:slash+1+dot]
}

// lookupGoPackage returns the asset and package a Go function belongs to.
func (t *table) lookupGoPackage(fn string) (model.Asset, string, bool) {
	if strings.HasPrefix(fn, "type:") || strings.HasPrefix(fn, "go:") {
		return model.Asset{}, "", false
	}
	pkg := goPackageOf(fn)
	for _, g := range t.packages {
		for _, p := range g.packages {
			if pkg == p || strings.HasPrefix(pkg, p+"/") {
				return g.asset, p, true
			}
		}
	}
	return model.Asset{}, "", false
}

// lookup returns the asset a symbol denotes.
func (t *table) lookup(name string) (model.Asset, bool) {
	for _, r := range t.symbols {
		if slices.Contains(r.names, name) {
			return r.asset, true
		}
		for _, p := range r.prefixes {
			if strings.HasPrefix(name, p) {
				return r.asset, true
			}
		}
	}
	return model.Asset{}, false
}
