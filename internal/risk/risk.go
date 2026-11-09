// Package risk computes the score that ranks findings for migration:
//
//	risk = exposure × secrecy_lifetime × quantum_status × confidence
//
// Every weight lives in weights.yaml; see docs/risk.md for the rationale.
package risk

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"path"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed weights.yaml
var weightsYAML []byte

// Exposure classes.
const (
	ExposureNetwork  = "network"
	ExposureInternal = "internal"
	ExposureTest     = "test"
)

// TestPaths are the path heuristics for test and example code.
type TestPaths struct {
	Dirs         []string `yaml:"dirs"`
	FileSuffixes []string `yaml:"file_suffixes"`
	FilePrefixes []string `yaml:"file_prefixes"`
	Files        []string `yaml:"files"`
}

// Weights holds every factor of the risk score.
type Weights struct {
	Version         int                `yaml:"version"`
	Exposure        map[string]float64 `yaml:"exposure"`
	SecrecyLifetime map[string]float64 `yaml:"secrecy_lifetime"`
	QuantumStatus   map[string]float64 `yaml:"quantum_status"`
	TestPaths       TestPaths          `yaml:"test_paths"`
	NetworkLayers   []model.Layer      `yaml:"network_layers"`
	NetworkSymbols  []string           `yaml:"network_symbols"`
}

// Parse decodes and validates weights. Every exposure class, primitive and
// quantum status needs a weight in [0, 1].
func Parse(data []byte) (*Weights, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var w Weights
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("risk: decoding weights: %w", err)
	}
	var errs []error
	if w.Version != 1 {
		errs = append(errs, fmt.Errorf("unsupported version %d", w.Version))
	}
	check := func(table string, m map[string]float64, keys []string) {
		for _, k := range keys {
			v, ok := m[k]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: no weight for %q", table, k))
			} else if !(v >= 0 && v <= 1) {
				errs = append(errs, fmt.Errorf("%s: weight for %q is %v, outside [0,1]", table, k, v))
			}
		}
		for k := range m {
			if !slices.Contains(keys, k) {
				errs = append(errs, fmt.Errorf("%s: unknown key %q", table, k))
			}
		}
	}
	check("exposure", w.Exposure, []string{ExposureNetwork, ExposureInternal, ExposureTest})
	check("secrecy_lifetime", w.SecrecyLifetime, []string{model.PrimitiveSignature, model.PrimitiveKEM,
		model.PrimitiveKeyAgreement, model.PrimitivePKE, model.PrimitiveHash, model.PrimitiveCipher, model.PrimitiveMAC})
	check("quantum_status", w.QuantumStatus, []string{model.QuantumVulnerable, model.QuantumWeakened,
		model.QuantumSafe, model.QuantumHybrid, model.QuantumBrokenNow})
	for _, l := range w.NetworkLayers {
		if !l.Valid() {
			errs = append(errs, fmt.Errorf("network_layers: unknown layer %q", l))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("risk: invalid weights: %w", err)
	}
	return &w, nil
}

// Default returns the embedded weights, parsed once.
var Default = sync.OnceValues(func() (*Weights, error) {
	return Parse(weightsYAML)
})

// ExposureOf classifies where a finding sits: test code first, then
// network-facing, then internal.
func (w *Weights) ExposureOf(f model.Finding) string {
	if w.isTestPath(f.Location.Path) {
		return ExposureTest
	}
	if slices.Contains(w.NetworkLayers, f.Location.Layer) {
		return ExposureNetwork
	}
	if f.Location.Layer == model.LayerSource {
		for _, prefix := range w.NetworkSymbols {
			if strings.HasPrefix(f.Location.Symbol, prefix) {
				return ExposureNetwork
			}
		}
	}
	return ExposureInternal
}

func (w *Weights) isTestPath(p string) bool {
	dir, file := path.Split(strings.ReplaceAll(p, `\`, "/"))
	for _, seg := range strings.Split(strings.Trim(dir, "/"), "/") {
		if containsFold(w.TestPaths.Dirs, seg) {
			return true
		}
	}
	if containsFold(w.TestPaths.Files, file) {
		return true
	}
	// Affixes match case-sensitively, so that FooTest.java is a test but
	// Latest.java is not.
	for _, s := range w.TestPaths.FileSuffixes {
		if strings.HasSuffix(file, s) {
			return true
		}
	}
	for _, s := range w.TestPaths.FilePrefixes {
		if strings.HasPrefix(file, s) {
			return true
		}
	}
	return false
}

func containsFold(list []string, s string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, s) })
}

// Factors are the four weights a finding's risk multiplies.
type Factors struct {
	Exposure, SecrecyLifetime, QuantumStatus, Confidence float64
}

// FactorsOf returns the factors of f's risk.
func (w *Weights) FactorsOf(f model.Finding) Factors {
	return Factors{
		Exposure:        w.Exposure[w.ExposureOf(f)],
		SecrecyLifetime: w.SecrecyLifetime[f.Asset.Primitive],
		QuantumStatus:   w.QuantumStatus[f.Asset.Quantum],
		Confidence:      f.Confidence,
	}
}

// Product multiplies the factors, rounded to three decimals as Score is.
func (x Factors) Product() float64 {
	return math.Round(x.Exposure*x.SecrecyLifetime*x.QuantumStatus*x.Confidence*1000) / 1000
}

// Score returns a finding's risk in [0, 1], rounded to three decimals.
func (w *Weights) Score(f model.Finding) float64 {
	return w.FactorsOf(f).Product()
}

// Apply sets every finding's Risk.
func (w *Weights) Apply(findings []model.Finding) {
	for i := range findings {
		findings[i].Risk = w.Score(findings[i])
	}
}
