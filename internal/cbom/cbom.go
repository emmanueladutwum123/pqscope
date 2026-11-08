// Package cbom converts findings to a CycloneDX 1.6 cryptography bill of
// materials (CBOM).
//
// Each distinct asset, an (algorithm, params, primitive) triple, becomes one
// cryptographic-asset component. Every finding of that asset is listed under
// the component's evidence.occurrences, with the finding ID as the occurrence
// bom-ref so that a CBOM entry can be traced back to pqscope's JSON output.
// Fields that CycloneDX has no place for, such as the quantum status, are
// recorded as properties in the "pqscope:" namespace.
package cbom

import (
	"cmp"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// SpecVersion is the CycloneDX version written.
const SpecVersion = "1.6"

// Property names in the pqscope namespace.
const (
	PropAlgorithm      = "pqscope:algorithm"
	PropParams         = "pqscope:params"
	PropPrimitive      = "pqscope:primitive"
	PropQuantum        = "pqscope:quantum"
	PropMigrationCivil = "pqscope:migration:civilian"
	PropMigrationCNSA2 = "pqscope:migration:cnsa2"
	PropPolicyPrefix   = "pqscope:policy:" // followed by the policy name
	PropRisk           = "pqscope:risk"
)

const (
	projectURL         = "https://github.com/emmanueladutwum123/pqscope"
	schemaURL          = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	componentRefPrefix = "crypto/algorithm/"
	techniqueOther     = "other"
)

// Options controls metadata that would otherwise make output nondeterministic.
type Options struct {
	ToolVersion  string
	Timestamp    time.Time // zero means now
	SerialNumber string    // empty means a random urn:uuid
}

// BOM is a CycloneDX document, limited to the fields pqscope writes.
type BOM struct {
	Schema       string      `json:"$schema"`
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata describes how the BOM was made.
type Metadata struct {
	Timestamp string `json:"timestamp"`
	Tools     Tools  `json:"tools"`
}

// Tools lists the tools that produced the BOM.
type Tools struct {
	Components []Component `json:"components"`
}

// Component is a CycloneDX component.
type Component struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
	CryptoProperties   *CryptoProperties   `json:"cryptoProperties,omitempty"`
	Evidence           *Evidence           `json:"evidence,omitempty"`
	Properties         []Property          `json:"properties,omitempty"`
}

// ExternalReference points to a resource about a component.
type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CryptoProperties describes a cryptographic asset.
type CryptoProperties struct {
	AssetType           string              `json:"assetType"`
	AlgorithmProperties AlgorithmProperties `json:"algorithmProperties"`
}

// AlgorithmProperties describes an algorithm. Pointers distinguish an
// unrecorded level from level 0.
type AlgorithmProperties struct {
	Primitive                string `json:"primitive"`
	ParameterSetIdentifier   string `json:"parameterSetIdentifier,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	ClassicalSecurityLevel   *int   `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int   `json:"nistQuantumSecurityLevel,omitempty"`
}

// Evidence records how and where a component was found.
type Evidence struct {
	Identity    []Identity   `json:"identity"`
	Occurrences []Occurrence `json:"occurrences"`
}

// Identity is evidence for the component's name.
type Identity struct {
	Field          string   `json:"field"`
	Confidence     float64  `json:"confidence"`
	ConcludedValue string   `json:"concludedValue"`
	Methods        []Method `json:"methods"`
}

// Method is one analysis technique that identified the component.
type Method struct {
	Technique  string  `json:"technique"`
	Confidence float64 `json:"confidence"`
	Value      string  `json:"value,omitempty"`
}

// Occurrence is one place a component was found.
type Occurrence struct {
	BOMRef            string `json:"bom-ref"`
	Location          string `json:"location"`
	Line              int    `json:"line,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

// Property is a name-value pair.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cdxPrimitive maps model primitives to CycloneDX algorithmProperties.primitive.
var cdxPrimitive = map[string]string{
	model.PrimitiveSignature:    "signature",
	model.PrimitiveKEM:          "kem",
	model.PrimitiveKeyAgreement: "key-agree",
	model.PrimitivePKE:          "pke",
	model.PrimitiveHash:         "hash",
	model.PrimitiveMAC:          "mac",
}

// cipherPrimitive refines model.PrimitiveCipher, which CycloneDX splits into
// block ciphers, stream ciphers and authenticated encryption.
var cipherPrimitive = map[string]string{
	"AES":               "block-cipher",
	"3DES":              "block-cipher",
	"DES":               "block-cipher",
	"RC4":               "stream-cipher",
	"ChaCha20-Poly1305": "ae",
}

// technique maps a discovery layer to a CycloneDX evidence technique.
var technique = map[model.Layer]string{
	model.LayerSource:  "source-code-analysis",
	model.LayerDeps:    "manifest-analysis",
	model.LayerConfig:  techniqueOther,
	model.LayerBinary:  "binary-analysis",
	model.LayerNetwork: "dynamic-analysis",
}

// Primitive returns the CycloneDX primitive for an asset.
func Primitive(a model.Asset) string {
	if a.Primitive == model.PrimitiveCipher {
		return cmp.Or(cipherPrimitive[a.Algorithm], "unknown")
	}
	return cmp.Or(cdxPrimitive[a.Primitive], "unknown")
}

type assetKey struct{ algorithm, params, primitive string }

// Build converts findings to a BOM. Findings must have unique IDs.
func Build(db *knowledge.DB, findings []model.Finding, opts Options) (*BOM, error) {
	serial := opts.SerialNumber
	if serial == "" {
		serial = "urn:uuid:" + newUUID()
	}
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	bom := &BOM{
		Schema:       schemaURL,
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial,
		Version:      1,
		Metadata: Metadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type:               "application",
				BOMRef:             "pqscope",
				Name:               "pqscope",
				Version:            opts.ToolVersion,
				ExternalReferences: []ExternalReference{{Type: "vcs", URL: projectURL}},
			}}},
		},
		Components: []Component{},
	}

	groups := map[assetKey][]model.Finding{}
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Derived != "" {
			continue // reconciliation results describe other findings; the CBOM is the inventory
		}
		if seen[f.ID] {
			return nil, fmt.Errorf("cbom: duplicate finding id %s", f.ID)
		}
		seen[f.ID] = true
		k := assetKey{f.Asset.Algorithm, f.Asset.Params, f.Asset.Primitive}
		groups[k] = append(groups[k], f)
	}
	for k, fs := range groups {
		bom.Components = append(bom.Components, component(db, k, fs))
	}
	slices.SortFunc(bom.Components, func(a, b Component) int { return strings.Compare(a.BOMRef, b.BOMRef) })
	return bom, nil
}

// Write builds a BOM and writes it as indented JSON.
func Write(w io.Writer, db *knowledge.DB, findings []model.Finding, opts Options) error {
	bom, err := Build(db, findings, opts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func component(db *knowledge.DB, k assetKey, fs []model.Finding) Component {
	slices.SortFunc(fs, func(a, b model.Finding) int {
		return cmp.Or(
			strings.Compare(a.Location.Path, b.Location.Path),
			cmp.Compare(a.Location.Line, b.Location.Line),
			strings.Compare(a.Location.Symbol, b.Location.Symbol),
			strings.Compare(a.ID, b.ID),
		)
	})
	a := fs[0].Asset
	name := db.Name(a)

	props := AlgorithmProperties{Primitive: Primitive(a)}
	entry, known := db.Lookup(a.Algorithm, a.Params)
	switch {
	case known && entry.Curve != "":
		props.Curve = entry.Curve
	case a.Params != "" && a.Params != model.ParamsUnknown:
		props.ParameterSetIdentifier = a.Params
	}
	if a.ClassicalBits > 0 {
		props.ClassicalSecurityLevel = ptr(a.ClassicalBits)
	}
	// CycloneDX defines level 0 as "none of the categories are met", which is
	// true of anything a quantum computer breaks. Otherwise only a recorded
	// FIPS category is written.
	switch {
	case a.Quantum == model.QuantumVulnerable || a.Quantum == model.QuantumBrokenNow:
		props.NISTQuantumSecurityLevel = ptr(0)
	case known && entry.SecurityCategory > 0:
		props.NISTQuantumSecurityLevel = ptr(entry.SecurityCategory)
	}

	// Identity confidence is the strongest single observation, per technique
	// and overall; the rules that fired are listed per technique.
	best := map[string]float64{}
	rulesBy := map[string][]string{}
	var occ []Occurrence
	var risk float64
	policies := map[string]string{}
	for _, f := range fs {
		tech := cmp.Or(technique[f.Location.Layer], techniqueOther)
		best[tech] = max(best[tech], f.Confidence)
		if f.RuleID != "" && !slices.Contains(rulesBy[tech], f.RuleID) {
			rulesBy[tech] = append(rulesBy[tech], f.RuleID)
		}
		occ = append(occ, Occurrence{
			BOMRef:            f.ID,
			Location:          f.Location.Path,
			Line:              f.Location.Line,
			Symbol:            f.Location.Symbol,
			AdditionalContext: f.Evidence,
		})
		risk = max(risk, f.Risk)
		for _, p := range f.Policy {
			policies[p.Policy] = worse(policies[p.Policy], p.Status)
		}
	}
	id := Identity{Field: "name", ConcludedValue: name}
	for _, tech := range slices.Sorted(maps.Keys(best)) {
		rules := rulesBy[tech]
		slices.Sort(rules)
		id.Methods = append(id.Methods, Method{Technique: tech, Confidence: round(best[tech]), Value: strings.Join(rules, ", ")})
		id.Confidence = max(id.Confidence, round(best[tech]))
	}

	properties := []Property{
		{PropAlgorithm, a.Algorithm},
		{PropParams, a.Params},
		{PropPrimitive, a.Primitive},
		{PropQuantum, a.Quantum},
	}
	if r, ok := db.Replacement(a); ok {
		properties = append(properties, Property{PropMigrationCivil, r.Civilian}, Property{PropMigrationCNSA2, r.CNSA2})
	}
	for _, p := range slices.Sorted(maps.Keys(policies)) {
		properties = append(properties, Property{PropPolicyPrefix + p, policies[p]})
	}
	if risk > 0 {
		properties = append(properties, Property{PropRisk, strconv.FormatFloat(round(risk), 'f', -1, 64)})
	}

	return Component{
		Type:             "cryptographic-asset",
		BOMRef:           componentRefPrefix + k.algorithm + "/" + k.params + "/" + k.primitive,
		Name:             name,
		CryptoProperties: &CryptoProperties{AssetType: "algorithm", AlgorithmProperties: props},
		Evidence:         &Evidence{Identity: []Identity{id}, Occurrences: occ},
		Properties:       properties,
	}
}

// worse returns the more urgent of two policy statuses. Unknown ranks below
// compliant, so that any decided verdict wins over it.
func worse(a, b string) string {
	if a == "" || model.PolicySeverity(b) > model.PolicySeverity(a) {
		return b
	}
	return a
}

// round keeps three decimals, so that 0.95*0.8 is written as 0.76.
func round(x float64) float64 {
	return math.Round(x*1000) / 1000
}

func ptr(n int) *int { return &n }

// newUUID returns a random RFC 4122 version 4 UUID.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
