package cbom

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Item is one algorithm component read back from a CBOM.
type Item struct {
	Name        string
	BOMRef      string
	Asset       model.Asset
	Resolved    bool // false when the component could not be matched to the knowledge DB
	Occurrences []Occurrence
}

// modelPrimitive maps CycloneDX primitives back to pqscope's.
var modelPrimitive = map[string]string{
	"signature":     model.PrimitiveSignature,
	"kem":           model.PrimitiveKEM,
	"key-agree":     model.PrimitiveKeyAgreement,
	"pke":           model.PrimitivePKE,
	"hash":          model.PrimitiveHash,
	"mac":           model.PrimitiveMAC,
	"block-cipher":  model.PrimitiveCipher,
	"stream-cipher": model.PrimitiveCipher,
	"ae":            model.PrimitiveCipher,
}

// Read decodes a CycloneDX BOM and returns its algorithm components.
//
// Components written by pqscope carry their exact asset in pqscope:
// properties. Components from other tools are matched to the knowledge DB by
// name, parameter set and curve, filtered by primitive; one that does not
// match exactly one entry is returned unresolved, with params "unknown".
func Read(r io.Reader, db *knowledge.DB) ([]Item, error) {
	var bom BOM
	if err := json.NewDecoder(r).Decode(&bom); err != nil {
		return nil, fmt.Errorf("cbom: decoding: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("cbom: bomFormat is %q, not CycloneDX", bom.BOMFormat)
	}
	var items []Item
	for _, c := range bom.Components {
		if c.Type != "cryptographic-asset" || c.CryptoProperties == nil || c.CryptoProperties.AssetType != "algorithm" {
			continue
		}
		item := Item{Name: c.Name, BOMRef: c.BOMRef}
		if c.Evidence != nil {
			item.Occurrences = c.Evidence.Occurrences
		}
		item.Asset, item.Resolved = resolve(db, c)
		items = append(items, item)
	}
	return items, nil
}

func resolve(db *knowledge.DB, c Component) (model.Asset, bool) {
	props := map[string]string{}
	for _, p := range c.Properties {
		props[p.Name] = p.Value
	}
	if alg, prim := props[PropAlgorithm], props[PropPrimitive]; alg != "" && prim != "" {
		a := model.Asset{Primitive: prim, Algorithm: alg, Params: props[PropParams], Quantum: props[PropQuantum]}
		if e, ok := db.Lookup(a.Algorithm, a.Params); ok {
			a.ClassicalBits = e.ClassicalBits
		}
		return a, true
	}

	ap := c.CryptoProperties.AlgorithmProperties
	prim := modelPrimitive[ap.Primitive]
	var match []knowledge.Entry
	for _, name := range []string{c.Name, ap.ParameterSetIdentifier} {
		for _, e := range db.Find(name) {
			if prim != "" && !slices.Contains(e.Primitives, prim) {
				continue
			}
			if ap.Curve != "" && e.Curve != "" && !strings.EqualFold(ap.Curve, e.Curve) {
				continue
			}
			if !slices.ContainsFunc(match, func(m knowledge.Entry) bool { return m.ID == e.ID }) {
				match = append(match, e)
			}
		}
	}
	if len(match) == 1 && prim != "" {
		if a, err := match[0].Asset(prim); err == nil {
			return a, true
		}
	}
	return model.Asset{Primitive: prim, Algorithm: c.Name, Params: model.ParamsUnknown}, false
}
