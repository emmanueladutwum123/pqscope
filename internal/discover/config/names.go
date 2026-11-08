package config

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed names.yaml
var namesYAML []byte

type namesDocument struct {
	Version int                         `yaml:"version"`
	Sources map[string]knowledge.Source `yaml:"sources"`
	Tables  map[string]struct {
		Sources []string            `yaml:"sources"`
		Names   map[string][]string `yaml:"names"`
	} `yaml:"tables"`
}

// names holds the resolved name tables, keyed by table then lower-cased name.
type names map[string]map[string][]model.Asset

// requiredTables are the tables the parsers look up.
var requiredTables = []string{
	"tls-groups", "tls13-suites", "tls12-kx", "tls12-auth", "tls12-cipher", "tls12-mac",
	"ssh-kex", "ssh-pubkey", "ssh-ciphers", "ssh-macs", "digests", "oids",
}

func parseNames(db *knowledge.DB, data []byte) (names, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc namesDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: decoding names: %w", err)
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
	out := names{}
	for tname, t := range doc.Tables {
		if len(t.Sources) == 0 {
			errs = append(errs, fmt.Errorf("table %s: no sources", tname))
		}
		for _, s := range t.Sources {
			if _, ok := doc.Sources[s]; !ok {
				errs = append(errs, fmt.Errorf("table %s: unknown source %q", tname, s))
			}
		}
		m := map[string][]model.Asset{}
		for name, refs := range t.Names {
			key := strings.ToLower(name)
			if _, dup := m[key]; dup {
				errs = append(errs, fmt.Errorf("table %s: %q listed twice (names ignore case)", tname, name))
			}
			for _, ref := range refs {
				a, err := resolveRef(db, ref)
				if err != nil {
					errs = append(errs, fmt.Errorf("table %s: %s: %w", tname, name, err))
					continue
				}
				m[key] = append(m[key], a)
			}
		}
		out[tname] = m
	}
	for _, t := range requiredTables {
		if _, ok := out[t]; !ok {
			errs = append(errs, fmt.Errorf("missing table %s", t))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("config: invalid names: %w", err)
	}
	return out, nil
}

// resolveRef turns "ENTRY:primitive" or "Family:primitive[:params]" into an
// asset.
func resolveRef(db *knowledge.DB, ref string) (model.Asset, error) {
	parts := strings.Split(ref, ":")
	if len(parts) < 2 || len(parts) > 3 || !model.ValidPrimitive(parts[1]) {
		return model.Asset{}, fmt.Errorf("bad asset %q", ref)
	}
	if e, ok := db.ByID(parts[0]); ok && len(parts) == 2 {
		return e.Asset(parts[1])
	}
	return familyAsset(db, parts[0], parts[1], append(parts[2:], model.ParamsUnknown)[0])
}

// familyAsset builds an asset for a family at params that may or may not be
// in the knowledge DB.
func familyAsset(db *knowledge.DB, family, primitive, params string) (model.Asset, error) {
	if e, ok := db.Lookup(family, params); ok {
		return e.Asset(primitive)
	}
	q, ok := db.FamilyQuantum(family)
	if !ok {
		return model.Asset{}, fmt.Errorf("%q is not a knowledge DB entry or algorithm family", family)
	}
	return model.Asset{Primitive: primitive, Algorithm: family, Params: params, Quantum: q}, nil
}

func (n names) lookup(table, name string) []model.Asset {
	return n[table][strings.ToLower(strings.TrimSpace(name))]
}
