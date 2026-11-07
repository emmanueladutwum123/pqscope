// Package knowledge holds pqscope's cited database of cryptographic algorithms:
// family, parameters, classical strength, quantum status and PQC replacement.
package knowledge

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

//go:embed algorithms.yaml
var algorithmsYAML []byte

// Source is a citable reference.
type Source struct {
	Title string `yaml:"title"`
	URL   string `yaml:"url"`
}

// Sizes holds encoded sizes in bytes. Zero means not applicable or not recorded.
type Sizes struct {
	PublicKey    int `yaml:"public_key"`
	PrivateKey   int `yaml:"private_key"`
	Ciphertext   int `yaml:"ciphertext"`
	Signature    int `yaml:"signature"`
	SharedSecret int `yaml:"shared_secret"`
}

// Replacement names the migration targets for one primitive, by entry ID.
type Replacement struct {
	Civilian string `yaml:"civilian"`
	CNSA2    string `yaml:"cnsa2"`
}

// Entry describes one algorithm at one parameter set.
type Entry struct {
	ID               string                 `yaml:"id"`
	Algorithm        string                 `yaml:"algorithm"`
	Params           string                 `yaml:"params"`
	Aliases          []string               `yaml:"aliases"`
	Primitives       []string               `yaml:"primitives"`
	ClassicalBits    int                    `yaml:"classical_bits"`
	Quantum          string                 `yaml:"quantum"`
	SecurityCategory int                    `yaml:"security_category"`
	Components       []string               `yaml:"components"`
	Sizes            Sizes                  `yaml:"sizes"`
	Replacement      map[string]Replacement `yaml:"replacement"`
	Sources          []string               `yaml:"sources"`
	Notes            string                 `yaml:"notes"`
}

// Asset returns the model.Asset for this entry used as the given primitive.
func (e Entry) Asset(primitive string) (model.Asset, error) {
	if !slices.Contains(e.Primitives, primitive) {
		return model.Asset{}, fmt.Errorf("knowledge: %s is not used as %q", e.ID, primitive)
	}
	return model.Asset{
		Primitive:     primitive,
		Algorithm:     e.Algorithm,
		Params:        e.Params,
		ClassicalBits: e.ClassicalBits,
		Quantum:       e.Quantum,
	}, nil
}

// DB is a validated, read-only algorithm database.
type DB struct {
	version int
	sources map[string]Source
	entries []Entry
	byID    map[string]int
	byName  map[string][]int
}

type document struct {
	Version int               `yaml:"version"`
	Sources map[string]Source `yaml:"sources"`
	Entries []Entry           `yaml:"entries"`
}

// Parse decodes and validates a database document. Unknown fields are errors.
func Parse(data []byte) (*DB, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("knowledge: decoding: %w", err)
	}

	db := &DB{
		version: doc.Version,
		sources: doc.Sources,
		entries: doc.Entries,
		byID:    make(map[string]int, len(doc.Entries)),
		byName:  make(map[string][]int),
	}
	var errs []error
	for i, e := range doc.Entries {
		if _, dup := db.byID[normalize(e.ID)]; dup {
			errs = append(errs, fmt.Errorf("duplicate id %q", e.ID))
		}
		db.byID[normalize(e.ID)] = i
		names := append([]string{e.ID, e.Params}, e.Aliases...)
		for _, name := range names {
			n := normalize(name)
			if !slices.Contains(db.byName[n], i) {
				db.byName[n] = append(db.byName[n], i)
			}
		}
	}
	if doc.Version < 1 {
		errs = append(errs, fmt.Errorf("invalid version %d", doc.Version))
	}
	for key, s := range doc.Sources {
		if s.Title == "" || !strings.HasPrefix(s.URL, "https://") {
			errs = append(errs, fmt.Errorf("source %q needs a title and an https url", key))
		}
	}
	for _, e := range doc.Entries {
		errs = append(errs, db.validateEntry(e)...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("knowledge: invalid database: %w", err)
	}
	return db, nil
}

func (db *DB) validateEntry(e Entry) []error {
	var errs []error
	report := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: "+format, append([]any{e.ID}, args...)...))
	}

	if e.ID == "" || e.Algorithm == "" || e.Params == "" {
		report("id, algorithm and params are required")
	}
	if len(e.Primitives) == 0 {
		report("no primitives")
	}
	for _, p := range e.Primitives {
		if !model.ValidPrimitive(p) {
			report("unknown primitive %q", p)
		}
	}
	if !model.ValidQuantum(e.Quantum) {
		report("unknown quantum status %q", e.Quantum)
	}
	if e.ClassicalBits < 0 {
		report("negative classical_bits")
	}
	if e.SecurityCategory < 0 || e.SecurityCategory > 5 {
		report("security_category %d outside 0..5", e.SecurityCategory)
	}
	if len(e.Sources) == 0 {
		report("no sources")
	}
	for _, s := range e.Sources {
		if _, ok := db.sources[s]; !ok {
			report("unknown source %q", s)
		}
	}

	needsReplacement := e.Quantum == model.QuantumVulnerable || e.Quantum == model.QuantumBrokenNow
	if needsReplacement {
		for _, p := range e.Primitives {
			if _, ok := e.Replacement[p]; !ok {
				report("no replacement for primitive %q", p)
			}
		}
	}
	for p, r := range e.Replacement {
		if !slices.Contains(e.Primitives, p) {
			report("replacement for unused primitive %q", p)
		}
		for _, target := range []string{r.Civilian, r.CNSA2} {
			t, ok := db.ByID(target)
			if !ok {
				report("replacement %q is not an entry", target)
				continue
			}
			if t.Quantum == model.QuantumVulnerable || t.Quantum == model.QuantumBrokenNow {
				report("replacement %q is itself %s", target, t.Quantum)
			}
		}
	}

	if (e.Quantum == model.QuantumHybrid) != (len(e.Components) > 0) {
		report("components must be listed exactly when quantum is hybrid")
	}
	strongest := 0
	for _, c := range e.Components {
		comp, ok := db.ByID(c)
		if !ok {
			report("component %q is not an entry", c)
			continue
		}
		strongest = max(strongest, comp.ClassicalBits)
	}
	if len(e.Components) > 0 && e.ClassicalBits != strongest {
		report("classical_bits %d is not the strongest component (%d)", e.ClassicalBits, strongest)
	}
	return errs
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Default returns the embedded database, parsed once.
var Default = sync.OnceValues(func() (*DB, error) {
	return Parse(algorithmsYAML)
})

// Version returns the database document version.
func (db *DB) Version() int { return db.version }

// Entries returns a copy of all entries in document order.
func (db *DB) Entries() []Entry { return slices.Clone(db.entries) }

// Source returns the source with the given key.
func (db *DB) Source(key string) (Source, bool) {
	s, ok := db.sources[key]
	return s, ok
}

// ByID returns the entry with the given ID, ignoring case.
func (db *DB) ByID(id string) (Entry, bool) {
	i, ok := db.byID[normalize(id)]
	if !ok {
		return Entry{}, false
	}
	return db.entries[i], true
}

// Lookup returns the entry for a canonical (algorithm, params) pair, as found
// in model.Asset, ignoring case. Params may also be an alias.
func (db *DB) Lookup(algorithm, params string) (Entry, bool) {
	for _, i := range db.byName[normalize(params)] {
		if strings.EqualFold(db.entries[i].Algorithm, algorithm) {
			return db.entries[i], true
		}
	}
	return Entry{}, false
}

// Find returns every entry matching a free-form name: an ID, params value or
// alias, ignoring case. A name can be ambiguous: "P-256" matches both ECDSA and
// ECDH, and the caller must disambiguate from context.
func (db *DB) Find(name string) []Entry {
	indexes := db.byName[normalize(name)]
	out := make([]Entry, 0, len(indexes))
	for _, i := range indexes {
		out = append(out, db.entries[i])
	}
	return out
}

// FamilyQuantum returns the quantum status shared by every entry of an
// algorithm family, for assets whose parameters are unknown. ok is false if the
// family is not in the database or its entries disagree.
func (db *DB) FamilyQuantum(algorithm string) (status string, ok bool) {
	for _, e := range db.entries {
		if !strings.EqualFold(e.Algorithm, algorithm) {
			continue
		}
		if status != "" && status != e.Quantum {
			return "", false
		}
		status = e.Quantum
	}
	return status, status != ""
}
