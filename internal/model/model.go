// Package model defines the types shared by every pqscope package. Finding is
// the only cross-package contract: discovery layers produce []Finding and
// everything downstream consumes it.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Layer identifies where in a system a finding was discovered.
type Layer string

// Discovery layers.
const (
	LayerSource  Layer = "source"
	LayerDeps    Layer = "deps"
	LayerConfig  Layer = "config"
	LayerBinary  Layer = "binary"
	LayerNetwork Layer = "network"
)

// Valid reports whether l is a known layer.
func (l Layer) Valid() bool {
	switch l {
	case LayerSource, LayerDeps, LayerConfig, LayerBinary, LayerNetwork:
		return true
	}
	return false
}

// Values for Asset.Primitive.
const (
	PrimitiveSignature    = "signature"
	PrimitiveKEM          = "kem"
	PrimitiveKeyAgreement = "key-agreement"
	PrimitivePKE          = "pke"
	PrimitiveHash         = "hash"
	PrimitiveCipher       = "cipher"
	PrimitiveMAC          = "mac"
)

// ValidPrimitive reports whether p is a known Asset.Primitive value.
func ValidPrimitive(p string) bool {
	switch p {
	case PrimitiveSignature, PrimitiveKEM, PrimitiveKeyAgreement, PrimitivePKE,
		PrimitiveHash, PrimitiveCipher, PrimitiveMAC:
		return true
	}
	return false
}

// Values for Asset.Quantum.
const (
	QuantumVulnerable = "vulnerable" // broken by a cryptographically relevant quantum computer
	QuantumWeakened   = "weakened"   // Grover-affected symmetric primitive
	QuantumSafe       = "safe"
	QuantumHybrid     = "hybrid"
	QuantumBrokenNow  = "broken-now" // already unsafe against classical attackers
)

// ValidQuantum reports whether q is a known Asset.Quantum value.
func ValidQuantum(q string) bool {
	switch q {
	case QuantumVulnerable, QuantumWeakened, QuantumSafe, QuantumHybrid, QuantumBrokenNow:
		return true
	}
	return false
}

// ParamsUnknown is the Asset.Params value used when parameters are not
// statically visible.
const ParamsUnknown = "unknown"

// Asset describes a cryptographic algorithm in use.
type Asset struct {
	Primitive     string `json:"primitive"`
	Algorithm     string `json:"algorithm"`
	Params        string `json:"params"`
	ClassicalBits int    `json:"classical_bits"`
	Quantum       string `json:"quantum"`
}

// Location describes where an asset was observed.
type Location struct {
	Layer  Layer  `json:"layer"`
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Symbol string `json:"symbol,omitempty"`
}

// Values for PolicyResult.Status, from least to most urgent. The years name
// the NIST IR 8547 transition points. Each policy row records its exact
// schedule in PolicyResult.Schedule.
const (
	// PolicyCompliant: allowed with no scheduled end.
	PolicyCompliant = "compliant"
	// PolicyDisallowed: allowed today, disallowed after 2035.
	PolicyDisallowed = "disallowed-2035"
	// PolicyDeprecated: allowed today, with restrictions starting after 2030.
	PolicyDeprecated = "deprecated-2030"
	// PolicyDisallowedNow: not allowed today, though not broken: removed from
	// the standard, below its minimum strength, or outside the suite.
	PolicyDisallowedNow = "disallowed-now"
	// PolicyBrokenNow: insecure against classical attack today.
	PolicyBrokenNow = "broken-now"
	// PolicyUnknown: the policy can't decide, usually because params are
	// unknown and the family's rows disagree. See PolicyResult.AtBest.
	PolicyUnknown = "unknown"
)

// ValidPolicyStatus reports whether s is a known PolicyResult.Status value.
func ValidPolicyStatus(s string) bool {
	switch s {
	case PolicyCompliant, PolicyDisallowed, PolicyDeprecated, PolicyDisallowedNow, PolicyBrokenNow, PolicyUnknown:
		return true
	}
	return false
}

// PolicySeverity orders statuses from compliant (0) to broken-now (4). It
// returns -1 for unknown and any unrecognised value.
func PolicySeverity(s string) int {
	switch s {
	case PolicyCompliant:
		return 0
	case PolicyDisallowed:
		return 1
	case PolicyDeprecated:
		return 2
	case PolicyDisallowedNow:
		return 3
	case PolicyBrokenNow:
		return 4
	}
	return -1
}

// PolicyResult is one policy's verdict on a finding.
type PolicyResult struct {
	Policy   string `json:"policy"`
	Status   string `json:"status"`
	Rule     string `json:"rule,omitempty"`     // ID of the policy row that decided
	Schedule string `json:"schedule,omitempty"` // the row's transition, in the policy's words
	// AtBest is set when Status is unknown and every row the asset could match
	// agrees on a floor: the least urgent status any of them gives.
	AtBest string `json:"at_best,omitempty"`
}

// Finding is a single observation of a cryptographic asset.
type Finding struct {
	ID         string         `json:"id"`
	Asset      Asset          `json:"asset"`
	Location   Location       `json:"location"`
	Evidence   string         `json:"evidence,omitempty"`
	Confidence float64        `json:"confidence"`
	RuleID     string         `json:"rule_id,omitempty"`
	Policy     []PolicyResult `json:"policy,omitempty"`
	Risk       float64        `json:"risk,omitempty"`
	LinkedIDs  []string       `json:"linked_ids,omitempty"`
	// Derived names the reconciliation rule that produced this finding, such
	// as "stale-dependency"; empty for findings observed by a discovery layer.
	Derived string `json:"derived,omitempty"`
	// Review explains why reconciliation flagged the finding: another layer
	// contradicts it.
	Review string `json:"review,omitempty"`
}

// ComputeID returns the stable ID for an (asset, location) pair. Only fields
// that identify the observation are hashed; ClassicalBits and Quantum come from
// the knowledge DB and are excluded so that correcting a DB entry does not
// change the IDs of existing findings. Encoding as a JSON array keeps field
// boundaries unambiguous.
func ComputeID(a Asset, l Location) string {
	b, err := json.Marshal([]any{a.Primitive, a.Algorithm, a.Params, l.Layer, l.Path, l.Line, l.Symbol})
	if err != nil {
		// Strings and ints always marshal.
		panic(fmt.Sprintf("model: encoding finding identity: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// NewFinding returns a Finding with its ID set from the asset and location.
func NewFinding(a Asset, l Location, confidence float64) Finding {
	return Finding{ID: ComputeID(a, l), Asset: a, Location: l, Confidence: confidence}
}

// Validate reports every structural problem with f.
func (f Finding) Validate() error {
	var errs []error
	if want := ComputeID(f.Asset, f.Location); f.ID != want {
		errs = append(errs, fmt.Errorf("id %q does not match computed id %q", f.ID, want))
	}
	if !ValidPrimitive(f.Asset.Primitive) {
		errs = append(errs, fmt.Errorf("unknown primitive %q", f.Asset.Primitive))
	}
	if strings.TrimSpace(f.Asset.Algorithm) == "" {
		errs = append(errs, errors.New("empty algorithm"))
	}
	if !ValidQuantum(f.Asset.Quantum) {
		errs = append(errs, fmt.Errorf("unknown quantum status %q", f.Asset.Quantum))
	}
	if !f.Location.Layer.Valid() {
		errs = append(errs, fmt.Errorf("unknown layer %q", f.Location.Layer))
	}
	if strings.TrimSpace(f.Location.Path) == "" {
		errs = append(errs, errors.New("empty location path"))
	}
	if f.Location.Line < 0 {
		errs = append(errs, fmt.Errorf("negative line %d", f.Location.Line))
	}
	// Written as a negated range check so that NaN is rejected too.
	if !(f.Confidence >= 0 && f.Confidence <= 1) {
		errs = append(errs, fmt.Errorf("confidence %v outside [0,1]", f.Confidence))
	}
	return errors.Join(errs...)
}
