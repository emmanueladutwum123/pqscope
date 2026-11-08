package model

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func validFinding() Finding {
	return NewFinding(
		Asset{Primitive: PrimitiveSignature, Algorithm: "RSA", Params: "2048", ClassicalBits: 112, Quantum: QuantumVulnerable},
		Location{Layer: LayerSource, Path: "main.go", Line: 12, Symbol: "rsa.GenerateKey"},
		0.95,
	)
}

func TestComputeIDGolden(t *testing.T) {
	// Pins the encoding: changing this value invalidates every stored finding ID.
	const want = "6eb3d2e434dcc963522fede8aab71ca4"
	f := validFinding()
	if f.ID != want {
		t.Fatalf("ComputeID = %q, want %q", f.ID, want)
	}
}

func TestComputeIDIgnoresKnowledgeFields(t *testing.T) {
	f := validFinding()
	a := f.Asset
	a.ClassicalBits = 128
	a.Quantum = QuantumBrokenNow
	if got := ComputeID(a, f.Location); got != f.ID {
		t.Errorf("ID changed with knowledge-derived fields: %q != %q", got, f.ID)
	}
}

func TestComputeIDDistinguishes(t *testing.T) {
	base := validFinding()
	tests := []struct {
		name   string
		mutate func(*Asset, *Location)
	}{
		{"primitive", func(a *Asset, _ *Location) { a.Primitive = PrimitivePKE }},
		{"algorithm", func(a *Asset, _ *Location) { a.Algorithm = "ECDSA" }},
		{"params", func(a *Asset, _ *Location) { a.Params = "3072" }},
		{"layer", func(_ *Asset, l *Location) { l.Layer = LayerBinary }},
		{"path", func(_ *Asset, l *Location) { l.Path = "other.go" }},
		{"line", func(_ *Asset, l *Location) { l.Line = 13 }},
		{"symbol", func(_ *Asset, l *Location) { l.Symbol = "rsa.SignPSS" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, l := base.Asset, base.Location
			tt.mutate(&a, &l)
			if ComputeID(a, l) == base.ID {
				t.Error("ID did not change")
			}
		})
	}
}

func TestComputeIDFieldBoundaries(t *testing.T) {
	a1 := Asset{Algorithm: "AB", Params: "C"}
	a2 := Asset{Algorithm: "A", Params: "BC"}
	if ComputeID(a1, Location{}) == ComputeID(a2, Location{}) {
		t.Error("IDs collide across a field boundary")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Finding)
		wantErr string
	}{
		{"valid", func(*Finding) {}, ""},
		{"confidence zero", func(f *Finding) { f.Confidence = 0 }, ""},
		{"confidence one", func(f *Finding) { f.Confidence = 1 }, ""},
		{"confidence high", func(f *Finding) { f.Confidence = 1.01 }, "confidence"},
		{"confidence negative", func(f *Finding) { f.Confidence = -0.01 }, "confidence"},
		{"confidence NaN", func(f *Finding) { f.Confidence = math.NaN() }, "confidence"},
		{"stale id", func(f *Finding) { f.ID = "stale" }, "does not match"},
		{"bad primitive", func(f *Finding) { f.Asset.Primitive = "magic"; f.ID = ComputeID(f.Asset, f.Location) }, "primitive"},
		{"empty algorithm", func(f *Finding) { f.Asset.Algorithm = ""; f.ID = ComputeID(f.Asset, f.Location) }, "algorithm"},
		{"bad quantum", func(f *Finding) { f.Asset.Quantum = "maybe" }, "quantum"},
		{"bad layer", func(f *Finding) { f.Location.Layer = "cloud"; f.ID = ComputeID(f.Asset, f.Location) }, "layer"},
		{"empty path", func(f *Finding) { f.Location.Path = ""; f.ID = ComputeID(f.Asset, f.Location) }, "path"},
		{"negative line", func(f *Finding) { f.Location.Line = -1; f.ID = ComputeID(f.Asset, f.Location) }, "line"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			tt.mutate(&f)
			err := f.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	f := validFinding()
	f.Evidence = "rsa.GenerateKey(rand.Reader, 2048)"
	f.RuleID = "go.rsa.generate"
	f.Policy = []PolicyResult{{Policy: "nist-ir-8547-2026", Status: PolicyDeprecated}}
	f.Risk = 0.5
	f.LinkedIDs = []string{"abc"}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var got Finding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, f) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, f)
	}
}

func TestPolicySeverity(t *testing.T) {
	order := []string{PolicyCompliant, PolicyDisallowed, PolicyDeprecated, PolicyDisallowedNow, PolicyBrokenNow}
	for i, s := range order {
		if !ValidPolicyStatus(s) || PolicySeverity(s) != i {
			t.Errorf("%s: valid=%v severity=%d, want %d", s, ValidPolicyStatus(s), PolicySeverity(s), i)
		}
	}
	if PolicySeverity(PolicyUnknown) != -1 || !ValidPolicyStatus(PolicyUnknown) || ValidPolicyStatus("maybe") || PolicySeverity("maybe") != -1 {
		t.Error("unknown handling")
	}
}
