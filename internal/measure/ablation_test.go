package measure

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/risk"
)

func TestComparePairs(t *testing.T) {
	tests := []struct {
		name                           string
		x, y                           []float64
		ordered, reversed, tied, split int64
		tau                            float64
		tauOK                          bool
	}{
		{"same", []float64{3, 2, 1}, []float64{3, 2, 1}, 3, 0, 0, 0, 1, true},
		{"reversed", []float64{3, 2, 1}, []float64{1, 2, 3}, 3, 3, 0, 0, -1, true},
		{"tied away", []float64{3, 2, 1}, []float64{1, 1, 1}, 3, 0, 3, 0, 0, false},
		{"split", []float64{1, 1}, []float64{2, 1}, 0, 0, 0, 1, 0, false},
		{"one swap", []float64{4, 3, 2, 1}, []float64{4, 2, 3, 1}, 6, 1, 0, 0, 4.0 / 6, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := comparePairs(tt.x, tt.y)
			if c.ordered != tt.ordered || c.reversed != tt.reversed || c.tied != tt.tied || c.split != tt.split {
				t.Errorf("got ordered %d reversed %d tied %d split %d", c.ordered, c.reversed, c.tied, c.split)
			}
			tau, ok := c.tauB()
			if ok != tt.tauOK || (ok && math.Abs(tau-tt.tau) > 1e-9) {
				t.Errorf("tau-b = %v, %v; want %v, %v", tau, ok, tt.tau, tt.tauOK)
			}
		})
	}
}

func TestSameTop(t *testing.T) {
	if !sameTop([]float64{1, 3, 3}, []float64{0, 5, 5}) {
		t.Error("same top set reported as changed")
	}
	if sameTop([]float64{1, 3, 3}, []float64{0, 5, 4}) {
		t.Error("smaller top set reported as the same")
	}
}

func finding(layer model.Layer, path, primitive string, conf float64) model.Finding {
	return model.Finding{
		Asset:      model.Asset{Primitive: primitive, Algorithm: "RSA", Quantum: model.QuantumVulnerable},
		Location:   model.Location{Layer: layer, Path: path},
		Confidence: conf,
	}
}

func TestAblateRisk(t *testing.T) {
	w, err := risk.Default()
	if err != nil {
		t.Fatal(err)
	}
	// A network-facing signature outranks a key agreement in test code, until
	// exposure is removed: then the key agreement's longer secrecy lifetime
	// puts it first.
	projects := map[string][]model.Finding{
		"a/b": {
			finding(model.LayerConfig, "nginx.conf", model.PrimitiveSignature, 1),
			finding(model.LayerSource, "test/x.go", model.PrimitiveKeyAgreement, 1),
			{Derived: "stale-dependency", Asset: model.Asset{Primitive: model.PrimitiveKEM, Quantum: model.QuantumVulnerable}, Confidence: 1},
		},
		"c/d": {finding(model.LayerSource, "main.go", model.PrimitiveSignature, 1)}, // one finding: left out
	}
	rows := AblateRisk(projects, w)
	if len(rows) != len(Ablations) {
		t.Fatalf("got %d rows, want %d", len(rows), len(Ablations))
	}
	byName := map[string]AblationRow{}
	for _, r := range rows {
		byName[r.Config] = r
		if r.Projects != 1 || r.Findings != 2 || r.Ordered != 1 {
			t.Errorf("%s: projects %d findings %d ordered %d; want 1, 2, 1 (derived and single-finding projects left out)", r.Config, r.Projects, r.Findings, r.Ordered)
		}
	}
	if r := byName["all factors"]; r.Reversed != 0 || r.Tied != 0 || r.TopChanged != 0 || r.TauB != 1 {
		t.Errorf("full score against itself: %+v", r)
	}
	if r := byName["without exposure"]; r.Reversed != 1 || r.TopChanged != 1 || r.TauB != -1 {
		t.Errorf("without exposure: %+v, want the pair reversed", r)
	}
	if r := byName["without confidence"]; r.Reversed != 0 || r.TopChanged != 0 {
		t.Errorf("without confidence: %+v, want no change at confidence 1", r)
	}
}

func TestReadFindingsArchive(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "findings.tar.gz")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	add := func(name string, v any) {
		data, _ := json.Marshal(v)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add("findings/owner__repo-name.json", []model.Finding{finding(model.LayerSource, "a.go", model.PrimitiveSignature, 0.9)})
	add("findings/._owner__repo-name.json", "macOS metadata, skipped")
	add("findings/notes.txt", "skipped")
	for _, c := range []interface{ Close() error }{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadFindingsArchive(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got["owner/repo-name"]) != 1 {
		t.Fatalf("got %v, want one project owner/repo-name with one finding", got)
	}
}
