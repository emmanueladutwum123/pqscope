package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/cbom"
	"github.com/emmanueladutwum123/pqscope/internal/discover/network"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/reconcile"
	"github.com/emmanueladutwum123/pqscope/internal/sarif"
	"github.com/emmanueladutwum123/pqscope/internal/schemas"
)

// reconcileFixture copies testdata/reconcile/app with a binary, and writes
// network findings as `pqscope net --findings` would.
func reconcileFixture(t *testing.T) (dir, netPath string) {
	t.Helper()
	dir = t.TempDir()
	src := filepath.Join("..", "..", "testdata", "reconcile", "app")
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.WriteFile(filepath.Join(dir, e.Name()), readFile(t, filepath.Join(src, e.Name())), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "server"), readFile(t, filepath.Join("..", "..", "testdata", "binaries", "crypto-elf")), 0o755); err != nil {
		t.Fatal(err)
	}

	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, prim, target, symbol string) model.Finding {
		e, _ := db.ByID(id)
		a, err := e.Asset(prim)
		if err != nil {
			t.Fatal(err)
		}
		f := model.NewFinding(a, model.Location{Layer: model.LayerNetwork, Path: target, Symbol: symbol}, network.NegotiatedConfidence)
		f.RuleID = "network.tls"
		return f
	}
	data, err := json.Marshal([]model.Finding{
		mk("X25519", "key-agreement", "app.example:443", "tls:negotiated-group"),
		mk("mlkem768x25519-sha256", "kem", "app.example:22", "ssh:kex"),
	})
	if err != nil {
		t.Fatal(err)
	}
	netPath = filepath.Join(t.TempDir(), "net.json")
	if err := os.WriteFile(netPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, netPath
}

// The milestone 8 acceptance test end to end: every derived type from a scan
// of the crafted fixture plus network findings, in every output format.
func TestScanReconciles(t *testing.T) {
	dir, netPath := reconcileFixture(t)
	out := t.TempDir()
	bomPath, sarifPath, htmlPath := filepath.Join(out, "c.json"), filepath.Join(out, "s.sarif"), filepath.Join(out, "r.html")
	jsonOut, err := execute("scan", "--json", "--with", netPath, "-o", bomPath, "--sarif", sarifPath, "--html", htmlPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(jsonOut), &findings); err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, f := range findings {
		if f.Derived != "" {
			types[f.Derived]++
			if len(f.Policy) != 2 || f.Risk == 0 {
				t.Errorf("%s: derived findings get policy and risk too: %+v %v", f.Derived, f.Policy, f.Risk)
			}
		}
	}
	for typ := range reconcile.Types {
		if types[typ] == 0 {
			t.Errorf("no %s finding (got %v)", typ, types)
		}
	}

	text, err := execute("scan", "--with", netPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RECONCILIATION", "declared-pqc-deployed-classical  app.example:443", "stale-dependency", "Flagged for review:", "derived by reconciliation"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q", want)
		}
	}

	bomData := readFile(t, bomPath)
	if err := schemas.ValidateCycloneDX(bomData); err != nil {
		t.Errorf("CBOM: %v", err)
	}
	var bom cbom.BOM
	_ = json.Unmarshal(bomData, &bom)
	for _, c := range bom.Components {
		for _, o := range c.Evidence.Occurrences {
			if strings.Contains(o.Location, "reconcile") {
				t.Errorf("derived finding in CBOM: %+v", o)
			}
		}
	}
	sarifData := readFile(t, sarifPath)
	if err := schemas.ValidateSARIF(sarifData); err != nil {
		t.Errorf("SARIF: %v", err)
	}
	var log sarif.Log
	_ = json.Unmarshal(sarifData, &log)
	ruleIDs := []string{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		ruleIDs = append(ruleIDs, r.ID)
		if strings.HasPrefix(r.ID, "reconcile.") && strings.HasPrefix(r.ShortDescription.Text, "pqscope rule") {
			t.Errorf("%s has no description", r.ID)
		}
	}
	if !slices.Contains(ruleIDs, "reconcile.config-overrides-library") {
		t.Errorf("SARIF rules = %v", ruleIDs)
	}
	if html := string(readFile(t, htmlPath)); !strings.Contains(html, "<h2>Reconciliation</h2>") || !strings.Contains(html, "<h2>Flagged for review</h2>") {
		t.Error("HTML report lacks the reconciliation sections")
	}

	// --no-reconcile turns it off.
	plain, err := execute("scan", "--json", "--no-reconcile", "--with", netPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, `"derived"`) || strings.Contains(plain, `"review"`) {
		t.Error("--no-reconcile still reconciled")
	}
}

func TestScanComponents(t *testing.T) {
	dir, netPath := reconcileFixture(t)
	comps := filepath.Join(t.TempDir(), "components.yaml")
	// The endpoints belong to another component, so nothing links them to
	// the project's declaration or configuration.
	if err := os.WriteFile(comps, []byte("components:\n  - {name: app, paths: [.]}\n  - {name: edge, hosts: [app.example]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := execute("scan", "--json", "--with", netPath, "--components", comps, dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, reconcile.DeclaredPQCDeployedClassical) || strings.Contains(out, `"review"`) {
		t.Error("findings in different components were linked")
	}
	if !strings.Contains(out, reconcile.StaleDependency) {
		t.Error("in-component derivations should remain")
	}
	if err := os.WriteFile(comps, []byte("components: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := execute("scan", "--components", comps, dir); err == nil {
		t.Error("empty components file accepted")
	}
}
