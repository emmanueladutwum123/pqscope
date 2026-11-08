package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/schemas"
	"github.com/emmanueladutwum123/pqscope/internal/testkeys"
)

// The milestone 5 acceptance test: scanning private keys, in every output
// format pqscope has, never emits private key material.
func TestNoPrivateKeyBytesInAnyOutput(t *testing.T) {
	set, err := testkeys.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	paths := map[string]string{
		"cbom": filepath.Join(out, "cbom.json"), "sarif": filepath.Join(out, "out.sarif"),
		"html": filepath.Join(out, "report.html"), "json": filepath.Join(out, "findings.json"),
	}
	text, err := execute("scan", "-o", paths["cbom"], "--sarif", paths["sarif"], "--html", paths["html"], set.Dir)
	if err != nil {
		t.Fatal(err)
	}
	jsonOut, err := execute("scan", "--json", set.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths["json"], []byte(jsonOut), 0o644); err != nil {
		t.Fatal(err)
	}
	reportOut, err := execute("report", paths["json"])
	if err != nil {
		t.Fatal(err)
	}
	policyOut, _ := execute("policy", "--json", "--policy", "nist-ir-8547-2026", "--policy", "cnsa-2.0", paths["cbom"])

	outputs := map[string]string{"text": text, "json": jsonOut, "report": reportOut, "policy": policyOut}
	for name, p := range paths {
		outputs[name] = string(readFile(t, p))
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(jsonOut), &findings); err != nil {
		t.Fatal(err)
	}
	private := 0
	for _, f := range findings {
		if strings.Contains(f.Location.Symbol, "private-key") {
			private++
		}
	}
	if private < 8 {
		t.Fatalf("only %d private-key findings; the test would prove little", private)
	}
	for name, content := range outputs {
		for _, secret := range set.Secrets {
			if strings.Contains(content, secret) {
				t.Errorf("%s output contains private key material: %.40s…", name, secret)
			}
		}
		if strings.Contains(content, "PRIVATE KEY-----") {
			t.Errorf("%s output contains a PEM private key header", name)
		}
	}
	if err := schemas.ValidateCycloneDX([]byte(outputs["cbom"])); err != nil {
		t.Errorf("CBOM with key material does not validate: %v", err)
	}
	if err := schemas.ValidateSARIF([]byte(outputs["sarif"])); err != nil {
		t.Errorf("SARIF with key material does not validate: %v", err)
	}
	if !strings.Contains(text, "Not classified:") || !strings.Contains(text, "encrypted PKCS#8") {
		t.Errorf("text output should list the encrypted PKCS#8 key as not classified:\n%s", text)
	}
}

func TestScanAllLayers(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	out, err := execute("scan", "--json", filepath.Join(root, "config"), "--layers", "config")
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Location.Layer != model.LayerConfig || len(f.Policy) != 2 || f.Risk == 0 && f.Asset.Quantum != "safe" {
			t.Errorf("%s:%d: layer %s policy %v risk %v", f.Location.Path, f.Location.Line, f.Location.Layer, f.Policy, f.Risk)
		}
	}
	if len(findings) < 40 {
		t.Errorf("only %d config findings", len(findings))
	}

	text, err := execute("scan", filepath.Join(root, "deps"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"go/go.mod:5", "deps", "files scanned, 1 skipped"} {
		if !strings.Contains(text, want) {
			t.Errorf("deps scan output missing %q:\n%s", want, text)
		}
	}

	if _, err := execute("scan", "--layers", "network", root); err == nil || !strings.Contains(err.Error(), "unsupported layer") {
		t.Errorf("unsupported layer: err = %v", err)
	}
}

// Dependency findings are capabilities: listed by the gate, but not failing
// it unless --include-deps is set.
func TestPolicyIncludeDeps(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("cryptography==47.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bom := filepath.Join(t.TempDir(), "cbom.json")
	if _, err := execute("scan", "-o", bom, dir); err != nil {
		t.Fatal(err)
	}
	saved, err := execute("scan", "--json", dir)
	if err != nil {
		t.Fatal(err)
	}
	findingsPath := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(findingsPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{bom, findingsPath} {
		out, err := execute("policy", input)
		if err != nil {
			t.Errorf("%s: deps-only assets failed the default gate: %v\n%s", filepath.Base(input), err, out)
		}
		if !strings.Contains(out, " deps ") || !strings.Contains(out, "only provided by dependencies") {
			t.Errorf("%s: output should mark deps-only assets:\n%s", filepath.Base(input), out)
		}
		if _, err := execute("policy", "--include-deps", input); err == nil {
			t.Errorf("%s: --include-deps should fail on cryptography 47's RSA", filepath.Base(input))
		}
	}
}

func TestScanBinaries(t *testing.T) {
	out, err := execute("scan", "--json", "--layers", "binary", filepath.Join("..", "..", "testdata", "binaries"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatal(err)
	}
	formats := map[string]bool{}
	for _, f := range findings {
		if f.Location.Layer != model.LayerBinary || len(f.Policy) != 2 {
			t.Errorf("%s %s: layer %s policy %v", f.Location.Path, f.Location.Symbol, f.Location.Layer, f.Policy)
		}
		if f.Location.Symbol == "import:RSA_generate_key_ex" {
			formats[f.Location.Path] = true
		}
	}
	if len(formats) != 3 {
		t.Errorf("RSA imports found in %v, want ELF, PE and Mach-O", formats)
	}
	text, err := execute("scan", "--layers", "binary", filepath.Join("..", "..", "testdata", "binaries"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "EVP_PKEY_encapsulate; the algorithm is chosen at run time") {
		t.Errorf("generic imports should be listed as not classified:\n%s", text)
	}
}
