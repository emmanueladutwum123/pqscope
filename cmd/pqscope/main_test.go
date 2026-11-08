package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/cbom"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/sarif"
	"github.com/emmanueladutwum123/pqscope/internal/schemas"
)

func execute(args ...string) (string, error) {
	return executeIn(nil, args...)
}

func executeIn(stdin io.Reader, args ...string) (string, error) {
	cmd := newRootCmd()
	var out bytes.Buffer
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVersion(t *testing.T) {
	out, err := execute("version")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pqscope ", version, runtime.Version()} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not contain %q", out, want)
		}
	}
}

func TestVersionRejectsArgs(t *testing.T) {
	if _, err := execute("version", "extra"); err == nil {
		t.Error("expected an error")
	}
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	src := "package p\nimport \"crypto/rsa\"\nfunc f() { rsa.GenerateKey(nil, 2048) }\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := execute("scan", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a.go:3", "RSA", "2048", "vulnerable", "go.rsa.generate", "1 findings in 1 files scanned"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}

	out, err = execute("scan", "--json", dir)
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(findings) != 1 || findings[0].Asset.Params != "2048" {
		t.Errorf("findings = %+v", findings)
	}

	out, err = execute("scan", "--json", t.TempDir())
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Errorf("empty scan = %q, %v; want []", out, err)
	}
}

func TestScanMissingPath(t *testing.T) {
	if _, err := execute("scan", filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("expected an error")
	}
}

func TestStubsFailRatherThanReportCleanScan(t *testing.T) {
	tests := []struct {
		args []string
	}{
		{[]string{"bench"}},
		{[]string{"eval"}},
	}
	for _, tt := range tests {
		t.Run(tt.args[0], func(t *testing.T) {
			_, err := execute(tt.args...)
			if !errors.Is(err, errNotImplemented) {
				t.Fatalf("error = %v, want errNotImplemented", err)
			}
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// scanOutputs scans dir writing every output format, validates the CBOM and
// SARIF against their schemas, and returns the findings and file contents.
func scanOutputs(t *testing.T, dir string) (findings []model.Finding, bomData, sarifData, html []byte) {
	t.Helper()
	out := t.TempDir()
	bomPath, sarifPath, htmlPath := filepath.Join(out, "cbom.json"), filepath.Join(out, "out.sarif"), filepath.Join(out, "report.html")
	stdout, err := execute("scan", "--json", "-o", bomPath, "--sarif", sarifPath, "--html", htmlPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatal(err)
	}
	bomData, sarifData, html = readFile(t, bomPath), readFile(t, sarifPath), readFile(t, htmlPath)
	if err := schemas.ValidateCycloneDX(bomData); err != nil {
		t.Errorf("CBOM does not validate against CycloneDX 1.6: %v", err)
	}
	if err := schemas.ValidateSARIF(sarifData); err != nil {
		t.Errorf("SARIF does not validate against SARIF 2.1.0: %v", err)
	}
	return findings, bomData, sarifData, html
}

// The labeled corpus is the largest body of real scanner output available, so
// every output format must validate on it.
func TestScanCorpusOutputsValidate(t *testing.T) {
	findings, bomData, sarifData, html := scanOutputs(t, filepath.Join("..", "..", "testdata", "corpus"))
	if len(findings) < 50 {
		t.Fatalf("only %d findings on the corpus", len(findings))
	}

	var bom cbom.BOM
	if err := json.Unmarshal(bomData, &bom); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range bom.Components {
		for _, o := range c.Evidence.Occurrences {
			ids[o.BOMRef] = true
		}
	}
	observed := 0
	for _, f := range findings {
		if f.Derived != "" {
			continue // reconciliation results are not inventory
		}
		observed++
		if !ids[f.ID] {
			t.Errorf("finding %s (%s:%d) missing from CBOM occurrences", f.ID, f.Location.Path, f.Location.Line)
		}
	}
	if len(ids) != observed {
		t.Errorf("CBOM has %d occurrences for %d observed findings", len(ids), observed)
	}

	var log sarif.Log
	if err := json.Unmarshal(sarifData, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != len(findings) {
		t.Errorf("SARIF has %d results for %d findings", len(run.Results), len(findings))
	}
	for _, r := range run.Tool.Driver.Rules {
		if strings.HasPrefix(r.ShortDescription.Text, "pqscope rule ") || !strings.HasPrefix(r.HelpURI, "https://") {
			t.Errorf("rule %s lacks its description or citation: %+v", r.ID, r)
		}
	}
	if !bytes.Contains(html, []byte(findings[0].Location.Path)) {
		t.Error("HTML report does not mention the first finding")
	}
}

func TestReportMatchesScan(t *testing.T) {
	dir := t.TempDir()
	src := "import hashlib\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n" +
		"hashlib.md5(b'x')\nrsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
	if err := os.WriteFile(filepath.Join(dir, "a.py"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, bomData, sarifData, _ := scanOutputs(t, dir)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v", findings)
	}
	saved, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	savedPath := filepath.Join(t.TempDir(), "findings.json")
	if err := os.WriteFile(savedPath, saved, 0o644); err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{savedPath, "-"} {
		t.Run(input, func(t *testing.T) {
			out := t.TempDir()
			bomPath, sarifPath, htmlPath := filepath.Join(out, "c.json"), filepath.Join(out, "s.sarif"), filepath.Join(out, "r.html")
			stdout, err := executeIn(bytes.NewReader(saved), "report", "-o", bomPath, "--sarif", sarifPath, "--html", htmlPath, input)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"MD5", "RSA-3072", "civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87", "2 findings\n"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("report output missing %q:\n%s", want, stdout)
				}
			}
			// SARIF carries no timestamps, so it must match the scan exactly.
			if got := readFile(t, sarifPath); !bytes.Equal(got, sarifData) {
				t.Errorf("SARIF from report differs from SARIF from scan:\n%s\n---\n%s", got, sarifData)
			}
			var fromScan, fromReport cbom.BOM
			_ = json.Unmarshal(bomData, &fromScan)
			if err := json.Unmarshal(readFile(t, bomPath), &fromReport); err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(fromScan.Components)
			b, _ := json.Marshal(fromReport.Components)
			if !bytes.Equal(a, b) {
				t.Error("CBOM components from report differ from scan")
			}
			if len(readFile(t, htmlPath)) == 0 {
				t.Error("empty HTML report")
			}
		})
	}
}

func TestReportRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	good := model.NewFinding(model.Asset{Primitive: "hash", Algorithm: "MD5", Params: "MD5", Quantum: "broken-now"},
		model.Location{Layer: model.LayerSource, Path: "a.py", Line: 1}, 0.9)
	tampered := good
	tampered.Location.Line = 2
	goodJSON, _ := json.Marshal([]model.Finding{good})
	tamperedJSON, _ := json.Marshal([]model.Finding{tampered})

	tests := []struct {
		name, content, wantErr string
	}{
		{"not json", "hello", "not a pqscope findings array"},
		{"object not array", `{"id": "x"}`, "not a pqscope findings array"},
		{"unknown field", strings.Replace(string(goodJSON), `"id"`, `"bogus":1,"id"`, 1), "bogus"},
		{"id does not match", string(tamperedJSON), "does not match computed id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := execute("report", path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
	if _, err := execute("report", filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file: expected an error")
	}
	if _, err := execute("report"); err == nil {
		t.Error("no argument: expected an error")
	}
}

func TestOutputWriteFailureLeavesNoFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "missing-dir", "cbom.json")
	if _, err := execute("scan", "-o", target, t.TempDir()); err == nil {
		t.Fatal("expected an error writing into a missing directory")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("leftover files: %v", entries)
	}
}

func TestWriteFileKeepsOldContentOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := os.WriteFile(path, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := writeFile(path, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return errors.New("boom")
	})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v", err)
	}
	if got := string(readFile(t, path)); got != "previous" {
		t.Errorf("content = %q, want the previous file untouched", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}

	if err := writeFile(path, func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err }); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if got := string(readFile(t, path)); got != "new" || info.Mode().Perm() != 0o644 {
		t.Errorf("content %q mode %v after successful write", got, info.Mode().Perm())
	}
}
