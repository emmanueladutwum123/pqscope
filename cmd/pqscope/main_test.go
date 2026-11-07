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

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

func execute(args ...string) (string, error) {
	cmd := newRootCmd()
	var out bytes.Buffer
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
		{[]string{"net", "--targets", "hosts.txt"}},
		{[]string{"bench"}},
		{[]string{"policy", "--policy", "nist-ir-8547-2026", "cbom.json"}},
		{[]string{"report"}},
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
