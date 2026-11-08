package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// TestMain lets tests run the real main, exit code included, by re-executing
// the test binary with PQSCOPE_RUN_MAIN set.
func TestMain(m *testing.M) {
	if os.Getenv("PQSCOPE_RUN_MAIN") == "1" {
		os.Args = append([]string{"pqscope"}, os.Args[1:]...)
		main()
		return
	}
	os.Exit(m.Run())
}

// run executes pqscope as a subprocess and returns its stdout, stderr and
// exit code.
func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "PQSCOPE_RUN_MAIN=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), code
}

func fixture(name string) string {
	return filepath.Join("..", "..", "testdata", "policy", name)
}

// The CI gate: scan to a CBOM or to findings JSON, then gate on it.
func TestPolicyGateExitCodes(t *testing.T) {
	tests := []struct {
		fixture  string
		args     []string
		wantCode int
		wantOut  string
	}{
		{"pq-only", nil, 0, "PASS: 0 of 2 assets at or above disallowed-2035"},
		{"pq-only", []string{"--policy", "cnsa-2.0"}, 0, "PASS"},
		{"hybrid", nil, 0, "PASS"},
		{"hybrid", []string{"--policy", "cnsa-2.0"}, 1, "X25519MLKEM768  kem        disallowed-now  1         FAIL"},
		{"classical", nil, 1, "RSA-2048  signature  deprecated-2030  1         FAIL  Deprecated after 2030; disallowed after 2035"},
		{"classical", []string{"--fail-on", "disallowed-now"}, 0, "PASS: 0 of 1 assets at or above disallowed-now"},
		{"classical", []string{"--policy", "nist-ir-8547-2026", "--policy", "cnsa-2.0", "--fail-on", "disallowed-now"}, 1, "cnsa-2.0: CNSA 2.0"},
	}
	for _, tt := range tests {
		for _, input := range []string{"cbom", "findings"} {
			name := tt.fixture + "/" + input + "/" + strings.Join(tt.args, " ")
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				path := filepath.Join(dir, "in.json")
				scanArgs := []string{"scan", "-o", path, fixture(tt.fixture)}
				if input == "findings" {
					scanArgs = []string{"scan", "--json", fixture(tt.fixture)}
				}
				out, stderr, code := run(t, scanArgs...)
				if code != 0 {
					t.Fatalf("scan exit %d: %s", code, stderr)
				}
				if input == "findings" {
					if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				out, stderr, code = run(t, append(append([]string{"policy"}, tt.args...), path)...)
				if code != tt.wantCode {
					t.Errorf("exit code %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.wantCode, out, stderr)
				}
				if !strings.Contains(out, tt.wantOut) {
					t.Errorf("stdout missing %q:\n%s", tt.wantOut, out)
				}
				if tt.wantCode == 1 && !strings.Contains(stderr, "policy gate failed") {
					t.Errorf("stderr = %q, want the gate failure", stderr)
				}
			})
		}
	}
}

func TestPolicyErrorsExitTwo(t *testing.T) {
	dir := t.TempDir()
	findings := filepath.Join(dir, "f.json")
	if err := os.WriteFile(findings, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		args    []string
		wantErr string
	}{
		{[]string{"policy", filepath.Join(dir, "missing.json")}, "no such file"},
		{[]string{"policy", "--policy", "pci-dss", findings}, "bundled policies: cnsa-2.0, nist-ir-8547-2026"},
		{[]string{"policy", "--fail-on", "compliant", findings}, "--fail-on"},
		{[]string{"policy"}, "accepts 1 arg"},
		{[]string{"eval"}, "not implemented"},
	}
	for _, tt := range tests {
		_, stderr, code := run(t, tt.args...)
		if code != exitError || !strings.Contains(stderr, tt.wantErr) {
			t.Errorf("%v: exit %d stderr %q, want exit %d mentioning %q", tt.args, code, stderr, exitError, tt.wantErr)
		}
	}
	if out, _, code := run(t, "policy", findings); code != 0 || !strings.Contains(out, "PASS: 0 of 0 assets") {
		t.Errorf("empty findings: exit %d, out %q", code, out)
	}
}

func TestPolicyJSONAndUnknown(t *testing.T) {
	dir := t.TempDir()
	unknown := model.NewFinding(model.Asset{Primitive: "signature", Algorithm: "RSA", Params: model.ParamsUnknown, Quantum: "vulnerable"},
		model.Location{Layer: model.LayerSource, Path: "a.go", Line: 1}, 0.76)
	data, _ := json.Marshal([]model.Finding{unknown})
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := execute("policy", path)
	if !errors.Is(err, errPolicyFailed) || !strings.Contains(out, "unknown (at best deprecated-2030)") {
		t.Errorf("unknown RSA should fail the default gate: err %v\n%s", err, out)
	}

	out, err = execute("policy", "--json", "--fail-on", "disallowed-now", path)
	if err != nil {
		t.Fatalf("unknown RSA is at best deprecated-2030, below disallowed-now: %v", err)
	}
	var verdicts []verdict
	if err := json.Unmarshal([]byte(out), &verdicts); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(verdicts) != 1 || verdicts[0].Result.Status != "unknown" || verdicts[0].Result.AtBest != "deprecated-2030" || verdicts[0].Fails || verdicts[0].Name != "RSA" {
		t.Errorf("verdicts = %+v", verdicts)
	}
}

// Policy input can come from standard input.
func TestPolicyStdin(t *testing.T) {
	saved, err := execute("scan", "--json", fixture("classical"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := executeIn(strings.NewReader(saved), "policy", "-")
	if !errors.Is(err, errPolicyFailed) || !strings.Contains(out, "RSA-2048") {
		t.Errorf("err %v, out %q", err, out)
	}
}

func TestExitCode(t *testing.T) {
	if exitCode(nil) != 0 || exitCode(errPolicyFailed) != 1 || exitCode(errNotImplemented) != 2 {
		t.Error("exit code mapping")
	}
}

// scan fills policy results and risk on every finding.
func TestScanAnnotates(t *testing.T) {
	out, err := execute("scan", "--json", fixture("classical"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []model.Finding
	if err := json.Unmarshal([]byte(out), &findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	f := findings[0]
	if len(f.Policy) != 2 || f.Policy[0].Policy != "nist-ir-8547-2026" || f.Policy[0].Status != "deprecated-2030" ||
		f.Policy[1].Policy != "cnsa-2.0" || f.Policy[1].Status != "disallowed-now" {
		t.Errorf("policy = %+v", f.Policy)
	}
	// internal exposure 0.6 × signature 0.5 × vulnerable 0.9 × confidence 0.95
	if f.Risk != 0.257 {
		t.Errorf("risk = %v, want 0.257", f.Risk)
	}
	if err := f.Validate(); err != nil {
		t.Error(err)
	}
}
