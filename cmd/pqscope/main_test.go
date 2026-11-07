package main

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
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

func TestStubsFailRatherThanReportCleanScan(t *testing.T) {
	tests := []struct {
		args []string
	}{
		{[]string{"scan", "."}},
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
