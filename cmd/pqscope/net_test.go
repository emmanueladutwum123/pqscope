package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/discover/network"
)

// These tests open no connections: every target is excluded or rejected
// before dialing. Live probing is covered by the network package's in-memory
// tests and by the Docker integration tests (go test -tags integration).
func TestNetExcludedTargets(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "hosts.txt")
	exclude := filepath.Join(dir, "exclude.txt")
	out := filepath.Join(dir, "net.jsonl")
	findings := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(targets, []byte("# test\n192.0.2.1\nssh://192.0.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exclude, []byte("192.0.2.0/24\n198.51.100.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := run(t, "net", "--targets", targets, "--exclude", exclude, "-o", out, "--findings", findings, "198.51.100.1:8443")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("records went to stdout despite -o: %q", stdout)
	}
	if !strings.Contains(stderr, "3 targets:") {
		t.Errorf("stderr = %q", stderr)
	}
	lines := strings.Split(strings.TrimSpace(string(readFile(t, out))), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d JSONL records, want 3", len(lines))
	}
	skipped := 0
	for _, l := range lines {
		var r network.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		if r.Skipped != "" {
			skipped++
		}
	}
	if skipped != 3 {
		t.Errorf("%d skipped, want all 3 targets excluded", skipped)
	}
	if got := strings.TrimSpace(string(readFile(t, findings))); got != "[]" && !strings.HasPrefix(got, "[") {
		t.Errorf("findings file = %q", got)
	}
}

func TestNetRejectsUnsafeOptions(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"net", "--retries", "3", "192.0.2.1"}, "retries"},
		{[]string{"net", "--rate", "5000", "192.0.2.1"}, "rate"},
		{[]string{"net", "--timeout", "1m", "192.0.2.1"}, "timeout"},
		{[]string{"net", "--groups", "X25519Kyber768Draft00", "192.0.2.1"}, "unknown TLS group"},
		{[]string{"net"}, "no targets"},
		{[]string{"net", "https://example.org"}, "unknown scheme"},
	}
	for _, tt := range tests {
		_, stderr, code := run(t, tt.args...)
		if code != exitError || !strings.Contains(stderr, tt.want) {
			t.Errorf("%v: exit %d, stderr %q; want exit %d mentioning %q", tt.args, code, stderr, exitError, tt.want)
		}
	}
}
