//go:build integration

package bench

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// End to end on loopback TCP, with one iteration per operation: every CSV is
// written and every size agrees with the knowledge DB.
func TestRunQuick(t *testing.T) {
	runs := t.TempDir()
	rep, err := Run(context.Background(), Options{Primitives: Quick, TLS: Quick, Runs: runs})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Primitives) != 3*len(Primitives()) {
		t.Errorf("%d primitive results, want %d", len(rep.Primitives), 3*len(Primitives()))
	}
	if len(rep.TLS) != 2*len(TLSClients) {
		t.Errorf("%d TLS results, want %d", len(rep.TLS), 2*len(TLSClients))
	}
	notRun := 0
	for _, e := range rep.Env {
		if e.Key == "status" {
			notRun++
		}
	}
	if notRun != 2 {
		t.Errorf("OpenSSL and netem should both be recorded as not run: %+v", rep.Env)
	}
	out := t.TempDir()
	if err := WriteCSVs(rep, out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rq4_primitives.csv", "rq4_sizes.csv", "rq4_tls.csv", "rq4_environment.csv"} {
		if fi, err := os.Stat(filepath.Join(out, name)); err != nil || fi.Size() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
}
