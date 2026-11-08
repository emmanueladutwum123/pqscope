// Command pqscope scans a system for quantum-vulnerable cryptography.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// errNotImplemented is returned by commands that do not exist yet, so that a
// script can never mistake a stub for a clean scan.
var errNotImplemented = errors.New("not implemented")

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pqscope",
		Short:         "Multi-layer post-quantum cryptography readiness scanner",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd(), newScanCmd(), newReportCmd())
	for _, stub := range []struct {
		name, short string
		milestone   int
	}{
		{"policy", "Evaluate a CBOM against a policy", 4},
		{"net", "Probe network endpoints for negotiated key exchange", 6},
		{"eval", "Run the evaluation harness", 10},
		{"bench", "Run migration-cost benchmarks", 11},
	} {
		root.AddCommand(newStubCmd(stub.name, stub.short, stub.milestone))
	}
	return root
}

func newStubCmd(name, short string, milestone int) *cobra.Command {
	return &cobra.Command{
		Use:                name,
		Short:              fmt.Sprintf("%s (not implemented yet)", short),
		DisableFlagParsing: true,
		RunE: func(*cobra.Command, []string) error {
			return fmt.Errorf("%s: %w (planned for milestone %d)", name, errNotImplemented, milestone)
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout())
		},
	}
}

func writeVersion(w io.Writer) error {
	_, err := fmt.Fprintf(w, "pqscope %s (%s, %s, %s/%s)\n",
		version, revision(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return err
}

// revision returns the VCS commit embedded by the Go toolchain, if any.
func revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	rev, dirty := "unknown", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
			if len(rev) > 12 {
				rev = rev[:12]
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}
