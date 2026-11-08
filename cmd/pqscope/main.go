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

// Exit codes. A failed policy gate is distinct from an error, so CI can tell
// "found disallowed crypto" from "could not run".
const (
	exitPolicyFailed = 1
	exitError        = 2
)

func main() {
	os.Exit(exitCode(newRootCmd().Execute()))
}

func exitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errPolicyFailed):
		return exitPolicyFailed
	default:
		return exitError
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "pqscope",
		Short:         "Multi-layer post-quantum cryptography readiness scanner",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(newVersionCmd(), newScanCmd(), newReportCmd(), newPolicyCmd(), newNetCmd(), newEvalCmd(), newBenchCmd(), newMeasureCmd())
	return root
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
