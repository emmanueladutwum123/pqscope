package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/bench"
)

func newBenchCmd() *cobra.Command {
	var runs, out, rev string
	var quick bool
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Run migration-cost benchmarks",
		Long: "Measure keygen, encapsulation, decapsulation, signing and verification latency\n" +
			"(mean, p50, p99) and wire sizes for classical and post-quantum primitives, and\n" +
			"TLS 1.3 ClientHello size and handshake latency for classical, hybrid and Go\n" +
			"default clients on loopback. Merges the OpenSSL size cross-check and the tc\n" +
			"netem TLS runs that bench/run.sh left under --runs, then writes\n" +
			"rq4_primitives.csv, rq4_sizes.csv, rq4_tls.csv and rq4_environment.csv to --out.\n\n" +
			"Exits non-zero if any measured size disagrees with the knowledge DB or OpenSSL.\n" +
			"`make bench` runs bench/run.sh, then this. A full run takes several minutes;\n" +
			"close other programs first, since the machine's load is in the numbers.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := bench.Options{
				Primitives: bench.Default,
				TLS:        bench.TLSLoopback,
				Runs:       runs,
				Extra:      map[string]string{"pqscope_revision": rev, "pqscope_version": version},
				Progress:   cmd.ErrOrStderr(),
			}
			if rev == "" {
				opts.Extra["pqscope_revision"] = revision()
			}
			if quick {
				opts.Primitives, opts.TLS = bench.Quick, bench.Quick
				opts.Extra["mode"] = "quick (one iteration per operation; not for publication)"
			}
			rep, runErr := bench.Run(cmd.Context(), opts)
			if rep == nil {
				return runErr
			}
			if err := bench.WriteCSVs(rep, out); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			for _, r := range rep.Primitives {
				_, _ = fmt.Fprintf(w, "%-16s %-9s %-7s p50=%12s p99=%12s n=%d\n", r.Algorithm, r.Impl, r.Op, dur(r.P50), dur(r.P99), r.N)
			}
			for _, r := range rep.TLS {
				if r.Op == bench.OpHandshake {
					_, _ = fmt.Fprintf(w, "tls %-12s %-14s %-22s %-16s CH=%dB p50=%s p99=%s\n", r.Env, r.Profile.Name, r.Client, r.Group, r.ClientHelloBytes, dur(r.P50), dur(r.P99))
				}
			}
			_, _ = fmt.Fprintf(w, "wrote %s/rq4_*.csv\n", out)
			return runErr
		},
	}
	cmd.Flags().StringVar(&runs, "runs", "bench/out", "bench/run.sh output `dir` (OpenSSL sizes, netem runs); empty to skip")
	cmd.Flags().StringVar(&out, "out", "paper/data", "output `dir` for CSVs")
	cmd.Flags().StringVar(&rev, "revision", "", "revision to record (default: from build info)")
	cmd.Flags().BoolVar(&quick, "quick", false, "one iteration per operation, to check the pipeline")
	return cmd
}

// dur formats nanoseconds for the terminal summary; the CSVs keep raw ns.
func dur(ns int64) string {
	switch {
	case ns >= 1e9:
		return fmt.Sprintf("%.2fs", float64(ns)/1e9)
	case ns >= 1e6:
		return fmt.Sprintf("%.2fms", float64(ns)/1e6)
	default:
		return fmt.Sprintf("%.1fµs", float64(ns)/1e3)
	}
}
