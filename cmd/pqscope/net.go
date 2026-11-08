package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/discover/network"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

func newNetCmd() *cobra.Command {
	var (
		targetsFile, excludeFile, outPath, findingsPath string
		groups                                          []string
		rate                                            float64
		timeout                                         time.Duration
		retries, workers                                int
		noHandshake                                     bool
	)
	cmd := &cobra.Command{
		Use:   "net [target...]",
		Short: "Probe TLS and SSH endpoints for the key exchange they negotiate",
		Long: "Probe endpoints with a TLS 1.3 ClientHello, which records the group the server\n" +
			"selects, and a full TLS handshake for the certificate chain; or, for SSH, read\n" +
			"the server's banner and KEXINIT. Nothing beyond the handshake is sent.\n\n" +
			"Targets: host, host:port, tls://host[:port] or ssh://host[:port]; port 22 means\n" +
			"SSH. Read from --targets (one per line) and the arguments.\n\n" +
			"Limits enforced on every run: at most --rate connections per second overall\n" +
			"(default 50, at most 1000), one connection at a time per host, a --timeout per\n" +
			"connection (default 5s, at most 30s), at most 2 --retries, and the --exclude\n" +
			"list, checked against host names and every resolved address. See\n" +
			"docs/scanning.md before scanning hosts you do not operate.\n\n" +
			"Writes one JSON record per target to -o (default standard output) and a\n" +
			"summary to standard error. --findings writes findings for `pqscope report`\n" +
			"and `pqscope policy`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			var targets []network.Target
			if targetsFile != "" {
				f, err := os.Open(targetsFile)
				if err != nil {
					return err
				}
				ts, err := network.ParseTargets(f)
				_ = f.Close() // read-only
				if err != nil {
					return fmt.Errorf("%s: %w", targetsFile, err)
				}
				targets = append(targets, ts...)
			}
			for _, a := range args {
				t, err := network.ParseTarget(a)
				if err != nil {
					return err
				}
				targets = append(targets, t)
			}
			if len(targets) == 0 {
				return fmt.Errorf("no targets: pass --targets or arguments")
			}
			var exclude *network.Exclude
			if excludeFile != "" {
				f, err := os.Open(excludeFile)
				if err != nil {
					return err
				}
				exclude, err = network.ParseExclude(f)
				_ = f.Close() // read-only
				if err != nil {
					return fmt.Errorf("%s: %w", excludeFile, err)
				}
			}
			db, err := knowledge.Default()
			if err != nil {
				return err
			}
			names, err := config.New(db)
			if err != nil {
				return err
			}
			p, err := network.New(db, names, network.Options{
				Groups: groups, Rate: rate, Timeout: timeout, Retries: retries, Workers: workers,
				Handshake: !noHandshake, Exclude: exclude, Version: version,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }() // closed explicitly below on success
				out = f
			}
			enc := json.NewEncoder(out)
			var all []model.Finding
			var stats netStats
			var writeErr error
			runErr := p.Run(cmd.Context(), targets, func(r network.Record) {
				stats.add(r)
				_ = annotate(db, r.Findings)
				all = append(all, r.Findings...)
				if writeErr == nil {
					writeErr = enc.Encode(r)
				}
			})
			if writeErr != nil {
				return writeErr
			}
			if f, ok := out.(*os.File); ok && f != os.Stdout {
				if err := f.Close(); err != nil {
					return err
				}
			}
			if findingsPath != "" {
				if err := writeFile(findingsPath, func(w io.Writer) error { return writeJSON(w, all) }); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), stats.String())
			return runErr
		},
	}
	f := cmd.Flags()
	f.StringVar(&targetsFile, "targets", "", "read targets from `file`, one per line")
	f.StringVar(&excludeFile, "exclude", "", "never connect to hosts, domains (.example.org), IPs or CIDRs listed in `file`")
	f.StringVarP(&outPath, "output", "o", "", "write JSONL records to `file` (default standard output)")
	f.StringVar(&findingsPath, "findings", "", "write findings as a JSON array to `file`")
	f.StringSliceVar(&groups, "groups", network.DefaultGroups, "TLS groups to offer, most preferred first; key shares go to the first two")
	f.Float64Var(&rate, "rate", network.DefaultRate, "connections per second, across all hosts (at most 1000)")
	f.DurationVar(&timeout, "timeout", network.DefaultTimeout, "timeout per connection (at most 30s)")
	f.IntVar(&retries, "retries", network.DefaultRetries, "retries after a failed connection (at most 2)")
	f.IntVar(&workers, "workers", 16, "hosts probed in parallel")
	f.BoolVar(&noHandshake, "no-handshake", false, "skip the full TLS handshake that collects certificates")
	return cmd
}

// netStats counts outcomes for the summary line.
type netStats struct {
	targets, hybrid, pq, classical, other, ssh, skipped, failed int
}

func (s *netStats) add(r network.Record) {
	s.targets++
	switch {
	case r.Skipped != "":
		s.skipped++
	case r.SSH != nil:
		if r.SSH.Error != "" {
			s.failed++
		} else {
			s.ssh++
		}
	case r.Hello != nil && r.Hello.Group != "":
		quantum := ""
		for _, f := range r.Findings {
			if strings.HasSuffix(f.Location.Symbol, "-group") {
				quantum = f.Asset.Quantum
			}
		}
		switch quantum {
		case model.QuantumHybrid:
			s.hybrid++
		case model.QuantumSafe:
			s.pq++
		default:
			s.classical++
		}
	case r.Hello != nil && r.Hello.Alert != "":
		s.other++
	default:
		s.failed++
	}
}

func (s netStats) String() string {
	return fmt.Sprintf("%d targets: %d hybrid, %d pure ML-KEM, %d classical, %d TLS alert, %d SSH, %d skipped, %d failed",
		s.targets, s.hybrid, s.pq, s.classical, s.other, s.ssh, s.skipped, s.failed)
}
