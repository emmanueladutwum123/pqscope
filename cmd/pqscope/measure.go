package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/measure"
)

func newMeasureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "measure",
		Short: "Build and analyse the paper's measurement datasets (RQ2, RQ3)",
		Long: "Prepare target lists for, and analyse the output of, the measurement runs in\n" +
			"measure/rq2.sh (federal .gov TLS endpoints) and measure/rq3.sh (critical\n" +
			"open-source projects). These subcommands read files only; the scripts do the\n" +
			"probing and cloning. See docs/measurement.md.",
	}
	cmd.AddCommand(newRQ2TargetsCmd(), newRQ2Cmd(), newRQ3SelectCmd(), newRQ3Cmd())
	return cmd
}

func readDotgov(path string) ([]measure.Domain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return measure.ParseDotgov(f)
}

// parseMeta reads repeated --meta key=value flags.
func parseMeta(kvs []string) ([][2]string, error) {
	var out [][2]string
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--meta %q: want key=value", kv)
		}
		out = append(out, [2]string{k, v})
	}
	return out, nil
}

func newRQ2TargetsCmd() *cobra.Command {
	var dotgov, out string
	cmd := &cobra.Command{
		Use:   "rq2-targets",
		Short: "Write the RQ2 targets file (apex and www of every federal .gov domain)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			domains, err := readDotgov(dotgov)
			if err != nil {
				return err
			}
			return writeFile(out, func(w io.Writer) error {
				bw := bufio.NewWriter(w)
				for _, e := range measure.RQ2Endpoints(domains) {
					if _, err := fmt.Fprintln(bw, measure.TargetLine(e.Host)); err != nil {
						return err
					}
				}
				return bw.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&dotgov, "dotgov", "", "CISA current-federal.csv `file`")
	cmd.Flags().StringVarP(&out, "output", "o", "-", "targets `file`")
	_ = cmd.MarkFlagRequired("dotgov")
	return cmd
}

func newRQ2Cmd() *cobra.Command {
	var dotgov, records, asnPath, out string
	var meta []string
	cmd := &cobra.Command{
		Use:   "rq2",
		Short: "Analyse an RQ2 scan into paper/data/rq2_*.csv",
		Long: "Join pqscope net records to the federal domains they probed, classify each\n" +
			"endpoint, map addresses to autonomous systems, and write rq2_endpoints.csv,\n" +
			"rq2_summary.csv, rq2_certificates.csv and rq2_meta.csv. Fails if any endpoint\n" +
			"has no record, so a partial scan cannot pass for a complete one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			extra, err := parseMeta(meta)
			if err != nil {
				return err
			}
			domains, err := readDotgov(dotgov)
			if err != nil {
				return err
			}
			rf, err := os.Open(records)
			if err != nil {
				return err
			}
			recs, err := measure.ReadRecords(rf)
			_ = rf.Close() // read-only
			if err != nil {
				return err
			}
			var asns *measure.ASNTable
			if asnPath != "" {
				af, err := os.Open(asnPath)
				if err != nil {
					return err
				}
				asns, err = measure.LoadASN(af)
				_ = af.Close() // read-only
				if err != nil {
					return err
				}
			}
			rep, err := measure.AnalyzeRQ2(measure.RQ2Endpoints(domains), recs, asns)
			if err != nil {
				return err
			}
			if err := rep.WriteCSVs(out, extra); err != nil {
				return err
			}
			for _, row := range rep.Summary() {
				if row[1] == "all" || row[0] == "scope" {
					_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(row, "\t"))
				}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s/rq2_*.csv\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dotgov, "dotgov", "", "CISA current-federal.csv `file` the targets came from")
	f.StringVar(&records, "records", "", "pqscope net JSONL `file`")
	f.StringVar(&asnPath, "asn", "", "iptoasn.com ip2asn-combined.tsv(.gz) `file`")
	f.StringVar(&out, "out", "paper/data", "output `dir`")
	f.StringArrayVar(&meta, "meta", nil, "extra `key=value` for rq2_meta.csv; repeatable")
	_ = cmd.MarkFlagRequired("dotgov")
	_ = cmd.MarkFlagRequired("records")
	return cmd
}

func readCriticality(path string) ([]measure.Project, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return measure.ReadCriticality(f)
}

func newRQ3SelectCmd() *cobra.Command {
	var crit, infoPath, out string
	var n, candidates int
	cmd := &cobra.Command{
		Use:   "rq3-select",
		Short: "List RQ3 candidates, or select the top distinct projects",
		Long: "Without --info, write the top --candidates repositories by OpenSSF Criticality\n" +
			"Score, one per line, for measure/rq3.sh to look up. With --info (repo, root\n" +
			"commit, size in KB, tab-separated), select the top --n distinct code bases:\n" +
			"repositories sharing a root commit with a higher-ranked one are duplicates.\n" +
			"Writes the selection as TSV: rank, repo, language, score, root, size, status.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			projects, err := readCriticality(crit)
			if err != nil {
				return err
			}
			if candidates < len(projects) {
				projects = projects[:candidates]
			}
			if infoPath == "" {
				return writeFile(out, func(w io.Writer) error {
					for _, p := range projects {
						if _, err := fmt.Fprintln(w, p.Repo); err != nil {
							return err
						}
					}
					return nil
				})
			}
			rows, err := measure.ReadTSV(infoPath)
			if err != nil {
				return err
			}
			info := map[string]measure.RepoInfo{}
			for _, r := range rows {
				if len(r) < 3 {
					return fmt.Errorf("%s: want repo, root, size_kb: %q", infoPath, r)
				}
				size, err := strconv.Atoi(r[2])
				if err != nil {
					return fmt.Errorf("%s: %s size %q", infoPath, r[0], r[2])
				}
				info[r[0]] = measure.RepoInfo{Root: r[1], SizeKB: size}
			}
			sel, err := measure.Select(projects, info, n)
			if err != nil {
				return err
			}
			return writeFile(out, func(w io.Writer) error {
				for _, s := range sel {
					if _, err := fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s\n", s.Rank, s.Repo, s.Language,
						strconv.FormatFloat(s.Score, 'f', -1, 64), s.Root, s.SizeKB, s.Status); err != nil {
						return err
					}
				}
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&crit, "criticality", "", "OpenSSF Criticality Score CSV(.gz) `file`")
	f.StringVar(&infoPath, "info", "", "repo, root commit, size_kb TSV `file`")
	f.IntVar(&n, "n", 100, "distinct projects to select")
	f.IntVar(&candidates, "candidates", 200, "top repositories to consider")
	f.StringVarP(&out, "output", "o", "-", "output `file`")
	_ = cmd.MarkFlagRequired("criticality")
	return cmd
}

func newRQ3Cmd() *cobra.Command {
	var selPath, scansPath, findings, out string
	var meta []string
	cmd := &cobra.Command{
		Use:   "rq3",
		Short: "Analyse an RQ3 run into paper/data/rq3_*.csv",
		Long: "Read the selection (from rq3-select), the scan status of each project\n" +
			"(repo, commit, status, seconds, tab-separated) and each scanned project's\n" +
			"findings, and write rq3_selection.csv, rq3_projects.csv, rq3_summary.csv,\n" +
			"rq3_algorithms.csv and rq3_meta.csv.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			extra, err := parseMeta(meta)
			if err != nil {
				return err
			}
			selRows, err := measure.ReadTSV(selPath)
			if err != nil {
				return err
			}
			var sel []measure.Selection
			for _, r := range selRows {
				if len(r) < 7 {
					return fmt.Errorf("%s: short row %q", selPath, r)
				}
				rank, err1 := strconv.Atoi(r[0])
				score, err2 := strconv.ParseFloat(r[3], 64)
				size, err3 := strconv.Atoi(r[5])
				if err1 != nil || err2 != nil || err3 != nil {
					return fmt.Errorf("%s: bad row %q", selPath, r)
				}
				sel = append(sel, measure.Selection{
					Project:  measure.Project{Rank: rank, Repo: r[1], Language: r[2], Score: score},
					RepoInfo: measure.RepoInfo{Root: r[4], SizeKB: size},
					Status:   r[6],
				})
			}
			scanRows, err := measure.ReadTSV(scansPath)
			if err != nil {
				return err
			}
			scans := map[string]measure.ScanStatus{}
			for _, r := range scanRows {
				if len(r) < 4 {
					return fmt.Errorf("%s: short row %q", scansPath, r)
				}
				secs, _ := strconv.Atoi(r[3])
				scans[r[0]] = measure.ScanStatus{Repo: r[0], Commit: r[1], Status: r[2], Seconds: secs}
			}
			rows, err := measure.AnalyzeRQ3(sel, scans, findings)
			if err != nil {
				return err
			}
			if err := measure.WriteRQ3(out, sel, rows, extra); err != nil {
				return err
			}
			for _, row := range measure.RQ3Summary(rows) {
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(row, "\t"))
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s/rq3_*.csv\n", out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&selPath, "selection", "", "selection TSV `file` from rq3-select")
	f.StringVar(&scansPath, "scans", "", "scan status TSV `file`")
	f.StringVar(&findings, "findings", "", "`dir` of <owner>__<repo>.json findings")
	f.StringVar(&out, "out", "paper/data", "output `dir`")
	f.StringArrayVar(&meta, "meta", nil, "extra `key=value` for rq3_meta.csv; repeatable")
	for _, req := range []string{"selection", "scans", "findings"} {
		_ = cmd.MarkFlagRequired(req)
	}
	return cmd
}
