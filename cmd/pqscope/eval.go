package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/eval"
)

func newEvalCmd() *cobra.Command {
	var corpus, runs, out string
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Score pqscope and competitor runs against the labeled corpus",
		Long: "Score pqscope, run in-process on every corpus case, and each competitor run\n" +
			"that eval/run.sh recorded under --runs, against the corpus labels. Writes\n" +
			"rq1_summary.csv, rq1_items.csv, rq1_tools.csv, rq1_ablation.csv and\n" +
			"rq1_corpus.csv to --out. Tools that did not run are listed as such.\n\n" +
			"`make eval` runs the competitors, then this, then eval/score.py, which\n" +
			"recomputes the summary from the items as a cross-check.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep, err := eval.Run(cmd.Context(), corpus, runs)
			if err != nil {
				return err
			}
			if err := eval.WriteCSVs(rep, out); err != nil {
				return err
			}
			for _, row := range eval.Summary(rep) {
				if row[1] == "file" && row[2] == "all" || row[0] == "tool" {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-16s %-6s %-6s P=%-6s R=%-6s F1=%-6s cases=%s\n", row[0], row[1], row[2], row[8], row[9], row[10], row[4])
				}
			}
			for _, t := range rep.Tools {
				if t.Status != "ran" {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s %s\n", t.Tool, t.Status, t.Reason)
				}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%d cases; wrote %s/rq1_*.csv\n", len(rep.Cases), out)
			return nil
		},
	}
	cmd.Flags().StringVar(&corpus, "corpus", "testdata/corpus", "labeled corpus `dir`")
	cmd.Flags().StringVar(&runs, "runs", "eval/out", "eval/run.sh output `dir`")
	cmd.Flags().StringVar(&out, "out", "paper/data", "output `dir` for CSVs")
	return cmd
}
