package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/rules"
)

func newScanCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan source code for cryptographic assets (Go and Python)",
		Long: "Scan a directory or file for cryptographic assets.\n\n" +
			"Only the source layer is implemented: Go and Python files. Dependencies,\n" +
			"configuration, binaries and the network are not scanned yet.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			db, err := knowledge.Default()
			if err != nil {
				return err
			}
			s, err := source.New(db, rules.FS)
			if err != nil {
				return err
			}
			res, err := s.Scan(cmd.Context(), root)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), res)
			}
			return writeText(cmd.OutOrStdout(), res)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "write findings as a JSON array")
	return cmd
}

func writeJSON(w io.Writer, res source.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	findings := res.Findings
	if findings == nil {
		findings = []model.Finding{}
	}
	return enc.Encode(findings)
}

func writeText(w io.Writer, res source.Result) error {
	var table strings.Builder
	table.WriteString("LOCATION\tALGORITHM\tPARAMS\tQUANTUM\tCONFIDENCE\tRULE\n")
	for _, f := range res.Findings {
		_, _ = fmt.Fprintf(&table, "%s:%d\t%s\t%s\t%s\t%.2f\t%s\n", // strings.Builder never fails
			f.Location.Path, f.Location.Line, f.Asset.Algorithm, f.Asset.Params,
			f.Asset.Quantum, f.Confidence, f.RuleID)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := io.WriteString(tw, table.String()); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	summary := fmt.Sprintf("\n%d findings in %d files scanned", len(res.Findings), res.FilesScanned)
	if n := len(res.Skipped); n > 0 {
		summary += fmt.Sprintf(", %d skipped", n)
	}
	if n := len(res.SyntaxErrors); n > 0 {
		summary += fmt.Sprintf(", %d with syntax errors", n)
	}
	_, err := io.WriteString(w, summary+"\n")
	return err
}
