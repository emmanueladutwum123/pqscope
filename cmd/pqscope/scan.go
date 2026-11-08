package main

import (
	"encoding/json"
	"io"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/report"
	"github.com/emmanueladutwum123/pqscope/rules"
)

func newScanCmd() *cobra.Command {
	var asJSON bool
	var out outputs
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan source code for cryptographic assets (Go and Python)",
		Long: "Scan a directory or file for cryptographic assets.\n\n" +
			"Only the source layer is implemented: Go and Python files. Dependencies,\n" +
			"configuration, binaries and the network are not scanned yet.\n\n" +
			"Each finding is evaluated under every bundled policy and given a risk score.\n" +
			"Use `pqscope policy` to gate CI on the result.\n\n" +
			"A summary goes to standard output, or the findings as JSON with --json.\n" +
			"-o, --sarif and --html also write a CycloneDX CBOM, a SARIF log and an\n" +
			"HTML report.",
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
			if err := annotate(db, res.Findings); err != nil {
				return err
			}
			sum := report.Summary{
				Target:       root,
				Counted:      true,
				FilesScanned: res.FilesScanned,
				Skipped:      len(res.Skipped),
				SyntaxErrors: len(res.SyntaxErrors),
			}
			if err := out.write(db, s, res.Findings, sum); err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), res.Findings)
			}
			return report.Text(cmd.OutOrStdout(), db, res.Findings, sum)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "write findings to standard output as a JSON array")
	out.register(cmd)
	return cmd
}

func writeJSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if findings == nil {
		findings = []model.Finding{}
	}
	return enc.Encode(findings)
}
