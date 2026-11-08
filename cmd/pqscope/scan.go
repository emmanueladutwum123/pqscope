package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/discover/deps"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/report"
	"github.com/emmanueladutwum123/pqscope/rules"
)

// scanLayers are the layers `scan` can run, in output order.
var scanLayers = []model.Layer{model.LayerSource, model.LayerConfig, model.LayerDeps}

func newScanCmd() *cobra.Command {
	var asJSON bool
	var layerNames []string
	var out outputs
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory for cryptographic assets",
		Long: "Scan a directory or file for cryptographic assets in three layers:\n\n" +
			"  source  Go and Python code\n" +
			"  config  nginx, Apache, sshd_config, openssl.cnf, Kubernetes, and key material\n" +
			"          (certificates, keys, CSRs); private keys are never output\n" +
			"  deps    go.mod, go.sum, requirements.txt, poetry.lock, package-lock.json,\n" +
			"          pom.xml and Cargo.lock, matched against known crypto libraries\n\n" +
			"Binaries and the network are not scanned yet. Each finding is evaluated under\n" +
			"every bundled policy and given a risk score; use `pqscope policy` to gate CI.\n\n" +
			"A summary goes to standard output, or the findings as JSON with --json.\n" +
			"-o, --sarif and --html also write a CycloneDX CBOM, a SARIF log and an\n" +
			"HTML report.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			layers, err := parseLayers(layerNames)
			if err != nil {
				return err
			}
			db, err := knowledge.Default()
			if err != nil {
				return err
			}
			src, err := source.New(db, rules.FS)
			if err != nil {
				return err
			}
			sum := report.Summary{Target: root, Counted: true}
			var findings []model.Finding
			for _, layer := range layers {
				switch layer {
				case model.LayerSource:
					res, err := src.Scan(cmd.Context(), root)
					if err != nil {
						return err
					}
					findings = append(findings, res.Findings...)
					sum.FilesScanned += res.FilesScanned
					sum.Skipped += len(res.Skipped)
					sum.SyntaxErrors += len(res.SyntaxErrors)
				case model.LayerConfig:
					cs, err := config.New(db)
					if err != nil {
						return err
					}
					res, err := cs.Scan(cmd.Context(), root)
					if err != nil {
						return err
					}
					findings = append(findings, res.Findings...)
					sum.FilesScanned += res.FilesScanned
					sum.Skipped += len(res.Skipped)
					sum.Notes = append(sum.Notes, res.Notes...)
				case model.LayerDeps:
					libs, err := knowledge.DefaultLibs()
					if err != nil {
						return err
					}
					res, err := deps.New(db, libs).Scan(cmd.Context(), root)
					if err != nil {
						return err
					}
					findings = append(findings, res.Findings...)
					sum.FilesScanned += res.FilesScanned
					sum.Skipped += len(res.Skipped)
				}
			}
			// Layers scan disjoint files, so ordering by location interleaves them.
			slices.SortStableFunc(findings, func(a, b model.Finding) int {
				return cmp.Or(strings.Compare(a.Location.Path, b.Location.Path), cmp.Compare(a.Location.Line, b.Location.Line))
			})
			if err := annotate(db, findings); err != nil {
				return err
			}
			if err := out.write(db, src, findings, sum); err != nil {
				return err
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), findings)
			}
			return report.Text(cmd.OutOrStdout(), db, findings, sum)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "write findings to standard output as a JSON array")
	cmd.Flags().StringSliceVar(&layerNames, "layers", []string{"source", "config", "deps"}, "layers to scan: source, config, deps")
	out.register(cmd)
	return cmd
}

func parseLayers(names []string) ([]model.Layer, error) {
	var out []model.Layer
	for _, l := range scanLayers {
		if slices.Contains(names, string(l)) {
			out = append(out, l)
		}
	}
	for _, n := range names {
		if !slices.Contains(scanLayers, model.Layer(n)) {
			return nil, fmt.Errorf("--layers: unknown or unsupported layer %q (want source, config or deps)", n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--layers: no layers selected")
	}
	return out, nil
}

func writeJSON(w io.Writer, findings []model.Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if findings == nil {
		findings = []model.Finding{}
	}
	return enc.Encode(findings)
}
