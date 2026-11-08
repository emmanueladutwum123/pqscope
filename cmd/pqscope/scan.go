package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/discover/binary"
	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/discover/deps"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/reconcile"
	"github.com/emmanueladutwum123/pqscope/internal/report"
	"github.com/emmanueladutwum123/pqscope/rules"
)

// scanLayers are the layers `scan` can run, in output order.
var scanLayers = []model.Layer{model.LayerSource, model.LayerConfig, model.LayerDeps, model.LayerBinary}

func newScanCmd() *cobra.Command {
	var asJSON, noReconcile bool
	var layerNames, with []string
	var componentsFile string
	var out outputs
	cmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan a directory for cryptographic assets",
		Long: "Scan a directory or file for cryptographic assets in four layers:\n\n" +
			"  source  Go and Python code\n" +
			"  config  nginx, Apache, sshd_config, openssl.cnf, Kubernetes, and key material\n" +
			"          (certificates, keys, CSRs); private keys are never output\n" +
			"  deps    go.mod, go.sum, requirements.txt, poetry.lock, package-lock.json,\n" +
			"          pom.xml and Cargo.lock, matched against known crypto libraries\n" +
			"  binary  ELF, PE and Mach-O: crypto library imports, Go build info and\n" +
			"          functions, and constants in stripped binaries\n\n" +
			"Use `pqscope net` for live endpoints, and --with to merge its findings.\n\n" +
			"Findings are then reconciled across layers: confirmed in two layers, their\n" +
			"confidence rises; contradicted, they are flagged for review; and derived\n" +
			"findings report declared-but-not-deployed PQC, configuration overriding a\n" +
			"library, crypto in binaries but not source, and stale dependencies. By default\n" +
			"the whole scan is one component; --components splits it. Each finding is evaluated under\n" +
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
				case model.LayerBinary:
					libs, err := knowledge.DefaultLibs()
					if err != nil {
						return err
					}
					bs, err := binary.New(db, libs, src.SymbolAssets("go"))
					if err != nil {
						return err
					}
					res, err := bs.Scan(cmd.Context(), root)
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
			for _, p := range with {
				fs, err := readFindings(cmd.InOrStdin(), p)
				if err != nil {
					return err
				}
				findings = append(findings, fs...)
			}
			if !noReconcile {
				var comps []reconcile.Component
				if componentsFile != "" {
					f, err := os.Open(componentsFile)
					if err != nil {
						return err
					}
					comps, err = reconcile.ParseComponents(f)
					_ = f.Close() // read-only
					if err != nil {
						return fmt.Errorf("%s: %w", componentsFile, err)
					}
				}
				libs, err := knowledge.DefaultLibs()
				if err != nil {
					return err
				}
				findings = reconcile.New(db, libs, comps).Run(findings)
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
	cmd.Flags().StringArrayVar(&with, "with", nil, "merge findings from `file` (such as `pqscope net --findings`) before reconciling; repeatable")
	cmd.Flags().StringVar(&componentsFile, "components", "", "split the scan into components for reconciliation (YAML `file`)")
	cmd.Flags().BoolVar(&noReconcile, "no-reconcile", false, "skip cross-layer reconciliation")
	cmd.Flags().StringSliceVar(&layerNames, "layers", []string{"source", "config", "deps", "binary"}, "layers to scan: source, config, deps, binary")
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
			return nil, fmt.Errorf("--layers: unknown or unsupported layer %q (want source, config, deps or binary)", n)
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
