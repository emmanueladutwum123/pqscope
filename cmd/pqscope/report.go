package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/emmanueladutwum123/pqscope/internal/cbom"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/report"
	"github.com/emmanueladutwum123/pqscope/internal/sarif"
	"github.com/emmanueladutwum123/pqscope/rules"
)

func newReportCmd() *cobra.Command {
	var out outputs
	cmd := &cobra.Command{
		Use:   "report <findings.json>",
		Short: "Render saved findings as terminal, HTML, CBOM or SARIF output",
		Long: "Render findings saved with `pqscope scan --json` (\"-\" reads standard input).\n\n" +
			"A summary goes to standard output. -o, --sarif and --html also write a\n" +
			"CycloneDX CBOM, a SARIF log and an HTML report.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findings, err := readFindings(cmd.InOrStdin(), args[0])
			if err != nil {
				return err
			}
			db, err := knowledge.Default()
			if err != nil {
				return err
			}
			s, err := source.New(db, rules.FS)
			if err != nil {
				return err
			}
			sum := report.Summary{Target: args[0]}
			if args[0] == "-" {
				sum.Target = ""
			}
			if err := out.write(db, s, findings, sum); err != nil {
				return err
			}
			return report.Text(cmd.OutOrStdout(), db, findings, sum)
		},
	}
	out.register(cmd)
	return cmd
}

// readFindings decodes and validates a JSON array of findings.
func readFindings(stdin io.Reader, path string) ([]model.Finding, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }() // read-only
		r = f
	}
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var findings []model.Finding
	if err := dec.Decode(&findings); err != nil {
		return nil, fmt.Errorf("%s: not a pqscope findings array: %w", path, err)
	}
	var errs []error
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("finding %d: %w", i, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return findings, nil
}

// outputs holds the file outputs shared by scan and report.
type outputs struct {
	cbom, sarif, html string
}

func (o *outputs) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.cbom, "output", "o", "", "write a CycloneDX 1.6 CBOM to `file`")
	cmd.Flags().StringVar(&o.sarif, "sarif", "", "write a SARIF 2.1.0 log to `file`")
	cmd.Flags().StringVar(&o.html, "html", "", "write a self-contained HTML report to `file`")
}

func (o outputs) write(db *knowledge.DB, s *source.Scanner, findings []model.Finding, sum report.Summary) error {
	if o.cbom != "" {
		err := writeFile(o.cbom, func(w io.Writer) error {
			return cbom.Write(w, db, findings, cbom.Options{ToolVersion: version})
		})
		if err != nil {
			return err
		}
	}
	if o.sarif != "" {
		meta := map[string]sarif.Rule{}
		for _, r := range s.Rules() {
			meta[r.ID] = sarif.Rule{Description: r.Description, Notes: r.Notes, HelpURI: r.Source}
		}
		err := writeFile(o.sarif, func(w io.Writer) error {
			return sarif.Write(w, db, findings, sarif.Options{ToolVersion: version, Rules: meta})
		})
		if err != nil {
			return err
		}
	}
	if o.html != "" {
		return writeFile(o.html, func(w io.Writer) error {
			return report.HTML(w, db, findings, sum, report.HTMLOptions{ToolVersion: version})
		})
	}
	return nil
}

// writeFile writes path through a temporary file in the same directory, so a
// failed write never leaves a truncated report behind.
func writeFile(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
