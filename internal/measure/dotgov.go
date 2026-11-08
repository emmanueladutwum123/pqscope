// Package measure turns measurement runs into the paper's RQ2 and RQ3
// datasets: which federal .gov endpoints negotiate hybrid post-quantum key
// exchange, and how much quantum-vulnerable cryptography critical open-source
// projects contain. It reads what other commands recorded (pqscope net
// records, pqscope scan findings) and never connects to anything itself.
package measure

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Domain is one row of CISA's federal .gov domain list
// (github.com/cisagov/dotgov-data, current-federal.csv).
type Domain struct {
	Name      string // lower case, no trailing dot
	Branch    string // the "Domain type" column, such as "Federal - Executive"
	Agency    string // "Organization name"
	SubAgency string // "Suborganization name"
}

// ParseDotgov reads current-federal.csv. Rows whose domain type does not
// start with "Federal" are skipped, so the full list (current-full.csv) can
// be passed too. Duplicate domains are an error.
func ParseDotgov(r io.Reader) ([]Domain, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("dotgov: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.TrimPrefix(h, "\ufeff"))] = i
	}
	for _, need := range []string{"Domain name", "Domain type", "Organization name"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("dotgov: no %q column (have %v)", need, header)
		}
	}
	field := func(rec []string, name string) string {
		i, ok := col[name]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var out []Domain
	seen := map[string]bool{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("dotgov: %w", err)
		}
		d := Domain{
			Name:      strings.TrimSuffix(strings.ToLower(field(rec, "Domain name")), "."),
			Branch:    field(rec, "Domain type"),
			Agency:    field(rec, "Organization name"),
			SubAgency: field(rec, "Suborganization name"),
		}
		if d.Name == "" || !strings.HasPrefix(d.Branch, "Federal") {
			continue
		}
		if !strings.HasSuffix(d.Name, ".gov") {
			return nil, fmt.Errorf("dotgov: %q is not a .gov domain", d.Name)
		}
		if seen[d.Name] {
			return nil, fmt.Errorf("dotgov: %q listed twice", d.Name)
		}
		seen[d.Name] = true
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, errors.New("dotgov: no federal domains")
	}
	slices.SortFunc(out, func(a, b Domain) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Endpoint is one host probed for a domain.
type Endpoint struct {
	Host   string
	Domain Domain
}

// RQ2Endpoints lists what RQ2 probes for each domain: the apex and www, both
// on port 443. CISA's list holds registered domains, not websites, and these
// are the two names a visitor types.
func RQ2Endpoints(domains []Domain) []Endpoint {
	out := make([]Endpoint, 0, 2*len(domains))
	for _, d := range domains {
		out = append(out, Endpoint{d.Name, d}, Endpoint{"www." + d.Name, d})
	}
	return out
}

// TargetLine is how an endpoint is written in a pqscope net targets file.
func TargetLine(host string) string { return "tls://" + host + ":443" }
