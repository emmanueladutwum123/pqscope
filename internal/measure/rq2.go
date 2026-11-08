package measure

import (
	"bufio"
	"cmp"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/discover/network"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Endpoint statuses, from best to worst. A domain takes the best status of
// its endpoints.
const (
	StatusHybrid      = "hybrid"          // negotiated a hybrid post-quantum group
	StatusPQ          = "pq-only"         // negotiated a pure post-quantum group
	StatusClassical   = "classical"       // TLS 1.3 with a classical group
	StatusTLS12       = "tls1.2-or-lower" // answered, but not with TLS 1.3
	StatusTLSError    = "tls-error"       // TCP connected, no usable TLS handshake
	StatusUnreachable = "unreachable"     // no TCP connection on 443
	StatusUnresolved  = "unresolvable"    // no address in DNS
	StatusExcluded    = "excluded"        // on the opt-out list; never contacted
)

var statusOrder = []string{StatusHybrid, StatusPQ, StatusClassical, StatusTLS12, StatusTLSError, StatusUnreachable, StatusUnresolved, StatusExcluded}

// responding are the statuses of an endpoint that speaks TLS: the
// denominator for adoption.
func responding(status string) bool {
	switch status {
	case StatusHybrid, StatusPQ, StatusClassical, StatusTLS12:
		return true
	}
	return false
}

// hybridGroups are crypto/tls's hybrid groups, for the fallback handshake,
// which reports Go's names rather than producing findings.
var hybridGroups = []string{tls.X25519MLKEM768.String(), tls.SecP256r1MLKEM768.String(), tls.SecP384r1MLKEM1024.String()}

// Classify returns an endpoint's status from its pqscope net record. The
// probe's own ClientHello, which offers X25519MLKEM768 and X25519 with key
// shares for both as current browsers do, decides; the full crypto/tls
// handshake decides only when that probe got no ServerHello (servers that
// answer TLS 1.2 or reject the probe).
func Classify(r network.Record) string {
	switch {
	case strings.HasPrefix(r.Skipped, "excluded"):
		return StatusExcluded
	case r.Skipped != "":
		return StatusUnresolved
	}
	for _, f := range r.Findings {
		if f.Location.Symbol != "tls:negotiated-group" && f.Location.Symbol != "tls:hello-retry-group" {
			continue
		}
		switch f.Asset.Quantum {
		case model.QuantumHybrid:
			return StatusHybrid
		case model.QuantumSafe:
			return StatusPQ
		default:
			return StatusClassical
		}
	}
	h, hs := r.Hello, r.Handshake
	if hs != nil && hs.Error == "" && hs.Version != "" {
		if hs.Version != "TLS 1.3" {
			return StatusTLS12
		}
		if slices.Contains(hybridGroups, hs.Group) {
			return StatusHybrid
		}
		return StatusClassical
	}
	dialFailed := func(err string) bool { return strings.HasPrefix(err, "dial ") }
	if (h == nil || dialFailed(h.Error)) && (hs == nil || dialFailed(hs.Error)) {
		return StatusUnreachable
	}
	return StatusTLSError
}

// EndpointRow is one probed endpoint, as rq2_endpoints.csv lists it.
type EndpointRow struct {
	Endpoint
	Address    string
	ASN        ASN
	Status     string
	Group      string // from the probe's ServerHello or HelloRetryRequest
	HelloRetry bool
	Version    string // from the full handshake
	LeafKey    string // leaf certificate's public key, such as RSA-2048
	LeafSig    string // leaf certificate's signature algorithm
	Error      string
	Time       time.Time
}

// RQ2 is the analysed scan.
type RQ2 struct {
	Endpoints []EndpointRow
	Meta      [][2]string
}

// ReadRecords reads pqscope net's JSONL output.
func ReadRecords(r io.Reader) ([]network.Record, error) {
	var out []network.Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for n := 1; sc.Scan(); n++ {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var rec network.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("record %d: %w", n, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

// AnalyzeRQ2 joins records to the endpoints they probed. Every endpoint must
// have exactly one record, so a partial scan cannot pass for a complete one.
func AnalyzeRQ2(endpoints []Endpoint, records []network.Record, asns *ASNTable) (*RQ2, error) {
	byHost := map[string]network.Record{}
	for _, r := range records {
		t, err := network.ParseTarget(r.Target)
		if err != nil {
			return nil, fmt.Errorf("record target %q: %w", r.Target, err)
		}
		host := strings.ToLower(t.Host)
		if _, dup := byHost[host]; dup {
			return nil, fmt.Errorf("two records for %s", host)
		}
		byHost[host] = r
	}
	rep := &RQ2{}
	var first, last time.Time
	for _, e := range endpoints {
		r, ok := byHost[e.Host]
		if !ok {
			return nil, fmt.Errorf("no record for %s: the scan is incomplete", e.Host)
		}
		delete(byHost, e.Host)
		row := EndpointRow{Endpoint: e, Status: Classify(r), Time: r.Time}
		if first.IsZero() || r.Time.Before(first) {
			first = r.Time
		}
		if r.Time.After(last) {
			last = r.Time
		}
		if r.Address != "" {
			row.Address = r.Address
			if ap, err := netip.ParseAddrPort(r.Address); err == nil && asns != nil {
				row.ASN, _ = asns.Lookup(ap.Addr())
			}
		}
		if h := r.Hello; h != nil {
			row.Group, row.HelloRetry = h.Group, h.HelloRetry
			row.Error = cmp.Or(h.Error, h.Alert)
		}
		if hs := r.Handshake; hs != nil {
			row.Version = hs.Version
			if len(hs.Certificates) > 0 {
				row.LeafKey, row.LeafSig = hs.Certificates[0].PublicKey, hs.Certificates[0].Signature
			}
			if row.Error == "" {
				row.Error = hs.Error
			}
		}
		if row.Status != StatusTLSError && row.Status != StatusUnreachable {
			row.Error = ""
		}
		rep.Endpoints = append(rep.Endpoints, row)
	}
	if len(byHost) > 0 {
		return nil, fmt.Errorf("%d records match no endpoint, such as %s", len(byHost), slices.Sorted(mapKeys(byHost))[0])
	}
	rep.Meta = [][2]string{
		{"endpoints", strconv.Itoa(len(rep.Endpoints))},
		{"domains", strconv.Itoa(len(domainStatuses(rep.Endpoints)))},
		{"scan_first_utc", first.UTC().Format(time.RFC3339)},
		{"scan_last_utc", last.UTC().Format(time.RFC3339)},
	}
	return rep, nil
}

func mapKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func better(a, b string) bool { return slices.Index(statusOrder, a) < slices.Index(statusOrder, b) }

type domainStatus struct {
	Domain
	Status string
}

// domainStatuses gives each domain the best status of its endpoints, in
// endpoint order.
func domainStatuses(rows []EndpointRow) []domainStatus {
	idx := map[string]int{}
	var out []domainStatus
	for _, r := range rows {
		i, ok := idx[r.Domain.Name]
		if !ok {
			idx[r.Domain.Name] = len(out)
			out = append(out, domainStatus{r.Domain, r.Status})
			continue
		}
		if better(r.Status, out[i].Status) {
			out[i].Status = r.Status
		}
	}
	return out
}

// tally counts statuses for one group.
type tally struct {
	n      int
	status map[string]int
}

func (t *tally) add(status string) {
	if t.status == nil {
		t.status = map[string]int{}
	}
	t.n++
	t.status[status]++
}

func (t *tally) responding() int {
	n := 0
	for s, c := range t.status {
		if responding(s) {
			n += c
		}
	}
	return n
}

// Summary returns rq2_summary.csv: for endpoints and for domains, overall and
// by branch, agency and (endpoints only, as a domain's two endpoints can sit
// with different providers) ASN, the count in each status and the share of
// TLS-speaking ones that negotiate hybrid, with its 95% interval.
func (rep *RQ2) Summary() [][]string {
	rows := [][]string{append(append([]string{"scope", "group_by", "key", "n", "responding"}, statusOrder...),
		"hybrid_share", "ci95_low", "ci95_high")}
	emit := func(scope, by string, groups map[string]*tally) {
		for _, k := range slices.Sorted(mapKeys(groups)) {
			t := groups[k]
			row := []string{scope, by, k, strconv.Itoa(t.n), strconv.Itoa(t.responding())}
			for _, s := range statusOrder {
				row = append(row, strconv.Itoa(t.status[s]))
			}
			p := Wilson(t.status[StatusHybrid], t.responding())
			rows = append(rows, append(row, f4(p.Value), f4(p.Low), f4(p.High)))
		}
	}
	group := func() (all, branch, agency, asn map[string]*tally) {
		return map[string]*tally{}, map[string]*tally{}, map[string]*tally{}, map[string]*tally{}
	}
	add := func(m map[string]*tally, k, status string) {
		if m[k] == nil {
			m[k] = &tally{}
		}
		m[k].add(status)
	}

	all, branch, agency, asn := group()
	for _, r := range rep.Endpoints {
		add(all, "all", r.Status)
		add(branch, r.Domain.Branch, r.Status)
		add(agency, r.Domain.Agency, r.Status)
		if responding(r.Status) {
			add(asn, asnKey(r.ASN), r.Status)
		}
	}
	emit("endpoint", "all", all)
	emit("endpoint", "branch", branch)
	emit("endpoint", "agency", agency)
	emit("endpoint", "asn", asn)

	all, branch, agency, _ = group()
	for _, d := range domainStatuses(rep.Endpoints) {
		add(all, "all", d.Status)
		add(branch, d.Branch, d.Status)
		add(agency, d.Agency, d.Status)
	}
	emit("domain", "all", all)
	emit("domain", "branch", branch)
	emit("domain", "agency", agency)
	return rows
}

func asnKey(a ASN) string {
	if a.Number == 0 {
		return "unknown"
	}
	return "AS" + strconv.Itoa(a.Number) + " " + a.Description
}

// Certificates returns rq2_certificates.csv: leaf certificate key and
// signature algorithms over TLS-speaking endpoints.
func (rep *RQ2) Certificates() [][]string {
	counts := map[[2]string]int{}
	for _, r := range rep.Endpoints {
		if responding(r.Status) {
			counts[[2]string{cmp.Or(r.LeafKey, "none"), cmp.Or(r.LeafSig, "none")}]++
		}
	}
	keys := make([][2]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	rows := [][]string{{"leaf_public_key", "leaf_signature", "endpoints"}}
	for _, k := range keys {
		rows = append(rows, []string{k[0], k[1], strconv.Itoa(counts[k])})
	}
	return rows
}

// WriteCSVs writes rq2_endpoints.csv, rq2_summary.csv, rq2_certificates.csv
// and rq2_meta.csv (the run's facts, with extra appended) to dir.
func (rep *RQ2) WriteCSVs(dir string, extra [][2]string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	endpoints := [][]string{{"domain", "host", "branch", "agency", "sub_agency", "address", "asn", "as_description",
		"status", "group", "hello_retry", "tls_version", "leaf_public_key", "leaf_signature", "error", "time_utc"}}
	for _, r := range rep.Endpoints {
		asn := ""
		if r.ASN.Number != 0 {
			asn = strconv.Itoa(r.ASN.Number)
		}
		endpoints = append(endpoints, []string{r.Domain.Name, r.Host, r.Domain.Branch, r.Domain.Agency, r.Domain.SubAgency,
			r.Address, asn, r.ASN.Description, r.Status, r.Group, strconv.FormatBool(r.HelloRetry), r.Version,
			r.LeafKey, r.LeafSig, r.Error, r.Time.UTC().Format(time.RFC3339)})
	}
	meta := [][]string{{"key", "value"}}
	for _, kv := range append(slices.Clone(rep.Meta), extra...) {
		meta = append(meta, kv[:])
	}
	for name, rows := range map[string][][]string{
		"rq2_endpoints.csv": endpoints, "rq2_summary.csv": rep.Summary(),
		"rq2_certificates.csv": rep.Certificates(), "rq2_meta.csv": meta,
	} {
		if err := writeCSV(filepath.Join(dir, name), rows); err != nil {
			return err
		}
	}
	return nil
}
