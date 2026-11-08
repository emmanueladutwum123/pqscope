package measure

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/discover/network"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

const dotgovCSV = "\ufeffDomain name,Domain type,Organization name,Suborganization name,City,State,Security contact email\n" +
	"B.GOV,Federal - Executive,Agency B,Office,Washington,DC,x@b.gov\n" +
	"a.gov,Federal - Legislative,\"Agency A, Congress\",,Washington,DC,\n" +
	"c.gov,City,Somewhere,,,,\n"

func TestParseDotgov(t *testing.T) {
	ds, err := ParseDotgov(strings.NewReader(dotgovCSV))
	if err != nil {
		t.Fatal(err)
	}
	want := []Domain{{"a.gov", "Federal - Legislative", "Agency A, Congress", ""}, {"b.gov", "Federal - Executive", "Agency B", "Office"}}
	if len(ds) != 2 || ds[0] != want[0] || ds[1] != want[1] {
		t.Errorf("got %+v", ds)
	}
	eps := RQ2Endpoints(ds)
	if len(eps) != 4 || eps[1].Host != "www.a.gov" || eps[2].Domain.Name != "b.gov" || TargetLine(eps[0].Host) != "tls://a.gov:443" {
		t.Errorf("endpoints %+v", eps)
	}
	for name, in := range map[string]string{
		"duplicate":  dotgovCSV + "a.gov,Federal - Executive,X,,,,\n",
		"not .gov":   dotgovCSV + "a.mil,Federal - Executive,X,,,,\n",
		"no columns": "Name,Type\na.gov,Federal\n",
		"no federal": "Domain name,Domain type,Organization name\nc.gov,City,X\n",
	} {
		if _, err := ParseDotgov(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

const asnTSV = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"2.0.0.0\t2.0.0.255\t20940\tUS\tAKAMAI-AS - Akamai Technologies, Inc.\n" +
	"2600::\t2600::ffff\t16509\tUS\tAMAZON-02 - Amazon.com, Inc.\n"

func TestASN(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(asnTSV))
	_ = zw.Close()
	for name, data := range map[string][]byte{"plain": []byte(asnTSV), "gzip": gz.Bytes()} {
		tbl, err := LoadASN(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for addr, want := range map[string]int{
			"1.0.0.1": 13335, "1.0.0.255": 13335, "1.0.2.9": 0, "2.0.0.7": 20940,
			"2600::1": 16509, "::ffff:2.0.0.7": 20940, "2.0.1.0": -1, "0.0.0.1": -1, "2601::": -1,
		} {
			a, ok := tbl.Lookup(netip.MustParseAddr(addr))
			got := a.Number
			if !ok {
				got = -1
			}
			if got != want {
				t.Errorf("%s: Lookup(%s) = %d, want %d", name, addr, got, want)
			}
		}
	}
	for _, bad := range []string{"", "1.0.0.0\t1.0.0.255\tx\tUS\td\n", "1.0.0.9\t1.0.0.1\t1\tUS\td\n", "1.0.0.0\t2600::\t1\tUS\td\n"} {
		if _, err := LoadASN(strings.NewReader(bad)); err == nil {
			t.Errorf("LoadASN(%q) should fail", bad)
		}
	}
}

func TestWilson(t *testing.T) {
	for _, tt := range []struct {
		k, n          int
		value, lo, hi float64
	}{
		{5, 10, 0.5, 0.2366, 0.7634},
		{0, 10, 0, 0, 0.2775},
		{10, 10, 1, 0.7225, 1},
		{0, 0, 0, 0, 0},
	} {
		p := Wilson(tt.k, tt.n)
		if math.Abs(p.Value-tt.value) > 1e-9 || math.Abs(p.Low-tt.lo) > 1e-4 || math.Abs(p.High-tt.hi) > 1e-4 {
			t.Errorf("Wilson(%d, %d) = %+v", tt.k, tt.n, p)
		}
	}
}

func groupFinding(symbol, quantum string) model.Finding {
	return model.Finding{Asset: model.Asset{Quantum: quantum}, Location: model.Location{Layer: model.LayerNetwork, Symbol: symbol}}
}

func TestClassify(t *testing.T) {
	dial := "dial tcp 192.0.2.1:443: i/o timeout"
	for _, tt := range []struct {
		name string
		r    network.Record
		want string
	}{
		{"excluded", network.Record{Skipped: "excluded address 192.0.2.1"}, StatusExcluded},
		{"no DNS", network.Record{Skipped: "unresolvable"}, StatusUnresolved},
		{"hybrid", network.Record{Findings: []model.Finding{groupFinding("tls:negotiated-group", model.QuantumHybrid)}}, StatusHybrid},
		{"hybrid by retry", network.Record{Findings: []model.Finding{groupFinding("tls:hello-retry-group", model.QuantumHybrid)}}, StatusHybrid},
		{"pure PQ", network.Record{Findings: []model.Finding{groupFinding("tls:negotiated-group", model.QuantumSafe)}}, StatusPQ},
		{"classical, cert findings ignored", network.Record{Findings: []model.Finding{
			groupFinding("tls:cert[0]:public-key", model.QuantumVulnerable), groupFinding("tls:negotiated-group", model.QuantumVulnerable)}}, StatusClassical},
		{"TLS 1.2 only", network.Record{Hello: &network.Hello{Alert: "protocol_version"}, Handshake: &network.Handshake{Version: "TLS 1.2"}}, StatusTLS12},
		{"handshake TLS 1.3 hybrid fallback", network.Record{Hello: &network.Hello{Error: "EOF"}, Handshake: &network.Handshake{Version: "TLS 1.3", Group: "X25519MLKEM768"}}, StatusHybrid},
		{"handshake TLS 1.3 classical fallback", network.Record{Hello: &network.Hello{Error: "EOF"}, Handshake: &network.Handshake{Version: "TLS 1.3", Group: "X25519"}}, StatusClassical},
		{"unreachable", network.Record{Hello: &network.Hello{Error: dial}, Handshake: &network.Handshake{Error: dial}}, StatusUnreachable},
		{"connected, no TLS", network.Record{Hello: &network.Hello{Error: "EOF"}, Handshake: &network.Handshake{Error: "tls: handshake failure"}}, StatusTLSError},
	} {
		if got := Classify(tt.r); got != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, got, tt.want)
		}
	}
}

func rec(host, addr string, findings ...model.Finding) network.Record {
	r := network.Record{Target: host + ":443", Probe: "tls", Address: addr, Time: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC), Findings: findings}
	r.Hello = &network.Hello{Group: "x"}
	r.Handshake = &network.Handshake{Version: "TLS 1.3", Certificates: []network.Certificate{{PublicKey: "ECDSA-P256", Signature: "ECDSA-SHA256"}}}
	return r
}

func TestAnalyzeRQ2(t *testing.T) {
	ds, err := ParseDotgov(strings.NewReader(dotgovCSV))
	if err != nil {
		t.Fatal(err)
	}
	eps := RQ2Endpoints(ds)
	tbl, err := LoadASN(strings.NewReader(asnTSV))
	if err != nil {
		t.Fatal(err)
	}
	hybrid, classical := groupFinding("tls:negotiated-group", model.QuantumHybrid), groupFinding("tls:negotiated-group", model.QuantumVulnerable)
	records := []network.Record{
		rec("a.gov", "1.0.0.1:443", classical),
		rec("www.a.gov", "1.0.0.2:443", hybrid),
		rec("b.gov", "2.0.0.1:443", classical),
		{Target: "www.b.gov:443", Skipped: "unresolvable", Time: time.Date(2026, 11, 8, 12, 5, 0, 0, time.UTC)},
	}
	rep, err := AnalyzeRQ2(eps, records, tbl)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Endpoints[1].Status != StatusHybrid || rep.Endpoints[0].ASN.Number != 13335 || rep.Endpoints[3].Status != StatusUnresolved {
		t.Errorf("endpoints %+v", rep.Endpoints)
	}
	if rep.Endpoints[0].LeafKey != "ECDSA-P256" {
		t.Error("leaf certificate not recorded")
	}
	sum := map[string][]string{}
	for _, row := range rep.Summary() {
		sum[row[0]+"/"+row[1]+"/"+row[2]] = row
	}
	// Endpoints: 4 probed, 3 respond, 1 hybrid. Domains: a.gov takes its best
	// endpoint (hybrid), b.gov is classical.
	if r := sum["endpoint/all/all"]; r[3] != "4" || r[4] != "3" || r[5] != "1" || r[len(r)-3] != "0.3333" {
		t.Errorf("endpoint/all = %v", r)
	}
	if r := sum["domain/all/all"]; r[3] != "2" || r[4] != "2" || r[5] != "1" || r[len(r)-3] != "0.5000" {
		t.Errorf("domain/all = %v", r)
	}
	if r := sum["endpoint/asn/AS13335 CLOUDFLARENET - Cloudflare, Inc."]; r == nil || r[3] != "2" {
		t.Errorf("asn rows = %v", sum)
	}
	if r := sum["domain/agency/Agency A, Congress"]; r == nil || r[5] != "1" {
		t.Errorf("agency rows = %v", r)
	}
	if c := rep.Certificates(); len(c) != 2 || c[1][2] != "3" {
		t.Errorf("certificates = %v", c)
	}

	if _, err := AnalyzeRQ2(eps, records[:3], tbl); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("missing record: %v", err)
	}
	if _, err := AnalyzeRQ2(eps, append(records, rec("c.gov", "")), tbl); err == nil {
		t.Error("an unexpected record should fail")
	}
	if _, err := AnalyzeRQ2(eps, append(records, rec("A.gov", "")), tbl); err == nil {
		t.Error("a duplicate record should fail")
	}

	dir := t.TempDir()
	if err := rep.WriteCSVs(dir, [][2]string{{"vantage", "test"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rq2_endpoints.csv", "rq2_summary.csv", "rq2_certificates.csv", "rq2_meta.csv"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Size() == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	meta, _ := os.ReadFile(filepath.Join(dir, "rq2_meta.csv"))
	if !strings.Contains(string(meta), "scan_last_utc,2026-11-08T12:05:00Z") || !strings.Contains(string(meta), "vantage,test") {
		t.Errorf("meta:\n%s", meta)
	}
}

func TestReadRecords(t *testing.T) {
	data, _ := json.Marshal(rec("a.gov", "1.0.0.1:443"))
	recs, err := ReadRecords(strings.NewReader(string(data) + "\n\n" + string(data) + "\n"))
	if err != nil || len(recs) != 2 || recs[1].Handshake.Certificates[0].PublicKey != "ECDSA-P256" {
		t.Errorf("%+v %v", recs, err)
	}
	if _, err := ReadRecords(strings.NewReader("{")); err == nil {
		t.Error("bad JSON should fail")
	}
}

const critCSV = "repo.url,repo.language,default_score\n" +
	"https://github.com/kernel/fork,C,0.8\n" +
	"https://github.com/torvalds/linux,C,0.9\n" +
	"https://gitlab.com/x/y,Go,0.99\n" +
	"https://github.com/big/repo,C++,0.7\n" +
	"https://github.com/a/lib,Go,0.6\n" +
	"https://github.com/b/app,Python,0.6\n" +
	"https://github.com/c/none,Go,\n"

func TestSelect(t *testing.T) {
	ps, err := ReadCriticality(strings.NewReader(critCSV))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range ps {
		names = append(names, p.Repo)
	}
	if strings.Join(names, " ") != "torvalds/linux kernel/fork big/repo a/lib b/app" || ps[0].Rank != 1 {
		t.Fatalf("order %v", names)
	}
	info := map[string]RepoInfo{
		"torvalds/linux": {"root1", 5_000_000}, "kernel/fork": {"root1", 4_000_000},
		"big/repo": {"root2", MaxRepoKB + 1}, "a/lib": {"root3", 10}, "b/app": {"root4", 10},
	}
	sel, err := Select(ps, info, 3)
	if err != nil {
		t.Fatal(err)
	}
	var status []string
	for _, s := range sel {
		status = append(status, s.Repo+"="+s.Status)
	}
	if got := strings.Join(status, "; "); got != "torvalds/linux=selected; kernel/fork=duplicate of torvalds/linux; big/repo=skipped: repository is 20 GB, above the 20 GB cap; a/lib=selected" {
		t.Errorf("selection: %s", got)
	}
	if _, err := Select(ps, info, 5); err == nil {
		t.Error("too few distinct projects should fail")
	}
	delete(info, "a/lib")
	if _, err := Select(ps, info, 3); err == nil {
		t.Error("a candidate without info should fail")
	}
}

func TestAnalyzeRQ3(t *testing.T) {
	dir := t.TempDir()
	vuln := func(layer model.Layer, path, alg string) model.Finding {
		return model.Finding{Asset: model.Asset{Algorithm: alg, Quantum: model.QuantumVulnerable}, Location: model.Location{Layer: layer, Path: path}}
	}
	write := func(repo string, fs []model.Finding) {
		data, _ := json.Marshal(fs)
		if err := os.WriteFile(filepath.Join(dir, FindingsFile(repo)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a/one", []model.Finding{
		vuln(model.LayerSource, "src/x.go", "RSA"),
		vuln(model.LayerConfig, "nginx.conf", "ECDH"),
		vuln(model.LayerSource, "test/x_test.go", "RSA"),
		{Asset: model.Asset{Algorithm: "AES", Quantum: model.QuantumWeakened}, Location: model.Location{Layer: model.LayerSource, Path: "a.go"}},
		{Asset: model.Asset{Algorithm: "RSA", Quantum: model.QuantumVulnerable}, Derived: "stale-dependency"},
	})
	write("b/two", []model.Finding{vuln(model.LayerDeps, "go.mod", "ECDSA")})
	write("c/three", nil)
	sel := []Selection{
		{Project: Project{Rank: 1, Repo: "a/one"}, Status: "selected"},
		{Project: Project{Rank: 2, Repo: "a/dup"}, Status: "duplicate of a/one"},
		{Project: Project{Rank: 3, Repo: "b/two"}, Status: "selected"},
		{Project: Project{Rank: 4, Repo: "c/three"}, Status: "selected"},
		{Project: Project{Rank: 5, Repo: "d/huge"}, Status: "skipped: too big"},
		{Project: Project{Rank: 6, Repo: "e/fail"}, Status: "selected"},
	}
	scans := map[string]ScanStatus{
		"a/one": {Status: "scanned"}, "b/two": {Status: "scanned"}, "c/three": {Status: "scanned"}, "e/fail": {Status: "clone failed"},
	}
	rows, err := AnalyzeRQ3(sel, scans, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 || rows[3].Scan.Status != "skipped: too big" {
		t.Fatalf("rows %+v", rows)
	}
	a := rows[0]
	if a.Findings != 5 || a.ByLayer[model.LayerSource] != 2 || a.ByLayer[model.LayerConfig] != 1 || a.Derived["stale-dependency"] != 1 ||
		a.ByExposure["network"] != 1 || a.ByExposure["test"] != 1 || a.ByExposure["internal"] != 1 {
		t.Errorf("a/one = %+v", a)
	}
	sum := map[string][]string{}
	for _, r := range RQ3Summary(rows) {
		sum[r[0]] = r
	}
	for metric, want := range map[string]string{
		"vulnerable:any-layer":                     "2/3",
		"vulnerable:used (source, config, binary)": "1/3",
		"vulnerable:layer:deps":                    "1/3",
		"vulnerable:exposure:network":              "1/3",
		"derived:stale-dependency":                 "1/3",
	} {
		if r := sum[metric]; r == nil || r[1]+"/"+r[2] != want {
			t.Errorf("%s = %v, want %s", metric, r, want)
		}
	}
	// One project each, so ties sort by name; a/one's two RSA findings count once per project.
	algs := RQ3Algorithms(rows)
	var got []string
	for _, r := range algs[1:] {
		got = append(got, strings.Join(r, ":"))
	}
	if strings.Join(got, " ") != "ECDH:1:1 ECDSA:1:1 RSA:1:2" {
		t.Errorf("algorithms %v", got)
	}
	scans["b/two"] = ScanStatus{Status: "scanned"}
	_ = os.Remove(filepath.Join(dir, FindingsFile("b/two")))
	if _, err := AnalyzeRQ3(sel, scans, dir); err == nil {
		t.Error("a scanned project without findings should fail")
	}
	if err := WriteRQ3(t.TempDir(), sel, rows, nil); err != nil {
		t.Fatal(err)
	}
}
