package bench

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
)

func TestSummarize(t *testing.T) {
	samples := make([]int64, 0, 100)
	for i := 100; i >= 1; i-- {
		samples = append(samples, int64(i))
	}
	st, err := summarize(samples)
	if err != nil {
		t.Fatal(err)
	}
	want := Stats{N: 100, Mean: 50.5, P50: 50, P99: 99, Min: 1, Max: 100}
	if st != want {
		t.Errorf("summarize = %+v, want %+v", st, want)
	}
	if samples[0] != 100 {
		t.Error("summarize sorted the caller's slice")
	}
	for _, tt := range []struct {
		n       int
		p       float64
		wantIdx int
	}{{1, 99, 0}, {2, 50, 0}, {3, 50, 1}, {200, 99, 197}, {10, 0, 0}} {
		s := make([]int64, tt.n)
		for i := range s {
			s[i] = int64(i)
		}
		if got := percentile(s, tt.p); got != int64(tt.wantIdx) {
			t.Errorf("percentile(n=%d, p=%v) = %d, want %d", tt.n, tt.p, got, tt.wantIdx)
		}
	}
	if _, err := summarize(nil); err == nil {
		t.Error("no samples should be an error")
	}
}

func TestMeasureIterations(t *testing.T) {
	calls := 0
	st, err := measure(Config{Warmup: 2, MinIters: 5, MaxIters: 5}, func() error { calls++; return nil })
	if err != nil || st.N != 5 || calls != 7 {
		t.Errorf("N=%d calls=%d err=%v; want 5 recorded after 2 warmup", st.N, calls, err)
	}
	boom := errors.New("boom")
	if _, err := measure(Quick, func() error { return boom }); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the op's error", err)
	}
}

// Every primitive runs, round-trips, and its sizes agree with the knowledge
// DB, which TestSizesMatchImplementations in turn ties to the implementations'
// own constants.
func TestPrimitives(t *testing.T) {
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range Primitives() {
		t.Run(p.Algorithm+"/"+p.Impl, func(t *testing.T) {
			if _, ok := db.ByID(p.Algorithm); !ok {
				t.Fatalf("%s is not a knowledge DB ID", p.Algorithm)
			}
			res, sizes, err := p.Run(Quick)
			if err != nil {
				t.Fatal(err)
			}
			wantOps := []string{OpKeygen, OpEncap, OpDecap}
			if p.Kind == "signature" {
				wantOps = []string{OpKeygen, OpSign, OpVerify}
			}
			if len(res) != len(wantOps) {
				t.Fatalf("%d results, want %d", len(res), len(wantOps))
			}
			for i, r := range res {
				if r.Op != wantOps[i] || r.N != 1 || r.P50 <= 0 || r.Algorithm != p.Algorithm || r.Impl != p.Impl {
					t.Errorf("result %d = %+v", i, r)
				}
			}
			rows, bad := crossCheck(db, sizes, nil)
			if len(bad) > 0 {
				t.Error(bad)
			}
			for _, r := range rows {
				if r.Bytes <= 0 {
					t.Errorf("%s: %d bytes", r.Field, r.Bytes)
				}
				if r.Agrees == "n/a" {
					t.Errorf("%s: the knowledge DB has no size to check against", r.Field)
				}
			}
		})
		seen[p.Algorithm] = true
	}
	// SPEC Section 11's list.
	for _, a := range []string{"X25519", "ECDH-P256", "ECDSA-P256", "RSA-2048", "RSA-3072", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-128s", "SLH-DSA-128f", "X25519MLKEM768"} {
		if !seen[a] {
			t.Errorf("%s is not benchmarked", a)
		}
	}
}

// The hybrid is checked part by part: a peer splitting its shares must get
// the same secrets as the standalone primitives produce.
func TestHybridComposition(t *testing.T) {
	h := hybridX25519MLKEM768()
	pk, decap, err := h.generate()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss, err := h.encap(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(pk) != 1216 || len(ct) != 1120 || len(ss) != 64 {
		t.Fatalf("sizes %d/%d/%d, want 1216/1120/64", len(pk), len(ct), len(ss))
	}
	// The X25519 half of the secret is X25519 between the trailing shares.
	got, err := decap(ct)
	if err != nil || string(got) != string(ss) {
		t.Fatalf("decap mismatch: %v", err)
	}
	if _, err := decap(ct[:100]); err == nil {
		t.Error("short ciphertext should fail")
	}
	if _, _, err := h.encap(pk[:32]); err == nil {
		t.Error("short public key should fail")
	}
}

func TestCrossCheck(t *testing.T) {
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	ossl := &OpenSSL{Sizes: map[[2]string]int{
		{"ML-KEM-768", FieldPublicKey}:  1184,
		{"ML-KEM-768", FieldCiphertext}: 1000, // wrong on purpose
		{"ECDSA-P256", FieldSignature}:  71,
	}}
	rows, bad := crossCheck(db, []SizeResult{
		{"ML-KEM-768", ImplStdlib, FieldPublicKey, 1184, false},
		{"ML-KEM-768", ImplStdlib, FieldCiphertext, 1088, false},
		{"ECDSA-P256", ImplStdlib, FieldSignature, 72, true},
		{"X25519", ImplStdlib, FieldCiphertext, 32, false},
		{"X25519", ImplStdlib, FieldSharedSecret, 31, false},
	}, ossl)
	want := []string{"yes", "no", "variable", "yes", "no"}
	for i, r := range rows {
		if r.Agrees != want[i] {
			t.Errorf("%s %s: agrees %q, want %q (%+v)", r.Algorithm, r.Field, r.Agrees, want[i], r)
		}
	}
	if len(bad) != 2 || !strings.Contains(bad[0], "OpenSSL 1000") {
		t.Errorf("mismatches = %q", bad)
	}
	if rows[3].DB != 32 {
		t.Errorf("X25519 ciphertext is checked against the public key size, got DB %d", rows[3].DB)
	}
}

func TestSPKIKeySize(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkix := func(pub any) []byte {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	// A post-quantum SPKI: the OID is irrelevant to the size.
	pq, err := asn1.Marshal(struct {
		Algorithm struct{ OID asn1.ObjectIdentifier }
		Key       asn1.BitString
	}{struct{ OID asn1.ObjectIdentifier }{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}}, asn1.BitString{Bytes: make([]byte, 1184), BitLength: 1184 * 8}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		alg  string
		der  []byte
		want int
	}{
		{"RSA-2048", pkix(&rsaKey.PublicKey), 256},
		{"ECDSA-P256", pkix(&ecKey.PublicKey), 65},
		{"X25519", pkix(xKey.PublicKey()), 32},
		{"ML-KEM-768", pq, 1184},
	} {
		if got, err := spkiKeySize(tt.alg, tt.der); err != nil || got != tt.want {
			t.Errorf("%s: %d, %v; want %d", tt.alg, got, err, tt.want)
		}
	}
	if _, err := spkiKeySize("X25519", append(pq, 0)); err == nil {
		t.Error("trailing data should fail")
	}
}

func TestLoadOpenSSL(t *testing.T) {
	dir := t.TempDir()
	if o, err := LoadOpenSSL(filepath.Join(dir, "missing")); o != nil || err != nil {
		t.Errorf("missing dir: %v, %v", o, err)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "version.txt"), []byte("OpenSSL 3.5.9 29 Sep 2026\n"))
	write(t, filepath.Join(dir, "X25519", "pub.der"), der)
	write(t, filepath.Join(dir, "X25519", "ct"), make([]byte, 32))
	write(t, filepath.Join(dir, "X25519", "ss"), make([]byte, 32))
	o, err := LoadOpenSSL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if o.Version != "OpenSSL 3.5.9 29 Sep 2026" || len(o.Sizes) != 3 || o.Sizes[[2]string{"X25519", FieldPublicKey}] != 32 {
		t.Errorf("loaded %+v", o)
	}
	write(t, filepath.Join(dir, "RSA-2048", "sig"), make([]byte, 256))
	if _, err := LoadOpenSSL(dir); err == nil {
		t.Error("an algorithm without pub.der should fail")
	}
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// pipeDialer serves each connection over net.Pipe, so the handshake code runs
// without sockets.
func pipeDialer(t *testing.T, cfg *tls.Config) dialer {
	return func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go serveConn(s, cfg)
		t.Cleanup(func() { _ = s.Close() })
		return c, nil
	}
}

func TestTLSHandshakes(t *testing.T) {
	cert, err := benchCertificate()
	if err != nil {
		t.Fatal(err)
	}
	prof := Profile{Name: "test", DelayMs: 20, LossPct: 1, MTU: 1500}
	res, err := benchClients(context.Background(), Config{Warmup: 1, MinIters: 3, MaxIters: 3}, "test-env", prof, cert, pipeDialer(t, serverConfig(cert)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2*len(TLSClients) {
		t.Fatalf("%d results, want %d", len(res), 2*len(TLSClients))
	}
	by := map[string]TLSResult{}
	for _, r := range res {
		if r.Env != "test-env" || r.Profile != prof || r.N != 3 || r.Failures != 0 || r.P50 <= 0 {
			t.Errorf("%+v", r)
		}
		if r.ClientBytes < r.ClientHelloBytes || r.ServerBytes < r.ServerHelloBytes {
			t.Errorf("%s: totals smaller than the hellos: %+v", r.Client, r)
		}
		if r.Op == OpConnectHandshake && r.P50 < by[r.Client].P50 {
			t.Errorf("%s: connect+handshake p50 below handshake p50", r.Client)
		}
		by[r.Client] = r
	}
	classical, hybrid, def := by["classical-x25519"], by["hybrid-x25519mlkem768"], by["go-default"]
	if classical.Group != "X25519" || hybrid.Group != "X25519MLKEM768" || def.Group != "X25519MLKEM768" {
		t.Errorf("groups: %s %s %s", classical.Group, hybrid.Group, def.Group)
	}
	// One key share each, so the ClientHellos differ by exactly the share
	// sizes: 1216 - 32 bytes (draft-ietf-tls-ecdhe-mlkem; RFC 7748).
	if d := hybrid.ClientHelloBytes - classical.ClientHelloBytes; d != 1184 {
		t.Errorf("hybrid ClientHello is %d bytes larger than classical, want 1184 (%d vs %d)", d, hybrid.ClientHelloBytes, classical.ClientHelloBytes)
	}
	// The server's share grows by the ML-KEM ciphertext: 1120 - 32.
	if d := hybrid.ServerHelloBytes - classical.ServerHelloBytes; d != 1088 {
		t.Errorf("hybrid ServerHello is %d bytes larger, want 1088", d)
	}
	if def.ClientHelloBytes <= hybrid.ClientHelloBytes {
		t.Errorf("Go's default ClientHello (%d) should carry an X25519 share on top of the hybrid one (%d)", def.ClientHelloBytes, hybrid.ClientHelloBytes)
	}
}

func TestTLSFailuresAreCounted(t *testing.T) {
	cert, err := benchCertificate()
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(context.Context) (net.Conn, error) { return nil, errors.New("refused") }
	_, err = benchClient(context.Background(), Config{MinIters: 2, MaxIters: 2}, clientConfig(cert, nil), refuse)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("err = %v", err)
	}
}

func TestFirstRecord(t *testing.T) {
	for _, tt := range []struct {
		prefix []byte
		typ    byte
		want   int
		ok     bool
	}{
		{[]byte{22, 3, 1, 0x05, 0xc8, 1}, 1, 5 + 0x5c8, true},
		{[]byte{22, 3, 3, 0x00, 0x7a, 2}, 2, 5 + 0x7a, true},
		{[]byte{22, 3, 3, 0x00, 0x7a, 2}, 1, 0, false},
		{[]byte{21, 3, 3, 0x00, 0x02, 2}, 2, 0, false},
		{[]byte{22, 3}, 1, 0, false},
	} {
		got, err := firstRecord(tt.prefix, tt.typ)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("firstRecord(%v, %d) = %d, %v", tt.prefix, tt.typ, got, err)
		}
	}
}

func TestEnvironment(t *testing.T) {
	rows := Environment("e", map[string]string{"zeta": "1", "alpha": "2"})
	keys := map[string]string{}
	for _, r := range rows {
		if r.Env != "e" || r.Value == "" {
			t.Errorf("row %+v", r)
		}
		keys[r.Key] = r.Value
	}
	for _, k := range []string{"date_utc", "goos", "goarch", "go_version", "num_cpu", "cpu_model", "memory_bytes", "kernel", "cpu_governor", "circl_version", "alpha", "zeta"} {
		if keys[k] == "" {
			t.Errorf("missing %s", k)
		}
	}
	if rows[len(rows)-2].Key != "alpha" {
		t.Error("extra facts should be sorted")
	}
}

func TestWriteCSVsAndLoadNetem(t *testing.T) {
	dir := t.TempDir()
	netemDir := filepath.Join(dir, "netem")
	tl := TLSResult{Env: EnvNetem, Profile: Profile{Name: "rtt40", DelayMs: 20, MTU: 1500}, Client: "c", Group: "X25519",
		ClientHelloBytes: 300, Op: OpHandshake, Stats: Stats{N: 2, Mean: 1.5, P50: 1, P99: 2, Min: 1, Max: 2}}
	data, err := json.Marshal(NetemRun{Env: []EnvRow{{EnvNetem, "kernel", "Linux 6"}, {EnvNetem, "date_utc", "x"}}, TLS: []TLSResult{tl}})
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(netemDir, "rtt40.json"), data)
	write(t, filepath.Join(netemDir, "rtt150.json"), data)
	runs, err := LoadNetem(netemDir)
	if err != nil || len(runs) != 2 || runs[0].TLS[0] != tl {
		t.Fatalf("LoadNetem = %+v, %v", runs, err)
	}
	if env := netemEnv(runs); len(env) != 1 || env[0].Key != "kernel" {
		t.Errorf("netemEnv = %+v; want the kernel once, without dates", env)
	}
	if env := netemEnv(nil); len(env) != 1 || env[0].Key != "status" {
		t.Errorf("netemEnv(nil) = %+v", env)
	}
	write(t, filepath.Join(netemDir, "bad.json"), []byte(`{"tls":[]}`))
	if _, err := LoadNetem(netemDir); err == nil {
		t.Error("a run without results should fail")
	}

	rep := &Report{
		Primitives: []PrimitiveResult{{"X25519", ImplStdlib, OpKeygen, Stats{N: 1, Mean: 10, P50: 10, P99: 10, Min: 10, Max: 10}}},
		Sizes:      []SizeRow{{SizeResult: SizeResult{"X25519", ImplStdlib, FieldPublicKey, 32, false}, DB: 32, Agrees: "yes"}},
		TLS:        []TLSResult{tl, {Env: EnvHost, Profile: Loopback, Client: "c", Op: OpHandshake, Stats: Stats{N: 1}}},
		Env:        []EnvRow{{EnvHost, "goos", "darwin"}},
	}
	out := filepath.Join(dir, "out")
	if err := WriteCSVs(rep, out); err != nil {
		t.Fatal(err)
	}
	read := func(name string) [][]string {
		f, err := os.Open(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		rows, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if rows := read("rq4_primitives.csv"); len(rows) != 2 || rows[1][0] != EnvHost || rows[1][6] != "10" {
		t.Errorf("primitives %v", rows)
	}
	if rows := read("rq4_sizes.csv"); len(rows) != 2 || rows[1][6] != "" || rows[1][7] != "yes" {
		t.Errorf("sizes %v (an absent OpenSSL value is empty, not 0)", rows)
	}
	rows := read("rq4_tls.csv")
	if len(rows) != 3 || rows[1][0] != EnvNetem || rows[2][0] != EnvHost && rows[1][3] != "40" {
		t.Errorf("tls %v", rows)
	}
	if rows[1][3] != "40" {
		t.Errorf("rtt_added_ms = %s, want twice the one-way delay", rows[1][3])
	}
	if rows := read("rq4_environment.csv"); len(rows) != 2 {
		t.Errorf("environment %v", rows)
	}
}
