package network

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// pipeDialer connects to in-process servers over net.Pipe: no sockets.
type pipeDialer struct {
	mu        sync.Mutex
	serve     func(addr string, c net.Conn)
	failFirst int // fail this many dials before succeeding
	dials     []string
	active    map[string]int
	maxActive map[string]int
	maxAll    int
	all       int
}

func (d *pipeDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, addr)
	if d.failFirst > 0 {
		d.failFirst--
		d.mu.Unlock()
		return nil, errors.New("connection refused")
	}
	host, _, _ := net.SplitHostPort(addr)
	if d.active == nil {
		d.active, d.maxActive = map[string]int{}, map[string]int{}
	}
	d.active[host]++
	d.all++
	d.maxActive[host] = max(d.maxActive[host], d.active[host])
	d.maxAll = max(d.maxAll, d.all)
	d.mu.Unlock()
	client, server := net.Pipe()
	go func() {
		d.serve(addr, server)
		_ = server.Close()
	}()
	return &trackedConn{Conn: client, done: func() {
		d.mu.Lock()
		d.active[host]--
		d.all--
		d.mu.Unlock()
	}}, nil
}

type trackedConn struct {
	net.Conn
	once sync.Once
	done func()
}

func (c *trackedConn) Close() error {
	c.once.Do(c.done)
	return c.Conn.Close()
}

type mapResolver map[string][]netip.Addr

func (r mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "server.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"server.test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func newProber(t *testing.T, d Dialer, opts Options) *Prober {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	names, err := config.New(db)
	if err != nil {
		t.Fatal(err)
	}
	opts.Dialer = d
	if opts.Resolver == nil {
		opts.Resolver = mapResolver{"server.test": {netip.MustParseAddr("192.0.2.10")}}
	}
	if opts.Rate == 0 {
		opts.Rate = MaxRate
	}
	p, err := New(db, names, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runOne(t *testing.T, p *Prober, target string) Record {
	t.Helper()
	tg, err := ParseTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	var got []Record
	if err := p.Run(context.Background(), []Target{tg}, func(r Record) { got = append(got, r) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d records", len(got))
	}
	return got[0]
}

func goTLSServer(t *testing.T, cfg *tls.Config) func(string, net.Conn) {
	cert := selfSigned(t)
	return func(_ string, c net.Conn) {
		cfg := cfg.Clone()
		cfg.Certificates = []tls.Certificate{cert}
		_ = tls.Server(c, cfg).Handshake() // fails once the prober hangs up; that is expected
	}
}

// The ServerHello probe tells hybrid from classical against a Go server. Go
// ignores the order of CurvePreferences, so server-side ordering is exercised
// against OpenSSL in the integration tests instead.
func TestHelloAgainstGo(t *testing.T) {
	tests := []struct {
		name       string
		server     *tls.Config
		group      string
		retry      bool
		alert      string
		findingSym string
	}{
		{"hybrid preferred", &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}, "X25519MLKEM768", false, "", "tls:negotiated-group"},
		{"classical only", &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}, "x25519", false, "", "tls:negotiated-group"},
		{"group without a share", &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}}, "secp256r1", true, "", "tls:hello-retry-group"},
		{"Go defaults", &tls.Config{}, "X25519MLKEM768", false, "", "tls:negotiated-group"},
		{"TLS 1.2 only", &tls.Config{MaxVersion: tls.VersionTLS12}, "", false, "protocol_version", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProber(t, &pipeDialer{serve: goTLSServer(t, tt.server)}, Options{})
			r := runOne(t, p, "server.test")
			h := r.Hello
			if h == nil || h.Group != tt.group || h.HelloRetry != tt.retry || h.Alert != tt.alert || h.Error != "" {
				t.Fatalf("hello = %+v", h)
			}
			if !slices.Equal(h.Offered, []string{"X25519MLKEM768", "x25519", "secp256r1"}) {
				t.Errorf("offered = %v", h.Offered)
			}
			if tt.group != "" && h.Version != "TLS 1.3" {
				t.Errorf("version = %q", h.Version)
			}
			if r.Address != "192.0.2.10:443" || r.Target != "server.test:443" {
				t.Errorf("address %q target %q", r.Address, r.Target)
			}
			var groups []model.Finding
			for _, f := range r.Findings {
				if strings.HasSuffix(f.Location.Symbol, "-group") {
					groups = append(groups, f)
				}
				if err := f.Validate(); err != nil {
					t.Error(err)
				}
			}
			if tt.findingSym == "" {
				if len(groups) != 0 {
					t.Errorf("group findings without a negotiated group: %+v", groups)
				}
				return
			}
			if len(groups) != 1 || groups[0].Location.Symbol != tt.findingSym || groups[0].Location.Layer != model.LayerNetwork ||
				groups[0].Location.Path != "server.test:443" {
				t.Fatalf("group findings = %+v", groups)
			}
		})
	}
}

func TestHybridFindingAsset(t *testing.T) {
	p := newProber(t, &pipeDialer{serve: goTLSServer(t, &tls.Config{})}, Options{})
	r := runOne(t, p, "server.test")
	var assets []string
	for _, f := range r.Findings {
		assets = append(assets, f.Location.Symbol+" "+f.Asset.Params+" "+f.Asset.Quantum)
	}
	for _, want := range []string{"tls:negotiated-group X25519MLKEM768 hybrid", "tls:cipher-suite 128 weakened"} {
		if !slices.Contains(assets, want) {
			t.Errorf("missing %q in %v", want, assets)
		}
	}
}

func TestCustomGroups(t *testing.T) {
	server := goTLSServer(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024, tls.CurveP384}})
	p := newProber(t, &pipeDialer{serve: server}, Options{Groups: []string{"SecP384r1MLKEM1024", "secp384r1"}})
	if h := runOne(t, p, "server.test").Hello; h.Group != "SecP384r1MLKEM1024" || h.HelloRetry {
		t.Errorf("hello = %+v", h)
	}
	p = newProber(t, &pipeDialer{serve: server}, Options{Groups: []string{"SecP256r1MLKEM768", "secp384r1"}, Shares: 1})
	if h := runOne(t, p, "server.test").Hello; h.Group != "secp384r1" || !h.HelloRetry {
		t.Errorf("only a SecP256r1MLKEM768 share sent: hello = %+v", h)
	}
}

func TestHandshakeCertificates(t *testing.T) {
	p := newProber(t, &pipeDialer{serve: goTLSServer(t, &tls.Config{})}, Options{Handshake: true})
	r := runOne(t, p, "server.test")
	hs := r.Handshake
	if hs == nil || hs.Error != "" || hs.Version != "TLS 1.3" || hs.Group != "X25519MLKEM768" || len(hs.Certificates) != 1 {
		t.Fatalf("handshake = %+v", hs)
	}
	if c := hs.Certificates[0]; c.PublicKey != "ECDSA-P256" || c.Signature != "ECDSA-SHA256" || !strings.Contains(c.Subject, "server.test") {
		t.Errorf("certificate = %+v", c)
	}
	var syms []string
	for _, f := range r.Findings {
		syms = append(syms, f.Location.Symbol+" "+f.Asset.Algorithm+" "+f.Asset.Params)
	}
	for _, want := range []string{"tls:cert[0]:x509:subject-public-key ECDSA P-256", "tls:cert[0]:x509:signature ECDSA P-256", "tls:cert[0]:x509:signature-hash SHA-2 SHA-256"} {
		if !slices.Contains(syms, want) {
			t.Errorf("missing %q in %v", want, syms)
		}
	}
}

func TestNotTLS(t *testing.T) {
	p := newProber(t, &pipeDialer{serve: func(_ string, c net.Conn) {
		_, _ = bufio.NewReader(c).Peek(1)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
	}}, Options{})
	if h := runOne(t, p, "server.test").Hello; h.Error != errNotTLS.Error() {
		t.Errorf("hello = %+v", h)
	}
}

func goSSHServer(t *testing.T, kex []string) func(string, net.Conn) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true, Config: ssh.Config{KeyExchanges: kex}}
	cfg.AddHostKey(signer)
	return func(_ string, c net.Conn) { _, _, _, _ = ssh.NewServerConn(c, cfg) }
}

func TestSSHAgainstGo(t *testing.T) {
	p := newProber(t, &pipeDialer{serve: goSSHServer(t, []string{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"})}, Options{})
	r := runOne(t, p, "server.test:22")
	s := r.SSH
	if s == nil || s.Error != "" || !strings.HasPrefix(s.Banner, "SSH-2.0-Go") {
		t.Fatalf("ssh = %+v", s)
	}
	for _, k := range []string{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"} {
		if !slices.Contains(s.Kex, k) {
			t.Errorf("kex %v missing %s", s.Kex, k)
		}
	}
	if !slices.Contains(s.HostKey, "ssh-ed25519") || len(s.Ciphers) == 0 || len(s.MACs) == 0 {
		t.Errorf("ssh = %+v", s)
	}
	var syms []string
	for _, f := range r.Findings {
		syms = append(syms, f.Location.Symbol+" "+f.Asset.Params)
		if f.Confidence != OfferedConfidence {
			t.Errorf("%s: confidence %v", f.Location.Symbol, f.Confidence)
		}
	}
	for _, want := range []string{"ssh:kex mlkem768x25519-sha256", "ssh:kex X25519", "ssh:kex P-256", "ssh:host-key Ed25519"} {
		if !slices.Contains(syms, want) {
			t.Errorf("missing %q in %v", want, syms)
		}
	}
}

// The SSH probe sends its identification string and nothing more.
func TestSSHSendsOnlyIdentification(t *testing.T) {
	sent := make(chan string, 1)
	p := newProber(t, &pipeDialer{serve: func(_ string, c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-Test\r\n")
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		// A minimal KEXINIT: message 20, cookie, ten empty name-lists, flag, reserved.
		payload := append([]byte{20}, make([]byte, 16+10*4+1+4)...)
		pad := 8 - (len(payload)+5)%8
		if pad < 4 {
			pad += 8
		}
		packet := append([]byte{byte(pad)}, payload...)
		packet = append(packet, make([]byte, pad)...)
		n := len(packet)
		_, _ = c.Write(append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, packet...))
		rest, _ := io.ReadAll(br)
		sent <- line + string(rest)
	}}, Options{Version: "1.2.3"})
	if r := runOne(t, p, "server.test:22"); r.SSH.Error != "" {
		t.Fatalf("ssh = %+v", r.SSH)
	}
	if got := <-sent; got != "SSH-2.0-pqscope_1.2.3 +"+ProjectURL+"\r\n" {
		t.Errorf("client sent %q", got)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in    string
		want  Target
		error bool
	}{
		{"example.org", Target{ProbeTLS, "example.org", 443}, false},
		{"example.org:8443", Target{ProbeTLS, "example.org", 8443}, false},
		{"example.org:22", Target{ProbeSSH, "example.org", 22}, false},
		{"ssh://example.org", Target{ProbeSSH, "example.org", 22}, false},
		{"ssh://example.org:2222", Target{ProbeSSH, "example.org", 2222}, false},
		{"tls://example.org:22", Target{ProbeTLS, "example.org", 22}, false},
		{"[2001:db8::1]:443", Target{ProbeTLS, "2001:db8::1", 443}, false},
		{"192.0.2.1", Target{ProbeTLS, "192.0.2.1", 443}, false},
		{"https://example.org", Target{}, true},
		{"example.org:99999", Target{}, true},
		{"", Target{}, true},
	}
	for _, tt := range tests {
		got, err := ParseTarget(tt.in)
		if (err != nil) != tt.error || got != tt.want {
			t.Errorf("ParseTarget(%q) = %+v, %v", tt.in, got, err)
		}
	}
	ts, err := ParseTargets(strings.NewReader("# federal sample\nexample.org\n\nssh://example.org # also SSH\n"))
	if err != nil || len(ts) != 2 || ts[1].Probe != ProbeSSH {
		t.Errorf("ParseTargets = %+v, %v", ts, err)
	}
}

func TestOptionLimits(t *testing.T) {
	db, _ := knowledge.Default()
	names, _ := config.New(db)
	for _, o := range []Options{
		{Retries: MaxRetries + 1}, {Rate: MaxRate * 2}, {Rate: -1}, {Timeout: MaxTimeout + time.Second},
		{Groups: []string{"X25519Kyber768Draft00"}},
	} {
		if _, err := New(db, names, o); err == nil {
			t.Errorf("New(%+v) accepted options outside the limits", o)
		}
	}
	p, err := New(db, names, Options{})
	if err != nil || p.opts.Rate != DefaultRate || p.opts.Timeout != DefaultTimeout || p.opts.Retries != 0 {
		t.Errorf("defaults: %+v, %v", p.opts, err)
	}
}
