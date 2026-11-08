package bench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sync"
	"time"
)

// TLSClient is one client configuration. Groups nil means Go's default.
type TLSClient struct {
	Name   string
	Groups []tls.CurveID
}

// TLSClients are the client configurations compared. The server is crypto/tls
// with its default groups, which accept all three.
var TLSClients = []TLSClient{
	{Name: "classical-x25519", Groups: []tls.CurveID{tls.X25519}},
	{Name: "hybrid-x25519mlkem768", Groups: []tls.CurveID{tls.X25519MLKEM768}},
	// Go's default offers several groups and sends key shares for both
	// X25519MLKEM768 and X25519, so its ClientHello is the largest.
	{Name: "go-default", Groups: nil},
}

// handshakeTimeout bounds one connection, so a lost packet costs at most this
// much, and a stuck run still ends.
const handshakeTimeout = 10 * time.Second

// Profile describes the network a TLS run measured. The values are what the
// caller configured (bench/run.sh sets them with tc netem); this package does
// not change the network.
type Profile struct {
	Name    string
	DelayMs float64 // one-way delay added on each packet; RTT is twice this
	LossPct float64 // per-packet loss
	MTU     int     // 0 when unchanged
}

// Loopback is the profile of an unmodified loopback interface.
var Loopback = Profile{Name: "loopback"}

// TLSResult is one client configuration's handshakes under one profile. The
// byte counts are medians over every handshake (the ECDSA signature in the
// server's CertificateVerify varies by a byte or two).
type TLSResult struct {
	Env     string
	Profile Profile
	Client  string
	Group   string // negotiated, as crypto/tls names it

	ClientHelloBytes int // the ClientHello record, header included
	ServerHelloBytes int // the ServerHello record, header included
	ClientBytes      int // everything the client sent during the handshake
	ServerBytes      int // everything the client received during the handshake

	Op       string // OpHandshake or OpConnectHandshake
	Failures int    // connections that failed and were not timed
	Stats
}

// TLS operation names.
const (
	OpHandshake        = "tls_handshake"             // after TCP is established
	OpConnectHandshake = "tcp_connect+tls_handshake" // from dial to a usable connection
)

// dialer opens a connection to the server.
type dialer func(ctx context.Context) (net.Conn, error)

// BenchTLS starts a crypto/tls server on loopback TCP and measures every
// client configuration against it. env names where it ran.
func BenchTLS(ctx context.Context, cfg Config, env string, prof Profile) ([]TLSResult, error) {
	cert, err := benchCertificate()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := serve(ln, serverConfig(cert))
	defer srv.stop()
	var d net.Dialer
	dial := func(ctx context.Context) (net.Conn, error) { return d.DialContext(ctx, "tcp", ln.Addr().String()) }
	return benchClients(ctx, cfg, env, prof, cert, dial)
}

func benchClients(ctx context.Context, cfg Config, env string, prof Profile, cert tls.Certificate, dial dialer) ([]TLSResult, error) {
	var out []TLSResult
	for _, c := range TLSClients {
		res, err := benchClient(ctx, cfg, clientConfig(cert, c.Groups), dial)
		if err != nil {
			return nil, fmt.Errorf("tls %s %s: %w", prof.Name, c.Name, err)
		}
		for i := range res {
			res[i].Env, res[i].Profile, res[i].Client = env, prof, c.Name
		}
		out = append(out, res...)
	}
	return out, nil
}

// sample is one handshake.
type sample struct {
	connect, handshake time.Duration
	group              string
	ch, sh, c2s, s2c   int
}

// benchClient runs handshakes under cfg's iteration rules. A failed
// connection (under packet loss, a timeout) is counted, not timed; more than
// half failing is an error.
func benchClient(ctx context.Context, cfg Config, tcfg *tls.Config, dial dialer) ([]TLSResult, error) {
	for range cfg.Warmup {
		if _, err := handshake(ctx, tcfg, dial); err != nil {
			return nil, err
		}
	}
	var samples []sample
	failures := 0
	var lastErr error
	start := time.Now()
	for len(samples) < cfg.MaxIters && (len(samples) < cfg.MinIters || time.Since(start) < cfg.MinTime) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, err := handshake(ctx, tcfg, dial)
		if err != nil {
			failures++
			lastErr = err
			if failures > max(cfg.MinIters, len(samples)) {
				return nil, fmt.Errorf("%d handshakes failed: %w", failures, lastErr)
			}
			continue
		}
		samples = append(samples, s)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("no handshake succeeded: %w", lastErr)
	}
	groups := map[string]bool{}
	var hs, total, ch, sh, c2s, s2c []int64
	for _, s := range samples {
		groups[s.group] = true
		hs = append(hs, s.handshake.Nanoseconds())
		total = append(total, (s.connect + s.handshake).Nanoseconds())
		ch, sh = append(ch, int64(s.ch)), append(sh, int64(s.sh))
		c2s, s2c = append(c2s, int64(s.c2s)), append(s2c, int64(s.s2c))
	}
	if len(groups) != 1 {
		return nil, fmt.Errorf("negotiated groups changed between handshakes: %v", groups)
	}
	base := TLSResult{
		Group:            samples[0].group,
		ClientHelloBytes: int(median(ch)),
		ServerHelloBytes: int(median(sh)),
		ClientBytes:      int(median(c2s)),
		ServerBytes:      int(median(s2c)),
		Failures:         failures,
	}
	var out []TLSResult
	for _, m := range []struct {
		op string
		v  []int64
	}{{OpHandshake, hs}, {OpConnectHandshake, total}} {
		st, err := summarize(m.v)
		if err != nil {
			return nil, err
		}
		r := base
		r.Op, r.Stats = m.op, st
		out = append(out, r)
	}
	return out, nil
}

func median(v []int64) int64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return percentile(s, 50)
}

// handshake makes one connection, completes the TLS handshake and closes it.
func handshake(ctx context.Context, tcfg *tls.Config, dial dialer) (sample, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	t0 := time.Now()
	raw, err := dial(ctx)
	if err != nil {
		return sample{}, err
	}
	t1 := time.Now()
	cc := &countingConn{Conn: raw}
	tc := tls.Client(cc, tcfg)
	defer func() { _ = tc.Close() }()
	if err := tc.HandshakeContext(ctx); err != nil {
		return sample{}, err
	}
	t2 := time.Now()
	ch, err := firstRecord(cc.wrote, 1)
	if err != nil {
		return sample{}, fmt.Errorf("client hello: %w", err)
	}
	sh, err := firstRecord(cc.read, 2)
	if err != nil {
		return sample{}, fmt.Errorf("server hello: %w", err)
	}
	return sample{
		connect: t1.Sub(t0), handshake: t2.Sub(t1),
		group: tc.ConnectionState().CurveID.String(),
		ch:    ch, sh: sh, c2s: cc.nWrote, s2c: cc.nRead,
	}, nil
}

// countingConn counts bytes each way and keeps the first few of each, enough
// to read the first record's header and handshake type.
type countingConn struct {
	net.Conn
	nRead, nWrote int
	read, wrote   []byte
}

const recordPrefix = 6 // 5-byte record header, then the handshake type

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.nRead += n
	if k := min(n, recordPrefix-len(c.read)); k > 0 {
		c.read = append(c.read, p[:k]...)
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.nWrote += n
	if k := min(n, recordPrefix-len(c.wrote)); k > 0 {
		c.wrote = append(c.wrote, p[:k]...)
	}
	return n, err
}

// firstRecord returns the size of the first TLS record, header included,
// after checking it is a handshake record carrying the wanted message type
// (1 ClientHello, 2 ServerHello; RFC 8446, Sections 5.1 and 4).
func firstRecord(prefix []byte, msgType byte) (int, error) {
	if len(prefix) < recordPrefix {
		return 0, errors.New("short record")
	}
	if prefix[0] != 22 || prefix[5] != msgType {
		return 0, fmt.Errorf("record type %d, handshake type %d; want 22, %d", prefix[0], prefix[5], msgType)
	}
	return 5 + (int(prefix[3])<<8 | int(prefix[4])), nil
}

// --- server ---

// benchCertificate is a self-signed ECDSA P-256 certificate, the key type most
// TLS servers now present. Its key lives only in memory for the run.
func benchCertificate() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pqscope-bench"},
		DNSNames:     []string{"pqscope-bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// serverConfig disables session tickets so every handshake is a full one.
func serverConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
}

// clientConfig verifies the server's certificate, as a real client would, and
// keeps no session cache.
func clientConfig(cert tls.Certificate, groups []tls.CurveID) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	return &tls.Config{
		RootCAs:          roots,
		ServerName:       "pqscope-bench",
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: groups,
	}
}

type server struct {
	ln net.Listener
	wg sync.WaitGroup
}

func serve(ln net.Listener, cfg *tls.Config) *server {
	s := &server{ln: ln}
	s.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Go(func() { serveConn(c, cfg) })
		}
	})
	return s
}

// serveConn completes the handshake, then reads until the client closes.
func serveConn(c net.Conn, cfg *tls.Config) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * handshakeTimeout))
	tc := tls.Server(c, cfg)
	if tc.Handshake() == nil {
		_, _ = io.Copy(io.Discard, tc)
	}
}

func (s *server) stop() {
	_ = s.ln.Close()
	s.wg.Wait()
}
