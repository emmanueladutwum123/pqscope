// Package network is the network layer. It probes live endpoints:
//
//   - TLS: a hand-built TLS 1.3 ClientHello offering a configurable group list.
//     The ServerHello or HelloRetryRequest names the group the server picked.
//     The prober reads nothing after it and never completes the key exchange.
//   - TLS certificates: a separate full handshake with crypto/tls collects
//     the certificate chain, then closes without sending application data.
//   - SSH: the identification banner and the server's KEXINIT, which lists the
//     key exchange, host key, cipher and MAC algorithms it offers. The prober
//     sends only its own identification string.
//
// Responsible-scanning limits are enforced here, not left to callers:
//
//   - a global rate limit (default 50 connections per second);
//   - one connection at a time per host;
//   - a timeout on every connection (default 5 s, at most 30 s);
//   - at most two retries;
//   - an exclude list checked against host names and every resolved address.
//
// See docs/scanning.md for the contact and opt-out policy.
package network

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/discover/config"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// ProjectURL identifies pqscope to the hosts it probes.
const ProjectURL = "https://github.com/emmanueladutwum123/pqscope"

// Probe kinds.
const (
	ProbeTLS = "tls"
	ProbeSSH = "ssh"
)

// Confidence values. A ServerHello reports what was negotiated; a KEXINIT
// lists what the server offers, which a client may or may not pick.
const (
	NegotiatedConfidence = 1.0
	OfferedConfidence    = 0.9
)

// Target is one endpoint to probe.
type Target struct {
	Probe string
	Host  string
	Port  int
}

// String returns host:port.
func (t Target) String() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// ParseTarget reads "host", "host:port", "[v6]:port", "tls://host[:port]" or
// "ssh://host[:port]". Port 22 means SSH; anything else TLS, on 443 by
// default.
func ParseTarget(s string) (Target, error) {
	s = strings.TrimSpace(s)
	probe := ""
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		probe, s = strings.ToLower(scheme), rest
		if probe != ProbeTLS && probe != ProbeSSH {
			return Target{}, fmt.Errorf("target %q: unknown scheme %q", s, scheme)
		}
	}
	s = strings.TrimSuffix(s, "/")
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		host, portStr = strings.Trim(s, "[]"), ""
	}
	port := 0
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("target %q: bad port", s)
		}
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return Target{}, fmt.Errorf("target %q: bad host", s)
	}
	switch {
	case probe == ProbeSSH && port == 0:
		port = 22
	case probe == "" && port == 22:
		probe = ProbeSSH
	case port == 0:
		port = 443
	}
	if probe == "" {
		probe = ProbeTLS
	}
	return Target{Probe: probe, Host: host, Port: port}, nil
}

// ParseTargets reads one target per line, ignoring blank lines and "#"
// comments.
func ParseTargets(r io.Reader) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if strings.TrimSpace(line) == "" {
			continue
		}
		t, err := ParseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, t)
	}
	return out, sc.Err()
}

// Options configures a Prober. Zero values take the defaults.
type Options struct {
	Groups    []string // offered TLS groups, most preferred first; default DefaultGroups
	Shares    int      // key shares sent, for the first groups; default 2
	Rate      float64  // connections per second; default DefaultRate, at most MaxRate
	Timeout   time.Duration
	Retries   int // extra attempts after a connection failure; at most MaxRetries
	Workers   int // hosts probed in parallel; default 16
	Handshake bool
	Exclude   *Exclude
	Dialer    Dialer
	Resolver  Resolver
	Version   string // pqscope version, sent in the SSH identification string
}

// Handshake is what a full crypto/tls handshake showed.
type Handshake struct {
	Version      string        `json:"version,omitempty"`
	CipherSuite  string        `json:"cipher_suite,omitempty"`
	Group        string        `json:"group,omitempty"` // as negotiated with Go's default preferences
	Certificates []Certificate `json:"certificates,omitempty"`
	Error        string        `json:"error,omitempty"`

	raw [][]byte // DER of each certificate, for findings
}

// Certificate summarises one certificate of the chain.
type Certificate struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature"`
	NotAfter  string `json:"not_after"`
}

// Record is the result for one target: one JSONL line of `pqscope net`.
type Record struct {
	Target    string          `json:"target"`
	Probe     string          `json:"probe"`
	Address   string          `json:"address,omitempty"` // the IP address connected to
	Time      time.Time       `json:"time"`
	Skipped   string          `json:"skipped,omitempty"`
	Attempts  int             `json:"attempts,omitempty"`
	Hello     *Hello          `json:"hello,omitempty"`
	Handshake *Handshake      `json:"handshake,omitempty"`
	SSH       *SSH            `json:"ssh,omitempty"`
	Findings  []model.Finding `json:"findings"`
}

// Prober runs probes within the responsible-scanning limits.
type Prober struct {
	opts    Options
	groups  []uint16
	limiter *Limiter
	db      *knowledge.DB
	names   *config.Scanner
	ident   string
}

// New validates options and returns a Prober.
func New(db *knowledge.DB, names *config.Scanner, opts Options) (*Prober, error) {
	if opts.Rate == 0 {
		opts.Rate = DefaultRate
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Workers == 0 {
		opts.Workers = 16
	}
	if opts.Shares == 0 {
		opts.Shares = 2
	}
	if len(opts.Groups) == 0 {
		opts.Groups = DefaultGroups
	}
	switch {
	case !(opts.Rate > 0 && opts.Rate <= MaxRate):
		return nil, fmt.Errorf("network: rate %v outside (0, %v] connections per second", opts.Rate, MaxRate)
	case opts.Timeout < 0 || opts.Timeout > MaxTimeout:
		return nil, fmt.Errorf("network: timeout %v outside (0, %v]", opts.Timeout, MaxTimeout)
	case opts.Retries < 0 || opts.Retries > MaxRetries:
		return nil, fmt.Errorf("network: retries %d outside [0, %d]", opts.Retries, MaxRetries)
	case opts.Workers < 0:
		return nil, errors.New("network: negative workers")
	}
	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{}
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	p := &Prober{opts: opts, limiter: NewLimiter(opts.Rate), db: db, names: names}
	for _, g := range opts.Groups {
		id, ok := GroupID(g)
		if !ok {
			return nil, fmt.Errorf("network: unknown TLS group %q", g)
		}
		p.groups = append(p.groups, id)
	}
	version := opts.Version
	if version == "" {
		version = "dev"
	}
	// RFC 4253, 4.2: SSH-2.0-softwareversion SP comments. The comment points
	// operators to the project page and its opt-out.
	p.ident = "SSH-2.0-pqscope_" + strings.ReplaceAll(version, "-", "_") + " +" + ProjectURL
	return p, nil
}

// Run probes every target and calls emit once per target, from one goroutine
// at a time. Targets on the same host are probed one after another; distinct
// hosts are probed in parallel, all under the global rate limit.
func (p *Prober) Run(ctx context.Context, targets []Target, emit func(Record)) error {
	byHost := map[string][]Target{}
	var hosts []string
	for _, t := range targets {
		h := strings.ToLower(t.Host)
		if _, ok := byHost[h]; !ok {
			hosts = append(hosts, h)
		}
		byHost[h] = append(byHost[h], t)
	}
	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range min(p.opts.Workers, max(len(hosts), 1)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				for _, t := range byHost[h] {
					if ctx.Err() != nil {
						return
					}
					r := p.probe(ctx, t)
					mu.Lock()
					emit(r)
					mu.Unlock()
				}
			}
		}()
	}
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

func (p *Prober) probe(ctx context.Context, t Target) Record {
	r := Record{Target: t.String(), Probe: t.Probe, Time: time.Now().UTC(), Findings: []model.Finding{}}
	addr, skip := p.resolve(ctx, t)
	if skip != "" {
		r.Skipped = skip
		return r
	}
	r.Address = addr
	switch t.Probe {
	case ProbeTLS:
		h := p.hello(ctx, t, addr, &r.Attempts)
		r.Hello = &h
		if p.opts.Handshake {
			hs := p.handshake(ctx, t, addr, &r.Attempts)
			r.Handshake = &hs
		}
	case ProbeSSH:
		s := p.ssh(ctx, addr, &r.Attempts)
		r.SSH = &s
	}
	r.Findings = p.findings(t, r)
	return r
}

// resolve returns the address to connect to, or why the target is skipped.
func (p *Prober) resolve(ctx context.Context, t Target) (string, string) {
	if p.opts.Exclude.Host(t.Host) {
		return "", "excluded"
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(t.Host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		rctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
		defer cancel()
		addrs, err = p.opts.Resolver.LookupNetIP(rctx, "ip", t.Host)
		if err != nil || len(addrs) == 0 {
			return "", "unresolvable"
		}
	}
	// A host is skipped if any of its addresses is excluded, so a DNS change
	// can't route the probe onto an excluded network.
	for _, a := range addrs {
		if p.opts.Exclude.Addr(a) {
			return "", "excluded address " + a.String()
		}
	}
	return net.JoinHostPort(addrs[0].Unmap().String(), strconv.Itoa(t.Port)), ""
}

// connect opens a rate-limited connection with a deadline, retrying failed
// dials up to Retries times.
func (p *Prober) connect(ctx context.Context, addr string, attempts *int) (net.Conn, error) {
	var err error
	for try := 0; try <= p.opts.Retries; try++ {
		if err := p.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		*attempts++
		dctx, cancel := context.WithTimeout(ctx, p.opts.Timeout)
		var c net.Conn
		c, err = p.opts.Dialer.DialContext(dctx, "tcp", addr)
		cancel()
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(p.opts.Timeout))
			return c, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, err
}

func serverName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

func (p *Prober) hello(ctx context.Context, t Target, addr string, attempts *int) Hello {
	h := Hello{}
	for _, g := range p.groups {
		h.Offered = append(h.Offered, GroupName(g))
	}
	msg, err := buildClientHello(serverName(t.Host), p.groups, p.opts.Shares)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	c, err := p.connect(ctx, addr, attempts)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	defer func() { _ = c.Close() }() // the probe ends here; nothing to flush
	if _, err := c.Write(msg); err != nil {
		h.Error = err.Error()
		return h
	}
	got, err := readServerHello(c)
	got.Offered = h.Offered
	if err != nil {
		got.Error = err.Error()
	}
	return got
}

func (p *Prober) handshake(ctx context.Context, t Target, addr string, attempts *int) Handshake {
	var hs Handshake
	c, err := p.connect(ctx, addr, attempts)
	if err != nil {
		hs.Error = err.Error()
		return hs
	}
	// Verification is off on purpose: the probe inventories the chain a server
	// presents, including self-signed and expired certificates.
	tc := tls.Client(c, &tls.Config{ServerName: serverName(t.Host), InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // inventory, not trust
	defer func() { _ = tc.Close() }()
	if err := tc.HandshakeContext(ctx); err != nil {
		hs.Error = err.Error()
		return hs
	}
	st := tc.ConnectionState()
	hs.Version = tls.VersionName(st.Version)
	hs.CipherSuite = tls.CipherSuiteName(st.CipherSuite)
	if st.CurveID != 0 {
		hs.Group = st.CurveID.String()
	}
	for _, cert := range st.PeerCertificates {
		c := Certificate{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
			Signature: cert.SignatureAlgorithm.String(), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339)}
		for _, m := range p.names.Certificate(cert.Raw) {
			if m.Symbol == "x509:subject-public-key" {
				c.PublicKey = p.db.Name(m.Asset)
			}
		}
		hs.Certificates = append(hs.Certificates, c)
		hs.raw = append(hs.raw, cert.Raw)
	}
	return hs
}

func (p *Prober) ssh(ctx context.Context, addr string, attempts *int) SSH {
	c, err := p.connect(ctx, addr, attempts)
	if err != nil {
		return SSH{Error: err.Error()}
	}
	defer func() { _ = c.Close() }()
	s, err := probeSSH(c, p.ident)
	if err != nil {
		s.Error = err.Error()
	}
	return s
}

// findings turns a record into findings located at the target.
func (p *Prober) findings(t Target, r Record) []model.Finding {
	out := []model.Finding{}
	seen := map[string]bool{}
	add := func(assets []model.Asset, symbol, evidence string, confidence float64) {
		for _, a := range assets {
			f := model.NewFinding(a, model.Location{Layer: model.LayerNetwork, Path: t.String(), Symbol: symbol}, confidence)
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			f.RuleID = "network." + strings.SplitN(symbol, ":", 2)[0]
			f.Evidence = evidence
			out = append(out, f)
		}
	}
	if h := r.Hello; h != nil && h.Group != "" {
		symbol, verb := "tls:negotiated-group", "ServerHello selected"
		if h.HelloRetry {
			symbol, verb = "tls:hello-retry-group", "HelloRetryRequest asked for"
		}
		add(p.names.Lookup("tls-groups", h.Group), symbol,
			fmt.Sprintf("%s %s (offered %s)", verb, h.Group, strings.Join(h.Offered, ", ")), NegotiatedConfidence)
		if !h.HelloRetry {
			add(p.names.Lookup("tls13-suites", h.CipherSuite), "tls:cipher-suite", "ServerHello selected "+h.CipherSuite, NegotiatedConfidence)
		}
	}
	if hs := r.Handshake; hs != nil {
		for i, der := range hs.raw {
			for _, m := range p.names.Certificate(der) {
				add([]model.Asset{m.Asset}, fmt.Sprintf("tls:cert[%d]:%s", i, m.Symbol), m.Evidence, NegotiatedConfidence)
			}
		}
	}
	if s := r.SSH; s != nil {
		for _, list := range []struct {
			names        []string
			table, label string
		}{
			{s.Kex, "ssh-kex", "kex"}, {s.HostKey, "ssh-pubkey", "host-key"},
			{s.Ciphers, "ssh-ciphers", "cipher"}, {s.MACs, "ssh-macs", "mac"},
		} {
			for _, n := range list.names {
				add(p.names.Lookup(list.table, n), "ssh:"+list.label, fmt.Sprintf("server offers %s (%s)", n, s.Banner), OfferedConfidence)
			}
		}
	}
	return out
}
