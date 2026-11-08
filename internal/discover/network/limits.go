package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Responsible-scanning limits. They are enforced by the prober itself, not
// left to the caller: Options outside these bounds are rejected.
const (
	DefaultRate    = 50.0 // connections per second, across all hosts
	MaxRate        = 1000.0
	DefaultTimeout = 5 * time.Second
	MaxTimeout     = 30 * time.Second
	DefaultRetries = 1
	MaxRetries     = 2 // "never retries more than twice"
)

// Limiter spaces connection attempts evenly at a fixed rate, with no burst:
// each Wait returns at least 1/rate after the previous one was scheduled.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

// NewLimiter returns a limiter allowing perSecond attempts per second.
func NewLimiter(perSecond float64) *Limiter {
	return &Limiter{
		interval: time.Duration(float64(time.Second) / perSecond),
		now:      time.Now,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}
}

// Wait blocks until the caller may open a connection.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	now := l.now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	if d := at.Sub(now); d > 0 {
		return l.sleep(ctx, d)
	}
	return nil
}

// Exclude is a list of hosts and networks never to connect to.
type Exclude struct {
	prefixes []netip.Prefix
	names    []string // exact host names, or ".example.org" for a domain and its subdomains
}

// ParseExclude reads one entry per line: an IP address, a CIDR prefix, a host
// name, or a domain starting with "." Blank lines and "#" comments are
// ignored.
func ParseExclude(r io.Reader) (*Exclude, error) {
	e := &Exclude{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case strings.Contains(line, "/"):
			p, err := netip.ParsePrefix(line)
			if err != nil {
				return nil, fmt.Errorf("exclude line %d: %w", n, err)
			}
			e.prefixes = append(e.prefixes, p.Masked())
		default:
			if a, err := netip.ParseAddr(line); err == nil {
				e.prefixes = append(e.prefixes, netip.PrefixFrom(a, a.BitLen()))
			} else {
				e.names = append(e.names, strings.ToLower(strings.TrimSuffix(line, ".")))
			}
		}
	}
	return e, sc.Err()
}

// Host reports whether a host name is excluded.
func (e *Exclude) Host(name string) bool {
	if e == nil {
		return false
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, n := range e.names {
		if name == n || (strings.HasPrefix(n, ".") && (strings.HasSuffix(name, n) || name == n[1:])) {
			return true
		}
	}
	return false
}

// Addr reports whether an address is excluded.
func (e *Exclude) Addr(a netip.Addr) bool {
	if e == nil {
		return false
	}
	a = a.Unmap()
	for _, p := range e.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Dialer opens connections. *net.Dialer satisfies it; tests substitute
// in-memory connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver looks up host addresses. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}
