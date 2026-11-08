package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock drives a Limiter without sleeping.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) install(l *Limiter) {
	l.now = func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
	l.sleep = func(_ context.Context, d time.Duration) error {
		c.mu.Lock()
		c.sleeps = append(c.sleeps, d)
		c.mu.Unlock()
		return nil
	}
}

func TestLimiterSpacing(t *testing.T) {
	l := NewLimiter(50)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	clock.install(l)
	for range 5 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []time.Duration{20 * time.Millisecond, 40 * time.Millisecond, 60 * time.Millisecond, 80 * time.Millisecond}
	if !slices.Equal(clock.sleeps, want) {
		t.Errorf("sleeps = %v, want %v (the first attempt goes at once)", clock.sleeps, want)
	}

	// After an idle second, there is no burst credit: attempts are spaced again.
	clock.now = clock.now.Add(time.Second)
	clock.sleeps = nil
	for range 3 {
		_ = l.Wait(context.Background())
	}
	if !slices.Equal(clock.sleeps, []time.Duration{20 * time.Millisecond, 40 * time.Millisecond}) {
		t.Errorf("after idling, sleeps = %v", clock.sleeps)
	}
}

// Concurrent callers each get their own slot.
func TestLimiterConcurrent(t *testing.T) {
	l := NewLimiter(50)
	clock := &fakeClock{now: time.Unix(1000, 0)}
	clock.install(l)
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = l.Wait(context.Background()) }()
	}
	wg.Wait()
	slices.Sort(clock.sleeps)
	if len(clock.sleeps) != 99 {
		t.Fatalf("%d of 100 callers waited, want 99", len(clock.sleeps))
	}
	for i, d := range clock.sleeps {
		if want := time.Duration(i+1) * 20 * time.Millisecond; d != want {
			t.Fatalf("slot %d = %v, want %v", i, d, want)
		}
	}
}

// With the real clock: 11 attempts at 100/s take at least 100 ms.
func TestLimiterRealTime(t *testing.T) {
	l := NewLimiter(100)
	start := time.Now()
	for range 11 {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("11 attempts at 100/s took %v", elapsed)
	}
}

func TestLimiterCancel(t *testing.T) {
	l := NewLimiter(1)
	_ = l.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

// slowAlert answers every TLS connection with an alert after a delay, so
// connections overlap if the prober allows them to.
func slowAlert(_ string, c net.Conn) {
	buf := make([]byte, 4096)
	_, _ = c.Read(buf)
	time.Sleep(15 * time.Millisecond)
	_, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, 40})
}

// One connection at a time per host; distinct hosts in parallel.
func TestPerHostConcurrency(t *testing.T) {
	d := &pipeDialer{serve: slowAlert}
	resolver := mapResolver{}
	var targets []Target
	for h := range 4 {
		host := "host" + strconv.Itoa(h) + ".test"
		resolver[host] = []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(h + 1)})}
		for port := 1; port <= 4; port++ {
			targets = append(targets, Target{ProbeTLS, host, 8440 + port})
		}
	}
	p := newProber(t, d, Options{Resolver: resolver, Handshake: true})
	var records int
	if err := p.Run(context.Background(), targets, func(Record) { records++ }); err != nil {
		t.Fatal(err)
	}
	if records != len(targets) {
		t.Errorf("%d records for %d targets", records, len(targets))
	}
	for host, n := range d.maxActive {
		if n != 1 {
			t.Errorf("%s had %d concurrent connections", host, n)
		}
	}
	if d.maxAll < 2 {
		t.Errorf("hosts were not probed in parallel (max %d connections)", d.maxAll)
	}
	if len(d.dials) != 2*len(targets) {
		t.Errorf("%d dials, want %d (ServerHello probe and handshake per target)", len(d.dials), 2*len(targets))
	}
}

// The global limit holds across hosts probed in parallel.
func TestRateLimitAcrossHosts(t *testing.T) {
	d := &pipeDialer{serve: func(_ string, c net.Conn) { _, _ = c.Write([]byte{21, 3, 3, 0, 2, 2, 40}) }}
	resolver := mapResolver{}
	var targets []Target
	for h := range 10 {
		host := "h" + strconv.Itoa(h) + ".test"
		resolver[host] = []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(h + 1)})}
		targets = append(targets, Target{ProbeTLS, host, 443})
	}
	p := newProber(t, d, Options{Resolver: resolver, Rate: 200})
	start := time.Now()
	if err := p.Run(context.Background(), targets, func(Record) {}); err != nil {
		t.Fatal(err)
	}
	// 10 connections at 200/s: the last starts at least 9 × 5 ms after the first.
	if elapsed := time.Since(start); elapsed < 45*time.Millisecond {
		t.Errorf("10 connections at 200/s finished in %v", elapsed)
	}
}

func TestRetries(t *testing.T) {
	for _, tt := range []struct {
		retries, failFirst, attempts int
		ok                           bool
	}{
		{0, 1, 1, false},
		{1, 1, 2, true},
		{2, 2, 3, true},
		{2, 5, 3, false}, // never more than two retries
	} {
		d := &pipeDialer{serve: slowAlert, failFirst: tt.failFirst}
		p := newProber(t, d, Options{Retries: tt.retries})
		r := runOne(t, p, "server.test")
		if r.Attempts != tt.attempts || (r.Hello.Error == "") != tt.ok {
			t.Errorf("retries %d, %d failures: attempts %d, hello %+v", tt.retries, tt.failFirst, r.Attempts, r.Hello)
		}
	}
}

func TestExclude(t *testing.T) {
	ex, err := ParseExclude(strings.NewReader(`
# opt-outs
optout.test
.agency.test
198.51.100.0/24
2001:db8::/32
192.0.2.99
`))
	if err != nil {
		t.Fatal(err)
	}
	resolver := mapResolver{
		"server.test":     {netip.MustParseAddr("192.0.2.10")},
		"moved.test":      {netip.MustParseAddr("192.0.2.11"), netip.MustParseAddr("198.51.100.7")},
		"www.agency.test": {netip.MustParseAddr("192.0.2.12")},
		"optout.test":     {netip.MustParseAddr("192.0.2.13")},
		"v6.test":         {netip.MustParseAddr("2001:db8::5")},
	}
	tests := map[string]string{
		"server.test":     "",
		"optout.test":     "excluded",
		"www.agency.test": "excluded",
		"agency.test":     "excluded",
		"moved.test":      "excluded address 198.51.100.7", // any resolved address counts
		"v6.test":         "excluded address 2001:db8::5",
		"198.51.100.20":   "excluded address 198.51.100.20",
		"192.0.2.99":      "excluded address 192.0.2.99",
		"missing.test":    "unresolvable",
	}
	for host, want := range tests {
		d := &pipeDialer{serve: slowAlert}
		p := newProber(t, d, Options{Exclude: ex, Resolver: resolver})
		r := runOne(t, p, host)
		if r.Skipped != want {
			t.Errorf("%s: skipped %q, want %q", host, r.Skipped, want)
		}
		if want != "" && len(d.dials) != 0 {
			t.Errorf("%s: dialed %v despite being skipped", host, d.dials)
		}
	}
	if _, err := ParseExclude(strings.NewReader("10.0.0.0/33\n")); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func TestTimeout(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	d := &pipeDialer{serve: func(_ string, c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		<-block // never answer
	}}
	p := newProber(t, d, Options{Timeout: 50 * time.Millisecond})
	start := time.Now()
	r := runOne(t, p, "server.test")
	if !strings.Contains(r.Hello.Error, "timeout") || time.Since(start) > 2*time.Second {
		t.Errorf("hello = %+v after %v", r.Hello, time.Since(start))
	}
}
