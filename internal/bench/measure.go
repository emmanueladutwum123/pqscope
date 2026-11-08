package bench

import (
	"errors"
	"math"
	"slices"
	"time"
)

// Config controls how many times each operation runs. An operation runs
// Warmup times unrecorded, then at least MinIters times and for at least
// MinTime, but never more than MaxIters times.
type Config struct {
	Warmup   int
	MinIters int
	MaxIters int
	MinTime  time.Duration
}

// Default is the configuration `make bench` uses. MinIters keeps p99 over at
// least 200 samples for the slowest operations (SLH-DSA-128s signing, RSA-3072
// key generation).
var Default = Config{Warmup: 5, MinIters: 200, MaxIters: 200_000, MinTime: 2 * time.Second}

// Quick runs every operation once, for tests.
var Quick = Config{MinIters: 1, MaxIters: 1}

// Stats summarises one operation's latencies in nanoseconds. Percentiles use
// the nearest-rank method over every recorded sample.
type Stats struct {
	N    int
	Mean float64
	P50  int64
	P99  int64
	Min  int64
	Max  int64
}

// measure times op under cfg. Every call is timed individually so the
// percentiles describe single operations, not batch averages; timer overhead
// (tens of nanoseconds) is included and is small next to the operations here.
func measure(cfg Config, op func() error) (Stats, error) {
	for range cfg.Warmup {
		if err := op(); err != nil {
			return Stats{}, err
		}
	}
	samples := make([]int64, 0, 1024)
	start := time.Now()
	for len(samples) < cfg.MaxIters && (len(samples) < cfg.MinIters || time.Since(start) < cfg.MinTime) {
		t0 := time.Now()
		err := op()
		d := time.Since(t0)
		if err != nil {
			return Stats{}, err
		}
		samples = append(samples, d.Nanoseconds())
	}
	return summarize(samples)
}

func summarize(samples []int64) (Stats, error) {
	if len(samples) == 0 {
		return Stats{}, errors.New("bench: no samples")
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	var sum float64
	for _, v := range s {
		sum += float64(v)
	}
	return Stats{
		N:    len(s),
		Mean: sum / float64(len(s)),
		P50:  percentile(s, 50),
		P99:  percentile(s, 99),
		Min:  s[0],
		Max:  s[len(s)-1],
	}, nil
}

// percentile returns the nearest-rank p-th percentile of sorted samples.
func percentile(sorted []int64, p float64) int64 {
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[max(rank, 1)-1]
}
