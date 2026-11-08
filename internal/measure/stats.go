package measure

import (
	"encoding/csv"
	"math"
	"os"
	"strconv"
)

// Proportion is k of n, with its Wilson score 95% interval (Wilson 1927),
// which stays inside [0, 1] and behaves for small n and for k near 0 or n.
type Proportion struct {
	K, N      int
	Value     float64
	Low, High float64
}

const z95 = 1.959963984540054

// Wilson returns k of n with its 95% interval. n = 0 gives zeros.
func Wilson(k, n int) Proportion {
	if n == 0 {
		return Proportion{K: k, N: n}
	}
	p := float64(k) / float64(n)
	nf := float64(n)
	denom := 1 + z95*z95/nf
	center := (p + z95*z95/(2*nf)) / denom
	half := z95 * math.Sqrt(p*(1-p)/nf+z95*z95/(4*nf*nf)) / denom
	return Proportion{K: k, N: n, Value: p, Low: math.Max(0, center-half), High: math.Min(1, center+half)}
}

func f4(x float64) string { return strconv.FormatFloat(math.Round(x*1e4)/1e4, 'f', 4, 64) }

func writeCSV(path string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.WriteAll(rows); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
