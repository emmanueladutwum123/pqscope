package bench

import (
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
)

// Environment names.
const (
	EnvHost  = "host"         // where `pqscope bench` runs
	EnvNetem = "docker-linux" // the Linux container bench/run.sh shapes with tc netem
)

// Options configures Run.
type Options struct {
	Primitives Config            // per-operation iterations for primitives
	TLS        Config            // per-client iterations for loopback TLS
	Runs       string            // bench/run.sh output; "" to merge nothing
	Extra      map[string]string // facts for the host's environment rows
	Progress   io.Writer         // progress lines; nil for none
}

// TLSLoopback measures a fixed 1000 handshakes per client. A time-based run
// on loopback would open tens of thousands of connections and could exhaust
// ephemeral ports while earlier ones sit in TIME_WAIT.
var TLSLoopback = Config{Warmup: 10, MinIters: 1000, MaxIters: 1000}

// Report is everything one benchmark run produced.
type Report struct {
	Primitives []PrimitiveResult
	Sizes      []SizeRow
	TLS        []TLSResult
	Env        []EnvRow
}

// SizeRow is a measured size with what the knowledge DB and OpenSSL say.
// Zero means the source has no value for it.
type SizeRow struct {
	SizeResult
	DB      int
	OpenSSL int
	Agrees  string // "yes", "no", "variable" (not compared), or "n/a" (nothing to compare)
}

// NetemRun is what bench/netem writes for one network profile.
type NetemRun struct {
	Env []EnvRow    `json:"env"`
	TLS []TLSResult `json:"tls"`
}

// Run measures every primitive and loopback TLS on this machine, then merges
// the OpenSSL sizes and netem runs that bench/run.sh left under opts.Runs. It
// returns the report even when sizes disagree, with an error naming them, so
// the evidence is still written.
func Run(ctx context.Context, opts Options) (*Report, error) {
	progress := func(format string, a ...any) {
		if opts.Progress != nil {
			_, _ = fmt.Fprintf(opts.Progress, format+"\n", a...)
		}
	}
	db, err := knowledge.Default()
	if err != nil {
		return nil, err
	}
	rep := &Report{Env: Environment(EnvHost, opts.Extra)}

	var sizes []SizeResult
	for _, p := range Primitives() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		progress("primitive %s (%s)", p.Algorithm, p.Impl)
		res, sz, err := p.Run(opts.Primitives)
		if err != nil {
			return nil, err
		}
		rep.Primitives = append(rep.Primitives, res...)
		sizes = append(sizes, sz...)
	}

	progress("tls on loopback")
	tlsRes, err := BenchTLS(ctx, opts.TLS, EnvHost, Loopback)
	if err != nil {
		return nil, err
	}
	rep.TLS = tlsRes

	var ossl *OpenSSL
	if opts.Runs != "" {
		if ossl, err = LoadOpenSSL(filepath.Join(opts.Runs, "openssl")); err != nil {
			return nil, err
		}
		netem, err := LoadNetem(filepath.Join(opts.Runs, "netem"))
		if err != nil {
			return nil, err
		}
		for _, r := range netem {
			rep.TLS = append(rep.TLS, r.TLS...)
		}
		rep.Env = append(rep.Env, netemEnv(netem)...)
	}
	switch {
	case ossl != nil:
		rep.Env = append(rep.Env, EnvRow{"openssl", "version", ossl.Version})
	default:
		rep.Env = append(rep.Env, EnvRow{"openssl", "status", "not run (no bench/run.sh output); sizes are not cross-checked against OpenSSL"})
	}

	var mismatches []string
	rep.Sizes, mismatches = crossCheck(db, sizes, ossl)
	if len(mismatches) > 0 {
		return rep, fmt.Errorf("bench: measured sizes disagree: %v", mismatches)
	}
	return rep, nil
}

// netemEnv keeps the container's environment once (it is the same machine for
// every profile) and notes when netem did not run.
func netemEnv(runs []NetemRun) []EnvRow {
	if len(runs) == 0 {
		return []EnvRow{{EnvNetem, "status", "not run (no bench/run.sh netem output); TLS rows are loopback on the host only"}}
	}
	seen := map[string]bool{}
	var out []EnvRow
	for _, r := range runs {
		for _, e := range r.Env {
			if e.Key == "date_utc" || seen[e.Key] {
				continue
			}
			seen[e.Key] = true
			out = append(out, e)
		}
	}
	return out
}

// LoadNetem reads every profile bench/netem wrote under dir, in name order.
// A missing dir returns nothing.
func LoadNetem(dir string) ([]NetemRun, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	var out []NetemRun
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var r NetemRun
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if len(r.TLS) == 0 {
			return nil, fmt.Errorf("%s: no TLS results", f)
		}
		out = append(out, r)
	}
	return out, nil
}

// crossCheck compares each measured size with the knowledge DB and OpenSSL.
// Variable-length encodings are reported, not compared. For Diffie-Hellman
// the "ciphertext" is the ephemeral public key, so the DB's public key size is
// what it is checked against.
func crossCheck(db *knowledge.DB, sizes []SizeResult, ossl *OpenSSL) ([]SizeRow, []string) {
	var rows []SizeRow
	var bad []string
	for _, s := range sizes {
		row := SizeRow{SizeResult: s}
		if e, ok := db.ByID(s.Algorithm); ok {
			row.DB = dbSize(e, s.Field)
		}
		if ossl != nil {
			row.OpenSSL = ossl.Sizes[[2]string{s.Algorithm, s.Field}]
		}
		row.Agrees = "n/a"
		switch {
		case s.Variable:
			row.Agrees = "variable"
		case row.DB != 0 || row.OpenSSL != 0:
			row.Agrees = "yes"
			for _, want := range []int{row.DB, row.OpenSSL} {
				if want != 0 && want != s.Bytes {
					row.Agrees = "no"
				}
			}
		}
		if row.Agrees == "no" {
			bad = append(bad, fmt.Sprintf("%s %s %s: measured %d, knowledge DB %d, OpenSSL %d", s.Algorithm, s.Impl, s.Field, s.Bytes, row.DB, row.OpenSSL))
		}
		rows = append(rows, row)
	}
	return rows, bad
}

func dbSize(e knowledge.Entry, field string) int {
	switch field {
	case FieldPublicKey:
		return e.Sizes.PublicKey
	case FieldCiphertext:
		if e.Sizes.Ciphertext == 0 && slices.Contains(e.Primitives, "key-agreement") {
			return e.Sizes.PublicKey
		}
		return e.Sizes.Ciphertext
	case FieldSignature:
		return e.Sizes.Signature
	case FieldSharedSecret:
		return e.Sizes.SharedSecret
	}
	return 0
}

// --- CSV ---

// WriteCSVs writes rq4_primitives.csv, rq4_sizes.csv, rq4_tls.csv and
// rq4_environment.csv to dir, rows sorted so reruns diff cleanly.
func WriteCSVs(rep *Report, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	prim := [][]string{{"env", "algorithm", "impl", "op", "n", "mean_ns", "p50_ns", "p99_ns", "min_ns", "max_ns"}}
	for _, r := range rep.Primitives {
		prim = append(prim, append([]string{EnvHost, r.Algorithm, r.Impl, r.Op}, stats(r.Stats)...))
	}
	sizes := [][]string{{"algorithm", "impl", "field", "bytes", "variable", "knowledge_db", "openssl", "agrees"}}
	for _, r := range rep.Sizes {
		sizes = append(sizes, []string{r.Algorithm, r.Impl, r.Field, itoa(r.Bytes), strconv.FormatBool(r.Variable), opt(r.DB), opt(r.OpenSSL), r.Agrees})
	}
	tlsRows := slices.Clone(rep.TLS)
	slices.SortStableFunc(tlsRows, func(a, b TLSResult) int {
		return cmp.Or(cmp.Compare(a.Env, b.Env), cmp.Compare(a.Profile.DelayMs, b.Profile.DelayMs),
			cmp.Compare(a.Profile.LossPct, b.Profile.LossPct), cmp.Compare(a.Profile.Name, b.Profile.Name))
	})
	tls := [][]string{{"env", "profile", "delay_ms", "rtt_added_ms", "loss_pct", "mtu", "client", "group",
		"client_hello_bytes", "server_hello_bytes", "client_bytes", "server_bytes", "op", "failures",
		"n", "mean_ns", "p50_ns", "p99_ns", "min_ns", "max_ns"}}
	for _, r := range tlsRows {
		p := r.Profile
		tls = append(tls, append([]string{r.Env, p.Name, ftoa(p.DelayMs), ftoa(2 * p.DelayMs), ftoa(p.LossPct), opt(p.MTU),
			r.Client, r.Group, itoa(r.ClientHelloBytes), itoa(r.ServerHelloBytes), itoa(r.ClientBytes), itoa(r.ServerBytes),
			r.Op, itoa(r.Failures)}, stats(r.Stats)...))
	}
	env := [][]string{{"env", "key", "value"}}
	for _, e := range rep.Env {
		env = append(env, []string{e.Env, e.Key, e.Value})
	}
	for name, rows := range map[string][][]string{
		"rq4_primitives.csv": prim, "rq4_sizes.csv": sizes, "rq4_tls.csv": tls, "rq4_environment.csv": env,
	} {
		if err := writeCSV(filepath.Join(dir, name), rows); err != nil {
			return err
		}
	}
	return nil
}

func stats(s Stats) []string {
	return []string{itoa(s.N), strconv.FormatFloat(s.Mean, 'f', 0, 64), i64(s.P50), i64(s.P99), i64(s.Min), i64(s.Max)}
}

func itoa(n int) string     { return strconv.Itoa(n) }
func i64(n int64) string    { return strconv.FormatInt(n, 10) }
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// opt writes 0 as empty: no value, as opposed to a measured zero.
func opt(n int) string {
	if n == 0 {
		return ""
	}
	return itoa(n)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

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
