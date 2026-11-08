// Command netem runs pqscope's TLS benchmark for one network profile and
// writes it as JSON. bench/run.sh runs it inside a Linux container after
// shaping the loopback interface with tc netem; the profile flags record what
// was set, they do not set it. It is separate from pqscope so that it builds
// without cgo for a Linux container.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/emmanueladutwum123/pqscope/internal/bench"
)

func main() {
	var prof bench.Profile
	var n int
	var out, revision, note string
	flag.StringVar(&prof.Name, "profile", "", "profile name")
	flag.Float64Var(&prof.DelayMs, "delay-ms", 0, "one-way delay netem adds, in ms")
	flag.Float64Var(&prof.LossPct, "loss", 0, "per-packet loss netem adds, in percent")
	flag.IntVar(&prof.MTU, "mtu", 0, "loopback MTU")
	flag.IntVar(&n, "n", 100, "handshakes per client configuration")
	flag.StringVar(&out, "o", "", "output JSON file")
	flag.StringVar(&revision, "revision", "", "pqscope revision")
	flag.StringVar(&note, "note", "", "where this container runs")
	flag.Parse()
	if prof.Name == "" || out == "" {
		fmt.Fprintln(os.Stderr, "usage: netem -profile NAME -o FILE [-delay-ms D] [-loss P] [-mtu M] [-n N]")
		os.Exit(2)
	}
	cfg := bench.Config{Warmup: 3, MinIters: n, MaxIters: n}
	res, err := bench.BenchTLS(context.Background(), cfg, bench.EnvNetem, prof)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	run := bench.NetemRun{
		Env: bench.Environment(bench.EnvNetem, map[string]string{"pqscope_revision": revision, "virtualization": note}),
		TLS: res,
	}
	data, err := json.MarshalIndent(run, "", "  ")
	if err == nil {
		err = os.WriteFile(out, append(data, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
