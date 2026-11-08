package bench

import (
	"runtime"
	"runtime/debug"
	"strconv"
	"time"
)

// EnvRow is one fact about where a benchmark ran.
type EnvRow struct {
	Env, Key, Value string
}

// Environment describes this machine and build for the rows of env. extra
// adds caller-known facts (the revision, how the network was shaped). Facts
// the platform does not expose are recorded as such rather than left out.
func Environment(env string, extra map[string]string) []EnvRow {
	p := platform()
	facts := [][2]string{
		{"date_utc", time.Now().UTC().Format(time.RFC3339)},
		{"goos", runtime.GOOS},
		{"goarch", runtime.GOARCH},
		{"go_version", runtime.Version()},
		{"num_cpu", strconv.Itoa(runtime.NumCPU())},
		{"gomaxprocs", strconv.Itoa(runtime.GOMAXPROCS(0))},
		{"cpu_model", p.cpu},
		{"memory_bytes", p.memory},
		{"kernel", p.kernel},
		{"cpu_governor", p.governor},
		{"circl_version", moduleVersion("github.com/cloudflare/circl")},
	}
	rows := make([]EnvRow, 0, len(facts)+len(extra))
	for _, f := range facts {
		rows = append(rows, EnvRow{env, f[0], f[1]})
	}
	for _, k := range sortedKeys(extra) {
		rows = append(rows, EnvRow{env, k, extra[k]})
	}
	return rows
}

type platformFacts struct {
	cpu, memory, kernel, governor string
}

func moduleVersion(path string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown (no build info)"
	}
	for _, d := range info.Deps {
		if d.Path == path {
			if d.Replace != nil {
				return d.Replace.Version
			}
			return d.Version
		}
	}
	return "not linked"
}

// orUnknown returns s, or a note saying the fact is not exposed.
func orUnknown(s, why string) string {
	if s == "" {
		return "unknown (" + why + ")"
	}
	return s
}
