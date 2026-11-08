package bench

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func platform() platformFacts {
	var kernel string
	if u := new(unix.Utsname); unix.Uname(u) == nil {
		kernel = unix.ByteSliceToString(u.Sysname[:]) + " " + unix.ByteSliceToString(u.Release[:])
	}
	gov, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
	governor := strings.TrimSpace(string(gov))
	if err != nil {
		governor = "not exposed (no cpufreq in this kernel or container)"
	}
	return platformFacts{
		cpu:      orUnknown(cpuModel(), "/proc/cpuinfo has no model name"),
		memory:   orUnknown(memTotal(), "/proc/meminfo unreadable"),
		kernel:   orUnknown(kernel, "uname failed"),
		governor: governor,
	}
}

// cpuModel reads the model name, or on arm64, which has none, the
// implementer and part codes.
func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if k = strings.TrimSpace(k); ok && fields[k] == "" {
			fields[k] = strings.TrimSpace(v)
		}
	}
	if m := fields["model name"]; m != "" {
		return m
	}
	if fields["CPU implementer"] != "" {
		return "arm64 CPU implementer " + fields["CPU implementer"] + " part " + fields["CPU part"]
	}
	return ""
}

func memTotal() string {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "MemTotal:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err == nil {
				return strconv.FormatUint(kb*1024, 10)
			}
		}
	}
	return ""
}
