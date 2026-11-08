package bench

import (
	"strconv"

	"golang.org/x/sys/unix"
)

func platform() platformFacts {
	cpu, _ := unix.Sysctl("machdep.cpu.brand_string")
	var memory string
	if m, err := unix.SysctlUint64("hw.memsize"); err == nil {
		memory = strconv.FormatUint(m, 10)
	}
	var kernel string
	if u := new(unix.Utsname); unix.Uname(u) == nil {
		kernel = unix.ByteSliceToString(u.Sysname[:]) + " " + unix.ByteSliceToString(u.Release[:])
	}
	return platformFacts{
		cpu:      orUnknown(cpu, "sysctl machdep.cpu.brand_string failed"),
		memory:   orUnknown(memory, "sysctl hw.memsize failed"),
		kernel:   orUnknown(kernel, "uname failed"),
		governor: "not applicable (macOS has no cpufreq governor; frequency is managed by the OS)",
	}
}
