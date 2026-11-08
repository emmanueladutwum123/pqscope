//go:build !darwin && !linux

package bench

func platform() platformFacts {
	const why = "not collected on this OS"
	return platformFacts{cpu: orUnknown("", why), memory: orUnknown("", why), kernel: orUnknown("", why), governor: orUnknown("", why)}
}
