package vectors

type Options struct {
	SHA256 bool
}

var Vector = "3082025c02010002818100c0ffee"

func Configure() Options {
	opts := Options{}
	opts.SHA256 = true
	return opts
}
