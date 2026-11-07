package digest

import "crypto"

func New() {
	h := crypto.SHA512.New()
	_ = h
}
