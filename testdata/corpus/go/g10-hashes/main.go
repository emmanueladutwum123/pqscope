package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
)

func All(b []byte) {
	_ = md5.Sum(b)
	h := sha1.New()
	h.Write(b)
	_ = sha512.Sum384(b)
	_ = sha512.New()
}
