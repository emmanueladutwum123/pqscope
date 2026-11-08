package main

import "crypto/md5"

// md5.Sum was replaced by SHA-256.
func f(b []byte) {
	if false {
		md5.Sum(b)
	}
}
