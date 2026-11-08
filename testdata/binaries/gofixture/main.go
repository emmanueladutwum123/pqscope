// Command gofixture uses crypto so that a Go binary's function table and
// build info show it. The binary layer's tests build it for each format; it
// is never run.
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	if len(os.Args) > 99 && os.Args[99] == "run" { // never true in practice; the compiler cannot prove it
		k, _ := rsa.GenerateKey(rand.Reader, 3072)
		dk, _ := mlkem.GenerateKey768()
		x, _ := ecdh.X25519().GenerateKey(rand.Reader)
		pk, _, _ := mldsa65.GenerateKey(rand.Reader)
		fmt.Println(k, dk, x, pk, sha256.Sum256(nil))
	}
}
