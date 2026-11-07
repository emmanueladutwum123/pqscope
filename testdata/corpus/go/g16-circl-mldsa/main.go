package pq

import "github.com/cloudflare/circl/sign/mldsa/mldsa65"

func Sign(msg []byte) ([]byte, error) {
	_, sk, err := mldsa65.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, mldsa65.SignatureSize)
	err = mldsa65.SignTo(sk, msg, nil, false, sig)
	return sig, err
}
