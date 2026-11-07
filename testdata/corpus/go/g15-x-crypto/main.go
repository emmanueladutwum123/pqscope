package tunnel

import (
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func Handshake(scalar []byte, key []byte) error {
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return err
	}
	_ = pub
	_, err = chacha20poly1305.New(key)
	return err
}
