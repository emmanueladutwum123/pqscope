package store

import "crypto/rsa"

type Record struct {
	Key *rsa.PublicKey
}

func Save(k *rsa.PublicKey) Record {
	return Record{Key: k}
}
