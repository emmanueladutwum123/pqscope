package main

import "crypto/mlkem"

func main() {
	dk, _ := mlkem.GenerateKey768()
	shared, ct := dk.EncapsulationKey().Encapsulate()
	_, _ = shared, ct
	big, _ := mlkem.GenerateKey1024()
	_ = big
}
