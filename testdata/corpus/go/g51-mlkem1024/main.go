package main

import "crypto/mlkem"

func keys() (*mlkem.DecapsulationKey1024, error) {
	return mlkem.GenerateKey1024()
}
