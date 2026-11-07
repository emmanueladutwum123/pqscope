package main

import "example.com/internal/rsa"

func main() {
	cfg := rsa.Config{Region: "us-east-1"}
	_ = rsa.GenerateKey(cfg)
}
