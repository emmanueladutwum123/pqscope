package main

import "crypto/tls"

var cfg = &tls.Config{
	MinVersion: tls.VersionTLS13,
	CurvePreferences: []tls.CurveID{
		tls.SecP256r1MLKEM768,
		tls.CurveP384,
	},
}
