# pqscope

A multi-layer post-quantum cryptography readiness scanner, in development.

NIST IR 8547 deprecates quantum-vulnerable public-key cryptography after 2030 and
disallows it after 2035. pqscope is being built to find that cryptography across source,
dependencies, configuration and key material, binaries and the network, then reconcile the
layers to expose gaps between what a system declares and what it actually deploys.

## Status

Milestone 1 of 13: the data model, the cited algorithm database and the CLI skeleton.
**pqscope cannot scan anything yet.** Only `pqscope version` works. Every other command
exits non-zero with a "not implemented" error, so a stub can't be mistaken for a clean scan.

## Build and test

Requires Go 1.26 or later.

```sh
make build         # writes bin/pqscope
make test          # go test -race ./...
make lint          # gofmt, go vet, staticcheck, golangci-lint
./bin/pqscope version
```

## Algorithm database

`internal/knowledge/algorithms.yaml` records each algorithm's family, parameters, classical
strength, quantum status, sizes and migration targets. The loader rejects any entry without
a citation. Tests check recorded key, ciphertext and signature sizes against the Go standard
library and [CIRCL](https://github.com/cloudflare/circl).

See [docs/CHANGELOG.md](docs/CHANGELOG.md) for progress.
