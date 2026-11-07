# pqscope

A multi-layer post-quantum cryptography readiness scanner, in development.

NIST IR 8547 deprecates quantum-vulnerable public-key cryptography after 2030 and
disallows it after 2035. pqscope is being built to find that cryptography across source,
dependencies, configuration and key material, binaries and the network, then reconcile the
layers to expose gaps between what a system declares and what it actually deploys.

## Status

Milestone 2 of 13. **Only the source layer works, for Go and Python.** Dependencies,
configuration, binaries and the network aren't scanned yet. Commands other than `version`
and `scan` exit non-zero with a "not implemented" error, so a stub can't be mistaken for a
clean scan.

```sh
$ pqscope scan ./server
LOCATION    ALGORITHM  PARAMS          QUANTUM     CONFIDENCE  RULE
main.go:9   Hybrid     X25519MLKEM768  hybrid      0.90        go.tls.x25519mlkem768
main.go:10  X25519     X25519          vulnerable  0.90        go.tls.x25519
main.go:11  ECDH       P-256           vulnerable  0.90        go.tls.p256

3 findings in 1 files scanned
```

Use `--json` to get findings as JSON instead of a table.

## Build and test

Requires Go 1.26 or later and a C compiler, because tree-sitter uses cgo.

```sh
make build         # writes bin/pqscope
make test          # go test -race ./..., including the corpus score
make lint          # gofmt, go vet, staticcheck, golangci-lint
./bin/pqscope version
```

## Source rules

The rule packs in `rules/` match fully qualified symbols after resolving imports, so aliased
imports are caught and look-alike packages are not. [docs/rules.md](docs/rules.md) describes
the format and the known blind spots. Each rule cites the API documentation it relies on.

A labeled corpus in [testdata/corpus](testdata/corpus) scores the rules on every test run.
The rules and labels have the same author, so read the scores as a regression check, not a
benchmark.

## Algorithm database

`internal/knowledge/algorithms.yaml` records each algorithm's family, parameters, classical
strength, quantum status, sizes and migration targets. The loader rejects any entry without
a citation. Tests check recorded key, ciphertext and signature sizes against the Go standard
library and [CIRCL](https://github.com/cloudflare/circl).

See [docs/CHANGELOG.md](docs/CHANGELOG.md) for progress.

## License

Apache-2.0. See [LICENSE](LICENSE).
