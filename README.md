# pqscope

A multi-layer post-quantum cryptography readiness scanner, in development.

NIST IR 8547 deprecates quantum-vulnerable public-key cryptography after 2030 and
disallows it after 2035. pqscope is being built to find that cryptography across source,
dependencies, configuration and key material, binaries and the network, then reconcile the
layers to expose gaps between what a system declares and what it actually deploys.

## Status

Milestone 5 of 13. Three layers work:

- **source:** Go and Python code;
- **config:** nginx, Apache, sshd, openssl.cnf, Kubernetes, and certificates and keys;
- **deps:** Go, Python, npm, Maven and Cargo manifests.

Binaries and the network aren't scanned yet. `version`, `scan`, `report` and `policy` work.
The other commands exit non-zero with a "not implemented" error, so a stub can't be mistaken
for a clean scan.

```sh
$ pqscope scan ./server
LOCATION    LAYER   ALGORITHM  PARAMS          QUANTUM     CONFIDENCE  RISK  RULE
main.go:9   source  Hybrid     X25519MLKEM768  hybrid      0.90        0.04  go.tls.x25519mlkem768
main.go:10  source  X25519     X25519          vulnerable  0.90        0.81  go.tls.x25519
main.go:11  source  ECDH       P-256           vulnerable  0.90        0.81  go.tls.p256

ASSET           PRIMITIVE      QUANTUM     FINDINGS  NIST-IR-8547-2026  CNSA-2.0        MIGRATE TO
ECDH-P256       key-agreement  vulnerable  1         deprecated-2030    disallowed-now  civilian: X25519MLKEM768 (hybrid); CNSA 2.0: ML-KEM-1024
X25519          key-agreement  vulnerable  1         deprecated-2030    disallowed-now  civilian: X25519MLKEM768 (hybrid); CNSA 2.0: ML-KEM-1024
X25519MLKEM768  kem            hybrid      1         compliant          disallowed-now  -

Quantum status: 2 vulnerable, 1 hybrid
nist-ir-8547-2026: 2 deprecated-2030, 1 compliant
cnsa-2.0: 3 disallowed-now
3 findings in 1 files scanned
```

Other output formats:

```sh
pqscope scan . -o cbom.json --sarif pqscope.sarif --html report.html
pqscope scan . --json > findings.json      # lossless findings
pqscope report findings.json --html report.html
```

## Policies and CI gating

Each finding is evaluated against NIST IR 8547 (final, October 2026) and CNSA 2.0, and gets a
risk score. `pqscope policy` exits 1 when any asset reaches a status, so it can gate CI:

```sh
pqscope scan . -o cbom.json
pqscope policy cbom.json                       # fails on anything NIST IR 8547 disallows, now or later
pqscope policy --policy cnsa-2.0 --fail-on disallowed-now cbom.json
```

Each policy rule cites the section of the document it comes from. See
[docs/policy.md](docs/policy.md) for the statuses and sources, and [docs/risk.md](docs/risk.md)
for the risk score. The CNSA 2.0 policy doesn't yet encode NSA's per-equipment-class deadlines.

## Dependencies and configuration

`scan` also reads dependency manifests and lockfiles, and maps known crypto libraries to what
they provide at their version. For example, pyca/cryptography provides ML-KEM from 48.0.0. It
reads TLS and SSH configuration, and certificates, keys and CSRs. Private keys are reported by
algorithm, size and public-key fingerprint only, and a test checks that their bytes never reach
any output. See [docs/layers.md](docs/layers.md).

## Output formats

The CBOM is CycloneDX 1.6, and the SARIF is 2.1.0 for GitHub code scanning. Tests validate
both against the official schemas. [docs/outputs.md](docs/outputs.md) describes how findings
map to each format.

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
