# Changelog

## Unreleased

### Milestone 2: source layer for Go and Python

- Add `internal/discover/source`, a tree-sitter engine driven by YAML rule packs. It resolves
  references through imports, follows same-file constants, and skips `if false` bodies.
- Add 85 cited rules: 43 in `rules/go.yaml` and 42 in `rules/python.yaml`. They cover the Go
  standard library, `golang.org/x/crypto`, CIRCL, pyca/cryptography, hashlib, hmac,
  PyCryptodome, paramiko, PyNaCl, liboqs-python and `ssl`. See `docs/rules.md`.
- Add a 62-case labeled corpus (30 Go, 32 Python) under `testdata/corpus`, scored by
  `go test`. It fails below 0.9 precision or recall.
- Add DSA and HMAC-SHA-1/384/512 entries to the knowledge DB.
- `pqscope scan [path]` now scans Go and Python source and prints a table, or JSON with
  `--json`.

Corpus results at this commit:

| Language | Precision | Recall | F1 | Params correct |
|---|---|---|---|---|
| Go | 1.000 | 0.981 | 0.990 | 50/51 |
| Python | 0.959 | 0.940 | 0.949 | 46/47 |

Known limits:

- Labels and rules have the same author, so these numbers measure consistency with the
  labeling convention, not real-world accuracy. Milestone 10 adds the independent evaluation.
- Misses kept in the corpus: methods on typed values (`g24`), dynamic `getattr` (`p25`), key
  sizes through wrappers (`g23`, `p24`), and EC keys used for ECDH reported as ECDSA (`p05`).

### Milestone 1: skeleton

- Add the repository layout, `Makefile` and CI for lint, test and the race detector.
- Add `internal/model` with `Finding`, `Asset`, `Location` and stable finding IDs.
- Add `internal/knowledge`, a cited algorithm database that validates itself on load.
- Add the CLI with a working `version` command. All other commands exit non-zero as
  "not implemented".

Known limits:

- CNSA 2.0 is cited through an IETF profile draft, because the NSA PDF could not be fetched
  by script. Replace this with the NSA document before the policy work in milestone 4.
- IR 8547 is cited at document level. Section numbers still need to be read from the report
  itself for milestone 4.
- Sizes for RSA-1024, RSA-4096, P-224, Ed448, X448 and DH, and ECDSA public keys, come from
  the cited standards and are not cross-checked against an implementation.
