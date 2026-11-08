# Changelog

## Unreleased

### Milestone 3: CBOM, SARIF and reports

- Add `internal/cbom`, which writes a CycloneDX 1.6 CBOM. Each distinct asset is a
  `cryptographic-asset` component that lists its findings as evidence occurrences.
- Add `internal/sarif`, which writes SARIF 2.1.0. The level follows the quantum status, and
  the rule descriptions and citations come from the rule packs.
- Add `internal/report`, with a terminal summary (findings, assets with migration targets,
  counts by quantum status) and a self-contained HTML report.
- `pqscope scan` gains `-o`, `--sarif` and `--html`. `pqscope report findings.json` renders
  saved `--json` output in any format.
- Vendor the official CycloneDX 1.6.2 and SARIF 2.1.0 (errata 01) schemas in
  `internal/schemas`, pinned by checksum. Tests validate every format against them,
  including a scan of the whole corpus.
- Add std-curves names (`curve`) to the elliptic-curve knowledge DB entries, and
  `Replacement`, `Migration` and `Name` lookups.

Validation:

- The CBOM and SARIF from scanning the corpus (100 findings) validate against the vendored
  schemas, with `format` keywords asserted.
- As an independent check, the CBOM also passes `cyclonedx-python-lib` 11.5.0's strict 1.6
  validator, and the SARIF passes Python `jsonschema` 4.26.0 against the same official
  schema. These checks were run by hand and are not in CI.

Known limits:

- Microsoft's SARIF multitool, which checks rules beyond the schema, was not run.
  Run it before publishing the GitHub Action in milestone 12.
- The CBOM summarises per-finding confidence and rule IDs per technique. `--json` is the
  lossless format.
- SARIF paths are relative to the scanned directory. Code scanning needs the repository
  root as the target.

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
