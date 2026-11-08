# Changelog

## Unreleased

### Milestone 4: policy engine, NIST IR 8547 and CNSA 2.0 policies, risk score

- Add `internal/policy` and the bundled policies `policies/nist-ir-8547-2026.yaml` and
  `policies/cnsa-2.0.yaml`. Every rule cites a document section. The loader requires every
  knowledge DB (entry, primitive) pair to be matched by exactly one rule. A hand-written test
  table checks all 66 pairs under both policies.
- Add `internal/risk`: `risk = exposure × secrecy_lifetime × quantum_status × confidence`, with
  every weight in `internal/risk/weights.yaml`. See `docs/risk.md`.
- Add `pqscope policy`, which reads a CBOM (including other tools' CBOMs, best effort) or saved
  findings. It exits 0 on pass, 1 when any asset reaches `--fail-on` (default
  `disallowed-2035`), and 2 on errors. CI now runs the built binary as a gate on fixtures that
  should pass and fail.
- `pqscope scan` fills each finding's policy verdicts and risk. The terminal and HTML reports
  show them, and the CBOM records the exact asset so it can be read back.
- Add the `disallowed-now` policy status, and the `rule`, `schedule` and `at_best` fields of
  `PolicyResult`.
- All commands now exit 2 on errors, not 1, so exit code 1 always means a failed policy gate.

Sources read for this milestone: NIST IR 8547 final (October 2026; PDF SHA-256
`3049cdfd...dc280`), SP 800-131A Rev. 2, FIPS 186-5, draft-becker-cnsa2-tls-profile-05 and
RFC 9151. IR 8547 final differs from the draft in ways the policy follows. Tables 2 and 4 give
every quantum-vulnerable family at 112 bits or more the same schedule (deprecated after 2030,
disallowed after 2035), with no split by strength, and DSA is no longer listed.

Known limits:

- NSA's CNSA 2.0 advisory could not be fetched: media.defense.gov refuses automated clients.
  NSA's per-equipment-class exclusive-use dates (2030 to 2033) are therefore not encoded, and
  CNSA 1.0 algorithms carry the 2035 NSM-10 target instead. The knowledge DB's `cnsa2` citation
  is still the IETF profile. Both need the NSA document.
- sntrup761x25519 is `unknown` under NIST IR 8547. Whether its X25519 input counts as an
  approved scheme for the hybrid rule is not settled here.
- Risk exposure uses path and symbol heuristics, with no reachability analysis.

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
  by script. Still open after milestone 4; see above.
- IR 8547 is cited at document level here. Milestone 4's policy cites its sections.
- Sizes for RSA-1024, RSA-4096, P-224, Ed448, X448 and DH, and ECDSA public keys, come from
  the cited standards and are not cross-checked against an implementation.
