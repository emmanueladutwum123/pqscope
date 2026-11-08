# Changelog

## Unreleased

### Milestone 8: reconciliation engine

- Add `internal/reconcile`. It links findings across layers within a component and derives:
  - `declared-pqc-deployed-classical`: PQC key establishment in source or dependencies, while an
    endpoint negotiates (TLS) or offers (SSH) only classical key exchange;
  - `config-overrides-library`: a dependency supports a hybrid for the protocol, but a group
    directive lists only classical groups;
  - `binary-without-source`: an algorithm family in a binary that no source finding uses;
  - `stale-dependency`: a pinned version without PQC, where a later version adds it.
- Confidence fusion:
  - corroboration across two or more of source, config, binary and network raises confidence
    by noisy-OR and links the findings;
  - a group directive contradicted by a negotiated TLS group or an offered SSH key exchange is
    flagged for review on both sides;
  - dependency capabilities take part in neither.
- Components (`--components`, YAML) scope linking by path prefix and host. By default the scan
  is one component.
- `pqscope scan` merges other runs' findings with `--with` (for example from `pqscope net
  --findings`), reconciles by default, and has `--no-reconcile` to turn it off. Reports gain
  reconciliation and review sections. Derived findings are not counted with observed ones and are
  left out of the CBOM. SARIF gets `reconcile.*` rules.
- Add `Derived` and `Review` fields to `model.Finding`, and `ByID` and `FirstPQC` to the library
  table.
- Add the crafted multi-layer fixture `testdata/reconcile/app`. The tests derive all four types
  from it with the real scanners, plus the review flag and corroboration, and check negative cases
  for every rule, component scoping, and stability under input order and re-runs.

Notes:

- An early version chose a derived finding's asset from whichever candidate came first, so IDs
  depended on input order. Findings are now put in a canonical order before any rule runs, and a
  test reverses the input to check this.
- Run end to end: `pqscope net` against a local OpenSSL server offering only X25519, merged into
  a scan of the fixture, produces all four derived types.

Known limits:

- Components come from path prefixes and host names. pqscope does not discover which endpoint
  serves which code.
- `config-overrides-library` reads library support from the dependency layer, not from the
  library the server process actually loads.

### Milestone 7: binary layer

- Add `internal/discover/binary`. It reads ELF, PE, Mach-O and universal Mach-O files and
  reports:
  - crypto library imports, and defined symbols in static binaries (OpenSSL, LibreSSL,
    BoringSSL, libsodium, liboqs, and OpenSSL 3.5's internal ML-KEM/ML-DSA/SLH-DSA);
  - for Go binaries, the functions and packages the linker kept, from the function table that
    survives `-s -w`;
  - for stripped binaries with nothing else, known constants as low-confidence evidence.
- Go build info feeds the dependency capability table. Module versions become deps findings
  located at the binary.
- Algorithm-agnostic imports (`EVP_PKEY_encapsulate`, `OQS_KEM_new`) are listed under "Not
  classified" instead of being guessed.
- Add `symbols.yaml`. Every symbol name was checked against the library's header, source or
  OpenSSL 3.5's `libcrypto.num`, and every entry is cited. A test checks each constant against
  values computed from the standards.
- Add test binaries built by `testdata/binaries/build.sh`:
  - an ELF linked against OpenSSL 3.5;
  - a PE importing from a libcrypto DLL;
  - a Mach-O linked against Homebrew OpenSSL;
  - a stripped static ELF with only constants.

  The tests also cross-compile a Go fixture for three formats, stripped and unstripped.
- `pqscope scan` runs the binary layer by default.
- The source and deps layers export the Go symbol-to-asset map and capability findings for
  reuse.

Notes:

- The Go compiler inlines small crypto functions, so `ecdh.X25519` and `mldsa65.GenerateKey`
  never appear by name. Matching by package catches them. Exact names are tried first because
  they can carry parameters.
- A fixture guarded by `len(os.Args) < 0` linked nothing: the compiler proved it false and
  removed the block. The fixture now uses a condition the compiler can't decide.

Known limits:

- Binaries that use ML-KEM only through OpenSSL's generic EVP API are not attributed to ML-KEM.
- Constants show presence, not use, and say nothing about which primitive uses a curve.
- The Mach-O test binary can only be rebuilt on macOS with Homebrew OpenSSL.

### Milestone 6: network layer

- Add `internal/discover/network`.
  - **TLS ServerHello probe:** a hand-built TLS 1.3 ClientHello with configurable groups
    (default X25519MLKEM768, x25519, secp256r1) and real ML-KEM/ECDH key shares. It records
    the group from the ServerHello or HelloRetryRequest and closes without completing the
    exchange.
  - **Certificate collection:** a separate `crypto/tls` handshake.
  - **SSH probe:** reads the banner and KEXINIT, sending only an identification string that
    names the project page.
- Responsible-scanning limits enforced in code, each tested:
  - a global rate limit (default 50/s, at most 1000), with spacing checked on a fake clock and
    in real time;
  - one connection per host;
  - timeouts (default 5 s, at most 30 s);
  - at most 2 retries;
  - an exclude list of names, domains, IPs and CIDRs, checked against every resolved address.
- Add `pqscope net`. It reads targets from `--targets` and arguments, writes JSONL records
  with `-o`, and can write findings for `report` and `policy` with `--findings`.
- Unit tests open no sockets: a pipe dialer connects to in-process Go TLS and SSH servers.
- Integration tests (`make integration`, a new CI job):
  - local OpenSSL 3.5+: hybrid, classical, server-preference tiers, and HelloRetryRequest;
  - OpenSSL 3.5.9 and a Go server in Docker: X25519MLKEM768 versus X25519;
  - OpenSSH 10.0 in Docker: offers mlkem768x25519-sha256 by default, and not when restricted.
- Add `docs/scanning.md`, the public page the probes point to, with what is sent, the
  enforced limits, and how to opt out.
- The config layer exports name lookups and certificate classification for reuse.

Notes:

- Go ignores the order of `tls.Config.CurvePreferences` and applies its own preference.
  OpenSSL 3.5+ treats `:`-separated groups as equal and `/` as preference tiers. The tests
  encode both behaviours.
- X25519MLKEM768 and its SecP variants are now RFC 10024 in the IANA registry.

Known limits:

- The ServerHello probe offers TLS 1.3 only. A TLS 1.2-only server answers with an alert,
  and its version and group come from the full handshake instead.
- SSH results are what the server offers, not what a given client would negotiate.
- Opt-outs are taken through GitHub issues. Add an email contact before large measurement
  runs.

### Milestone 5: dependency and config/key-material layers

- Add `internal/discover/deps`. It parses go.mod, go.sum, requirements*.txt, poetry.lock,
  package-lock.json (v1 to v3), pom.xml and Cargo.lock, and reports what each known crypto
  library provides at its version. Findings carry the package purl.
- Add `internal/knowledge/libs.yaml`, a cited library capability table. It covers the Go
  standard library, CIRCL, x/crypto, pyca/cryptography, liboqs-python, PyCryptodome, node-forge,
  jsrsasign, noble-post-quantum, Bouncy Castle, rustls, ring and OpenSSL via openssl-src. Every
  version boundary comes from release notes (for example cryptography 48.0.0, CIRCL 1.4.0/1.5.0/
  1.6.2, Bouncy Castle 1.79, rustls 0.23.22, x/crypto v0.38.0, Go 1.24/1.26, OpenSSL 3.5.0).
- Add `internal/discover/config`. It reads nginx, Apache, sshd/ssh config, openssl.cnf,
  Kubernetes (TLS Secrets, ingress-nginx, cert-manager) and key material (PEM/DER certificates,
  CSRs, PKCS#1/#8, SEC 1, DSA and OpenSSH keys, DH parameters, authorized_keys). Name tables live
  in `names.yaml` with registry citations. Post-quantum keys are recognised by NIST OID.
- Private keys are reported by algorithm, size and public-key fingerprint only.
  `TestNoPrivateKeyBytesInAnyOutput` generates keys at test time and checks every output format
  for any private-key encoding. A deliberate leak makes it fail.
- `pqscope scan` runs all three layers (`--layers` to choose) and lists unclassifiable material
  under "Not classified". The reports gain a layer column.
- `pqscope policy` leaves deps-only assets out of the gate unless `--include-deps` is set.
- Add `internal/discover/walk`, a shared file walker used by all layers.

Known limits:

- Dependency findings show availability, not use. Reconciliation is milestone 8.
- `go.sum` is read only without a sibling `go.mod`. `requirements.txt` versions count only when
  pinned with `==`.
- OpenSSL cipher-string keywords (`HIGH`, `ECDHE+AESGCM`) are not expanded. A certificate's
  issuer key size is unknown unless the certificate is self-signed.
- Encrypted PKCS#8 keys can't be classified, so they are listed as notes.
- The config and deps layers have fixture tests but no labeled corpus yet. Precision and recall
  for them come with milestone 10.

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
