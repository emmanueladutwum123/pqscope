# Changelog

## Unreleased

### Milestone 13: paper draft

- Add the paper draft in `paper/`: LaTeX sources in `main.tex` and `sections/`, references in
  `refs.bib`. It covers the design, RQ1 to RQ4, discussion, related work and ethics.
- Add `paper/gen.py`. It reads `paper/data` (and the raw RQ2 records) and writes every number
  as a `\data{key}` macro, plus every table and figure, into `paper/generated/`. Standard
  library only, like `eval/score.py`. Figures are pgfplots, so no plotting library is needed.
  Where the text makes a claim about the data ("every miss is a hard positive", "no handshake
  failed", "one size cap"), the generator stops if the data stop supporting it.
- Add `paper/check_numbers.py`, which fails on any digit typed into the paper's prose apart
  from named standards, algorithms and policy dates, and `paper/test_paper.py`.
- Add `make paper-numbers`, `make paper-check` and `make paper` (PDF via tectonic), and a
  `paper` CI job that runs `paper-check`.
- New derived numbers, computed by the generator rather than measured again:
  - RQ2: probe against `crypto/tls`. Both see a group on 1,615 endpoints; they agree on hybrid
    versus classical for all 1,615 and on the exact group for 1,601. The other 14 servers
    chose P-384 or P-521, which only `crypto/tls` offers. The two record group names
    differently (IANA versus Go), which the comparison normalizes.
  - RQ2: provider versus agency. Among groups with at least 10 TLS endpoints, 62.4% of
    endpoints sit in a nearly uniform AS (at most 10% or at least 90% hybrid), against 14.9%
    in a nearly uniform agency.
- Every reference was checked against its primary source. Executive Order 14412 against the
  Federal Register (91 FR 38483), M-26-15 on whitehouse.gov, the hybrid TLS group as RFC 10024,
  and the two concurrent measurement studies on arXiv.

- Add the risk-score ablation the spec asks for: `pqscope measure risk-ablation` and
  `make risk-ablation`, written to `paper/data/risk_ablation*.csv` and to section 6.3 of the
  paper. It re-scores RQ3's 13,082 findings with each factor set to 1 in turn. Every factor
  changes the ranking:
  - Quantum status most overall: 16.4% of ordered pairs reverse, median tau-b 0.593.
  - Exposure most at the top: the highest-risk findings change in 45 of 72 projects.
  - Confidence least: 0.8% of pairs reverse, median tau-b 0.992.

  The ablation shows each factor matters, not that its weights are right. See
  [risk.md](risk.md#ablation).
- `risk.Weights.FactorsOf` exposes the four factors, and `Score` is now their product.

- Target ACM IMC 2027, Cycle 2 (abstract 31 March 2027, paper 7 April 2027), chosen over IMC
  Cycle 1 and PAM 2027, whose deadlines were days away.
  - Add `paper/imc.tex`, the anonymous submission in IMC's required format (`acmart`,
    `sigconf,anonymous,nonacm`, letter paper, numbered pages). It shares every section with
    the preprint, `main.tex`.
  - Ethics, Open Science and Generative AI are now appendices, as IMC requires.
  - The tool is called AnonPQ in the submission, and the repository link and revision hashes
    are withheld.
  - `make paper` builds both.

- Rewrite related work after a literature search. It adds 20 references, each checked against
  Crossref by DOI or against arXiv:
  - crypto-misuse analyzers (CryptoLint, CrySL, CryptoGuard);
  - recent inventory, binary and packet-inspection work;
  - open-source PQC readiness (ASE 2026);
  - concurrent post-quantum TLS measurements, including Wickramasinghe et al., accepted to
    IMC 2026;
  - government HTTPS measurement;
  - post-quantum TLS cost studies;
  - NCCoE and CISA guidance on discovery.

- Add monthly repeats of the RQ2 scan:
  - `measure/rq2-monthly.sh` writes `paper/data/rq2_trend/<YYYY-MM>/` from the baseline's
    vantage point, and skips the run on any other network;
  - `measure/rq2-monthly-install.sh` schedules it with launchd on the 8th of each month;
  - `measure/rq2.sh` takes `RQ2_DATA` to write somewhere other than the baseline.

  Snapshots are committed by hand after review.

- Audit RQ3's findings for precision on real code, the reviewer question RQ1's
  self-labeled corpus can't answer. `measure/rq3_audit.py` samples 165 findings (50 each from
  source, config and deps, plus all 15 binary ones), fetches each file at the scanned commit,
  and reads every certificate and key again with OpenSSL. Proposed labels:
  - precision is 96% for source, 100% for config, 96% for deps and 100% for binaries, or 99%
    weighted by layer size;
  - error classes: classical halves of hybrid schemes (2), and RSA key transport credited to
    rustls, which only does RSA signatures (2; 39 findings scan-wide, no project changes);
  - 58% of dependency findings come from Go toolchain directives, and 4 projects count as
    having vulnerable dependencies only for that reason.

  The paper reports this in section 6. It shows a red notice until the author confirms every
  label.

Known limits of the draft:

- The Generative AI appendix IMC requires is a placeholder for the author to complete.
- The audit's labels were proposed by an AI assistant and await the author's confirmation
  (`confirmed_by` in `paper/data/rq3_audit.csv`).
- pqscope's library table credits rustls and ring with RSA key transport. Both offer RSA for
  signatures only. Fixing it needs capabilities per primitive, not per algorithm family.
- CI checks the numbers but doesn't build the PDF, since tectonic isn't on the runners.

## v0.12.0 (2026-11-08)

### Milestone 12: measurement runs and the GitHub Action

- Add the GitHub Action (`action.yml` at the repository root, where the Marketplace requires
  it). It builds pqscope from the tagged source, scans, uploads SARIF to code scanning, and
  optionally gates on a policy. It is a composite action rather than the Docker action the
  spec sketched, because a Docker action can't call `upload-sarif` itself. CI runs it on
  itself on every push. See [action.md](action.md).
- Add `pqscope scan --sarif-root`, which prefixes SARIF paths when the scanned directory is a
  subdirectory. This fixes the milestone 3 limit where code scanning couldn't locate those
  files.
- Add `internal/measure` and `pqscope measure`:
  - `rq2-targets` and `rq2`: CISA's federal `.gov` list in; endpoint classification, AS
    mapping and Wilson 95% intervals by branch, agency and AS out;
  - `rq3-select` and `rq3`: OpenSSF Criticality Score in; dedupe by root commit, size cap,
    then prevalence by layer and exposure out.

  Analysis fails on incomplete or duplicated scan records.
- Add `measure/rq2.sh` and `measure/rq3.sh`, which run the measurements and publish
  `paper/data/rq2_*` and `rq3_*` with raw evidence under `paper/data/raw/`. Add
  `measure/exclude.txt`, the opt-out list `docs/scanning.md` promises. See
  [measurement.md](measurement.md).
- Fix: a TypeScript `import x = require("m")` crashed the whole source scan. It has no `source`
  field, and the JS frontend dereferenced it. Scanning facebook/react and babel/babel for RQ3
  found it. A panic in any language frontend now skips that one file, reported with the reason,
  instead of ending the scan.

### Milestone 11: migration-cost benchmarks

- Add `internal/bench` and `pqscope bench`. They time keygen, encap/decap and sign/verify (mean,
  p50, p99, min, max, sample count) for:
  - X25519 and P-256;
  - RSA-2048 and RSA-3072;
  - ECDSA P-256;
  - ML-KEM-512, -768 and -1024, in CIRCL, plus -768 and -1024 in the standard library;
  - ML-DSA-44, -65 and -87;
  - SLH-DSA-128s and -128f;
  - the X25519MLKEM768 hybrid, composed as `crypto/tls` does.

  Every primitive is checked before it is timed. Wire sizes are measured from real outputs.
- Add a TLS benchmark. It measures ClientHello and ServerHello record sizes, bytes each way, the
  negotiated group and handshake latency for classical X25519, hybrid X25519MLKEM768 and Go
  default clients against a `crypto/tls` server.
- Add `bench/run.sh`. In alpine containers pinned by digest, it:
  - produces OpenSSL 3.5 keys, ciphertexts and signatures for the size cross-check;
  - runs the TLS benchmark (`bench/netem`, built without cgo) under six `tc netem` profiles:
    loopback, MTU 1500, 2, 40 and 150 ms added RTT, and 40 ms with 1% loss.
- `pqscope bench` writes `paper/data/rq4_{primitives,sizes,tls,environment}.csv`. It fails if
  any measured size disagrees with the knowledge DB or OpenSSL.
- `rq4_environment.csv` records, for the host and the container, the CPU, memory, kernel, CPU
  governor, Go, CIRCL, OpenSSL, Docker and netem versions, and the pqscope revision.
- Add `make bench`. `make paper-data` now runs it too.
- CI's integration job runs the whole pipeline with a few iterations, so the OpenSSL size
  cross-check runs on every push.
- Fix: `eval/run.sh` stages the corpus in `eval/out/_corpus-stage`. Before, the staged copy's Go
  files looked like packages of this module to `go vet ./...` and `go mod tidy` after a local
  `make eval`.
- Remove the "not implemented" stub machinery; every command now exists.

Known limits: see [bench.md](bench.md#known-limits). The latencies come from one machine
(an Apple M2 laptop, with netem runs in Docker Desktop's Linux VM) and one run. The TLS numbers
are Go's TLS stack only, with an ECDSA certificate.

### Milestone 10: evaluation harness and a 202-case corpus

- Grow the corpus to 202 cases across all five layers:
  - source: 153 cases (Go 38, Python 40, Java 26, C/C++ 24, JS/TS 25);
  - config: 24;
  - deps: 14;
  - binary: 6;
  - network: 5.

  It now includes public certificates, keys and CSRs generated with OpenSSL (private keys
  discarded), two new test binaries (a libsodium ELF and a no-crypto ELF), and network servers
  run in Docker.
- Add `eval/run.sh`. It runs CBOMkit-theia, CBOMkit (sonar-cryptography via cbomkit-action
  v2.3.0), cryptoscan-pqc 0.1.1, pqc-audit (pqc-migration-audit at a pinned commit) and Semgrep
  1.184.0 with pinned community crypto rules. Each runs once over the corpus in a container pinned
  by digest. It also starts and probes the network servers. Keylens is recorded as unavailable:
  no crypto scanner by that name exists.
- Add `internal/eval` and `pqscope eval`. They score every tool per layer, language and
  granularity (file+family and file+line+family), run a layer ablation for pqscope, and write
  `paper/data/rq1_{summary,items,tools,ablation,corpus}.csv`.
- Add `eval/score.py`, which recomputes every summary number from the per-item outcomes with a
  separate implementation and fails on any difference. CI runs the pipeline on every push.
- Add `make eval`, `make eval-score` and `make paper-data`.
- Fix: SARIF rules for the config, binary, deps and network layers now carry a description and a
  documentation link. Before, only source rules did. The larger corpus exposed this.

pqscope at this commit, from `paper/data/rq1_summary.csv` (file granularity, all 202 cases, with
network cases probed): precision 0.9968, recall 0.9750. In the ablation from `rq1_ablation.csv`,
turning off the source, config, deps, binary or network layer lowers recall to 0.366, 0.800,
0.909, 0.913 and 0.913 respectively.

Known limits:

- **Competitor runs, added after this milestone.** The first `make eval` exposed harness bugs,
  fixed before any competitor numbers were committed:
  - competitors could read the answer key (`labels.yaml`); they now scan a staged copy without it;
  - CBOMkit merged same-named files into two modules; it now runs once per case;
  - pqc-audit's findings exit code was read as a failure;
  - several tools' path and algorithm names were misparsed.

  `paper/data/rq1_*` now has every competitor except Keylens. pqc-audit's report schema is
  undocumented, so its adapter reads any objects with a path and an algorithm.
- **One author for rules and labels.** pqscope's scores measure consistency with the labeling
  convention.
- **One honest network miss.** When a server sends a HelloRetryRequest, pqscope doesn't report
  the cipher suite.

### Milestone 9: Java, C/C++ and JavaScript/TypeScript

- Add source frontends for Java, C/C++ (C and C++ grammars by extension) and JS/TS (JavaScript,
  TypeScript and TSX grammars by extension).
- Add three rule packs, each rule cited:
  - `rules/java.yaml` (20 rules): JCA factories and `NamedParameterSpec`, including the JDK 24+
    ML-KEM and ML-DSA names;
  - `rules/c.yaml` (37 rules): OpenSSL 1.x/3.x including ML-KEM/ML-DSA by name, libsodium, liboqs
    and Windows CNG;
  - `rules/js.yaml` (24 rules): Node `crypto` including the `ml-kem-*` and `ml-dsa-*` key types,
    WebCrypto, node-forge, jsrsasign, noble and TweetNaCl.
- Engine extensions:
  - per-extension grammars;
  - a per-language dead-code hook (C's `#if 0`);
  - `arg[N].prop` extractors for options objects;
  - case-insensitive `select` with `prefix*` keys;
  - `select_params_from`, which reads a selected algorithm's size or curve from another argument
    and keeps it only if the knowledge DB knows it for that algorithm.
- A parameter value is now used only if it is a literal or is mapped by `params_map`. Before, a
  constant resolved to some other symbol could have been recorded as a bogus key size. The Go and
  Python scores are unchanged.
- The order of two findings on one line no longer depends on the sort implementation.
- Add 51 labeled corpus cases: 18 Java, 16 C/C++ and 17 JS/TS.

Corpus results at this commit (same author for rules and labels; see the corpus README):

| Language | Cases | Precision | Recall | F1 | Params correct |
|---|---|---|---|---|---|
| Go | 30 | 1.000 | 0.981 | 0.990 | 50/51 |
| Python | 32 | 0.959 | 0.940 | 0.949 | 46/47 |
| Java | 18 | 1.000 | 0.963 | 0.981 | 21/26 |
| C/C++ | 16 | 1.000 | 0.962 | 0.980 | 22/25 |
| JS/TS | 17 | 1.000 | 0.955 | 0.977 | 21/21 |

Known limits:

- The new misses are kept in the corpus: a concatenated Java algorithm name (`j13`), a C function
  pointer (`c16`), and a JS name computed at run time (`js15`).
- Java key sizes set by `initialize()`, and C key sizes set by a separate call, stay unknown.
  That accounts for 5 of 26 Java and 2 of 25 C params.
- C names resolve to themselves, so a project function reusing an OpenSSL name would match.
- The corpus is still 113 cases across five languages. Milestone 10 needs at least 200, and adds
  competitor tools as an independent check.

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
