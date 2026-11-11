# Evaluation harness (RQ1)

```sh
make eval         # run competitors and network servers in Docker, score, cross-check
make eval-score   # score whatever eval/out already holds
```

`make eval` runs three steps:

1. **`eval/run.sh all`** runs each competitor once over `testdata/corpus` in a pinned container,
   then starts the network corpus servers and probes them with pqscope. Raw output goes to
   `eval/out/<tool>/`, and every run gets a `tool.json` recording its version, source and status.
   A tool that can't run is recorded as unavailable with the reason.
2. **`pqscope eval`** scans every corpus case with pqscope in-process, reads each competitor's
   output, scores everything against the labels, and writes `paper/data/rq1_*.csv`.
3. **`eval/score.py`** recomputes the summary from the per-item outcomes with a separate
   implementation, and fails if any number differs.

`eval/run.sh competitors` downloads and runs third-party code, namely the images and packages
below. `eval/run.sh network` runs only pqscope, against servers built from `alpine:3.22`.

## Tools

| Tool | What it scans | Pinned as | Output read |
|---|---|---|---|
| pqscope | all five layers | this tree, in-process | findings |
| CBOMkit-theia | certificates, keys, configs in directories (not source) | `ghcr.io/cbomkit/cbomkit-theia@sha256:46a72ead…` | CycloneDX CBOM |
| CBOMkit (sonar-cryptography) | Java and Python source | `ghcr.io/cbomkit/cbomkit-action:v2.3.0@sha256:47c25052…` | CycloneDX CBOM |
| cryptoscan-pqc | source | PyPI `cryptoscan-pqc==0.1.1` in `python:3.12-slim@sha256:5e2bdb1b…` | CycloneDX CBOM |
| pqc-audit | source | `danieleschmidt/pqc-migration-audit@2b11fc59` (its CLI is `pqc-audit`) | JSON report, read by keys |
| Semgrep | source (weak-crypto rules) | `semgrep/semgrep:1.184.0@sha256:cc1b6826…`, rules from `semgrep/semgrep-rules@16b9e6d4` limited to crypto rules for Go, Python, Java, JavaScript and C | Semgrep JSON |
| Keylens | Python and JavaScript source, lockfiles | `qelens/cbom@8d75d874`, built from its Dockerfile (`keylens/cbom` redirects to `qelens/cbom`) | default JSON, read by keys |

The spec named Keylens and pqc-audit. A search on 2026-11-08 missed Keylens because its organization
had been renamed. It is `qelens/cbom` (KeyLens CLI tools). For pqc-audit, the closest match is
pqc-migration-audit, whose command is `pqc-audit`.

## Scoring

Each finding becomes `(case, file, line, algorithm family)`. Families are pqscope's algorithm
names: RSA, ECDSA, ECDH, EdDSA, X25519, DH, DSA, ML-KEM, ML-DSA, SLH-DSA, Hybrid, AES, 3DES, DES,
RC4, ChaCha20-Poly1305, MD5, SHA-1, SHA-2, SHA-3 and HMAC. Other tools' names are mapped by keyword
(`internal/eval/corpus.go`). For Semgrep the rule ID is used, because messages often name the
replacement algorithm too. A generic EC name (`EC`, `EC-secp384r1`, pqc-audit's `ECC`) maps to
ECDSA, the corpus convention for EC keys. That undercounts a tool on lines labeled ECDH. Paths are assigned to cases by their first two components under the
corpus mount.

Each tool is scored on every case at two granularities:

- **file**: file and family. This is fair to tools that report no line numbers, and it is the
  headline metric.
- **line**: file, line and family.

Dependency cases count only post-quantum families (ML-KEM, ML-DSA, SLH-DSA, hybrids), because
post-quantum capability is what the dependency layer adds. Network findings are matched at file
`target`. A tool that doesn't cover a layer scores misses there. That is intended, because RQ1
asks what single-layer tools miss.

## Outputs (`paper/data`)

| File | Contents |
|---|---|
| `rq1_summary.csv` | tp, fp, fn, precision, recall and F1 per tool, granularity, layer and language, with `all` rows |
| `rq1_items.csv` | every scored item and its outcome, which score.py recomputes the summary from |
| `rq1_tools.csv` | version, source and status of every tool |
| `rq1_ablation.csv` | pqscope with each layer turned off, at file granularity |
| `rq1_corpus.csv` | every case, with its layer, language, kind and label count |

## Harness details

- **Competitors never see the answer key.** They scan a staged copy of the corpus without
  `labels.yaml`, READMEs and the network server definitions. A finding in one of those files is
  dropped anyway.
- **CBOMkit runs once per Java and Python case.** Its indexer merges the corpus's many
  `Main.java` and `main.py` files into one module, so it scanned only two cases when run once.
- **A non-zero exit can still count as a run.** If a tool exits non-zero but writes its output
  (pqc-audit exits 1 when it finds something, to gate CI), the run counts, and `rq1_tools.csv`
  records the exit code.

## Caveats

- pqscope's rules and the corpus labels have the same author. Read pqscope's scores as
  consistency with the labeling convention, not independent accuracy. The competitors give the
  independent comparison, though their scores also depend on that convention.
- The keyword mapping can mislabel a competitor's finding whose name is ambiguous. The
  per-item CSV makes every such case checkable.
- Network cases are scored for pqscope only, because no competitor probes endpoints.
