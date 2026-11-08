# Ground-truth corpus

Each case is a directory `<group>/<case>/` holding its files and a `labels.yaml`. Source cases are
grouped by language: `go`, `python`, `java`, `c` (C and C++) and `js` (JavaScript and TypeScript).
The other layers each have a group: `config`, `deps`, `binary` and `network`. There are 202 cases
in all; `paper/data/rq1_corpus.csv` lists them.

Layer-specific conventions:

- **config:** each directive line is labeled with every algorithm family it enables. A certificate,
  key or CSR is labeled at line 1 with its key and, for certificates and CSRs, its signature
  digest. Key material was generated with OpenSSL, and the private keys were discarded, so none
  is committed.
- **deps:** each manifest line is labeled only with the post-quantum capabilities the package
  provides at its version (ML-KEM, ML-DSA, SLH-DSA, hybrids). Hard negatives are versions without
  any.
- **binary:** each binary is labeled at line 0 with the families it imports, or the constants a
  stripped binary contains. The binaries are copies of `testdata/binaries`, built by its
  `build.sh`.
- **network:** `server.env` and `server.sh` describe a server that `eval/run.sh` runs in Docker.
  Findings are labeled at file `target`, line 0. Servers pin their algorithms explicitly, so the
  labels don't depend on software defaults.

```yaml
kind: positive            # positive | hard-positive | hard-negative
description: "..."
expect:
  - {file: main.go, line: 11, algorithm: SHA-2, params: "SHA-256", primitive: hash}
```

`internal/discover/source/corpus_test.go` scans every case and scores it.

## Labeling convention

Labels record what the code does, not what pqscope detects. Cases that pqscope misses stay
in the corpus.

1. Label each line where code names a cryptographic algorithm from a supported library:
   a function call, a constant, or a class.
2. Label each (line, algorithm) pair at most once.
3. Curves and key sizes passed as arguments are params of the labeled call, not separate
   labels. Hashes are separate labels, because they are algorithms in their own right.
4. Type mentions, such as `*rsa.PrivateKey` in a signature, are not labeled.
5. A method call on a key object is labeled only when the file never names the algorithm
   any other way, so its type is the only evidence (case `g24-type-only`).
6. Signature-algorithm identifiers such as `x509.SHA256WithRSA` are labeled by their
   public-key algorithm only.
7. `params` is the true value when a reader can determine it from the case. Use
   `"unknown"` only when the code doesn't determine it.
8. Comments, strings, code under `if false`, and unrelated packages with crypto-like names
   are not labeled.

## Scoring

A finding matches a label when file, line and algorithm agree. Precision and recall come from
those matches. Params and primitive agreement are reported separately, for matched findings
only.

## Limitations

The same author wrote the rules and the labels, so these scores measure consistency with the
convention above more than real-world accuracy. The independent evaluation, with competitor
tools and a larger corpus, belongs to milestone 10.

## Generated cases

The `java`, `c` and `js` cases were written with an inline-marker generator: each expected
finding was marked on its source line, and the marker was turned into the label. Labels therefore
always point at the right line. They still record what the code does, including findings pqscope
is known to miss (`j13`, `c16`, `js15`) and params it can't resolve.
