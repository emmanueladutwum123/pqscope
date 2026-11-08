# Ground-truth corpus

Each case is a directory `<lang>/<case>/` holding one source file and a `labels.yaml`. The
languages are `go`, `python`, `java`, `c` (C and C++) and `js` (JavaScript and TypeScript).

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
