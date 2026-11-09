# Risk score

Each finding gets a risk score in [0, 1] that ranks it for migration:

```
risk = exposure × secrecy_lifetime × quantum_status × confidence
```

Every weight is in [`internal/risk/weights.yaml`](../internal/risk/weights.yaml), and the
loader rejects a file that leaves any class, primitive or status without a weight in [0, 1].
The score is an ordering, not a probability. The weights are judgement calls, documented here
so they can be argued with. [Ablation](#ablation) measures how much each one changes the
ranking.

## Exposure

| Class | Weight | Assigned when |
|---|---|---|
| test | 0.2 | The path looks like test or example code (`test/`, `examples/`, `testdata/`, `*_test.go`, `test_*.py`, `FooTest.java`, ...) |
| network | 1.0 | The finding comes from the network or config layer, or a source symbol configures TLS or SSH (`crypto/tls.`, `golang.org/x/crypto/ssh.`, `ssl.`, `paramiko.`) |
| internal | 0.6 | Anything else |

Test paths are checked first, so a TLS setting in a test file is still test code. The checks
are path and symbol heuristics. pqscope does no reachability analysis, so a crypto call in a
network handler that doesn't touch a TLS API counts as internal.

## Secrecy lifetime

This factor applies Mosca's inequality: migrate now if the data's shelf life plus the
migration time exceeds the time until a cryptographically relevant quantum computer exists.

| Primitive | Weight | Why |
|---|---|---|
| kem, key-agreement, pke | 1.0 | Harvest now, decrypt later. Recorded traffic is already exposed. |
| cipher | 0.8 | Protects confidentiality directly, but quantum attacks only halve key strength |
| signature | 0.5 | A forgery only matters while the signature is still checked or the key trusted |
| mac, hash | 0.3 | Integrity, usually short-lived |

## Quantum status

| Status | Weight |
|---|---|
| broken-now | 1.0 |
| vulnerable | 0.9 |
| weakened | 0.2 |
| hybrid | 0.05 |
| safe | 0.0 |

Broken-now is above vulnerable because it fails without a quantum computer. Hybrid keeps a
small weight because its classical half still needs replacing eventually.

## Confidence

This is the finding's confidence from the source rule, which is already 20% lower when
parameters could not be resolved.

## Worked examples

| Finding | Exposure | Lifetime | Status | Confidence | Risk |
|---|---|---|---|---|---|
| `tls.CurveP256` in server code | 1.0 | 1.0 | 0.9 | 0.90 | 0.81 |
| `rsa.GenerateKey(rand.Reader, 2048)` in `main.go` | 0.6 | 0.5 | 0.9 | 0.95 | 0.26 |
| `md5.Sum` in `x_test.go` | 0.2 | 0.3 | 1.0 | 0.95 | 0.06 |

## Ablation

```sh
make risk-ablation   # paper/data/risk_ablation.csv from paper/data/raw/rq3_findings.tar.gz
```

`pqscope measure risk-ablation` re-scores every finding of the RQ3 scan of critical open-source
projects five ways: with all factors, then with each factor set to 1 for every finding. It
compares each project's ranking with the full score's. Rankings are compared within projects,
because a project migrates its own findings. Derived findings, and projects with fewer than two
findings, are left out. For each scoring, `risk_ablation.csv` has:

| Column | Meaning |
|---|---|
| `pairs_ordered` | Pairs of findings in the same project that the full score orders strictly, summed over projects |
| `reversed`, `reversed_share` | Of those, the pairs this scoring puts the other way round |
| `tied`, `tied_share` | Of those, the pairs this scoring can no longer tell apart |
| `split` | Pairs the full score ties that this scoring orders |
| `top_changed`, `top_changed_share` | Projects whose highest-risk findings (every finding at the top score) differ |
| `tau_b_median`, `tau_b_projects` | Median Kendall's tau-b against the full score, over projects where it is defined |

The pair counts are pooled, so projects with many findings weigh most. The tau-b median and the
top-changed share count each project once. A factor whose removal changes little adds little to
the ranking. That doesn't make it wrong, only redundant on this population.
