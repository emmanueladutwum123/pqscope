# Risk score

Each finding gets a risk score in [0, 1] that ranks it for migration:

```
risk = exposure × secrecy_lifetime × quantum_status × confidence
```

Every weight is in [`internal/risk/weights.yaml`](../internal/risk/weights.yaml), and the
loader rejects a file that leaves any class, primitive or status without a weight in [0, 1].
The score is an ordering, not a probability. The weights are judgement calls, documented here
so they can be argued with. The paper's ablation (milestone 10) will measure how much each
factor changes the ranking.

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
