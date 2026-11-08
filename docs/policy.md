# Policies

pqscope evaluates every finding against versioned policy files in [`policies/`](../policies).
`pqscope scan` records each policy's verdict on each finding. `pqscope policy` turns the verdicts
into a CI gate.

```sh
pqscope scan . -o cbom.json
pqscope policy cbom.json                                  # NIST IR 8547, fail on disallowed-2035 or worse
pqscope policy --policy cnsa-2.0 --fail-on disallowed-now cbom.json
pqscope scan . --json | pqscope policy -                  # saved findings work too
```

Assets seen only in dependency manifests are what a library makes available, not what the code
uses. The gate lists them as `deps` and doesn't fail on them unless you pass `--include-deps`.

| Exit code | Meaning |
|---|---|
| 0 | No asset reaches `--fail-on` |
| 1 | At least one asset reaches `--fail-on` |
| 2 | Error: bad input, unknown policy or flag |

## Statuses

From least to most urgent:

| Status | Meaning |
|---|---|
| `compliant` | Allowed with no scheduled end |
| `disallowed-2035` | Allowed today, disallowed after 2035 |
| `deprecated-2030` | Allowed today, restricted after 2030 (the row's schedule gives the exact transition) |
| `disallowed-now` | Not allowed today, though not broken: removed from the standard, below its minimum strength, or outside the suite |
| `broken-now` | Insecure against classical attack today |
| `unknown` | The policy can't decide |

`disallowed-now` is not in the spec's original list. It is there because "broken" would be
false for DSA-2048, ChaCha20-Poly1305, or ML-KEM-768 under CNSA 2.0. Anything the knowledge DB
marks `broken-now` is `broken-now` under every policy; the loader enforces it.

`--fail-on` defaults to `disallowed-2035`, which fails on anything a policy disallows now or
later. Under NIST IR 8547 that means all quantum-vulnerable public-key crypto. Use
`--fail-on disallowed-now` to fail only on what is disallowed today.

### Unknown parameters

When a finding's params are unknown, such as an RSA key whose size comes from a function
argument, every knowledge DB entry of the family used as the same primitive is considered:

- If their rules agree, that status applies. All AES sizes are compliant under NIST IR 8547.
- If not, the status is `unknown`, and `at_best` records the least urgent status the asset
  could have. Unknown-size RSA is at best `deprecated-2030` under NIST IR 8547, because
  RSA-1024 would be `disallowed-now`.

An unknown asset fails the gate only if its best case reaches the threshold. Unknown-size RSA
fails the default gate. An algorithm no rule covers stays `unknown` with no best case and never
fails.

## Policy format

```yaml
version: 1
id: nist-ir-8547-2026          # must match the file name
title: NIST IR 8547 (final, October 2026)
sources:
  ir8547: {title: "...", url: "https://doi.org/10.6028/NIST.IR.8547"}
rules:
  - id: rsa-signature
    entries: [RSA-2048, RSA-3072, RSA-4096]   # knowledge DB entry IDs
    primitives: [signature]                   # optional; default is every primitive of each entry
    status: deprecated-2030
    schedule: Deprecated after 2030; disallowed after 2035
    legacy_use: "..."                         # optional
    note: "..."                               # optional
    cite: {source: ir8547, section: "Sec. 4.1.1, Table 2"}
```

The loader rejects a policy unless every (entry, primitive) pair in the knowledge DB is matched
by exactly one rule. Adding an algorithm to the knowledge DB therefore forces a decision in every
policy. `internal/policy/policy_test.go` holds a hand-written table of the expected status of all
66 pairs under both policies.

## NIST IR 8547 (`nist-ir-8547-2026`)

Built from the final report (October 2026). Section numbers were read from the PDF.

- **Quantum-vulnerable at ≥ 112 bits** (RSA, ECDSA, EdDSA, ECDH, finite-field DH, MQV): Tables 2
  and 4 give one schedule for all of them, deprecated after 2030 and disallowed after 2035
  (`deprecated-2030`). The final report does not split them by strength. X25519 and X448 are
  covered by the Sec. 4.1.2 statement that all quantum-vulnerable cryptography follows this
  schedule.
- **Already disallowed:** RSA-1024 (SP 800-131A Rev. 2, Sec. 3 and 6) and DSA, which FIPS 186-5
  Sec. 4 no longer approves for signing.
- **Compliant:** ML-KEM, ML-DSA, SLH-DSA (Tables 3 and 5), AES (Table 6), SHA-2 and SHA-3
  (Table 8), and HMAC with SHA-2. Hybrids with an ML-KEM component are compliant by the Sec. 3.2.1
  rule that a combination is FIPS-validatable when one input is approved.
- **Not approved:** sntrup761 and ChaCha20-Poly1305 are `disallowed-now`. sntrup761x25519 is
  `unknown`, because it is not settled whether X25519 counts as an approved input.
- **HMAC-SHA-1:** footnote 4 deprecates SHA-1 for all remaining uses and disallows it in
  FIPS-validated modules after 2030 (`deprecated-2030`).

## CNSA 2.0 (`cnsa-2.0`)

- **Compliant:** the suite, ML-KEM-1024, ML-DSA-87, AES-256, SHA-384 and SHA-512, plus HMAC on a
  suite hash.
- **`disallowed-2035`:** CNSA 1.0 algorithms (RSA-3072/4096, P-384, DH-3072), which the profile
  calls a bridge.
- **`disallowed-now`:** everything else. That includes ML-KEM-768, ML-DSA-65, SLH-DSA and every
  hybrid, because a CNSA-compliant TLS server must not accept them.

**Limitation:** the NSA advisory that sets per-equipment-class exclusive-use dates (2030 to 2033)
could not be retrieved by script, so those dates are not encoded. CNSA 1.0 algorithms carry the
NSM-10 2035 target that IR 8547 Sec. 4 restates, which is the latest possible date, not the date
that applies to every system. The suite itself is sourced from NSA-authored documents: the CNSA 2.0
TLS 1.3 profile (draft-becker-cnsa2-tls-profile-05) and RFC 9151.
