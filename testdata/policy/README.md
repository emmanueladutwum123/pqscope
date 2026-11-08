# Policy gate fixtures

Small programs used by the CLI tests and the CI gate check.

| Directory | Contents | `nist-ir-8547-2026` | `cnsa-2.0` |
|---|---|---|---|
| `pq-only` | ML-KEM-1024, SHA-384 | pass | pass |
| `hybrid` | X25519MLKEM768 TLS group, SHA-256 | pass | fail (disallowed-now) |
| `classical` | RSA-2048 key generation | fail (deprecated-2030) | fail (disallowed-now) |
