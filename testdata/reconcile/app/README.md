# Reconciliation fixture

A small service whose layers disagree. `internal/reconcile` tests scan it with every file layer,
copy in `testdata/binaries/crypto-elf` as `bin/server`, and add network findings for
`app.example:443` (negotiates X25519) and `app.example:22` (offers mlkem768x25519-sha256).

| Derived finding | Why |
|---|---|
| declared-pqc-deployed-classical | `requirements.txt` pins cryptography 48.0.0, which provides ML-KEM, but app.example:443 negotiates X25519 |
| config-overrides-library | `Cargo.lock` vendors OpenSSL 3.5.4 (openssl-src), which supports X25519MLKEM768, but `nginx.conf` lists only X25519 and P-256 |
| binary-without-source | `bin/server` imports RSA, ECDSA, AES, SHA-256 and MD5 functions; `app.py` uses none of them |
| stale-dependency | `Cargo.lock` pins rustls 0.23.10; X25519MLKEM768 arrived in 0.23.22 |
| review flag | `sshd_config` allows curve25519-sha256 only, but app.example:22 offers mlkem768x25519-sha256 |
| corroboration | X25519 appears in `app.py`, `nginx.conf` and the TLS handshake |
