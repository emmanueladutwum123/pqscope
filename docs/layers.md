# Dependency and config layers

`pqscope scan` runs three layers by default. Choose them with `--layers source,config,deps`.
The source layer is described in [rules.md](rules.md).

## Dependencies (`deps`)

| File | What is read |
|---|---|
| `go.mod` | `require` directives, plus the `toolchain` directive (or `go` if there is none) as the standard library version |
| `go.sum` | Only when there is no `go.mod` beside it. Modules with source hashes only, at their highest version. |
| `requirements*.txt` | Package lines. Only `==` and `===` pin a version; other specifiers leave it unknown. |
| `poetry.lock`, `Cargo.lock` | `[[package]]` name and version |
| `package-lock.json` | Lockfile v2/v3 `packages`, or v1 nested `dependencies` |
| `pom.xml` | `dependencies` and `dependencyManagement`, with `${property}` substitution |

Each package is looked up in [`internal/knowledge/libs.yaml`](../internal/knowledge/libs.yaml).
For every library it knows, that table cites what the library provides from which version, for
example "pyca/cryptography provides ML-KEM and ML-DSA from 48.0.0". A known library produces one
finding per asset it provides at the declared version. Unknown packages produce nothing.

Covered libraries:

- **Go:** the standard library, CIRCL, `golang.org/x/crypto`
- **Python:** pyca/cryptography, liboqs-python, PyCryptodome
- **JavaScript:** node-forge, jsrsasign, @noble/post-quantum
- **Java:** Bouncy Castle
- **Rust:** rustls, ring, and OpenSSL through `openssl-src`

**A dependency finding means "available", not "used".** Its confidence is 0.5. The finding's
symbol is the package's purl, such as `pkg:pypi/cryptography@48.0.0`. `pqscope policy` lists
deps-only assets but doesn't fail on them unless you pass `--include-deps`. Without that, every
project using a classical-capable library would fail the gate. Reconciliation (milestone 8) will
compare these capabilities with what source, config and the network show.

Limits:

- Versions compare segment by segment. OpenSSL's letter releases, such as `1.1.1k`, would be read
  as pre-releases. No capability row depends on one.
- An unpinned version counts only capabilities available in every version.
- Rows without post-quantum algorithms mean the cited documentation listed none on the table's
  `checked` date.

## Configuration and key material (`config`)

| Source | What is read |
|---|---|
| nginx (`*.conf`, `sites-*`) | `ssl_ecdh_curve`, `ssl_ciphers`, `ssl_conf_command Groups/Curves/CipherString/Ciphersuites` |
| Apache httpd (`*.conf`) | `SSLOpenSSLConfCmd` (same commands), `SSLCipherSuite [TLSv1.3]` |
| `sshd_config`, `ssh_config`, `*_config.d/` | `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms`, `Ciphers`, `MACs` |
| `openssl.cnf`, `*.cnf` | `Groups`, `Curves`, `CipherString`, `Ciphersuites` in any section, plus `default_bits` and `default_md` |
| Kubernetes YAML | `kubernetes.io/tls` Secrets, ingress-nginx ConfigMap `ssl-ciphers`/`ssl-ecdh-curve`, the Ingress `ssl-ciphers` annotation, and cert-manager `Certificate.spec.privateKey` |
| Key material | PEM and DER certificates, CSRs, public and private keys (PKCS#1, PKCS#8, SEC 1, DSA, OpenSSH), DH parameters, `authorized_keys` and `*.pub` |

Names map to assets through [`internal/discover/config/names.yaml`](../internal/discover/config/names.yaml).
Each table there cites its registry or manual: IANA TLS groups, RFC 8446, OpenSSL's cipher names,
OpenSSH and the SSH RFCs, and NIST's post-quantum OIDs. Unknown names are ignored. In SSH lists, a
leading `-` (remove from defaults) produces nothing, and so does a `!` exclusion in an OpenSSL
cipher list. Cipher-string keywords such as `HIGH` need OpenSSL to expand, so they are ignored too.

Key material is recognised by extension (`.pem .crt .cer .key .csr .pub .der .p8`) and by name
(`id_rsa`, `ssh_host_*_key`, `authorized_keys`). Other text files are searched for embedded PEM
blocks, except source code (test vectors belong to the source layer), documentation and lockfiles.

Each certificate produces up to three findings:

- its subject key;
- the issuer's signature algorithm;
- that signature's digest.

The issuer's key size isn't in the certificate, so it's unknown unless the certificate is
self-signed. Post-quantum keys and signatures, and Ed448/X448, which Go's `crypto/x509` doesn't
parse, are recognised by OID.

### Private keys are never output

A private key is reported by its algorithm, size, the SHA-256 fingerprint of its public half,
and its path. Evidence for key material is built only from public data: fingerprints, certificate
names and dates. Evidence for config directives is the directive line, and only lines with a
recognised directive are used.

The guarantee is tested by `TestNoPrivateKeyBytesInAnyOutput`. That test generates RSA, ECDSA,
Ed25519, X25519, DSA-format, ML-DSA (by OID), OpenSSH (plain and passphrase-protected) and
Kubernetes Secret keys at test time. No private key is committed to the repository. The test runs
`scan`, `report` and `policy` with every output format, and then searches each output for every
PEM body line, base64 and hex encoding, and private scalar in hex and decimal. A deliberate leak
of file contents into the evidence field makes it fail.

Encrypted PKCS#8 keys hide their algorithm, so they are listed under "Not classified" instead.
Legacy encrypted PEM keys (`Proc-Type: 4,ENCRYPTED`) show their family but not their size.
