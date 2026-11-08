# Source rule packs

Rule packs live in `rules/<lang>.yaml` and are embedded in the binary. The source layer
parses each file with tree-sitter and matches it against the pack for its language. Go and
Python are supported.

## Pack format

```yaml
version: 1
lang: go            # go | python | java | c | js
rules:
  - id: go.rsa.generate
    call: crypto/rsa.GenerateKey
    asset: {primitive: signature, algorithm: RSA}
    params_from: arg[1]
    confidence: 0.95
    source: https://pkg.go.dev/crypto/rsa#GenerateKey
```

| Field | Meaning |
|---|---|
| `id` | Unique across all packs. |
| `call` | One or more fully qualified functions. Matches calls, so arguments are available. |
| `ref` | One or more fully qualified symbols. Matches any reference, called or not. |
| `query` | A raw tree-sitter query. `@match` (or the first capture) is the location. |
| `asset` | `primitive`, `algorithm` and optionally fixed `params`. |
| `params_from` | Where to read params: `arg[N]`, `arg[N].prop` (a property of an object literal, such as Node's `{modulusLength: 2048}`), `kwarg[name]` (Python) or `capture[name]` (queries). The first one that resolves wins. |
| `params_map` | Maps a resolved value, such as `crypto/elliptic.P256`, to params such as `P-256`. |
| `select` | Maps a resolved value to a whole asset, for APIs that take the algorithm as an argument, such as `hashlib.new("md5")`. Keys match case-insensitively, and a key ending in `*` matches by prefix (`AES/*`, `aes-256-*`), with the longest prefix winning. If the value can't be resolved, nothing is reported. |
| `select_params_from` | For `select` rules, where to read params the selected asset leaves open, such as the curve in `generateKeyPairSync('ec', {namedCurve})`. A value is used only if the knowledge DB knows it for the selected algorithm, after `params_map`. |
| `confidence` | 0 to 1. Multiplied by 0.8 when `params_from` can't resolve a value. |
| `source` | Required https citation for the API behaviour the rule relies on. |
| `notes` | Optional; known limitations of the rule. |

Each rule needs exactly one of `call`, `ref` or `query`. Each symbol belongs to one rule, so
one reference can't produce duplicate findings. The loader rejects a pack whose algorithms,
params or primitives don't match the knowledge DB.

## Why symbols instead of raw queries

A query like `(#eq? @fn "rsa.GenerateKey")` matches text. It misses `r.GenerateKey` after
`import r "crypto/rsa"`, and it fires on an unrelated package that happens to be named
`rsa`. `call` and `ref` rules first resolve each reference through the file's imports to a
fully qualified symbol, so both cases are handled. Raw queries remain available for patterns
that can't be resolved this way, such as a method called on an object of unknown type.

## Static resolution

Arguments are evaluated without running the code:

- integer and string literals; Python f-strings are not treated as literals;
- references to imported symbols, including calls such as `elliptic.P256()`;
- names assigned exactly once in the same file, following up to four hops.

Anything else, including function parameters, leaves params as `unknown`.

## Known blind spots

- Methods called on a typed value, such as `k.Sign(...)` where `k` is a `*rsa.PrivateKey`
  parameter, aren't attributed to an algorithm.
- Dynamic lookups such as `getattr(hashlib, "md5")` aren't resolved.
- Values passed into a wrapper function aren't traced across the call.
- A Python EC key from `ec.generate_private_key` is reported as ECDSA even when it is used
  for ECDH.
- Dead code is only recognised in literal forms: `if false` (Go, Java, JS/TS, C++), `if False`
  / `if 0` (Python), `if (0)` and `#if 0` (C/C++).
- Java: the key size or curve passed to a later `initialize()` call isn't linked to the
  `getInstance()` that created the generator, so it stays unknown. `XDH` names a family, not one
  algorithm, and isn't reported.
- C/C++: a function referenced without being called, such as `md = EVP_sha1;`, isn't seen. Neither
  is a key size set by a separate call, such as `EVP_PKEY_CTX_set_rsa_keygen_bits` after
  `EVP_PKEY_CTX_new_id`. Names resolve to themselves, so a project function that reuses an OpenSSL
  name, such as `RSA_new`, would match. C++ qualified names (`mylib::MD5`) and member calls
  (`k->RSA_new()`) don't.
- JS/TS: algorithm names computed at run time (`['sha', '256'].join('')`, template literals with
  substitutions) aren't resolved. `crypto` is treated as WebCrypto's global unless the file defines
  its own `crypto`.

## Languages

| Pack | Files | Imports and names | Libraries |
|---|---|---|---|
| `go.yaml` | `.go` | Import paths, with aliases | Standard library, `golang.org/x/crypto`, CIRCL |
| `python.yaml` | `.py` | `import`, `from ... import`, aliases | pyca/cryptography, hashlib, hmac, PyCryptodome, paramiko, PyNaCl, liboqs-python, ssl |
| `java.yaml` | `.java` | Single-type and wildcard imports, fully qualified names | JCA (`KeyPairGenerator`, `Signature`, `Cipher`, `KEM`, ...), `NamedParameterSpec` constants including ML-KEM and ML-DSA |
| `c.yaml` | `.c`, `.h` (C grammar); `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`, `.hxx` (C++ grammar) | Global function names; macro constants as arguments; `#define` and single-assignment variables followed | OpenSSL 1.x and 3.x (including ML-KEM/ML-DSA by name), libsodium, liboqs, Windows CNG |
| `js.yaml` | `.js`, `.mjs`, `.cjs`, `.jsx` (JavaScript grammar); `.ts`, `.mts`, `.cts` (TypeScript); `.tsx` (TSX) | ES imports (default, namespace, named, aliased), `require()` with destructuring, the `node:` prefix, the WebCrypto global | Node.js `crypto` (including ML-KEM and ML-DSA key types), WebCrypto, node-forge, jsrsasign, noble, TweetNaCl |
