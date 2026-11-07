# Source rule packs

Rule packs live in `rules/<lang>.yaml` and are embedded in the binary. The source layer
parses each file with tree-sitter and matches it against the pack for its language. Go and
Python are supported.

## Pack format

```yaml
version: 1
lang: go            # go | python
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
| `params_from` | Where to read params: `arg[N]`, `kwarg[name]` (Python) or `capture[name]` (queries). The first one that resolves wins. |
| `params_map` | Maps a resolved value, such as `crypto/elliptic.P256`, to params such as `P-256`. |
| `select` | Maps a resolved value to a whole asset, for APIs that take the algorithm as an argument, such as `hashlib.new("md5")`. If the value can't be resolved, nothing is reported. |
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
- Dead code is only recognised in the literal form `if false` (Go), or `if False` / `if 0`
  (Python).
