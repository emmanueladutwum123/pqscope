# Vendored JSON schemas

pqscope's tests validate its CBOM and SARIF output against these files. They are copied
unmodified from upstream, so the tests need no network access. `schemas_test.go` checks
the SHA-256 of each file, so any edit fails the build.

| File | Upstream | SHA-256 |
|---|---|---|
| `bom-1.6.schema.json` | [CycloneDX/specification@1.6.2](https://github.com/CycloneDX/specification/blob/1.6.2/schema/bom-1.6.schema.json) | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| `spdx.schema.json` | [CycloneDX/specification@1.6.2](https://github.com/CycloneDX/specification/blob/1.6.2/schema/spdx.schema.json) | `c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6` |
| `jsf-0.82.schema.json` | [CycloneDX/specification@1.6.2](https://github.com/CycloneDX/specification/blob/1.6.2/schema/jsf-0.82.schema.json) | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `sarif-schema-2.1.0.json` | [oasis-tcs/sarif-spec@a560296](https://github.com/oasis-tcs/sarif-spec/blob/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json) (errata 01) | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |

Validation asserts `format` keywords such as `date-time` and `iri-reference`, which
JSON Schema otherwise treats as annotations.
