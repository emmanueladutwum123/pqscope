# Output formats

`pqscope scan` and `pqscope report` write the same outputs:

| Flag | Format |
|---|---|
| none | Terminal summary on standard output |
| `--json` (scan only) | pqscope findings as a JSON array on standard output; the lossless format |
| `-o file` | CycloneDX 1.6 CBOM |
| `--sarif file` | SARIF 2.1.0 log |
| `--html file` | Self-contained HTML report |

`pqscope report findings.json` renders findings saved with `scan --json`, so a scan can be
reported in several formats without rescanning. It rejects input with unknown fields or a
finding whose ID doesn't match its asset and location.

Files are written through a temporary file and renamed into place, so a failed write leaves
any earlier file untouched.

## Validation

Tests validate CBOM and SARIF output against the official schemas, vendored unmodified in
[`internal/schemas`](../internal/schemas) with their upstream commits and checksums. The CLI
tests scan the whole labeled corpus and validate the result. The schemas' `format` keywords,
such as `date-time`, are asserted rather than treated as annotations.

## CycloneDX CBOM

Each distinct asset, meaning an (algorithm, params, primitive) triple, becomes one
`cryptographic-asset` component with `assetType: algorithm`. Every finding of that asset is
an entry in `evidence.occurrences`, with the finding ID as the occurrence `bom-ref`.

| CycloneDX field | Source |
|---|---|
| `name` | Knowledge DB entry ID, such as `RSA-2048`. Algorithm alone when params are unknown. |
| `bom-ref` | `crypto/algorithm/<algorithm>/<params>/<primitive>` |
| `algorithmProperties.primitive` | Mapped from pqscope primitives. `key-agreement` becomes `key-agree`. `cipher` becomes `block-cipher`, `stream-cipher` or `ae` by algorithm. |
| `algorithmProperties.curve` | std-curves name from the knowledge DB, such as `nist/P-256`, as CycloneDX recommends |
| `algorithmProperties.parameterSetIdentifier` | Params, for assets without a curve. Omitted when unknown. |
| `algorithmProperties.classicalSecurityLevel` | Knowledge DB `classical_bits`, when recorded |
| `algorithmProperties.nistQuantumSecurityLevel` | 0 for quantum-vulnerable and broken assets, which CycloneDX defines as meeting no category. Otherwise the FIPS category from the knowledge DB, or omitted if none is recorded. |
| `evidence.identity` | Highest finding confidence, overall and per technique. The method `value` lists the rules that fired. |
| `evidence.occurrences` | Path, line, symbol and evidence snippet of each finding |

Discovery layers map to evidence techniques as follows: source is `source-code-analysis`,
deps is `manifest-analysis`, binary is `binary-analysis`, network is `dynamic-analysis`, and
config is `other`.

Properties in the `pqscope:` namespace record what CycloneDX has no field for:

| Property | Value |
|---|---|
| `pqscope:quantum` | `vulnerable`, `weakened`, `safe`, `hybrid` or `broken-now` |
| `pqscope:migration:civilian`, `pqscope:migration:cnsa2` | Replacement entry IDs, when the asset needs one |
| `pqscope:policy:<name>` | Worst policy verdict across the asset's findings (filled from milestone 4) |
| `pqscope:risk` | Highest risk score across the asset's findings (filled from milestone 4) |

The CBOM is not lossless. Per-finding confidence and rule IDs are summarised per technique.
Keep the `--json` output when exact findings matter.

## SARIF

One SARIF rule is written per pqscope rule that produced a finding. Each rule has a
generated description, its pack notes as `fullDescription`, and its API citation as
`helpUri`.

| Quantum status | SARIF level |
|---|---|
| `broken-now` | `error` |
| `vulnerable` | `warning` |
| `weakened`, `hybrid`, `safe` | `note` |

Policy verdicts, which arrive in milestone 4, don't change the level yet. The message names
the asset and its migration targets. The finding's asset, confidence and migration are in
the result's property bag, and the finding ID is the partial fingerprint
`pqscopeFindingId/v1`.

Artifact URIs are relative to the scanned directory, under `uriBaseId` `%SRCROOT%`. For
GitHub code scanning, scan the repository root so the paths line up. Network findings carry
a logical location (`kind: endpoint`) instead of a file.

## HTML

The HTML report is one file with inline CSS and a small inline filter script. It makes no
network requests, and its content security policy (`default-src 'none'`) forbids them. All
finding text goes through `html/template` escaping. The report contains:

- counts by quantum status;
- an asset table with migration targets;
- a findings table you can filter by text and status.
